# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

"""Structure aware fuzz tests for SPNEGO and NTLM token parsing.

These tests generate bounded malformed inputs around the ASN.1 TLV
structures, the SPNEGO negotiation tokens, the NTLM length/offset
security buffers, and the NTLM AV_PAIR layouts. Malformed inputs must
only ever surface as library defined protocol errors (subclasses of
:class:`spnego.exceptions.SpnegoError`) at the public ``step()``
boundary. They must never leak ``ValueError``, ``KeyError``, or any
other unhandled exception to the caller.

The valid token parse/repack round trips are fully deterministic, they
do not depend on the time of day, external services, or uncontrolled
randomness. Every failing input keeps its structural information, either
in the test id or in the failure message as a hex dump, so the offending
bytes can always be reproduced.
"""

import struct
import typing

import pytest

import spnego
import spnego._spnego as sp
from spnego._asn1 import (
    TagClass,
    TypeTagNumber,
    pack_asn1,
    pack_asn1_enumerated,
    pack_asn1_object_identifier,
    pack_asn1_octet_string,
    pack_asn1_sequence,
)
from spnego._context import GSSMech
from spnego._ntlm_raw.messages import (
    Authenticate,
    AvFlags,
    AvId,
    Challenge,
    FileTime,
    Negotiate,
    NegotiateFlags,
    NTClientChallengeV2,
    NTLMMessage,
    SingleHost,
    TargetInfo,
    Version,
)
from spnego.exceptions import SpnegoError

# Fixed values so the valid tokens are byte for byte reproducible no
# matter when or where the tests run.
FIXED_SERVER_CHALLENGE = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
FIXED_TIMESTAMP = FileTime(2021, 4, 5, 6, 7, 8)  # naive datetimes are treated as UTC when packed
FIXED_VERSION = Version(major=6, minor=1, build=7601, revision=0x0F)

BASE_FLAGS = (
    NegotiateFlags.unicode
    | NegotiateFlags.request_target
    | NegotiateFlags.ntlm
    | NegotiateFlags.always_sign
    | NegotiateFlags.extended_session_security
    | NegotiateFlags.target_info
    | NegotiateFlags.key_128
    | NegotiateFlags.key_56
)


def build_target_info() -> TargetInfo:
    """Builds a deterministic TargetInfo with a mix of AV_PAIR types."""
    target_info = TargetInfo()
    target_info[AvId.nb_computer_name] = "SERVER01"
    target_info[AvId.nb_domain_name] = "DOMAIN"
    target_info[AvId.dns_computer_name] = "server01.domain.local"
    target_info[AvId.timestamp] = FIXED_TIMESTAMP
    target_info[AvId.flags] = AvFlags.mic
    target_info[AvId.channel_bindings] = b"\xaa" * 16
    target_info[AvId.single_host] = SingleHost(size=48, z4=0, custom_data=b"\x01" * 8, machine_id=b"\x02" * 32)

    return target_info


def build_ntlm_negotiate() -> bytes:
    """Builds a deterministic NTLM Negotiate message."""
    return Negotiate(
        flags=BASE_FLAGS | NegotiateFlags.version,
        domain_name="DOMAIN",
        workstation="WORKSTATION",
        version=FIXED_VERSION,
    ).pack()


def build_ntlm_challenge() -> bytes:
    """Builds a deterministic NTLM Challenge message."""
    return Challenge(
        flags=BASE_FLAGS | NegotiateFlags.target_type_server | NegotiateFlags.version,
        server_challenge=FIXED_SERVER_CHALLENGE,
        target_name="DOMAIN",
        target_info=build_target_info(),
        version=FIXED_VERSION,
    ).pack()


def build_ntlm_authenticate() -> bytes:
    """Builds a deterministic NTLM Authenticate message."""
    return Authenticate(
        flags=BASE_FLAGS | NegotiateFlags.key_exch | NegotiateFlags.version,
        lm_challenge_response=b"\x11" * 24,
        nt_challenge_response=b"\x22" * 24,
        domain_name="DOMAIN",
        username="user",
        workstation="WORKSTATION",
        encrypted_session_key=b"\x33" * 16,
        version=FIXED_VERSION,
        mic=b"\x44" * 16,
    ).pack()


def build_neg_token_init() -> bytes:
    """Builds a deterministic SPNEGO NegTokenInit wrapped in an InitialContextToken."""
    return sp.NegTokenInit(
        mech_types=[GSSMech.ntlm.value, GSSMech.kerberos.value],
        req_flags=sp.ContextFlags.mutual | sp.ContextFlags.conf,
        mech_token=build_ntlm_negotiate(),
        mech_list_mic=b"\x55" * 16,
    ).pack()


def build_neg_token_init2() -> bytes:
    """Builds a deterministic SPNEGO NegTokenInit2 with the negHints field."""
    return sp.NegTokenInit(
        mech_types=[GSSMech.ntlm.value],
        hint_name=b"not_defined_in_RFC4178@please_ignore",
        hint_address=b"\x01\x02\x03\x04",
        mech_list_mic=b"\x66" * 16,
    ).pack()


def build_neg_token_resp() -> bytes:
    """Builds a deterministic SPNEGO NegTokenResp."""
    return sp.NegTokenResp(
        neg_state=sp.NegState.accept_incomplete,
        supported_mech=GSSMech.ntlm.value,
        response_token=b"\x77" * 8,
        mech_list_mic=b"\x88" * 16,
    ).pack()


def build_nested_initial_context_token(depth: int) -> bytes:
    """Builds an InitialContextToken nested ``depth`` levels deep."""
    token = pack_asn1(TagClass.context_specific, True, 0, pack_asn1_sequence([]))
    for _ in range(depth):
        token = pack_asn1(
            TagClass.application,
            True,
            0,
            pack_asn1_object_identifier(GSSMech.spnego.value, tag=True) + token,
        )

    return token


def build_challenge_with_target_info(target_info: bytes, declared_length: typing.Optional[int] = None) -> bytes:
    """Builds an NTLM Challenge message with a raw TargetInfo payload.

    The message is packed manually so the TargetInfo bytes can contain
    malformed AV_PAIR structures that the normal packers would never
    produce. The declared_length can override the security buffer
    length to declare more bytes than the message actually contains.
    """
    flags = BASE_FLAGS & ~NegotiateFlags.version
    msg = bytearray(b"NTLMSSP\x00" + struct.pack("<I", 2))
    msg += struct.pack("<HHI", 0, 0, 48 + len(target_info))  # TargetName, empty
    msg += struct.pack("<I", flags)
    msg += FIXED_SERVER_CHALLENGE
    msg += b"\x00" * 8  # Reserved
    length = len(target_info) if declared_length is None else declared_length
    msg += struct.pack("<HHI", length, length, 48)  # TargetInfo
    msg += target_info

    return bytes(msg)


def build_authenticate_with_av_pairs(av_pairs: bytes, domain: str, username: str) -> bytes:
    """Builds an NTLM Authenticate message with a raw NTLMv2 AV_PAIR payload."""
    nt_client_challenge = (
        b"\x01\x01"  # RespType, HiRespType
        + b"\x00" * 2  # Reserved1
        + b"\x00" * 4  # Reserved2
        + FIXED_TIMESTAMP.pack()
        + b"\xcc" * 8  # ChallengeFromClient
        + b"\x00" * 4  # Reserved3
        + av_pairs
    )
    nt_response = b"\x00" * 16 + nt_client_challenge

    return Authenticate(
        flags=BASE_FLAGS & ~NegotiateFlags.version & ~NegotiateFlags.target_info,
        nt_challenge_response=nt_response,
        domain_name=domain,
        username=username,
    ).pack()


def build_negotiate_with_domain_buffer(length: int, offset: int) -> bytes:
    """Builds an NTLM Negotiate message with a mutated DomainName security buffer."""
    msg = bytearray(build_ntlm_negotiate())
    msg[16:24] = struct.pack("<HHI", length, length, offset)

    return bytes(msg)


def _spnego_acceptor_step(token: bytes) -> None:
    """Feeds a token to a SPNEGO acceptor, requires the ntlm_cred fixture."""
    server = spnego.server(protocol="negotiate", options=spnego.NegotiateOptions.use_negotiate)
    server.step(in_token=token)


def _spnego_initiator_step(token: bytes) -> None:
    """Feeds a token to a SPNEGO initiator that has sent its NegTokenInit."""
    client = spnego.client(
        username="user",
        password="password",
        protocol="negotiate",
        options=spnego.NegotiateOptions.use_negotiate | spnego.NegotiateOptions.use_ntlm,
    )
    client.step()
    client.step(in_token=token)


def _ntlm_acceptor_step(token: bytes) -> None:
    """Feeds a token to an NTLM acceptor, requires the ntlm_cred fixture."""
    server = spnego.server(protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)
    server.step(in_token=token)


def _ntlm_acceptor_authenticate_step(token: bytes) -> None:
    """Feeds an Authenticate message to an NTLM acceptor, requires the ntlm_cred fixture."""
    server = spnego.server(protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)
    server.step(in_token=build_ntlm_negotiate())
    server.step(in_token=token)


def _ntlm_initiator_step(token: bytes) -> None:
    """Feeds a Challenge message to an NTLM initiator."""
    client = spnego.client(
        username="user",
        password="password",
        protocol="ntlm",
        options=spnego.NegotiateOptions.use_ntlm,
    )
    client.step()
    client.step(in_token=token)


def _assert_raises_library_error(step_func, token: bytes) -> None:
    """Asserts a malformed token raises a library defined error with the input structure preserved."""
    try:
        step_func(token)
    except SpnegoError:
        return
    except Exception as e:
        pytest.fail(
            f"Malformed input leaked {type(e).__name__} instead of a library defined error: {e}\n"
            f"input ({len(token)} bytes): {token.hex()}"
        )

    pytest.fail(f"Malformed input ({len(token)} bytes) did not raise an error: {token.hex()}")


def _assert_no_foreign_exception(step_func, token: bytes, mutation: str) -> None:
    """Asserts a mutated token either parses or raises a library defined error."""
    try:
        step_func(token)
    except SpnegoError:
        pass
    except Exception as e:
        pytest.fail(
            f"Malformed input leaked {type(e).__name__} instead of a library defined error: {e}\n"
            f"mutation: {mutation}\n"
            f"input ({len(token)} bytes): {token.hex()}"
        )


def _mutations(token: bytes):
    """Generates bounded deterministic truncations and single byte flips of a token."""
    for i in range(len(token)):
        yield f"truncated at offset {i}", token[:i]
        yield f"byte at offset {i} flipped", token[:i] + bytes([token[i] ^ 0xFF]) + token[i + 1 :]


# ---------------------------------------------------------------------------
# Valid token parse/repack round trips - byte and semantic identity
# ---------------------------------------------------------------------------


def test_neg_token_init_round_trip():
    raw = build_neg_token_init()
    assert build_neg_token_init() == raw, "token generation is not deterministic"

    token = sp.unpack_token(raw)

    assert isinstance(token, sp.NegTokenInit)
    assert token.mech_types == [GSSMech.ntlm.value, GSSMech.kerberos.value]
    assert token.req_flags == sp.ContextFlags.mutual | sp.ContextFlags.conf
    assert token.mech_token == build_ntlm_negotiate()
    assert token.hint_name is None
    assert token.hint_address is None
    assert token.mech_list_mic == b"\x55" * 16

    assert token.pack() == raw
    assert sp.unpack_token(token.pack()).pack() == raw


def test_neg_token_init2_round_trip():
    raw = build_neg_token_init2()
    assert build_neg_token_init2() == raw, "token generation is not deterministic"

    token = sp.unpack_token(raw)

    assert isinstance(token, sp.NegTokenInit)
    assert token.mech_types == [GSSMech.ntlm.value]
    assert token.req_flags is None
    assert token.mech_token is None
    assert token.hint_name == b"not_defined_in_RFC4178@please_ignore"
    assert token.hint_address == b"\x01\x02\x03\x04"
    assert token.mech_list_mic == b"\x66" * 16

    assert token.pack() == raw
    assert sp.unpack_token(token.pack()).pack() == raw


def test_neg_token_resp_round_trip():
    raw = build_neg_token_resp()
    assert build_neg_token_resp() == raw, "token generation is not deterministic"

    token = sp.unpack_token(raw)

    assert isinstance(token, sp.NegTokenResp)
    assert token.neg_state == sp.NegState.accept_incomplete
    assert token.supported_mech == GSSMech.ntlm.value
    assert token.response_token == b"\x77" * 8
    assert token.mech_list_mic == b"\x88" * 16

    assert token.pack() == raw
    assert sp.unpack_token(token.pack()).pack() == raw


def test_ntlm_negotiate_round_trip():
    raw = build_ntlm_negotiate()
    assert build_ntlm_negotiate() == raw, "message generation is not deterministic"

    msg = Negotiate.unpack(raw)

    expected_flags = (
        BASE_FLAGS
        | NegotiateFlags.version
        | NegotiateFlags.oem_domain_name_supplied
        | NegotiateFlags.oem_workstation_supplied
    )
    assert msg.flags == expected_flags
    assert msg.domain_name == "DOMAIN"
    assert msg.workstation == "WORKSTATION"
    assert msg.version == FIXED_VERSION

    rebuilt = Negotiate(flags=msg.flags, domain_name=msg.domain_name, workstation=msg.workstation, version=msg.version)
    assert rebuilt.pack() == raw
    assert msg.pack() == raw


def test_ntlm_challenge_round_trip():
    raw = build_ntlm_challenge()
    assert build_ntlm_challenge() == raw, "message generation is not deterministic"

    msg = Challenge.unpack(raw)

    assert msg.flags & NegotiateFlags.unicode
    assert msg.flags & NegotiateFlags.target_info
    assert msg.server_challenge == FIXED_SERVER_CHALLENGE
    assert msg.target_name == "DOMAIN"
    assert msg.version == FIXED_VERSION

    target_info = msg.target_info
    assert isinstance(target_info, TargetInfo)
    assert target_info[AvId.nb_computer_name] == "SERVER01"
    assert target_info[AvId.nb_domain_name] == "DOMAIN"
    assert target_info[AvId.dns_computer_name] == "server01.domain.local"
    assert target_info[AvId.timestamp] == FIXED_TIMESTAMP
    assert target_info[AvId.flags] == AvFlags.mic
    assert target_info[AvId.channel_bindings] == b"\xaa" * 16
    assert target_info[AvId.single_host] == SingleHost(
        size=48, z4=0, custom_data=b"\x01" * 8, machine_id=b"\x02" * 32
    )

    rebuilt = Challenge(
        flags=msg.flags,
        server_challenge=msg.server_challenge,
        target_name=msg.target_name,
        target_info=msg.target_info,
        version=msg.version,
    )
    assert rebuilt.pack() == raw
    assert msg.pack() == raw


def test_ntlm_authenticate_round_trip():
    raw = build_ntlm_authenticate()
    assert build_ntlm_authenticate() == raw, "message generation is not deterministic"

    msg = Authenticate.unpack(raw)

    assert msg.flags & NegotiateFlags.unicode
    assert msg.flags & NegotiateFlags.key_exch
    assert msg.lm_challenge_response == b"\x11" * 24
    assert msg.nt_challenge_response == b"\x22" * 24
    assert msg.domain_name == "DOMAIN"
    assert msg.user_name == "user"
    assert msg.workstation == "WORKSTATION"
    assert msg.encrypted_random_session_key == b"\x33" * 16
    assert msg.version == FIXED_VERSION
    assert msg.mic == b"\x44" * 16

    rebuilt = Authenticate(
        flags=msg.flags,
        lm_challenge_response=msg.lm_challenge_response,
        nt_challenge_response=msg.nt_challenge_response,
        domain_name=msg.domain_name,
        username=msg.user_name,
        workstation=msg.workstation,
        encrypted_session_key=msg.encrypted_random_session_key,
        version=msg.version,
        mic=msg.mic,
    )
    assert rebuilt.pack() == raw
    assert msg.pack() == raw


def test_target_info_round_trip():
    raw = build_target_info().pack()
    assert build_target_info().pack() == raw, "AV_PAIR generation is not deterministic"

    target_info = TargetInfo.unpack(raw)

    assert list(target_info) == [
        AvId.nb_computer_name,
        AvId.nb_domain_name,
        AvId.dns_computer_name,
        AvId.timestamp,
        AvId.flags,
        AvId.channel_bindings,
        AvId.single_host,
        AvId.eol,
    ]
    assert target_info.pack() == raw
    assert TargetInfo.unpack(target_info.pack()).pack() == raw


def test_unpack_token_deeply_nested_initial_context_token():
    # A deeply nested token must not exhaust the Python stack.
    token = build_nested_initial_context_token(1500)

    actual = sp.unpack_token(token)

    assert isinstance(actual, sp.NegTokenInit)
    assert actual.mech_types == []


# ---------------------------------------------------------------------------
# Malformed SPNEGO/ASN.1 inputs - must raise a library defined error
# ---------------------------------------------------------------------------

_ICT_BODY = pack_asn1_object_identifier(GSSMech.spnego.value, tag=True) + pack_asn1(
    TagClass.context_specific, True, 0, pack_asn1_sequence([])
)


def _ict(inner: bytes) -> bytes:
    return sp.InitialContextToken(GSSMech.spnego.value, inner).pack()


SPNEGO_ACCEPTOR_MALFORMED = [
    pytest.param(b"\x60", id="tlv-missing-length-octet"),
    pytest.param(b"\x60\x83\x01\x02", id="tlv-long-form-length-octets-truncated"),
    pytest.param(b"\x7f\x81", id="tlv-high-tag-number-form-truncated"),
    pytest.param(b"\x1f\x25\x00", id="tlv-unknown-universal-tag-number"),
    pytest.param(b"\x60\x84\xff\xff\xff\xff" + _ICT_BODY, id="tlv-overlong-declared-length"),
    pytest.param(b"\x60\x82\xff\xff" + _ICT_BODY, id="tlv-declared-length-exceeds-remaining"),
    pytest.param(b"\x60\x00" + _ICT_BODY, id="tlv-zero-length-with-content"),
    pytest.param(b"\x60\x80" + _ICT_BODY + b"\x00\x00", id="tlv-indefinite-length"),
    pytest.param(
        pack_asn1(TagClass.application, True, 1, _ICT_BODY),
        id="initial-context-token-wrong-application-tag-number",
    ),
    pytest.param(
        pack_asn1(TagClass.context_specific, True, 2, pack_asn1_sequence([])),
        id="negotiation-token-unknown-choice",
    ),
    pytest.param(
        sp.NegTokenInit(mech_types=[]).pack(),
        id="neg-token-init-empty-mech-types",
    ),
    pytest.param(
        sp.NegTokenInit(mech_types=["1.2.3.4"]).pack(),
        id="neg-token-init-unknown-mech-oid",
    ),
    pytest.param(
        _ict(
            pack_asn1(
                TagClass.context_specific,
                True,
                0,
                pack_asn1_sequence(
                    [
                        pack_asn1(
                            TagClass.context_specific,
                            True,
                            0,
                            pack_asn1_sequence([pack_asn1_octet_string(b"\x2b")]),
                        )
                    ]
                ),
            )
        ),
        id="neg-token-init-mech-types-not-an-oid",
    ),
    pytest.param(
        _ict(
            pack_asn1(
                TagClass.context_specific,
                True,
                0,
                pack_asn1_sequence(
                    [pack_asn1(TagClass.context_specific, True, 7, pack_asn1_octet_string(b"\x01\x02"))]
                ),
            )
        ),
        id="neg-token-init-unknown-context-tag",
    ),
    pytest.param(
        sp.NegTokenInit(
            mech_types=[GSSMech.ntlm.value],
            mech_token=b"NTLMSSP\x00" + struct.pack("<I", 99) + b"\x00" * 40,
        ).pack(),
        id="neg-token-init-ntlm-unknown-message-type",
    ),
    pytest.param(
        build_nested_initial_context_token(1500),
        id="initial-context-token-deeply-nested",
    ),
]


@pytest.mark.parametrize("token", SPNEGO_ACCEPTOR_MALFORMED)
def test_fuzz_spnego_acceptor_malformed_raises_library_error(token, ntlm_cred):
    _assert_raises_library_error(_spnego_acceptor_step, token)


def test_fuzz_spnego_acceptor_truncated_neg_token_init_raises_library_error(ntlm_cred):
    token = build_neg_token_init()
    truncated = token[: len(token) // 2]

    _assert_raises_library_error(_spnego_acceptor_step, truncated)


SPNEGO_INITIATOR_MALFORMED = [
    pytest.param(
        pack_asn1(
            TagClass.context_specific,
            True,
            1,
            pack_asn1_sequence(
                [
                    pack_asn1(
                        TagClass.context_specific,
                        True,
                        0,
                        pack_asn1(TagClass.universal, False, TypeTagNumber.enumerated, b"\x63"),
                    )
                ]
            ),
        ),
        id="neg-token-resp-unknown-neg-state",
    ),
    pytest.param(
        pack_asn1(
            TagClass.context_specific,
            True,
            1,
            pack_asn1_sequence(
                [
                    pack_asn1(
                        TagClass.context_specific,
                        True,
                        0,
                        pack_asn1(TagClass.universal, False, TypeTagNumber.enumerated, b""),
                    )
                ]
            ),
        ),
        id="neg-token-resp-empty-neg-state",
    ),
    pytest.param(
        sp.NegTokenResp(neg_state=sp.NegState.accept_incomplete, supported_mech="1.2.3.4.5").pack(),
        id="neg-token-resp-unknown-supported-mech",
    ),
    pytest.param(
        sp.NegTokenResp(neg_state=sp.NegState.accept_incomplete, supported_mech=GSSMech.spnego.value).pack(),
        id="neg-token-resp-unoffered-supported-mech",
    ),
    pytest.param(
        sp.NegTokenResp(neg_state=sp.NegState.reject).pack(),
        id="neg-token-resp-reject-without-token",
    ),
    pytest.param(
        build_neg_token_resp()[:5],
        id="neg-token-resp-truncated",
    ),
]


@pytest.mark.parametrize("token", SPNEGO_INITIATOR_MALFORMED)
def test_fuzz_spnego_initiator_malformed_raises_library_error(token):
    _assert_raises_library_error(_spnego_initiator_step, token)


SPNEGO_ACCEPTOR_MALFORMED_NO_RAISE = [
    pytest.param(b"", id="empty-token"),
    pytest.param(
        _ict(
            pack_asn1(
                TagClass.context_specific,
                True,
                0,
                pack_asn1_sequence(
                    [
                        pack_asn1(
                            TagClass.context_specific,
                            True,
                            0,
                            sp.pack_mech_type_list([GSSMech.ntlm.value]),
                        ),
                        pack_asn1(
                            TagClass.context_specific,
                            True,
                            0,
                            sp.pack_mech_type_list([GSSMech.ntlm.value]),
                        ),
                    ]
                ),
            )
        ),
        id="neg-token-init-duplicate-mech-types-tag",
    ),
    pytest.param(build_neg_token_init() + b"\xff" * 4, id="trailing-garbage-after-token"),
]


@pytest.mark.parametrize("token", SPNEGO_ACCEPTOR_MALFORMED_NO_RAISE)
def test_fuzz_spnego_acceptor_malformed_no_foreign_exception(token, ntlm_cred):
    _assert_no_foreign_exception(_spnego_acceptor_step, token, "hand crafted malformed input")


# ---------------------------------------------------------------------------
# Malformed NTLM inputs - must raise a library defined error
# ---------------------------------------------------------------------------

NTLM_ACCEPTOR_MALFORMED = [
    pytest.param(b"", id="ntlm-empty"),
    pytest.param(b"NTLMSSP\x00", id="ntlm-signature-only"),
    pytest.param(b"NTLMSSP\x00\x01", id="ntlm-truncated-message-type"),
    pytest.param(b"\xde\xad\xbe\xef" * 16, id="ntlm-garbage"),
    pytest.param(b"NTLMSSP\x00" + struct.pack("<I", 99) + b"\x00" * 40, id="ntlm-unknown-message-type"),
    pytest.param(b"NTLMSSP\x00" + struct.pack("<I", 0) + b"\x00" * 40, id="ntlm-message-type-zero"),
    pytest.param(build_ntlm_negotiate()[:20], id="ntlm-negotiate-truncated"),
    pytest.param(
        Negotiate(flags=0, domain_name="DOMAIN").pack(),
        id="ntlm-negotiate-no-encoding-flag",
    ),
]


@pytest.mark.parametrize("token", NTLM_ACCEPTOR_MALFORMED)
def test_fuzz_ntlm_acceptor_malformed_raises_library_error(token, ntlm_cred):
    _assert_raises_library_error(_ntlm_acceptor_step, token)


NTLM_ACCEPTOR_MALFORMED_NO_RAISE = [
    pytest.param(
        build_negotiate_with_domain_buffer(0xFFFF, 32),
        id="security-buffer-overlong-declared-length",
    ),
    pytest.param(
        build_negotiate_with_domain_buffer(4, 0xFFFFFFF0),
        id="security-buffer-offset-beyond-end",
    ),
    pytest.param(
        build_negotiate_with_domain_buffer(0, 0xFFFFFFFF),
        id="security-buffer-zero-length-with-offset",
    ),
]


@pytest.mark.parametrize("token", NTLM_ACCEPTOR_MALFORMED_NO_RAISE)
def test_fuzz_ntlm_acceptor_malformed_no_foreign_exception(token, ntlm_cred):
    _assert_no_foreign_exception(_ntlm_acceptor_step, token, "hand crafted malformed input")


NTLM_INITIATOR_MALFORMED = [
    pytest.param(b"\xde\xad\xbe\xef" * 16, id="challenge-garbage"),
    pytest.param(b"NTLMSSP\x00" + struct.pack("<I", 99) + b"\x00" * 40, id="challenge-unknown-message-type"),
    pytest.param(build_ntlm_challenge()[:30], id="challenge-truncated"),
    pytest.param(
        build_challenge_with_target_info(b"\x01\x00\xff\xffAB", declared_length=0xFFFF),
        id="challenge-target-info-overlong-declared-length",
    ),
]


@pytest.mark.parametrize("token", NTLM_INITIATOR_MALFORMED)
def test_fuzz_ntlm_initiator_malformed_raises_library_error(token):
    _assert_raises_library_error(_ntlm_initiator_step, token)


# Malformed AV_PAIR layouts, fed to the initiator through the Challenge
# TargetInfo field and to the acceptor through the Authenticate NTLMv2
# client challenge.
MALFORMED_AV_PAIRS = [
    pytest.param(b"\x01", id="av-pair-truncated-av-id"),
    pytest.param(b"\x01\x00\x04", id="av-pair-truncated-av-len"),
    pytest.param(b"\x01\x00\xff\xffAB", id="av-pair-truncated-value"),
    pytest.param(
        struct.pack("<HH", AvId.flags, 2) + b"AB" + b"\x00\x00\x00\x00",
        id="av-pair-flags-wrong-length",
    ),
    pytest.param(
        struct.pack("<HH", AvId.timestamp, 4) + b"ABCD" + b"\x00\x00\x00\x00",
        id="av-pair-timestamp-truncated",
    ),
    pytest.param(
        struct.pack("<HH", AvId.timestamp, 8) + b"\xff" * 8 + b"\x00\x00\x00\x00",
        id="av-pair-timestamp-overflow",
    ),
    pytest.param(
        struct.pack("<HH", AvId.single_host, 4) + b"ABCD" + b"\x00\x00\x00\x00",
        id="av-pair-single-host-truncated",
    ),
    pytest.param(
        struct.pack("<HH", AvId.nb_domain_name, 3) + b"ABC" + b"\x00\x00\x00\x00",
        id="av-pair-text-odd-length",
    ),
]


@pytest.mark.parametrize("av_pairs", MALFORMED_AV_PAIRS)
def test_fuzz_ntlm_initiator_malformed_av_pairs_raise_library_error(av_pairs):
    token = build_challenge_with_target_info(av_pairs)

    _assert_raises_library_error(_ntlm_initiator_step, token)


@pytest.mark.parametrize("av_pairs", MALFORMED_AV_PAIRS)
def test_fuzz_ntlm_acceptor_malformed_av_pairs_raise_library_error(av_pairs, ntlm_cred):
    domain, _, username = ntlm_cred[0].partition("\\")
    token = build_authenticate_with_av_pairs(av_pairs, domain, username)

    _assert_raises_library_error(_ntlm_acceptor_authenticate_step, token)


WELL_FORMED_BUT_UNUSUAL_AV_PAIRS = [
    pytest.param(
        struct.pack("<HH", 0x0063, 4) + b"\x01\x02\x03\x04" + b"\x00\x00\x00\x00",
        id="av-pair-unknown-av-id",
    ),
    pytest.param(
        struct.pack("<HH", AvId.nb_domain_name, 4) + "AB".encode("utf-16-le")
        + struct.pack("<HH", AvId.nb_domain_name, 4) + "CD".encode("utf-16-le")
        + b"\x00\x00\x00\x00",
        id="av-pair-duplicate-av-id",
    ),
    pytest.param(
        struct.pack("<HH", AvId.nb_domain_name, 4) + "AB".encode("utf-16-le"),
        id="av-pair-missing-eol",
    ),
    pytest.param(
        struct.pack("<HH", 0x0063, 0) + b"\x00\x00\x00\x00",
        id="av-pair-zero-length-unknown-av-id",
    ),
]


@pytest.mark.parametrize("av_pairs", WELL_FORMED_BUT_UNUSUAL_AV_PAIRS)
def test_fuzz_ntlm_initiator_unusual_av_pairs_no_foreign_exception(av_pairs):
    token = build_challenge_with_target_info(av_pairs)

    _assert_no_foreign_exception(_ntlm_initiator_step, token, "unusual but bounded AV_PAIR layout")


NTLM_AUTHENTICATE_MALFORMED = [
    pytest.param(b"", id="authenticate-empty"),
    pytest.param(b"NTLMSSP\x00" + struct.pack("<I", 99) + b"\x00" * 52, id="authenticate-unknown-message-type"),
    pytest.param(build_ntlm_authenticate()[:40], id="authenticate-truncated"),
    pytest.param(
        Authenticate(flags=BASE_FLAGS).pack(),
        id="authenticate-anonymous",
    ),
]


@pytest.mark.parametrize("token", NTLM_AUTHENTICATE_MALFORMED)
def test_fuzz_ntlm_acceptor_authenticate_malformed_raises_library_error(token, ntlm_cred):
    _assert_raises_library_error(_ntlm_acceptor_authenticate_step, token)


# ---------------------------------------------------------------------------
# Bounded deterministic mutation sweeps - no non-library exception may escape
# ---------------------------------------------------------------------------


def test_fuzz_sweep_spnego_acceptor(ntlm_cred):
    token = build_neg_token_init()
    for mutation, mutated in _mutations(token):
        _assert_no_foreign_exception(_spnego_acceptor_step, mutated, mutation)


def test_fuzz_sweep_spnego_initiator():
    token = build_neg_token_resp()
    for mutation, mutated in _mutations(token):
        _assert_no_foreign_exception(_spnego_initiator_step, mutated, mutation)


def test_fuzz_sweep_ntlm_acceptor_negotiate(ntlm_cred):
    token = build_ntlm_negotiate()
    for mutation, mutated in _mutations(token):
        _assert_no_foreign_exception(_ntlm_acceptor_step, mutated, mutation)


def test_fuzz_sweep_ntlm_initiator_challenge():
    token = build_ntlm_challenge()
    for mutation, mutated in _mutations(token):
        _assert_no_foreign_exception(_ntlm_initiator_step, mutated, mutation)


def test_fuzz_sweep_ntlm_acceptor_authenticate(ntlm_cred):
    token = build_ntlm_authenticate()
    for mutation, mutated in _mutations(token):
        _assert_no_foreign_exception(_ntlm_acceptor_authenticate_step, mutated, mutation)


# ---------------------------------------------------------------------------
# Low level unpack contract - malformed structures raise ValueError only
# ---------------------------------------------------------------------------

LOW_LEVEL_VALUE_ERROR_CASES = [
    pytest.param(sp.unpack_token, b"", id="unpack-token-empty"),
    pytest.param(sp.unpack_token, b"\x60", id="unpack-token-missing-length-octet"),
    pytest.param(sp.unpack_token, b"\x60\x83\x01\x02", id="unpack-token-long-form-length-truncated"),
    pytest.param(sp.unpack_token, b"\x7f\x81", id="unpack-token-high-tag-number-truncated"),
    pytest.param(NTLMMessage.unpack, b"", id="ntlm-message-empty"),
    pytest.param(NTLMMessage.unpack, b"NTLMSSP\x00\x01", id="ntlm-message-truncated-type"),
    pytest.param(
        NTLMMessage.unpack,
        b"NTLMSSP\x00" + struct.pack("<I", 99) + b"\x00" * 20,
        id="ntlm-message-unknown-type",
    ),
    pytest.param(Negotiate.unpack, b"NTLMSSP\x00" + struct.pack("<I", 2) + b"\x00" * 36, id="ntlm-wrong-message-type"),
    pytest.param(TargetInfo.unpack, b"\x01", id="target-info-truncated-av-id"),
    pytest.param(TargetInfo.unpack, b"\x01\x00\x04", id="target-info-truncated-av-len"),
    pytest.param(TargetInfo.unpack, b"\x01\x00\xff\xffAB", id="target-info-truncated-value"),
    pytest.param(TargetInfo.unpack, struct.pack("<HH", AvId.flags, 2) + b"AB", id="target-info-flags-wrong-length"),
    pytest.param(FileTime.unpack, b"\x00" * 7, id="filetime-wrong-length"),
    pytest.param(FileTime.unpack, b"\xff" * 8, id="filetime-overflow"),
    pytest.param(Version.unpack, b"\x00" * 7, id="version-wrong-length"),
    pytest.param(SingleHost.unpack, b"\x00" * 7, id="single-host-too-short"),
    pytest.param(NTClientChallengeV2.unpack, b"\x00" * 31, id="nt-client-challenge-too-short"),
]


@pytest.mark.parametrize("unpack_func, data", LOW_LEVEL_VALUE_ERROR_CASES)
def test_low_level_unpack_malformed_raises_value_error(unpack_func, data):
    # The low level unpack functions define ValueError as their parse
    # failure contract, they must never leak struct.error, KeyError,
    # IndexError, or OverflowError for malformed structures.
    with pytest.raises(ValueError):
        unpack_func(data)
