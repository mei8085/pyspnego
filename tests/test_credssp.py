# -*- coding: utf-8 -*-
# Copyright: (c) 2020, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import re
import socket

import pytest

import spnego
import spnego._credssp as credssp
from spnego._credssp_structures import NegoData, TSRequest
from spnego.exceptions import (
    BadBindingsError,
    FeatureMissingError,
    InvalidTokenError,
    NegotiateOptions,
    NoContextError,
    OperationNotAvailableError,
    SpnegoError,
)
from spnego.tls import default_tls_context, generate_tls_certificate


@pytest.mark.parametrize(
    "expected, usage, nonce",
    [
        (b"\x00\x01", "initiate", None),
        (
            b"\x45\x90\xc2\x6c\x83\x7d\xac\xdf\x3d\xa8\xfa\xe5\x78\x26\x4d\x9e"
            b"\x45\x48\x6a\xfc\x39\x51\xf2\x1e\xf3\x57\x06\x4c\xd5\x5f\xbb\xb5",
            "initiate",
            b"\x00\x00",
        ),
        (b"\x01\x01", "accept", None),
        (
            b"\xcd\xf4\xff\xee\x6c\xb6\x39\x5e\x5b\x69\x2c\x2d\xa3\x97\x38\x6f"
            b"\x6a\x1e\xab\x2d\x3a\x62\x71\x81\x6a\x04\xc7\xa2\x91\x4d\x33\x3f",
            "accept",
            b"\x00\x00",
        ),
    ],
)
def test_pub_key_auth(expected, usage, nonce):
    actual = credssp._get_pub_key_auth(b"\x00\x01", usage, nonce=nonce)

    assert actual == expected


@pytest.mark.parametrize(
    "protocol, cipher, expected",
    [
        ["TLSv1.3", "TLS_AES_128_GCM_SHA256", 17],
        ["TLSv1.3", "TLS_AES_256_GCM_SHA384", 17],
        ["TLSv1.2", "ECDHE-RSA-AES128-GCM-SHA256", 16],
        ["TLSv1.2", "RC4-MD5", 16],
        ["TLSv1.2", "ECDH-ECDSA-3DES-SHA256", 34],
        ["TLSv1.2", "ECDH-RSA-AES-SHA384", 50],
        ["TLSv1.2", "ECDH-RSA-AES", 2],
    ],
)
def test_get_credssp_trailer_length(protocol, cipher, expected):
    actual = credssp._tls_trailer_length(30, protocol, cipher)
    assert actual == expected


def test_credssp_no_iov():
    assert not credssp.CredSSPProxy("username", "password").iov_available()


def test_credssp_iov_not_available():
    expected = (
        "The system is missing the GSSAPI IOV extension headers or CredSSP is being requested, "
        "cannot utilize wrap_iov and unwrap_iov"
    )
    with pytest.raises(FeatureMissingError, match=re.escape(expected)):
        credssp.CredSSPProxy("username", "password", options=spnego.NegotiateOptions.wrapping_iov)


def test_credssp_no_session_key():
    with pytest.raises(FeatureMissingError, match="The protocol selected does not support getting the session key"):
        credssp.CredSSPProxy("user", "password", options=NegotiateOptions.session_key)


def test_credssp_fail_getting_session_key():
    context = credssp.CredSSPProxy("username", "password")

    with pytest.raises(OperationNotAvailableError, match="CredSSP does not have a session key to share"):
        _ = context.session_key


def test_credssp_wrap_iov_fail():
    with pytest.raises(OperationNotAvailableError, match="CredSSP does not offer IOV wrapping"):
        credssp.CredSSPProxy("username", "password").wrap_iov([])


def test_credssp_unwrap_iov_fail():
    with pytest.raises(OperationNotAvailableError, match="CredSSP does not offer IOV wrapping"):
        credssp.CredSSPProxy("username", "password").unwrap_iov([])


def test_credssp_sign_fail():
    with pytest.raises(OperationNotAvailableError, match="CredSSP does not offer signing"):
        credssp.CredSSPProxy("username", "password").sign(b"")


def test_credssp_verify_fail():
    with pytest.raises(OperationNotAvailableError, match="CredSSP does not offer verification"):
        credssp.CredSSPProxy("username", "password").verify(b"", b"")


def test_credssp_wrap_no_context():
    with pytest.raises(SpnegoError, match="Invalid TLS state when wrapping data"):
        credssp.CredSSPProxy("username", "password").wrap(b"data")


def test_credssp_query_message_sizes_fail():
    with pytest.raises(NoContextError, match="Cannot get message sizes until context has been established"):
        credssp.CredSSPProxy("username", "password").query_message_sizes()


def test_credssp_invalid_handshake(ntlm_cred):
    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], protocol="credssp")
    s = credssp.CredSSPProxy(None, None, protocol="credssp", usage="accept")

    server_hello = s.step(c.step())
    assert server_hello is not None

    with pytest.raises(InvalidTokenError, match="TLS handshake for CredSSP"):
        c.step(b"\x00" + server_hello)


def test_credssp_server_without_pub_key():
    context = default_tls_context(usage="accept")
    with pytest.raises(OperationNotAvailableError, match="Provided tls context does not have a public key set"):
        credssp.CredSSPProxy("username", "password", usage="accept", credssp_tls_context=context)


@pytest.mark.parametrize("version", [2, 5])
def test_credssp_invalid_client_authentication_v2(version, ntlm_cred, monkeypatch):
    monkeypatch.setattr(credssp, "_CREDSSP_VERSION", version)

    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp")
    s = credssp.CredSSPProxy(None, None, hostname=socket.gethostname(), protocol="credssp", usage="accept")

    # Set up the state so the server can send the error code
    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    bad_request = TSRequest(credssp._CREDSSP_VERSION, nego_tokens=NegoData(b"\x00"))
    actual = s.step(c.wrap(bad_request.pack()).data)

    # On CredSSP v2 or 5 there is no error message from the server, just no token
    assert actual is None


@pytest.mark.parametrize("version", [3, 4, 6])
def test_credssp_invalid_client_authentication(version, ntlm_cred, monkeypatch):
    monkeypatch.setattr(credssp, "_CREDSSP_VERSION", version)

    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp")
    s = credssp.CredSSPProxy(None, None, hostname=socket.gethostname(), protocol="credssp", usage="accept")

    # Set up the state so the server can send the error code
    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    assert server_tls_token is not None
    c.unwrap(server_tls_token)
    bad_request = TSRequest(credssp._CREDSSP_VERSION, nego_tokens=NegoData(b"\x00"))
    error_msg = s.step(c.wrap(bad_request.pack()).data)

    expected = re.escape("Received NTStatus in TSRequest from acceptor, Context: Authentication")
    with pytest.raises(InvalidTokenError, match=expected):
        c.step(error_msg)


def test_credssp_no_pub_key_after_auth(ntlm_cred):
    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp")
    s = credssp.CredSSPProxy(None, None, hostname=socket.gethostname(), protocol="credssp", usage="accept")

    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    ntlm3_pub_key = c.step(server_tls_token)

    # Send back a TSRequest without the public key.
    assert ntlm3_pub_key is not None
    s.unwrap(ntlm3_pub_key)
    ts_request = TSRequest(credssp._CREDSSP_VERSION)

    with pytest.raises(InvalidTokenError, match="Acceptor did not response with pubKeyAuth info"):
        c.step(s.wrap(ts_request.pack()).data)


def test_credssp_pub_key_mismatch_initiator(ntlm_cred):
    options = NegotiateOptions.use_ntlm
    c = credssp.CredSSPProxy(
        ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp", options=options
    )
    s = credssp.CredSSPProxy(
        None, None, hostname=socket.gethostname(), protocol="credssp", usage="accept", options=options
    )

    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    ntlm3_pub_key = c.step(server_tls_token)

    s_auth_context = s._auth_context
    assert s_auth_context is not None

    # Send back a TSRequest with a bad pub_key_auth value.
    assert ntlm3_pub_key is not None
    request = TSRequest.unpack(s.unwrap(ntlm3_pub_key).data)
    assert request.nego_tokens is not None
    s_auth_context.step(request.nego_tokens[0].nego_token)
    ts_request = TSRequest(credssp._CREDSSP_VERSION, pub_key_auth=s_auth_context.wrap(b"bad").data)

    with pytest.raises(BadBindingsError, match="Public key verification failed, potential man in the middle attack"):
        c.step(s.wrap(ts_request.pack()).data)


def test_credssp_pub_key_mismatch_acceptor(ntlm_cred):
    options = NegotiateOptions.use_ntlm
    c = credssp.CredSSPProxy(
        ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp", options=options
    )
    s = credssp.CredSSPProxy(
        None, None, hostname=socket.gethostname(), protocol="credssp", usage="accept", options=options
    )

    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    # Craft the TSRequest with the NTLMv3 token and invalid pub_key_auth
    assert server_tls_token is not None
    ntlm2_request = TSRequest.unpack(c.unwrap(server_tls_token).data)
    assert ntlm2_request.nego_tokens is not None
    ntlm3 = c._auth_context.step(ntlm2_request.nego_tokens[0].nego_token)
    assert ntlm3 is not None

    request = TSRequest(
        credssp._CREDSSP_VERSION, nego_tokens=NegoData(ntlm3), pub_key_auth=c._auth_context.wrap(b"bad").data
    )

    with pytest.raises(BadBindingsError, match="Public key verification failed, potential man in the middle attack"):
        s.step(c.wrap(request.pack()).data)


def test_credssp_no_credential(ntlm_cred):
    options = NegotiateOptions.use_ntlm
    c = credssp.CredSSPProxy(
        ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp", options=options
    )
    s = credssp.CredSSPProxy(
        None, None, hostname=socket.gethostname(), protocol="credssp", usage="accept", options=options
    )

    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        assert not c.complete
        assert not s.complete

        server_tls_token = s.step(client_tls_token)
        assert not c.complete
        assert not s.complete

    ntlm3_pub_key = c.step(server_tls_token)
    assert ntlm3_pub_key is not None

    pub_key_resp = s.step(ntlm3_pub_key)
    assert pub_key_resp is not None
    server_pub_key = TSRequest.unpack(c.unwrap(pub_key_resp).data)

    # Unpack the TSRequest properly and craft a TSRequest without a credential
    assert server_pub_key.pub_key_auth is not None
    c._auth_context.unwrap(server_pub_key.pub_key_auth)

    request = TSRequest(credssp._CREDSSP_VERSION)

    with pytest.raises(InvalidTokenError, match="No credential received on CredSSP TSRequest from initiator"):
        s.step(c.wrap(request.pack()).data)


def _tamper_ts_request_version(
    token: bytes,
    reader: credssp.CredSSPProxy,
    writer: credssp.CredSSPProxy,
    version: int,
) -> bytes:
    """Rewrites the version field of a TLS wrapped TSRequest.

    This simulates a man in the middle that has terminated the TLS channel and
    tampers with the CredSSP protocol version to force a downgrade, e.g. to
    bring back the CVE-2018-0886 susceptible protocol versions. The token is
    unwrapped with the reader (the intended recipient), modified, and wrapped
    again with the writer (the apparent sender) so the tampered token is still
    valid TLS data for the recipient.
    """
    ts_request = TSRequest.unpack(reader.unwrap(token).data)
    downgraded = TSRequest(
        version,
        nego_tokens=ts_request.nego_tokens,
        auth_info=ts_request.auth_info,
        pub_key_auth=ts_request.pub_key_auth,
        error_code=ts_request.error_code,
        client_nonce=ts_request.client_nonce,
    )

    return writer.wrap(downgraded.pack()).data


@pytest.mark.parametrize(
    "c_version, s_version",
    [(6, 6), (6, 5), (5, 6), (6, 2), (2, 6), (5, 5), (3, 4), (2, 2)],
)
def test_credssp_version_negotiation_pub_key_binding(c_version, s_version, ntlm_cred, monkeypatch):
    """Pub key binding holds across all negotiated version combinations.

    Whatever version the peers negotiate down to, the public key authentication
    is still verified and a successful exchange must mean both the inner
    authentication and the outer TLS key binding succeeded.
    """
    monkeypatch.setattr(credssp, "_CREDSSP_VERSION", 6)

    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp")
    s = credssp.CredSSPProxy(None, None, hostname=socket.gethostname(), protocol="credssp", usage="accept")

    def step(proxy: credssp.CredSSPProxy, version: int, token: bytes) -> bytes:
        # _CREDSSP_VERSION is a module global so it is toggled around each step
        # to simulate peers with different maximum protocol versions.
        credssp._CREDSSP_VERSION = version
        return proxy.step(token)

    token = step(c, c_version, None)
    while True:
        token = step(s, s_version, token)
        if c.complete and s.complete:
            break

        token = step(c, c_version, token)

    expected_version = min(c_version, s_version)
    assert c.get_extra_info("protocol_version") == expected_version
    assert s.get_extra_info("protocol_version") == expected_version

    # The delegated credential only arrives if the inner authentication and the
    # public key binding both succeeded.
    credential = s.get_extra_info("client_credential")
    assert credential is not None
    assert credential.password == ntlm_cred[1]


def test_credssp_version_downgrade_mitm_completes_at_lower_version(ntlm_cred):
    """A version downgrade is not misreported as a stronger protocol.

    With the default minimum protocol of 2 a MITM can downgrade the exchange to
    version 2 and the authentication still completes (backwards compatibility).
    The negotiated version must be observable as 2 on both peers so the weaker
    security posture is not misjudged as a fully mitigated exchange.
    """
    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp")
    s = credssp.CredSSPProxy(None, None, hostname=socket.gethostname(), protocol="credssp", usage="accept")

    # Run the TLS handshake but keep back the client's first TSRequest so the
    # MITM can tamper with it before the server processes it.
    server_tls_token = None
    client_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        if c._auth_context is not None:
            break

        server_tls_token = s.step(client_tls_token)

    # Relay the TSRequests, downgrading the version field in both directions
    # like a MITM forcing the CVE-2018-0886 susceptible protocol.
    assert client_tls_token is not None
    out_token = _tamper_ts_request_version(client_tls_token, s, c, 2)
    in_token = s.step(out_token)
    while True:
        in_token = _tamper_ts_request_version(in_token, c, s, 2)
        out_token = c.step(in_token)
        if c.complete and s.complete:
            break

        out_token = _tamper_ts_request_version(out_token, s, c, 2)
        in_token = s.step(out_token)
        if s.complete:
            break

    assert c.complete
    assert s.complete
    assert c.get_extra_info("protocol_version") == 2
    assert s.get_extra_info("protocol_version") == 2


def test_credssp_version_downgrade_mitm_client_rejects(ntlm_cred):
    """A client with a minimum protocol must reject a downgraded exchange."""
    c = credssp.CredSSPProxy(
        ntlm_cred[0],
        ntlm_cred[1],
        hostname=socket.gethostname(),
        protocol="credssp",
        credssp_min_protocol=5,
    )
    s = credssp.CredSSPProxy(None, None, hostname=socket.gethostname(), protocol="credssp", usage="accept")

    server_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        server_tls_token = s.step(client_tls_token)

    # The MITM rewrites the server response to version 2, the client must not
    # continue with the weaker protocol.
    downgraded = _tamper_ts_request_version(server_tls_token, c, s, 2)

    expected = "did not meet the minimum requirements"
    with pytest.raises(InvalidTokenError, match=expected):
        c.step(downgraded)

    assert not c.complete


def test_credssp_version_downgrade_mitm_server_rejects(ntlm_cred):
    """A server with a minimum protocol must reject a downgraded exchange."""
    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp")
    s = credssp.CredSSPProxy(
        None,
        None,
        hostname=socket.gethostname(),
        protocol="credssp",
        usage="accept",
        credssp_min_protocol=5,
    )

    # Run the TLS handshake but keep back the client's first TSRequest so the
    # MITM can tamper with it before the server processes it.
    server_tls_token = None
    client_tls_token = None
    while c._auth_context is None:
        client_tls_token = c.step(server_tls_token)
        if c._auth_context is not None:
            break

        server_tls_token = s.step(client_tls_token)

    assert client_tls_token is not None
    ts_request = TSRequest.unpack(s.unwrap(client_tls_token).data)
    assert ts_request.version == 6

    forged = c.wrap(TSRequest(2, nego_tokens=ts_request.nego_tokens).pack()).data

    expected = "did not meet the minimum requirements"
    with pytest.raises(InvalidTokenError, match=expected):
        s.step(forged)

    assert not s.complete


@pytest.mark.parametrize("version", [2, 5, 6])
def test_credssp_mitm_tls_public_key_mismatch_rejected(version, ntlm_cred, monkeypatch):
    """Inner auth success cannot compensate for a wrong outer TLS public key.

    Simulates a MITM that terminates TLS with its own certificate: the client
    binds the authentication to the key it saw while the server holds a
    different key. Even though the inner NTLM authentication succeeds the
    exchange must be rejected at every protocol version, including the
    downgraded ones.
    """
    monkeypatch.setattr(credssp, "_CREDSSP_VERSION", version)

    c = credssp.CredSSPProxy(ntlm_cred[0], ntlm_cred[1], hostname=socket.gethostname(), protocol="credssp")
    s = credssp.CredSSPProxy(None, None, hostname=socket.gethostname(), protocol="credssp", usage="accept")

    # The server ends up holding a different public key than the one the client
    # saw in the TLS handshake, as if a MITM presented its own certificate.
    s._tls_context.public_key = generate_tls_certificate()[2]

    def exchange() -> None:
        token = c.step()
        for _ in range(20):
            token = s.step(token)
            token = c.step(token)

        raise AssertionError("CredSSP exchange did not fail as expected")

    expected = "Public key verification failed, potential man in the middle attack"
    with pytest.raises(BadBindingsError, match=expected):
        exchange()

    # The inner authentication succeeded but the missing outer key binding
    # keeps the exchange rejected and no credential is delegated.
    assert s._auth_context is not None
    assert s._auth_context.complete
    assert not s.complete
    assert s.get_extra_info("client_credential") is None


def test_credssp_inner_auth_failure_not_masked_by_tls(ntlm_cred):
    """A valid TLS channel and public key cannot rescue failed inner auth.

    The inverse of the public key binding checks: the outer TLS key matches but
    the inner authentication (wrong password) fails. The failure must surface
    and neither peer may report a completed context.
    """
    c = credssp.CredSSPProxy(ntlm_cred[0], "invalid password", hostname=socket.gethostname(), protocol="credssp")
    s = credssp.CredSSPProxy(None, None, hostname=socket.gethostname(), protocol="credssp", usage="accept")

    def exchange() -> None:
        token = c.step()
        for _ in range(20):
            token = s.step(token)
            if token is None:
                # CredSSP v2/5 style failure, the server just stops responding.
                return

            token = c.step(token)

        raise AssertionError("CredSSP exchange did not fail as expected")

    expected = "Received NTStatus in TSRequest from acceptor"
    with pytest.raises(SpnegoError, match=expected):
        exchange()

    assert not c.complete
    assert not s.complete
    assert s.get_extra_info("client_credential") is None
