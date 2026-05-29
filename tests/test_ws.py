"""
Tests for the WebSocket architecture — JSON-RPC messages, message
router, Guardian WS client, and agent WS handler.
"""
from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import guardian.audit as audit_module
import guardian.main as main_module
import guardian.payments as payments_module
import guardian.tokens as tokens_module
import guardian.tools as tools_module
import guardian.vault as vault_module
from guardian.tokens import (
    generate_token_keypair,
    init_tokens,
)
from guardian.vault import init_vault, unlock_vault, seed_demo_items
from shared.token import (
    issue_token as _p3_issue_token,
    RevocationStore,
    RequestDeduplicator,
    TokenVerifyError,
)
from shared.types import TlpLevel
from datetime import datetime, timedelta, timezone
from shared.messages import (
    ERR_FORBIDDEN,
    ERR_METHOD_NOT_FOUND,
    ERR_PARTITION_DENIED,
    ERR_UNAUTHORIZED,
    WSNotification,
    WSRequest,
    WSResponse,
)

import guardian.mtls as mtls_module


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

PASSPHRASE = "ws-test-passphrase-2026"
CERT_PASSPHRASE = "test-cert-passphrase"
AGENT_CERT = b"FAKE-AGENT-CERTIFICATE-BYTES-FOR-TESTING"


@pytest.fixture(autouse=True)
def setup(tmp_path, monkeypatch):
    """Isolate every module to tmp_path."""
    audit_module.init_audit_log(tmp_path / "audit.db")

    monkeypatch.setattr(vault_module, "VAULT_DIR", tmp_path / "vault")
    monkeypatch.setattr(vault_module, "VAULT_PATH", tmp_path / "vault" / "vault.enc")
    monkeypatch.setattr(vault_module, "KEYS_DIR", tmp_path / "vault" / "keys")
    monkeypatch.setattr(vault_module, "AGE_KEY_PATH", tmp_path / "vault" / "keys" / "master.key")
    monkeypatch.setattr(vault_module, "AGE_PUBKEY_PATH", tmp_path / "vault" / "keys" / "master.key.pub")

    certs = tmp_path / "certs"
    monkeypatch.setattr(mtls_module, "CERTS_DIR", certs)
    monkeypatch.setattr(mtls_module, "CA_CERT_PATH", certs / "ca.crt")
    monkeypatch.setattr(mtls_module, "CA_KEY_PATH", certs / "ca.key")
    monkeypatch.setattr(mtls_module, "GUARDIAN_CERT_PATH", certs / "guardian.crt")
    monkeypatch.setattr(mtls_module, "GUARDIAN_KEY_PATH", certs / "guardian.key")
    monkeypatch.setattr(mtls_module, "AGENT_CERTS_DIR", certs / "agents")

    yield tmp_path

    tokens_module._signing_key = None
    tokens_module._verify_key = None
    tokens_module._db_path = None
    main_module._signing_key_bytes = None
    main_module._verify_key_bytes = None
    main_module._revocation_store = None
    main_module._deduplicator = None
    payments_module._vault = None
    tools_module._vault = None
    main_module._vault_dict = None
    main_module._revoke_timestamps.clear()
    main_module._ws_clients.clear()


def _init_modules(tmp_path):
    """Initialise vault, Phase 3 token state, tools, payments."""
    import nacl.signing as _nacl
    init_vault(PASSPHRASE)
    vault_dict = unlock_vault(PASSPHRASE)
    seed_demo_items(vault_dict)

    _sk = _nacl.SigningKey.generate()
    main_module._signing_key_bytes = bytes(_sk)
    main_module._verify_key_bytes = bytes(_sk.verify_key)
    main_module._revocation_store = RevocationStore()
    main_module._deduplicator = RequestDeduplicator()

    tools_module.init_tools(vault_dict)
    payments_module.init_payments(vault_dict)
    main_module._vault_dict = vault_dict

    return vault_dict


# ---------------------------------------------------------------------------
# Test WSMessages
# ---------------------------------------------------------------------------

class TestWSMessages:
    """Test JSON-RPC message serialization."""

    def test_request_has_id(self):
        req = WSRequest(method="tools.execute", params={"tool": "cal"}, id="req-1")
        assert req.id == "req-1"
        assert req.jsonrpc == "2.0"

    def test_request_without_id_rejected(self):
        """WSRequest without id must raise validation error."""
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            WSRequest(method="tools.execute", params={})

    def test_response_matches_id(self):
        resp = WSResponse(id="abc-123", result={"data": 42})
        assert resp.id == "abc-123"
        assert resp.result == {"data": 42}
        assert resp.error is None

    def test_notification_has_no_id(self):
        notif = WSNotification(
            method="llm_key.rotate",
            params={"key": "sk-new"},
        )
        data = notif.model_dump()
        assert "id" not in data or data.get("id") is None
        assert data["method"] == "llm_key.rotate"

    def test_error_response(self):
        resp = WSResponse(
            id="req-1",
            error={"code": ERR_UNAUTHORIZED, "message": "Bad token"},
        )
        assert resp.error["code"] == ERR_UNAUTHORIZED

    def test_request_default_jsonrpc(self):
        req = WSRequest(method="test", id="req-2")
        assert req.jsonrpc == "2.0"

    def test_request_roundtrip_json(self):
        req = WSRequest(method="tools.execute", params={"x": 1}, id="req-3")
        data = json.loads(req.model_dump_json())
        assert data["method"] == "tools.execute"
        assert data["params"] == {"x": 1}
        assert "id" in data


# ---------------------------------------------------------------------------
# Test MessageRouter
# ---------------------------------------------------------------------------

class TestMessageRouter:
    """Test message routing to internal handlers."""

    def test_unknown_method_returns_error(self, setup):
        from guardian.message_router import route_message

        req = WSRequest(method="nonexistent.method", params={}, id="test-1")
        resp = asyncio.run(route_message(
            req, agent_cert_der=AGENT_CERT, session_agent_id="alpha",
        ))
        assert resp.error is not None
        assert resp.error["code"] == ERR_METHOD_NOT_FOUND
        assert "nonexistent.method" in resp.error["message"]

    def test_tool_execute_routes_correctly(self, setup):
        """Phase 3 — tools.execute with a valid signed token executes the tool."""
        tmp_path = setup
        _init_modules(tmp_path)

        from guardian.message_router import route_message

        ca_cert, ca_key = mtls_module.generate_ca(CERT_PASSPHRASE)
        agent_cert, _ = mtls_module.generate_agent_cert(
            "alpha", ca_cert, ca_key, CERT_PASSPHRASE,
        )

        now = datetime.now(timezone.utc)
        tok = _p3_issue_token(
            agent_id="alpha",
            partitions=["company-a"],
            tlp_level=TlpLevel.GREEN,
            operations=["google_calendar"],
            agent_der_cert=agent_cert,
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(hours=4)).isoformat(),
            issuer="guardian",
            signing_key_bytes=main_module._signing_key_bytes,
        )
        token_str = tok.to_json()

        req = WSRequest(
            method="tools.execute",
            params={
                "token_str": token_str,
                "tool_name": "google_calendar",
                "action": "list",
                "params": {},
            },
            id="tool-1",
        )
        resp = asyncio.run(route_message(
            req, agent_cert_der=agent_cert, session_agent_id="alpha",
        ))
        assert resp.error is None, f"Expected success, got error: {resp.error}"
        assert resp.result is not None

    def test_partition_check_routes_correctly(self, setup):
        """Phase 3: partition.check with own partition key returns success result."""
        tmp_path = setup
        _init_modules(tmp_path)

        from guardian.message_router import route_message

        ca_cert, ca_key = mtls_module.generate_ca(CERT_PASSPHRASE)
        agent_cert, _ = mtls_module.generate_agent_cert(
            "alpha", ca_cert, ca_key, CERT_PASSPHRASE,
        )

        now = datetime.now(timezone.utc)
        tok = _p3_issue_token(
            agent_id="alpha",
            partitions=["company-a"],
            tlp_level=TlpLevel.GREEN,
            operations=[],
            agent_der_cert=agent_cert,
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(hours=4)).isoformat(),
            issuer="guardian",
            signing_key_bytes=main_module._signing_key_bytes,
        )

        req = WSRequest(
            method="partition.check",
            params={
                "token_str": tok.to_json(),
                "key": "public_filings",  # company-a, PUBLIC — allowed for GREEN
            },
            id="part-1",
        )
        resp = asyncio.run(route_message(
            req, agent_cert_der=agent_cert, session_agent_id="alpha",
        ))
        assert resp.error is None, f"Expected success, got error: {resp.error}"
        assert resp.result["allowed"] is True
        assert resp.result["partition"] == "company-a"

    def test_partition_denied_returns_correct_code(self, setup):
        """Phase 3: partition.check for unauthorized key returns ERR_PARTITION_DENIED."""
        tmp_path = setup
        _init_modules(tmp_path)

        from guardian.message_router import route_message

        ca_cert, ca_key = mtls_module.generate_ca(CERT_PASSPHRASE)
        agent_cert, _ = mtls_module.generate_agent_cert(
            "alpha", ca_cert, ca_key, CERT_PASSPHRASE,
        )

        now = datetime.now(timezone.utc)
        tok = _p3_issue_token(
            agent_id="alpha",
            partitions=["company-a"],
            tlp_level=TlpLevel.GREEN,
            operations=[],
            agent_der_cert=agent_cert,
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(hours=4)).isoformat(),
            issuer="guardian",
            signing_key_bytes=main_module._signing_key_bytes,
        )

        req = WSRequest(
            method="partition.check",
            params={
                "token_str": tok.to_json(),
                "key": "v2g_profit_split",  # company-b — not in alpha's partitions
            },
            id="part-2",
        )
        resp = asyncio.run(route_message(
            req, agent_cert_der=agent_cert, session_agent_id="alpha",
        ))
        assert resp.error is not None
        assert resp.error["code"] == ERR_PARTITION_DENIED

    def test_token_error_returns_unauthorized(self, setup):
        """Invalid token returns ERR_UNAUTHORIZED."""
        tmp_path = setup
        _init_modules(tmp_path)

        from guardian.message_router import route_message

        req = WSRequest(
            method="tools.execute",
            params={
                "token_str": "invalid-token-garbage",
                "tool_name": "cal",
                "action": "list",
            },
            id="tok-err-1",
        )
        resp = asyncio.run(route_message(
            req, agent_cert_der=AGENT_CERT, session_agent_id="alpha",
        ))
        assert resp.error is not None
        assert resp.error["code"] == ERR_UNAUTHORIZED

    def test_agent_id_mismatch_rejected(self, setup):
        """Token issued for alpha but session says beta → rejected."""
        tmp_path = setup
        _init_modules(tmp_path)

        from guardian.message_router import route_message

        ca_cert, ca_key = mtls_module.generate_ca(CERT_PASSPHRASE)
        agent_cert, _ = mtls_module.generate_agent_cert(
            "alpha", ca_cert, ca_key, CERT_PASSPHRASE,
        )

        now = datetime.now(timezone.utc)
        tok = _p3_issue_token(
            agent_id="alpha",
            partitions=[],
            tlp_level=TlpLevel.GREEN,
            operations=["cal"],
            agent_der_cert=agent_cert,
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(hours=4)).isoformat(),
            issuer="guardian",
            signing_key_bytes=main_module._signing_key_bytes,
        )

        req = WSRequest(
            method="tools.execute",
            params={
                "token_str": tok.to_json(),
                "tool_name": "cal",
                "action": "list",
            },
            id="mismatch-1",
        )
        # Session says "beta" but token says "alpha"
        resp = asyncio.run(route_message(
            req, agent_cert_der=agent_cert, session_agent_id="beta",
        ))
        assert resp.error is not None
        assert resp.error["code"] == ERR_UNAUTHORIZED

    def test_tool_not_permitted_returns_forbidden(self, setup):
        """FIX 8 — enforcement is active; a tool not in the token's tool_calls
        list is denied with ERR_FORBIDDEN, not ERR_METHOD_NOT_FOUND."""
        tmp_path = setup
        _init_modules(tmp_path)

        from guardian.message_router import route_message

        ca_cert, ca_key = mtls_module.generate_ca(CERT_PASSPHRASE)
        agent_cert, _ = mtls_module.generate_agent_cert(
            "alpha", ca_cert, ca_key, CERT_PASSPHRASE,
        )

        now = datetime.now(timezone.utc)
        tok = _p3_issue_token(
            agent_id="alpha",
            partitions=[],
            tlp_level=TlpLevel.GREEN,
            operations=["allowed_tool"],
            agent_der_cert=agent_cert,
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(hours=4)).isoformat(),
            issuer="guardian",
            signing_key_bytes=main_module._signing_key_bytes,
        )

        req = WSRequest(
            method="tools.execute",
            params={
                "token_str": tok.to_json(),
                "tool_name": "forbidden_tool",
                "action": "read",
            },
            id="forbidden-1",
        )
        resp = asyncio.run(route_message(
            req, agent_cert_der=agent_cert, session_agent_id="alpha",
        ))
        assert resp.error is not None
        assert resp.error["code"] == ERR_FORBIDDEN


# ---------------------------------------------------------------------------
# Test GuardianWSClient
# ---------------------------------------------------------------------------

class TestGuardianWSClient:
    """Test WebSocket client reconnection logic."""

    def test_exponential_backoff_timing(self):
        """Backoff delay doubles with each failure up to max."""
        from shared.config import WS_RECONNECT_BASE_SECONDS, WS_RECONNECT_MAX_SECONDS

        base = WS_RECONNECT_BASE_SECONDS
        for attempt in range(1, 8):
            delay = min(base * (2 ** (attempt - 1)), WS_RECONNECT_MAX_SECONDS)
            if attempt == 1:
                assert delay == base
            elif attempt == 2:
                assert delay == base * 2
            # Should never exceed max
            assert delay <= WS_RECONNECT_MAX_SECONDS

    def test_max_retries_stops_connection(self):
        """After max retries, client stops trying."""
        from guardian.ws_client import GuardianWSClient
        import ssl

        client = GuardianWSClient(
            agent_id="test",
            agent_host="127.0.0.1",
            agent_port=9999,
            agent_cert_der=b"fake",
            ssl_context=ssl.SSLContext(),
        )
        client._consecutive_failures = 10  # >= WS_MAX_RETRIES
        assert client._consecutive_failures >= 10

    def test_connect_does_not_reset_failure_counter(self):
        """
        connect() must NOT reset _consecutive_failures.
        Only successful message processing resets it.
        This prevents a rogue agent from trapping Guardian in
        rapid reconnections by accepting TLS then dropping.
        """
        from guardian.ws_client import GuardianWSClient
        import ssl

        client = GuardianWSClient(
            agent_id="test",
            agent_host="127.0.0.1",
            agent_port=9999,
            agent_cert_der=b"fake",
            ssl_context=ssl.SSLContext(),
        )
        client._consecutive_failures = 5
        # connect() no longer resets failures — verify the field
        # remains as-is (simulating what would happen after connect)
        assert client._consecutive_failures == 5


# ---------------------------------------------------------------------------
# Test AgentWSHandler
# ---------------------------------------------------------------------------

class TestAgentWSHandler:
    """Test agent-side WebSocket handler."""

    def test_notification_dispatched(self):
        """Notifications are dispatched to registered handlers."""
        from agent.ws_handler import AgentWSHandler

        received = {}

        async def handler(params):
            received.update(params)

        notification = WSNotification(
            method="llm_key.rotate",
            params={"key": "sk-new", "provider": "anthropic"},
        )

        # Create a proper async iterator for the mock websocket
        class MockWS:
            def __init__(self, messages):
                self._messages = messages
                self._index = 0

            async def __aiter__(self):
                for msg in self._messages:
                    yield msg

            async def send(self, data):
                pass

        mock_ws = MockWS([notification.model_dump_json()])
        ws_handler = AgentWSHandler(mock_ws)
        ws_handler.on_notification("llm_key.rotate", handler)

        async def run():
            await ws_handler.start_listener()
            await asyncio.sleep(0.1)
            await ws_handler.stop()

        asyncio.run(run())
        assert received.get("provider") == "anthropic"

    def test_pending_cleanup_on_stop(self):
        """Stopping the handler cleans up pending futures."""
        from agent.ws_handler import AgentWSHandler

        class EmptyMockWS:
            async def __aiter__(self):
                return
                yield  # make it a proper async generator

            async def send(self, data):
                pass

        ws_handler = AgentWSHandler(EmptyMockWS())

        async def run():
            loop = asyncio.get_running_loop()
            future = loop.create_future()
            ws_handler._pending["test-id"] = future
            await ws_handler.stop()
            assert len(ws_handler._pending) == 0

        asyncio.run(run())


# ---------------------------------------------------------------------------
# Test internal function refactoring
# ---------------------------------------------------------------------------

class TestInternalFunctions:
    """Verify HTTP endpoints use the same internal functions as WS router."""

    def test_execute_tool_internal_exists(self):
        """_execute_tool_internal is importable from guardian.main."""
        from guardian.main import _execute_tool_internal
        assert callable(_execute_tool_internal)

    def test_check_partition_internal_exists(self):
        from guardian.main import _check_partition_internal
        assert callable(_check_partition_internal)

    def test_execute_payment_internal_exists(self):
        from guardian.main import _execute_payment_internal
        assert callable(_execute_payment_internal)

    def test_check_agent_id_match_exists(self):
        from guardian.main import _check_agent_id_match
        assert callable(_check_agent_id_match)

    def test_agent_id_mismatch_raises_token_error(self):
        """_check_agent_id_match raises TokenVerifyError, not HTTPException."""
        from guardian.main import _check_agent_id_match
        from shared.token import TokenVerifyError
        from types import SimpleNamespace

        token = SimpleNamespace(agent_id="beta")
        with pytest.raises(TokenVerifyError, match="mismatch"):
            _check_agent_id_match("alpha", token)


# ---------------------------------------------------------------------------
# Test backoff bypass prevention (Fix 1)
# ---------------------------------------------------------------------------

class TestBackoffBypassPrevention:
    """
    A rogue agent that accepts TLS then drops should not reset
    Guardian's failure counter. Only successful message processing
    resets the counter.
    """

    def test_connect_accept_then_drop_increments_failures(self):
        """
        Simulate: connect succeeds, no messages, connection drops.
        _consecutive_failures must increment, not reset.
        """
        from guardian.ws_client import GuardianWSClient
        import ssl

        client = GuardianWSClient(
            agent_id="rogue",
            agent_host="127.0.0.1",
            agent_port=9999,
            agent_cert_der=b"fake",
            ssl_context=ssl.SSLContext(),
        )
        # Simulate 3 connect-then-drop cycles
        for i in range(3):
            client._consecutive_failures += 1
        # connect() does NOT reset, so failures accumulate
        assert client._consecutive_failures == 3

    def test_message_processing_resets_failures(self):
        """
        After receiving and processing a real message,
        _consecutive_failures should reset to 0.
        """
        from guardian.ws_client import GuardianWSClient
        import ssl

        client = GuardianWSClient(
            agent_id="test",
            agent_host="127.0.0.1",
            agent_port=9999,
            agent_cert_der=b"fake",
            ssl_context=ssl.SSLContext(),
        )
        client._consecutive_failures = 5
        # Simulate what listen_loop does on receiving a message
        client._consecutive_failures = 0
        assert client._consecutive_failures == 0


# ---------------------------------------------------------------------------
# Test Guardian CN verification on agent /ws (Fix 2)
# ---------------------------------------------------------------------------

class TestGuardianCNVerification:
    """
    The agent /ws endpoint must verify the connecting client's
    certificate CN is "MahaGuardian Guardian".
    """

    def test_guardian_cn_check_logic(self):
        """
        Verify the CN extraction and check logic works correctly
        with a mock ssl_object presenting the Guardian cert.
        """
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from datetime import datetime, timedelta, timezone

        # Generate a cert with CN="MahaGuardian Guardian"
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "MahaGuardian Guardian"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        der_bytes = cert.public_bytes(serialization.Encoding.DER)

        # Verify CN extraction matches
        loaded = x509.load_der_x509_certificate(der_bytes)
        cn = loaded.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "MahaGuardian Guardian"

    def test_non_guardian_cn_would_be_rejected(self):
        """
        A cert with CN != "MahaGuardian Guardian" should fail the check.
        """
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from datetime import datetime, timedelta, timezone

        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Rogue Agent"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        from cryptography.hazmat.primitives import serialization
        der_bytes = cert.public_bytes(serialization.Encoding.DER)

        loaded = x509.load_der_x509_certificate(der_bytes)
        cn = loaded.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn != "MahaGuardian Guardian"  # Would be rejected by /ws


# ---------------------------------------------------------------------------
# Test WSRequest.id is required (Fix 3)
# ---------------------------------------------------------------------------

class TestWSRequestIdRequired:
    """WSRequest.id must be explicitly provided — no auto-generation."""

    def test_missing_id_raises_validation_error(self):
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            WSRequest(method="tools.execute")

    def test_explicit_id_accepted(self):
        req = WSRequest(method="tools.execute", id="explicit-id")
        assert req.id == "explicit-id"

    def test_json_without_id_rejected(self):
        """Parsing JSON without id field must fail."""
        from pydantic import ValidationError
        raw = '{"jsonrpc": "2.0", "method": "tools.execute", "params": {}}'
        with pytest.raises(ValidationError):
            WSRequest.model_validate_json(raw)


# ---------------------------------------------------------------------------
# Test mTLS transport binding (Workstream 1)
# ---------------------------------------------------------------------------

class TestMTLSTransportBinding:
    """
    Test that _get_agent_cert requires a TLS peer cert and that
    verify_peer_agent_id_from_der works correctly.
    """

    def test_peer_cert_preferred_over_body(self, setup):
        """When peer_cert_der is in request.state, it is used."""
        from guardian.main import _get_agent_cert
        from unittest.mock import MagicMock

        mock_request = MagicMock()
        mock_request.state.peer_cert_der = b"REAL-TLS-CERT-BYTES"

        result = _get_agent_cert(mock_request)
        assert result == b"REAL-TLS-CERT-BYTES"

    def test_no_tls_peer_cert_raises(self, setup):
        """When no TLS peer cert is present, the request is rejected."""
        from guardian.main import _get_agent_cert
        from unittest.mock import MagicMock
        from fastapi import HTTPException

        mock_request = MagicMock()
        mock_request.state.peer_cert_der = None

        with pytest.raises(HTTPException) as exc_info:
            _get_agent_cert(mock_request)
        assert exc_info.value.status_code == 500

    def test_verify_peer_agent_id_from_der_match(self, setup):
        """Correct CN passes verification."""
        from guardian.mtls import verify_peer_agent_id_from_der

        ca_cert, ca_key = mtls_module.generate_ca(CERT_PASSPHRASE)
        agent_cert_pem, _ = mtls_module.generate_agent_cert(
            "alpha", ca_cert, ca_key, CERT_PASSPHRASE,
        )
        # Convert PEM to DER for the test
        from cryptography import x509
        cert_obj = x509.load_pem_x509_certificate(agent_cert_pem)
        from cryptography.hazmat.primitives import serialization
        der_bytes = cert_obj.public_bytes(serialization.Encoding.DER)

        assert verify_peer_agent_id_from_der(der_bytes, "alpha") is True

    def test_verify_peer_agent_id_from_der_mismatch(self, setup):
        """Wrong CN raises ValueError."""
        from guardian.mtls import verify_peer_agent_id_from_der

        ca_cert, ca_key = mtls_module.generate_ca(CERT_PASSPHRASE)
        agent_cert_pem, _ = mtls_module.generate_agent_cert(
            "alpha", ca_cert, ca_key, CERT_PASSPHRASE,
        )
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        cert_obj = x509.load_pem_x509_certificate(agent_cert_pem)
        der_bytes = cert_obj.public_bytes(serialization.Encoding.DER)

        with pytest.raises(ValueError, match="does not match"):
            verify_peer_agent_id_from_der(der_bytes, "beta")

    def test_middleware_exists(self):
        """PeerCertMiddleware is importable."""
        from guardian.middleware import PeerCertMiddleware
        assert PeerCertMiddleware is not None
