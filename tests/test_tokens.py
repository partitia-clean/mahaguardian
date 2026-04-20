"""
Tests for guardian/tokens.py — Guardian Access Token issuing and verification.
"""
from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

import guardian.audit as audit_module
import guardian.tokens as tokens_module
from guardian.tokens import (
    TokenAgentMismatchError,
    TokenExpiredError,
    TokenInvalidError,
    TokenRevokedError,
    generate_token_keypair,
    init_tokens,
    issue_token,
    revoke_all_tokens,
    revoke_token,
    verify_token,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

AGENT_CERT = b"FAKE-AGENT-CERTIFICATE-BYTES-FOR-TESTING"
OTHER_CERT = b"DIFFERENT-AGENT-CERTIFICATE-BYTES"

PERMISSIONS = {
    "data_classifications": ["PUBLIC", "INTERNAL"],
    "vault_read": ["personal"],
    "vault_write": [],
    "tool_calls": ["google_calendar", "ft_news"],
    "payment_execute": True,
}


@pytest.fixture(autouse=True)
def setup_modules(tmp_path):
    """Initialise audit and token modules in temp directories."""
    audit_db = tmp_path / "audit.db"
    audit_module.init_audit_log(audit_db)

    private_key, public_key = generate_token_keypair()
    revoc_db = tmp_path / "revocations.db"
    init_tokens(private_key, public_key, revoc_db)

    yield tmp_path

    # Reset module state
    tokens_module._signing_key = None
    tokens_module._verify_key = None
    tokens_module._db_path = None


# ---------------------------------------------------------------------------
# generate_token_keypair
# ---------------------------------------------------------------------------

class TestGenerateTokenKeypair:
    def test_returns_bytes_tuple(self):
        priv, pub = generate_token_keypair()
        assert isinstance(priv, bytes)
        assert isinstance(pub, bytes)

    def test_keys_are_32_bytes(self):
        priv, pub = generate_token_keypair()
        assert len(priv) == 32
        assert len(pub) == 32

    def test_each_call_unique(self):
        kp1 = generate_token_keypair()
        kp2 = generate_token_keypair()
        assert kp1[0] != kp2[0]


# ---------------------------------------------------------------------------
# init_tokens
# ---------------------------------------------------------------------------

class TestInitTokens:
    def test_creates_revocation_db(self, tmp_path):
        priv, pub = generate_token_keypair()
        db = tmp_path / "init_test.db"
        init_tokens(priv, pub, db)
        assert db.exists()

    def test_creates_parent_dirs(self, tmp_path):
        priv, pub = generate_token_keypair()
        db = tmp_path / "nested" / "dir" / "revoc.db"
        init_tokens(priv, pub, db)
        assert db.exists()

    def test_idempotent(self, tmp_path):
        priv, pub = generate_token_keypair()
        db = tmp_path / "idem.db"
        init_tokens(priv, pub, db)
        init_tokens(priv, pub, db)  # should not raise


# ---------------------------------------------------------------------------
# issue_token
# ---------------------------------------------------------------------------

class TestIssueToken:
    def test_returns_json_string(self):
        token_str = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        token = json.loads(token_str)
        assert isinstance(token, dict)

    def test_contains_required_fields(self):
        token_str = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        token = json.loads(token_str)
        for field in ("token_id", "agent_id", "issued_at", "expires_at",
                       "permissions", "agent_cert_fingerprint", "sig"):
            assert field in token

    def test_agent_id_matches(self):
        token = json.loads(issue_token("alpha", AGENT_CERT, PERMISSIONS))
        assert token["agent_id"] == "alpha"

    def test_permissions_match(self):
        token = json.loads(issue_token("alpha", AGENT_CERT, PERMISSIONS))
        assert token["permissions"] == PERMISSIONS

    def test_sig_is_base64(self):
        token = json.loads(issue_token("alpha", AGENT_CERT, PERMISSIONS))
        sig_bytes = base64.b64decode(token["sig"])
        assert len(sig_bytes) == 64  # ed25519 signature

    def test_custom_lifetime(self):
        token = json.loads(issue_token("alpha", AGENT_CERT, PERMISSIONS, lifetime_hours=1))
        issued = datetime.fromisoformat(token["issued_at"])
        expires = datetime.fromisoformat(token["expires_at"])
        delta = expires - issued
        assert abs(delta.total_seconds() - 3600) < 2

    def test_audit_logged(self):
        issue_token("alpha", AGENT_CERT, PERMISSIONS)
        entries = audit_module.query_log(action="token.issue")
        assert len(entries) >= 1
        assert entries[-1]["agent_id"] == "alpha"

    def test_raises_if_not_initialised(self, tmp_path):
        tokens_module._signing_key = None
        with pytest.raises(RuntimeError, match="not initialised"):
            issue_token("alpha", AGENT_CERT, PERMISSIONS)


# ---------------------------------------------------------------------------
# verify_token
# ---------------------------------------------------------------------------

class TestVerifyToken:
    def test_valid_token_returns_verified_payload(self):
        token_str = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        result = verify_token(token_str, AGENT_CERT)
        assert result["permissions"] == PERMISSIONS
        assert result["agent_id"] == "alpha"
        assert "token_id" in result
        assert "issued_at" in result
        assert "expires_at" in result

    def test_wrong_agent_cert_raises(self):
        token_str = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        with pytest.raises(TokenAgentMismatchError):
            verify_token(token_str, OTHER_CERT)

    def test_expired_token_raises(self):
        token_str = issue_token("alpha", AGENT_CERT, PERMISSIONS, lifetime_hours=0)
        # Token with 0 hours is already expired
        with pytest.raises(TokenExpiredError):
            verify_token(token_str, AGENT_CERT)

    def test_tampered_payload_raises(self):
        token_str = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        token = json.loads(token_str)
        token["agent_id"] = "evil"
        tampered = json.dumps(token, sort_keys=True, separators=(",", ":"))
        with pytest.raises(TokenInvalidError, match="signature"):
            verify_token(tampered, AGENT_CERT)

    def test_invalid_json_raises(self):
        with pytest.raises(TokenInvalidError, match="not valid JSON"):
            verify_token("not json at all", AGENT_CERT)

    def test_missing_sig_raises(self):
        token_str = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        token = json.loads(token_str)
        del token["sig"]
        no_sig = json.dumps(token)
        with pytest.raises(TokenInvalidError, match="no signature"):
            verify_token(no_sig, AGENT_CERT)

    def test_wrong_signing_key_raises(self, tmp_path):
        token_str = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        # Re-init with different keys
        new_priv, new_pub = generate_token_keypair()
        init_tokens(new_priv, new_pub, tmp_path / "revoc2.db")
        with pytest.raises(TokenInvalidError, match="signature"):
            verify_token(token_str, AGENT_CERT)

    def test_verify_audit_logged(self):
        token_str = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        verify_token(token_str, AGENT_CERT)
        entries = audit_module.query_log(action="token.verify")
        assert any(e["result"] == "success" for e in entries)

    def test_expired_audit_logged(self):
        token_str = issue_token("alpha", AGENT_CERT, PERMISSIONS, lifetime_hours=0)
        with pytest.raises(TokenExpiredError):
            verify_token(token_str, AGENT_CERT)
        entries = audit_module.query_log(action="token.verify")
        assert any("expired" in e["result"] for e in entries)


# ---------------------------------------------------------------------------
# Revocation
# ---------------------------------------------------------------------------

class TestRevocation:
    def test_revoke_token_blocks_verify(self):
        token_str = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        token_id = json.loads(token_str)["token_id"]
        revoke_token(token_id, agent_id="alpha")
        with pytest.raises(TokenRevokedError):
            verify_token(token_str, AGENT_CERT)

    def test_revoke_all_tokens_blocks_verify(self):
        token_str = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        revoke_all_tokens("alpha")
        with pytest.raises(TokenRevokedError):
            verify_token(token_str, AGENT_CERT)

    def test_revoke_one_agent_does_not_affect_other(self):
        token_alpha = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        token_beta = issue_token("beta", OTHER_CERT, PERMISSIONS)
        revoke_all_tokens("alpha")
        # beta should still work
        result = verify_token(token_beta, OTHER_CERT)
        assert result["permissions"] == PERMISSIONS

    def test_revoke_token_audit_logged(self):
        revoke_token("fake-token-id", agent_id="alpha")
        entries = audit_module.query_log(action="token.revoke")
        assert len(entries) >= 1

    def test_revoke_all_audit_logged(self):
        revoke_all_tokens("alpha")
        entries = audit_module.query_log(action="token.revoke_all")
        assert len(entries) >= 1
        assert entries[-1]["agent_id"] == "alpha"

    def test_revoke_idempotent(self):
        revoke_token("same-id", agent_id="alpha")
        revoke_token("same-id", agent_id="alpha")  # should not raise

    def test_revoke_all_idempotent(self):
        revoke_all_tokens("alpha")
        revoke_all_tokens("alpha")  # should not raise


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

class TestTokenEdgeCases:
    def test_multiple_tokens_for_same_agent(self):
        t1 = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        t2 = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        # Both should verify
        assert verify_token(t1, AGENT_CERT)["permissions"] == PERMISSIONS
        assert verify_token(t2, AGENT_CERT)["permissions"] == PERMISSIONS
        # Revoking one doesn't affect the other
        tid1 = json.loads(t1)["token_id"]
        revoke_token(tid1, agent_id="alpha")
        with pytest.raises(TokenRevokedError):
            verify_token(t1, AGENT_CERT)
        assert verify_token(t2, AGENT_CERT)["permissions"] == PERMISSIONS

    def test_empty_permissions(self):
        empty_perms = {
            "data_classifications": [],
            "vault_read": [],
            "vault_write": [],
            "tool_calls": [],
            "payment_execute": False,
        }
        token_str = issue_token("alpha", AGENT_CERT, empty_perms)
        result = verify_token(token_str, AGENT_CERT)
        assert result["permissions"] == empty_perms

    def test_path_traversal_agent_id_rejected(self):
        """FIX D: agent_id with path traversal must be rejected."""
        with pytest.raises(ValueError, match="Invalid agent_id"):
            issue_token("../../etc/passwd", AGENT_CERT, PERMISSIONS)

    def test_slash_agent_id_rejected(self):
        with pytest.raises(ValueError, match="Invalid agent_id"):
            issue_token("alpha/beta", AGENT_CERT, PERMISSIONS)


# ---------------------------------------------------------------------------
# Strict JSON parsing (F-006)
# ---------------------------------------------------------------------------

class TestStrictTokenParsing:
    def test_duplicate_key_rejected(self):
        """Token JSON with duplicate keys must be rejected."""
        # Craft raw JSON with duplicate "agent_id" key
        token_str = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        # Inject a duplicate key by string manipulation
        duplicate_json = token_str[:-1] + ',"agent_id":"evil"}'
        with pytest.raises(TokenInvalidError, match="Duplicate key"):
            verify_token(duplicate_json, AGENT_CERT)

    def test_unknown_field_rejected(self):
        """Token JSON with unknown fields must be rejected."""
        token_str = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        token = json.loads(token_str)
        token["evil_field"] = "malicious"
        tampered = json.dumps(token, sort_keys=True, separators=(",", ":"))
        with pytest.raises(TokenInvalidError, match="Unknown fields"):
            verify_token(tampered, AGENT_CERT)

    def test_valid_token_with_all_known_fields_passes(self):
        """Valid token with only known fields passes strict parsing."""
        token_str = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        result = verify_token(token_str, AGENT_CERT)
        assert result["agent_id"] == "alpha"


# ---------------------------------------------------------------------------
# Payment limits not in token (F-007)
# ---------------------------------------------------------------------------

class TestPaymentLimitsNotInToken:
    def test_issued_token_has_no_payment_limit(self):
        """Issued token must NOT contain payment_auto_approve_limit_gbp."""
        token_str = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        token = json.loads(token_str)
        assert "payment_auto_approve_limit_gbp" not in token["permissions"]

    def test_token_still_has_payment_execute(self):
        """Token still carries payment_execute bool for authorization."""
        token_str = issue_token("alpha", AGENT_CERT, PERMISSIONS)
        token = json.loads(token_str)
        assert token["permissions"]["payment_execute"] is True
