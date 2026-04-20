"""
Tests for shared/token.py — Phase 3 AccessToken verification.

One test per verification step:
  - wrong signature
  - expired token
  - revoked token (by token_id)
  - revoked agent (by agent_id)
  - wrong cert (fingerprint mismatch)
  - valid token
  - duplicate request_id within window
  - cert_fingerprint format is 'sha256:<hex>'
  - revocation store persists on mutation
"""
from __future__ import annotations

import base64
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import nacl.signing
import pytest

from shared.token import (
    AccessToken,
    DuplicateRequestError,
    RequestDeduplicator,
    RevocationStore,
    TokenBindingError,
    TokenExpiredError,
    TokenRevokedError,
    TokenSignatureError,
    cert_fingerprint,
    issue_token,
    verify_token_binding,
)
from shared.types import TlpLevel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

AGENT_DER  = b"FAKE-DER-CERT-BYTES-ALPHA"
OTHER_DER  = b"FAKE-DER-CERT-BYTES-OTHER"

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()

def _future(hours: int = 4) -> str:
    return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()

def _past(hours: int = 1) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()


@pytest.fixture
def keypair():
    sk = nacl.signing.SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


@pytest.fixture
def revocation():
    return RevocationStore()


@pytest.fixture
def deduplicator():
    return RequestDeduplicator()


@pytest.fixture
def valid_token(keypair):
    sk_bytes, _ = keypair
    return issue_token(
        agent_id="alpha",
        partitions=["company-a"],
        tlp_level=TlpLevel.AMBER,
        operations=["vault.read"],
        agent_der_cert=AGENT_DER,
        issued_at=_now(),
        expires_at=_future(4),
        issuer="guardian",
        signing_key_bytes=sk_bytes,
    )


# ---------------------------------------------------------------------------
# Step 1: Signature verification
# ---------------------------------------------------------------------------

def test_bad_signature_rejected(keypair, revocation):
    sk_bytes, vk_bytes = keypair
    token = issue_token(
        agent_id="alpha", partitions=["company-a"],
        tlp_level=TlpLevel.AMBER, operations=["vault.read"],
        agent_der_cert=AGENT_DER, issued_at=_now(), expires_at=_future(),
        issuer="guardian", signing_key_bytes=sk_bytes,
    )
    token.signature = base64.b64encode(b"\x00" * 64).decode("ascii")
    with pytest.raises(TokenSignatureError):
        verify_token_binding(token, AGENT_DER, revocation, vk_bytes)


def test_wrong_verify_key_rejected(keypair, revocation):
    sk_bytes, _ = keypair
    token = issue_token(
        agent_id="alpha", partitions=["company-a"],
        tlp_level=TlpLevel.AMBER, operations=["vault.read"],
        agent_der_cert=AGENT_DER, issued_at=_now(), expires_at=_future(),
        issuer="guardian", signing_key_bytes=sk_bytes,
    )
    other_vk = bytes(nacl.signing.SigningKey.generate().verify_key)
    with pytest.raises(TokenSignatureError):
        verify_token_binding(token, AGENT_DER, revocation, other_vk)


# ---------------------------------------------------------------------------
# Step 2: Expiry
# ---------------------------------------------------------------------------

def test_expired_token_rejected(keypair, revocation):
    sk_bytes, vk_bytes = keypair
    token = issue_token(
        agent_id="alpha", partitions=["company-a"],
        tlp_level=TlpLevel.AMBER, operations=["vault.read"],
        agent_der_cert=AGENT_DER, issued_at=_past(2), expires_at=_past(1),
        issuer="guardian", signing_key_bytes=sk_bytes,
    )
    with pytest.raises(TokenExpiredError):
        verify_token_binding(token, AGENT_DER, revocation, vk_bytes)


# ---------------------------------------------------------------------------
# Step 3: Revocation
# ---------------------------------------------------------------------------

def test_revoked_token_id_rejected(keypair, revocation, valid_token):
    _, vk_bytes = keypair
    revocation.revoke_token(valid_token.token_id)
    with pytest.raises(TokenRevokedError):
        verify_token_binding(valid_token, AGENT_DER, revocation, vk_bytes)


def test_revoked_agent_id_rejected(keypair, revocation, valid_token):
    _, vk_bytes = keypair
    revocation.revoke_agent("alpha")
    with pytest.raises(TokenRevokedError):
        verify_token_binding(valid_token, AGENT_DER, revocation, vk_bytes)


# ---------------------------------------------------------------------------
# Step 4: cert_fingerprint
# ---------------------------------------------------------------------------

def test_wrong_cert_rejected(keypair, revocation, valid_token):
    _, vk_bytes = keypair
    with pytest.raises(TokenBindingError):
        verify_token_binding(valid_token, OTHER_DER, revocation, vk_bytes)


def test_cert_fingerprint_format():
    fp = cert_fingerprint(AGENT_DER)
    assert fp.startswith("sha256:")
    hex_part = fp[len("sha256:"):]
    assert len(hex_part) == 64
    assert all(c in "0123456789abcdef" for c in hex_part)


def test_cert_fingerprint_in_issued_token(keypair):
    sk_bytes, _ = keypair
    token = issue_token(
        agent_id="alpha", partitions=["company-a"],
        tlp_level=TlpLevel.AMBER, operations=["vault.read"],
        agent_der_cert=AGENT_DER, issued_at=_now(), expires_at=_future(),
        issuer="guardian", signing_key_bytes=sk_bytes,
    )
    assert token.cert_fingerprint == cert_fingerprint(AGENT_DER)
    assert token.cert_fingerprint.startswith("sha256:")


# ---------------------------------------------------------------------------
# Valid token passes all checks
# ---------------------------------------------------------------------------

def test_valid_token_accepted(keypair, revocation, valid_token):
    _, vk_bytes = keypair
    # Should not raise
    verify_token_binding(valid_token, AGENT_DER, revocation, vk_bytes)


# ---------------------------------------------------------------------------
# Request deduplication
# ---------------------------------------------------------------------------

def test_duplicate_request_id_rejected(keypair, revocation, deduplicator, valid_token):
    _, vk_bytes = keypair
    rid = "req-abc-123"
    verify_token_binding(valid_token, AGENT_DER, revocation, vk_bytes,
                         request_id=rid, deduplicator=deduplicator)
    with pytest.raises(DuplicateRequestError):
        verify_token_binding(valid_token, AGENT_DER, revocation, vk_bytes,
                             request_id=rid, deduplicator=deduplicator)


def test_different_request_ids_accepted(keypair, revocation, deduplicator, valid_token):
    _, vk_bytes = keypair
    verify_token_binding(valid_token, AGENT_DER, revocation, vk_bytes,
                         request_id="req-1", deduplicator=deduplicator)
    verify_token_binding(valid_token, AGENT_DER, revocation, vk_bytes,
                         request_id="req-2", deduplicator=deduplicator)


def test_no_dedup_without_request_id(keypair, revocation, valid_token):
    """Not passing request_id skips deduplication silently."""
    _, vk_bytes = keypair
    verify_token_binding(valid_token, AGENT_DER, revocation, vk_bytes)
    verify_token_binding(valid_token, AGENT_DER, revocation, vk_bytes)


# ---------------------------------------------------------------------------
# Revocation store persists on mutation
# ---------------------------------------------------------------------------

def test_revocation_persist_called_on_revoke_token():
    persist = MagicMock()
    store = RevocationStore(persist_callback=persist)
    store.revoke_token("tok-123")
    persist.assert_called_once()
    snapshot = persist.call_args[0][0]
    assert "tok-123" in snapshot["revoked_tokens"]


def test_revocation_persist_called_on_revoke_agent():
    persist = MagicMock()
    store = RevocationStore(persist_callback=persist)
    store.revoke_agent("alpha")
    persist.assert_called_once()
    snapshot = persist.call_args[0][0]
    assert "alpha" in snapshot["revoked_agents"]


def test_revocation_store_load_restore():
    store = RevocationStore()
    store.load({"revoked_tokens": {"t1": "2026-01-01"}, "revoked_agents": {}})
    assert store.is_revoked("t1", "nobody")


# ---------------------------------------------------------------------------
# AccessToken schema fields
# ---------------------------------------------------------------------------

def test_token_has_partitions(valid_token):
    assert valid_token.partitions == ["company-a"]


def test_token_has_tlp_level(valid_token):
    assert valid_token.tlp_level == TlpLevel.AMBER


def test_token_has_nonce(valid_token):
    assert len(valid_token.nonce) > 0


def test_token_roundtrips_json(valid_token):
    d = valid_token.to_dict()
    t2 = AccessToken.from_dict(d)
    assert t2.token_id == valid_token.token_id
    assert t2.partitions == valid_token.partitions
    assert t2.tlp_level  == valid_token.tlp_level


# ---------------------------------------------------------------------------
# FIX F8: Replay protection boundary-value tests
# ---------------------------------------------------------------------------

class TestReplayBoundary:
    """Verify that the 60-second deduplication window has precise boundary semantics."""

    def _make_deduplicator(self):
        from shared.token import RequestDeduplicator
        return RequestDeduplicator()

    def test_duplicate_within_window_rejected(self):
        """Same request_id within 60s → DuplicateRequestError."""
        from shared.token import DuplicateRequestError
        import unittest.mock as mock

        d = self._make_deduplicator()
        t0 = 1000.0
        with mock.patch("time.monotonic", return_value=t0):
            d.check_and_register("req-1")

        # Still within 59.99s → must reject
        with mock.patch("time.monotonic", return_value=t0 + 59.99):
            with pytest.raises(DuplicateRequestError):
                d.check_and_register("req-1")

    def test_duplicate_after_window_accepted(self):
        """Same request_id after 60.01s → accepted (window expired)."""
        from shared.token import DuplicateRequestError
        import unittest.mock as mock

        d = self._make_deduplicator()
        t0 = 1000.0
        with mock.patch("time.monotonic", return_value=t0):
            d.check_and_register("req-2")

        # After 60.01s the entry's expiry has passed → must accept
        with mock.patch("time.monotonic", return_value=t0 + 60.01):
            d.check_and_register("req-2")  # must not raise

    def test_duplicate_at_exact_boundary_accepted(self):
        """At T=60.0 exactly the entry is expired (expiry == now → not strictly >)."""
        from shared.token import DuplicateRequestError
        import unittest.mock as mock

        d = self._make_deduplicator()
        t0 = 1000.0
        with mock.patch("time.monotonic", return_value=t0):
            d.check_and_register("req-3")

        # expiry = t0 + 60.0 = 1060.0; now = 1060.0; expiry > now is False → accepted
        with mock.patch("time.monotonic", return_value=t0 + 60.0):
            d.check_and_register("req-3")  # must not raise

    def test_different_request_ids_not_conflated(self):
        """Different request_ids within the window must both be accepted."""
        d = self._make_deduplicator()
        d.check_and_register("req-a")
        d.check_and_register("req-b")  # must not raise

    def test_expiry_check_independent_of_prune_schedule(self):
        """Expiry boundary must be deterministic regardless of when _maybe_prune runs."""
        from shared.token import DuplicateRequestError
        import unittest.mock as mock

        d = self._make_deduplicator()
        t0 = 1000.0

        # Register at T=0
        with mock.patch("time.monotonic", return_value=t0):
            d.check_and_register("req-x")

        # At T=59 run a separate request to prevent prune from running
        # (prune runs every 60s; last_prune is still t0, elapsed=59 < 60 → no prune)
        with mock.patch("time.monotonic", return_value=t0 + 59.0):
            with pytest.raises(DuplicateRequestError):
                d.check_and_register("req-x")

        # At T=60.01, even without prune, expiry check alone must allow it
        with mock.patch("time.monotonic", return_value=t0 + 60.01):
            d.check_and_register("req-x")  # must not raise
