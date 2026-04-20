"""
Phase 3 Step 7 tests — 8-step async enforce() pipeline.

Covers:
  - ALLOW path: returns DataItem
  - Token invalid (bad signature) → EnforcementDenied
  - Token expired → EnforcementDenied
  - Token revoked → EnforcementDenied
  - Duplicate request_id → EnforcementDenied (Step 2b)
  - Key not found → EnforcementDenied (anti-probing)
  - Ambiguous key → AmbiguousKeyError
  - Confused-deputy in params → ConfusedDeputyError
  - TLP DENY → EnforcementDenied
  - TLP ELEVATE + callback approves → DataItem
  - TLP ELEVATE + callback denies → ElevateTimeoutError
  - TLP ELEVATE + no callback → ElevateTimeoutError
  - Second call with same request_id → EnforcementDenied (replay protection)
"""
from __future__ import annotations

import base64
import uuid
from datetime import datetime, timedelta, timezone

import pytest
import pytest_asyncio
import nacl.signing

import guardian.audit as audit_module
from guardian.enforcer import (
    AmbiguousKeyError,
    ConfusedDeputyError,
    EnforcementDenied,
    ElevateTimeoutError,
    VaultRequest,
    enforce,
)
from shared.data_item import DataItem
from shared.token import (
    AccessToken,
    RequestDeduplicator,
    RevocationStore,
    issue_token,
)
from shared.types import Classification, TlpLevel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_audit(tmp_path):
    audit_module.init_audit_log(tmp_path / "audit.db")
    yield


@pytest.fixture
def signing_keypair():
    sk = nacl.signing.SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


@pytest.fixture
def agent_der_cert():
    # Minimal fake DER cert bytes (just needs to be hashable)
    return b"fake-der-cert-bytes-for-testing"


@pytest.fixture
def revocation():
    return RevocationStore()


@pytest.fixture
def deduplicator():
    return RequestDeduplicator()


def _make_token(
    signing_key_bytes: bytes,
    agent_der_cert: bytes,
    *,
    partitions: list[str],
    tlp_level: TlpLevel,
    expires_delta_seconds: int = 3600,
    agent_id: str = "test-agent",
) -> AccessToken:
    now = datetime.now(timezone.utc)
    return issue_token(
        agent_id=agent_id,
        partitions=partitions,
        tlp_level=tlp_level,
        operations=["vault.read"],
        agent_der_cert=agent_der_cert,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(seconds=expires_delta_seconds)).isoformat(),
        issuer="test-guardian",
        signing_key_bytes=signing_key_bytes,
    )


def _make_request(
    token: AccessToken,
    peer_der_cert: bytes,
    key: str = "secret",
    params: dict = None,
    request_id: str = None,
) -> VaultRequest:
    return VaultRequest(
        key=key,
        params=params if params is not None else {},
        request_id=request_id or str(uuid.uuid4()),
        token=token,
        peer_der_cert=peer_der_cert,
    )


def _restricted_vault() -> dict[str, DataItem]:
    item = DataItem(
        item_id="secret",
        owner_partition="company-a",
        classification=Classification.RESTRICTED,
        value="top_secret_value",
    )
    return {"secret/company-a": item}


def _public_vault() -> dict[str, DataItem]:
    item = DataItem(
        item_id="pub",
        owner_partition="company-a",
        classification=Classification.PUBLIC,
        value="open_value",
    )
    return {"pub/company-a": item}


# ---------------------------------------------------------------------------
# ALLOW paths
# ---------------------------------------------------------------------------

class TestEnforceAllow:
    @pytest.mark.asyncio
    async def test_red_restricted_allows(self, signing_keypair, agent_der_cert, revocation, deduplicator):
        sk, vk = signing_keypair
        token = _make_token(sk, agent_der_cert, partitions=["company-a"], tlp_level=TlpLevel.RED)
        req = _make_request(token, agent_der_cert)
        item = await enforce(
            req,
            vault_items=_restricted_vault(),
            revocation_store=revocation,
            verify_key_bytes=vk,
            deduplicator=deduplicator,
            known_partitions=["company-a"],
        )
        assert item.item_id == "secret"
        assert item.value == "top_secret_value"

    @pytest.mark.asyncio
    async def test_clear_public_allows(self, signing_keypair, agent_der_cert, revocation, deduplicator):
        sk, vk = signing_keypair
        token = _make_token(sk, agent_der_cert, partitions=["company-a"], tlp_level=TlpLevel.CLEAR)
        req = _make_request(token, agent_der_cert, key="pub")
        item = await enforce(
            req,
            vault_items=_public_vault(),
            revocation_store=revocation,
            verify_key_bytes=vk,
            deduplicator=deduplicator,
            known_partitions=["company-a"],
        )
        assert item.item_id == "pub"


# ---------------------------------------------------------------------------
# Token validation failures
# ---------------------------------------------------------------------------

class TestEnforceTokenFailures:
    @pytest.mark.asyncio
    async def test_bad_signature_raises(self, signing_keypair, agent_der_cert, revocation, deduplicator):
        sk, vk = signing_keypair
        token = _make_token(sk, agent_der_cert, partitions=["company-a"], tlp_level=TlpLevel.RED)
        # Use a different verify key
        _, wrong_vk = bytes(nacl.signing.SigningKey.generate()), bytes(nacl.signing.SigningKey.generate().verify_key)
        req = _make_request(token, agent_der_cert)
        with pytest.raises(EnforcementDenied) as exc_info:
            await enforce(
                req,
                vault_items=_restricted_vault(),
                revocation_store=revocation,
                verify_key_bytes=wrong_vk,
                deduplicator=deduplicator,
                known_partitions=["company-a"],
            )
        assert exc_info.value.safe_message == "access_denied"

    @pytest.mark.asyncio
    async def test_expired_token_raises(self, signing_keypair, agent_der_cert, revocation, deduplicator):
        sk, vk = signing_keypair
        token = _make_token(
            sk, agent_der_cert, partitions=["company-a"], tlp_level=TlpLevel.RED,
            expires_delta_seconds=-1,  # already expired
        )
        req = _make_request(token, agent_der_cert)
        with pytest.raises(EnforcementDenied) as exc_info:
            await enforce(
                req,
                vault_items=_restricted_vault(),
                revocation_store=revocation,
                verify_key_bytes=vk,
                deduplicator=deduplicator,
                known_partitions=["company-a"],
            )
        assert exc_info.value.safe_message == "access_denied"

    @pytest.mark.asyncio
    async def test_revoked_token_raises(self, signing_keypair, agent_der_cert, revocation, deduplicator):
        sk, vk = signing_keypair
        token = _make_token(sk, agent_der_cert, partitions=["company-a"], tlp_level=TlpLevel.RED)
        revocation.revoke_token(token.token_id)
        req = _make_request(token, agent_der_cert)
        with pytest.raises(EnforcementDenied) as exc_info:
            await enforce(
                req,
                vault_items=_restricted_vault(),
                revocation_store=revocation,
                verify_key_bytes=vk,
                deduplicator=deduplicator,
                known_partitions=["company-a"],
            )
        assert exc_info.value.safe_message == "access_denied"

    @pytest.mark.asyncio
    async def test_wrong_cert_raises(self, signing_keypair, agent_der_cert, revocation, deduplicator):
        sk, vk = signing_keypair
        token = _make_token(sk, agent_der_cert, partitions=["company-a"], tlp_level=TlpLevel.RED)
        req = _make_request(token, b"wrong-cert-bytes")  # different cert
        with pytest.raises(EnforcementDenied):
            await enforce(
                req,
                vault_items=_restricted_vault(),
                revocation_store=revocation,
                verify_key_bytes=vk,
                deduplicator=deduplicator,
                known_partitions=["company-a"],
            )


# ---------------------------------------------------------------------------
# Step 2b: Replay protection
# ---------------------------------------------------------------------------

class TestEnforceReplayProtection:
    @pytest.mark.asyncio
    async def test_duplicate_request_id_raises(self, signing_keypair, agent_der_cert, revocation, deduplicator):
        sk, vk = signing_keypair
        token = _make_token(sk, agent_der_cert, partitions=["company-a"], tlp_level=TlpLevel.RED)
        rid = "req-replay-test"
        req1 = _make_request(token, agent_der_cert, request_id=rid)
        req2 = _make_request(token, agent_der_cert, request_id=rid)

        await enforce(
            req1,
            vault_items=_restricted_vault(),
            revocation_store=revocation,
            verify_key_bytes=vk,
            deduplicator=deduplicator,
            known_partitions=["company-a"],
        )

        # Second call with same request_id must be rejected
        with pytest.raises(EnforcementDenied) as exc_info:
            await enforce(
                req2,
                vault_items=_restricted_vault(),
                revocation_store=revocation,
                verify_key_bytes=vk,
                deduplicator=deduplicator,
                known_partitions=["company-a"],
            )
        assert exc_info.value.reason_code == "duplicate_request"
        assert exc_info.value.safe_message == "access_denied"

    @pytest.mark.asyncio
    async def test_different_request_ids_accepted(self, signing_keypair, agent_der_cert, revocation, deduplicator):
        sk, vk = signing_keypair
        token = _make_token(sk, agent_der_cert, partitions=["company-a"], tlp_level=TlpLevel.RED)
        vault = _restricted_vault()

        item1 = await enforce(
            _make_request(token, agent_der_cert, request_id="req-a"),
            vault_items=vault, revocation_store=revocation,
            verify_key_bytes=vk, deduplicator=deduplicator,
            known_partitions=["company-a"],
        )
        item2 = await enforce(
            _make_request(token, agent_der_cert, request_id="req-b"),
            vault_items=vault, revocation_store=revocation,
            verify_key_bytes=vk, deduplicator=deduplicator,
            known_partitions=["company-a"],
        )
        assert item1.item_id == item2.item_id == "secret"


# ---------------------------------------------------------------------------
# Vault access denials
# ---------------------------------------------------------------------------

class TestEnforceVaultDenials:
    @pytest.mark.asyncio
    async def test_key_not_found_raises(self, signing_keypair, agent_der_cert, revocation, deduplicator):
        sk, vk = signing_keypair
        token = _make_token(sk, agent_der_cert, partitions=["company-a"], tlp_level=TlpLevel.RED)
        req = _make_request(token, agent_der_cert, key="nonexistent")
        with pytest.raises(EnforcementDenied) as exc_info:
            await enforce(
                req,
                vault_items=_restricted_vault(),
                revocation_store=revocation,
                verify_key_bytes=vk,
                deduplicator=deduplicator,
                known_partitions=["company-a"],
            )
        assert exc_info.value.safe_message == "access_denied"

    @pytest.mark.asyncio
    async def test_not_found_same_message_as_partition_denied(
        self, signing_keypair, agent_der_cert, revocation, deduplicator
    ):
        sk, vk = signing_keypair
        vault = _restricted_vault()

        # Not found
        token_a = _make_token(sk, agent_der_cert, partitions=["company-a"], tlp_level=TlpLevel.RED)
        with pytest.raises(EnforcementDenied) as e1:
            await enforce(
                _make_request(token_a, agent_der_cert, key="ghost"),
                vault_items=vault, revocation_store=revocation,
                verify_key_bytes=vk, deduplicator=deduplicator,
                known_partitions=["company-a"],
            )

        # Wrong partition
        token_b = _make_token(sk, agent_der_cert, partitions=["company-b"], tlp_level=TlpLevel.RED,
                               agent_id="agent-b")
        with pytest.raises(EnforcementDenied) as e2:
            await enforce(
                _make_request(token_b, agent_der_cert, key="secret"),
                vault_items=vault, revocation_store=revocation,
                verify_key_bytes=vk, deduplicator=deduplicator,
                known_partitions=["company-a"],
            )

        assert e1.value.safe_message == e2.value.safe_message == "access_denied"

    @pytest.mark.asyncio
    async def test_ambiguous_key_raises(self, signing_keypair, agent_der_cert, revocation, deduplicator):
        sk, vk = signing_keypair
        token = _make_token(sk, agent_der_cert, partitions=["p1", "p2"], tlp_level=TlpLevel.RED)
        vault = {
            "dup/p1": DataItem("dup", "p1", Classification.PUBLIC, "v1"),
            "dup/p2": DataItem("dup", "p2", Classification.PUBLIC, "v2"),
        }
        req = _make_request(token, agent_der_cert, key="dup")
        with pytest.raises(AmbiguousKeyError):
            await enforce(
                req,
                vault_items=vault,
                revocation_store=revocation,
                verify_key_bytes=vk,
                deduplicator=deduplicator,
                known_partitions=["p1", "p2"],
            )

    @pytest.mark.asyncio
    async def test_confused_deputy_raises(self, signing_keypair, agent_der_cert, revocation, deduplicator):
        sk, vk = signing_keypair
        token = _make_token(sk, agent_der_cert, partitions=["company-a"], tlp_level=TlpLevel.RED)
        req = _make_request(token, agent_der_cert, params={"hint": "company-a"})
        with pytest.raises(ConfusedDeputyError):
            await enforce(
                req,
                vault_items=_restricted_vault(),
                revocation_store=revocation,
                verify_key_bytes=vk,
                deduplicator=deduplicator,
                known_partitions=["company-a"],
            )


# ---------------------------------------------------------------------------
# TLP enforcement
# ---------------------------------------------------------------------------

class TestEnforceTlp:
    @pytest.mark.asyncio
    async def test_tlp_deny_green_restricted(self, signing_keypair, agent_der_cert, revocation, deduplicator):
        sk, vk = signing_keypair
        token = _make_token(sk, agent_der_cert, partitions=["company-a"], tlp_level=TlpLevel.GREEN)
        req = _make_request(token, agent_der_cert)
        with pytest.raises(EnforcementDenied) as exc_info:
            await enforce(
                req,
                vault_items=_restricted_vault(),
                revocation_store=revocation,
                verify_key_bytes=vk,
                deduplicator=deduplicator,
                known_partitions=["company-a"],
            )
        assert exc_info.value.safe_message == "access_denied"

    @pytest.mark.asyncio
    async def test_tlp_elevate_callback_approves(self, signing_keypair, agent_der_cert, revocation, deduplicator):
        sk, vk = signing_keypair
        token = _make_token(sk, agent_der_cert, partitions=["company-a"], tlp_level=TlpLevel.AMBER_STRICT)

        async def approve(_item):
            return True

        req = _make_request(token, agent_der_cert)
        item = await enforce(
            req,
            vault_items=_restricted_vault(),
            revocation_store=revocation,
            verify_key_bytes=vk,
            deduplicator=deduplicator,
            elevate_callback=approve,
            known_partitions=["company-a"],
        )
        assert item.item_id == "secret"

    @pytest.mark.asyncio
    async def test_tlp_elevate_callback_denies(self, signing_keypair, agent_der_cert, revocation, deduplicator):
        sk, vk = signing_keypair
        token = _make_token(sk, agent_der_cert, partitions=["company-a"], tlp_level=TlpLevel.AMBER_STRICT)

        async def deny(_item):
            return False

        req = _make_request(token, agent_der_cert)
        with pytest.raises(ElevateTimeoutError):
            await enforce(
                req,
                vault_items=_restricted_vault(),
                revocation_store=revocation,
                verify_key_bytes=vk,
                deduplicator=deduplicator,
                elevate_callback=deny,
                known_partitions=["company-a"],
            )

    @pytest.mark.asyncio
    async def test_tlp_elevate_no_callback_raises(self, signing_keypair, agent_der_cert, revocation, deduplicator):
        sk, vk = signing_keypair
        token = _make_token(sk, agent_der_cert, partitions=["company-a"], tlp_level=TlpLevel.AMBER_STRICT)
        req = _make_request(token, agent_der_cert)
        with pytest.raises(ElevateTimeoutError):
            await enforce(
                req,
                vault_items=_restricted_vault(),
                revocation_store=revocation,
                verify_key_bytes=vk,
                deduplicator=deduplicator,
                elevate_callback=None,
                known_partitions=["company-a"],
            )

    @pytest.mark.asyncio
    async def test_elevate_timeout_error_is_enforcement_denied(
        self, signing_keypair, agent_der_cert, revocation, deduplicator
    ):
        sk, vk = signing_keypair
        token = _make_token(sk, agent_der_cert, partitions=["company-a"], tlp_level=TlpLevel.AMBER_STRICT)
        req = _make_request(token, agent_der_cert)
        with pytest.raises(EnforcementDenied):  # ElevateTimeoutError is EnforcementDenied
            await enforce(
                req,
                vault_items=_restricted_vault(),
                revocation_store=revocation,
                verify_key_bytes=vk,
                deduplicator=deduplicator,
                known_partitions=["company-a"],
            )
