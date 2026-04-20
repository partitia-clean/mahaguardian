"""
Phase 3 Step 8 — Integration truth-table tests.

12 parametrized cases: agent profile × data key.
Uses DEMO_ITEMS seeded into a vault dict, real AccessTokens, and the
full 8-step async enforce() pipeline.

Agent profiles
--------------
director_overview   partitions=[company-a, company-b]  TLP=RED
director_asst_a     partitions=[company-a]              TLP=RED
director_asst_b     partitions=[company-b]              TLP=RED
financial_analyst_a partitions=[company-a]              TLP=AMBER_STRICT
external_agent_a    partitions=[company-a]              TLP=GREEN
external_agent_b    partitions=[company-b]              TLP=GREEN

Truth table (12 cases)
----------------------
director_overview    / client_count       → ALLOW
director_overview    / v2g_profit_split   → ALLOW
director_asst_a      / client_count       → ALLOW
director_asst_a      / v2g_profit_split   → DENY  (partition)
director_asst_b      / client_count       → DENY  (partition)
director_asst_b      / v2g_profit_split   → ALLOW
financial_analyst_a  / client_count       → ELEVATE  (callback approves)
financial_analyst_a  / public_filings     → ALLOW
external_agent_a     / client_count       → DENY  (TLP: GREEN + RESTRICTED)
external_agent_a     / public_filings     → ALLOW
external_agent_b     / v2g_profit_split   → DENY  (TLP: GREEN + RESTRICTED)
external_agent_b     / ev_driver_earnings → ALLOW
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest
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
from shared.token import AccessToken, RequestDeduplicator, RevocationStore, issue_token
from shared.types import TlpLevel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_audit(tmp_path):
    audit_module.init_audit_log(tmp_path / "audit.db")
    yield


@pytest.fixture(scope="session")
def signing_keypair():
    sk = nacl.signing.SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


@pytest.fixture(scope="session")
def agent_der_cert():
    return b"integration-test-der-cert"


@pytest.fixture(scope="session")
def seeded_vault_items():
    """Build vault items directly without calling audit-logging seed function."""
    from shared.data_item import DEMO_ITEMS
    return {
        f"{item.item_id}/{item.owner_partition}": item
        for item in DEMO_ITEMS
    }


@pytest.fixture(scope="function")
def revocation():
    return RevocationStore()


@pytest.fixture(scope="function")
def deduplicator():
    return RequestDeduplicator()


@pytest.fixture(scope="session")
def all_known_partitions(seeded_vault_items):
    """All partition IDs in the system — passed to enforce() as known_partitions."""
    return list({item.owner_partition for item in seeded_vault_items.values()})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _token(
    sk: bytes,
    der_cert: bytes,
    *,
    agent_id: str,
    partitions: list[str],
    tlp_level: TlpLevel,
) -> AccessToken:
    now = datetime.now(timezone.utc)
    return issue_token(
        agent_id=agent_id,
        partitions=partitions,
        tlp_level=tlp_level,
        operations=["vault.read"],
        agent_der_cert=der_cert,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(hours=1)).isoformat(),
        issuer="integration-guardian",
        signing_key_bytes=sk,
    )


def _req(token: AccessToken, der_cert: bytes, key: str) -> VaultRequest:
    return VaultRequest(
        key=key,
        params={},
        request_id=str(uuid.uuid4()),
        token=token,
        peer_der_cert=der_cert,
    )


# ---------------------------------------------------------------------------
# Agent profiles
# ---------------------------------------------------------------------------

AGENT_PROFILES = {
    "director_overview":    dict(partitions=["company-a", "company-b"], tlp_level=TlpLevel.RED),
    "director_asst_a":      dict(partitions=["company-a"],              tlp_level=TlpLevel.RED),
    "director_asst_b":      dict(partitions=["company-b"],              tlp_level=TlpLevel.RED),
    "financial_analyst_a":  dict(partitions=["company-a"],              tlp_level=TlpLevel.AMBER_STRICT),
    "external_agent_a":     dict(partitions=["company-a"],              tlp_level=TlpLevel.GREEN),
    "external_agent_b":     dict(partitions=["company-b"],              tlp_level=TlpLevel.GREEN),
}

# outcome: "allow" | "deny" | "elevate"
TRUTH_TABLE = [
    ("director_overview",   "client_count",       "allow"),
    ("director_overview",   "v2g_profit_split",   "allow"),
    ("director_asst_a",     "client_count",       "allow"),
    ("director_asst_a",     "v2g_profit_split",   "deny"),
    ("director_asst_b",     "client_count",       "deny"),
    ("director_asst_b",     "v2g_profit_split",   "allow"),
    ("financial_analyst_a", "client_count",       "elevate"),
    ("financial_analyst_a", "public_filings",     "allow"),
    ("external_agent_a",    "client_count",       "deny"),
    ("external_agent_a",    "public_filings",     "allow"),
    ("external_agent_b",    "v2g_profit_split",   "deny"),
    ("external_agent_b",    "ev_driver_earnings", "allow"),
]


# ---------------------------------------------------------------------------
# Integration truth-table
# ---------------------------------------------------------------------------

class TestIntegrationTruthTable:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("agent_name,key,expected", TRUTH_TABLE)
    async def test_truth_table(
        self,
        agent_name: str,
        key: str,
        expected: str,
        signing_keypair,
        agent_der_cert,
        seeded_vault_items,
        revocation,
        deduplicator,
        all_known_partitions,
    ):
        sk, vk = signing_keypair
        profile = AGENT_PROFILES[agent_name]
        token = _token(sk, agent_der_cert, agent_id=agent_name, **profile)
        req = _req(token, agent_der_cert, key)

        if expected == "allow":
            item = await enforce(
                req,
                vault_items=seeded_vault_items,
                revocation_store=revocation,
                verify_key_bytes=vk,
                deduplicator=deduplicator,
                known_partitions=all_known_partitions,
            )
            assert isinstance(item, DataItem)
            assert item.item_id == key

        elif expected == "deny":
            with pytest.raises(EnforcementDenied) as exc_info:
                await enforce(
                    req,
                    vault_items=seeded_vault_items,
                    revocation_store=revocation,
                    verify_key_bytes=vk,
                    deduplicator=deduplicator,
                    known_partitions=all_known_partitions,
                )
            # Verify the safe message never leaks details
            assert exc_info.value.safe_message == "access_denied"

        elif expected == "elevate":
            # ELEVATE with an approving callback → item returned
            async def approve(_item: DataItem) -> bool:
                return True

            item = await enforce(
                req,
                vault_items=seeded_vault_items,
                revocation_store=revocation,
                verify_key_bytes=vk,
                deduplicator=deduplicator,
                elevate_callback=approve,
                known_partitions=all_known_partitions,
            )
            assert isinstance(item, DataItem)
            assert item.item_id == key

        else:
            pytest.fail(f"Unknown expected outcome: {expected!r}")

    @pytest.mark.asyncio
    @pytest.mark.parametrize("agent_name,key,expected", [
        case for case in TRUTH_TABLE if case[2] == "allow"
    ])
    async def test_allow_never_leaks_denied_response(
        self,
        agent_name: str,
        key: str,
        expected: str,
        signing_keypair,
        agent_der_cert,
        seeded_vault_items,
        revocation,
        deduplicator,
        all_known_partitions,
    ):
        """ALLOW responses return a DataItem — no EnforcementDenied raised."""
        sk, vk = signing_keypair
        profile = AGENT_PROFILES[agent_name]
        token = _token(sk, agent_der_cert, agent_id=agent_name, **profile)

        async def approve(_item):
            return True

        item = await enforce(
            _req(token, agent_der_cert, key),
            vault_items=seeded_vault_items,
            revocation_store=revocation,
            verify_key_bytes=vk,
            deduplicator=deduplicator,
            elevate_callback=approve,
            known_partitions=all_known_partitions,
        )
        assert item.item_id == key
        # Safe message does not appear in DataItem
        assert not hasattr(item, "safe_message")

    @pytest.mark.asyncio
    @pytest.mark.parametrize("agent_name,key,expected", [
        case for case in TRUTH_TABLE if case[2] == "deny"
    ])
    async def test_deny_safe_message_is_access_denied(
        self,
        agent_name: str,
        key: str,
        expected: str,
        signing_keypair,
        agent_der_cert,
        seeded_vault_items,
        revocation,
        deduplicator,
        all_known_partitions,
    ):
        """All DENY paths expose only 'access_denied' to the caller."""
        sk, vk = signing_keypair
        profile = AGENT_PROFILES[agent_name]
        token = _token(sk, agent_der_cert, agent_id=agent_name, **profile)

        with pytest.raises(EnforcementDenied) as exc_info:
            await enforce(
                _req(token, agent_der_cert, key),
                vault_items=seeded_vault_items,
                revocation_store=revocation,
                verify_key_bytes=vk,
                deduplicator=deduplicator,
                known_partitions=all_known_partitions,
            )

        e = exc_info.value
        # safe_message must be "access_denied"
        assert e.safe_message == "access_denied"
        # Internal reason_code must NOT be "access_denied" (it's more specific)
        assert e.reason_code != "access_denied"
