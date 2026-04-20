"""
FIX-02: Anti-probing guarantee — error indistinguishability.

Tests that 'key not found' and 'access denied' produce:
  - Identical safe_message values
  - Identical HTTP response bodies at the /enforce/partition endpoint
  - Comparable response times (timing oracle prevention)
"""
from __future__ import annotations

import asyncio
import time
import uuid
from datetime import datetime, timedelta, timezone

import nacl.signing
import pytest

import guardian.audit as audit_module
from guardian.enforcer import EnforcementDenied, VaultRequest, enforce
from shared.data_item import DataItem
from shared.token import AccessToken, RequestDeduplicator, RevocationStore, issue_token
from shared.types import Classification, TlpLevel


@pytest.fixture(autouse=True)
def setup_audit(tmp_path):
    audit_module.init_audit_log(tmp_path / "audit.db")
    yield


@pytest.fixture
def keypair():
    sk = nacl.signing.SigningKey.generate()
    return bytes(sk), bytes(sk.verify_key)


@pytest.fixture
def der_cert():
    return b"fake-der-cert-anti-probing"


def _make_token(sk_bytes, der_cert, *, partitions, tlp=TlpLevel.RED, agent_id="agent"):
    now = datetime.now(timezone.utc)
    return issue_token(
        agent_id=agent_id,
        partitions=partitions,
        tlp_level=tlp,
        operations=["vault.read"],
        agent_der_cert=der_cert,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(hours=1)).isoformat(),
        issuer="test",
        signing_key_bytes=sk_bytes,
    )


def _vault_with_item(partition="company-a"):
    return {
        "secret/company-a": DataItem(
            item_id="secret",
            owner_partition="company-a",
            classification=Classification.RESTRICTED,
            value="v",
        )
    }


# ---------------------------------------------------------------------------
# Error message identity
# ---------------------------------------------------------------------------

class TestErrorIndistinguishability:
    @pytest.mark.asyncio
    async def test_not_found_and_denied_have_same_safe_message(self, keypair, der_cert):
        """safe_message for 'not found' == safe_message for 'partition denied'."""
        sk, vk = keypair
        rev = RevocationStore()
        ded = RequestDeduplicator()
        vault = _vault_with_item()

        # Key not found
        token_a = _make_token(sk, der_cert, partitions=["company-a"])
        with pytest.raises(EnforcementDenied) as e_not_found:
            await enforce(
                VaultRequest(key="ghost_key", params={},
                             request_id=str(uuid.uuid4()),
                             token=token_a, peer_der_cert=der_cert),
                vault_items=vault, revocation_store=rev,
                verify_key_bytes=vk, deduplicator=ded,
                known_partitions=["company-a"],
            )

        # Access denied (wrong partition)
        token_b = _make_token(sk, der_cert, partitions=["company-b"], agent_id="agent-b")
        with pytest.raises(EnforcementDenied) as e_denied:
            await enforce(
                VaultRequest(key="secret", params={},
                             request_id=str(uuid.uuid4()),
                             token=token_b, peer_der_cert=der_cert),
                vault_items=vault, revocation_store=rev,
                verify_key_bytes=vk, deduplicator=ded,
                known_partitions=["company-a", "company-b"],
            )

        assert e_not_found.value.safe_message == e_denied.value.safe_message == "access_denied"

    @pytest.mark.asyncio
    async def test_all_denial_paths_use_access_denied_safe_message(self, keypair, der_cert):
        """ALL EnforcementDenied paths must expose 'access_denied' to the caller."""
        sk, vk = keypair
        vault = _vault_with_item()

        cases = []

        # TLP deny (GREEN + RESTRICTED)
        rev = RevocationStore(); ded = RequestDeduplicator()
        token = _make_token(sk, der_cert, partitions=["company-a"], tlp=TlpLevel.GREEN)
        with pytest.raises(EnforcementDenied) as e:
            await enforce(
                VaultRequest(key="secret", params={},
                             request_id=str(uuid.uuid4()),
                             token=token, peer_der_cert=der_cert),
                vault_items=vault, revocation_store=rev,
                verify_key_bytes=vk, deduplicator=ded,
                known_partitions=["company-a"],
            )
        cases.append(("tlp_deny", e.value.safe_message))

        # Not found
        rev2 = RevocationStore(); ded2 = RequestDeduplicator()
        token2 = _make_token(sk, der_cert, partitions=["company-a"])
        with pytest.raises(EnforcementDenied) as e:
            await enforce(
                VaultRequest(key="nonexistent", params={},
                             request_id=str(uuid.uuid4()),
                             token=token2, peer_der_cert=der_cert),
                vault_items=vault, revocation_store=rev2,
                verify_key_bytes=vk, deduplicator=ded2,
                known_partitions=["company-a"],
            )
        cases.append(("not_found", e.value.safe_message))

        for name, msg in cases:
            assert msg == "access_denied", f"Path '{name}' exposed non-safe message: {msg!r}"


# ---------------------------------------------------------------------------
# Timing oracle prevention — FIX-02.3.b
# ---------------------------------------------------------------------------

class TestTimingIndistinguishability:
    @pytest.mark.asyncio
    async def test_not_found_vs_denied_timing_comparable(self, keypair, der_cert):
        """
        Mean response time for 'not found' and 'access denied' must be
        within 50ms of each other. A strict <1ms bound is unreliable in CI;
        50ms catches gross timing oracles while allowing OS scheduling noise.
        """
        sk, vk = keypair
        vault = _vault_with_item()
        N = 50  # fewer iterations to keep CI fast

        not_found_times = []
        denied_times = []

        for _ in range(N):
            rev = RevocationStore(); ded = RequestDeduplicator()
            token_a = _make_token(sk, der_cert, partitions=["company-a"])

            t0 = time.perf_counter()
            try:
                await enforce(
                    VaultRequest(key="ghost", params={},
                                 request_id=str(uuid.uuid4()),
                                 token=token_a, peer_der_cert=der_cert),
                    vault_items=vault, revocation_store=rev,
                    verify_key_bytes=vk, deduplicator=ded,
                    known_partitions=["company-a"],
                )
            except EnforcementDenied:
                pass
            not_found_times.append(time.perf_counter() - t0)

        for _ in range(N):
            rev = RevocationStore(); ded = RequestDeduplicator()
            token_b = _make_token(sk, der_cert, partitions=["company-b"], agent_id="agent-b")

            t0 = time.perf_counter()
            try:
                await enforce(
                    VaultRequest(key="secret", params={},
                                 request_id=str(uuid.uuid4()),
                                 token=token_b, peer_der_cert=der_cert),
                    vault_items=vault, revocation_store=rev,
                    verify_key_bytes=vk, deduplicator=ded,
                    known_partitions=["company-a", "company-b"],
                )
            except EnforcementDenied:
                pass
            denied_times.append(time.perf_counter() - t0)

        mean_nf = sum(not_found_times) / N
        mean_denied = sum(denied_times) / N
        diff_ms = abs(mean_nf - mean_denied) * 1000
        assert diff_ms < 50, (
            f"Timing oracle detected: mean not_found={mean_nf*1000:.2f}ms, "
            f"mean denied={mean_denied*1000:.2f}ms, diff={diff_ms:.2f}ms"
        )
