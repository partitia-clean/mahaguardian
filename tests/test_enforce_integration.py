"""
FIX-05: Integration tests proving enforce() depends on the canonical
enforcement chain (check_tlp, scan_params, find_items) and is NOT a bypass.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, AsyncMock

import nacl.signing
import pytest

import guardian.audit as audit_module
from guardian.enforcer import (
    ConfusedDeputyError,
    EnforcementDenied,
    VaultRequest,
    enforce,
    _find_items_no_tlp_check,
    scan_params,
)
from shared.data_item import DataItem
from shared.token import AccessToken, RequestDeduplicator, RevocationStore, issue_token
from shared.tlp_matrix import check_tlp
from shared.types import Classification, Decision, TlpLevel


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
    return b"fake-der-cert-integration"


def _make_token(sk, cert, *, partitions, tlp=TlpLevel.RED, agent_id="agent"):
    now = datetime.now(timezone.utc)
    return issue_token(
        agent_id=agent_id,
        partitions=partitions,
        tlp_level=tlp,
        operations=["vault.read"],
        agent_der_cert=cert,
        issued_at=now.isoformat(),
        expires_at=(now + timedelta(hours=1)).isoformat(),
        issuer="test",
        signing_key_bytes=sk,
    )


def _vault():
    return {
        "secret/company-a": DataItem(
            item_id="secret",
            owner_partition="company-a",
            classification=Classification.RESTRICTED,
            value="v",
        )
    }


class TestEnforceCallsCanonicalFunctions:
    """Prove that enforce() delegates to canonical enforcement primitives."""

    @pytest.mark.asyncio
    async def test_enforce_calls_check_tlp(self, keypair, der_cert):
        """enforce() must go through check_tlp() from shared/tlp_matrix.py."""
        sk, vk = keypair
        token = _make_token(sk, der_cert, partitions=["company-a"], tlp=TlpLevel.GREEN)
        rev = RevocationStore(); ded = RequestDeduplicator()

        with patch("guardian.enforcer.check_tlp", wraps=check_tlp) as mock_tlp:
            with pytest.raises(EnforcementDenied):
                await enforce(
                    VaultRequest(key="secret", params={},
                                 request_id=str(uuid.uuid4()),
                                 token=token, peer_der_cert=der_cert),
                    vault_items=_vault(), revocation_store=rev,
                    verify_key_bytes=vk, deduplicator=ded,
                    known_partitions=["company-a"],
                )
            # check_tlp must have been called
            assert mock_tlp.called, "enforce() must call check_tlp()"

    @pytest.mark.asyncio
    async def test_enforce_calls_scan_params(self, keypair, der_cert):
        """enforce() must go through scan_params() for confused-deputy detection."""
        sk, vk = keypair
        token = _make_token(sk, der_cert, partitions=["company-a"])
        rev = RevocationStore(); ded = RequestDeduplicator()

        with patch("guardian.enforcer.scan_params", wraps=scan_params) as mock_scan:
            with pytest.raises(ConfusedDeputyError):
                await enforce(
                    VaultRequest(key="secret",
                                 params={"hint": "company-a"},
                                 request_id=str(uuid.uuid4()),
                                 token=token, peer_der_cert=der_cert),
                    vault_items=_vault(), revocation_store=rev,
                    verify_key_bytes=vk, deduplicator=ded,
                    known_partitions=["company-a"],
                )
            assert mock_scan.called, "enforce() must call scan_params()"

    @pytest.mark.asyncio
    async def test_enforce_calls_find_items(self, keypair, der_cert):
        """enforce() must go through find_items() for partition resolution."""
        sk, vk = keypair
        token = _make_token(sk, der_cert, partitions=["company-a"])
        rev = RevocationStore(); ded = RequestDeduplicator()

        with patch("guardian.enforcer._find_items_no_tlp_check",
                   wraps=_find_items_no_tlp_check) as mock_find:
            await enforce(
                VaultRequest(key="secret", params={},
                             request_id=str(uuid.uuid4()),
                             token=token, peer_der_cert=der_cert),
                vault_items=_vault(), revocation_store=rev,
                verify_key_bytes=vk, deduplicator=ded,
                known_partitions=["company-a"],
            )
            assert mock_find.called, "enforce() must call _find_items_no_tlp_check()"

    @pytest.mark.asyncio
    async def test_denial_logged_in_audit(self, keypair, der_cert, tmp_path):
        """Every DENY decision from enforce() must appear in the audit log."""
        sk, vk = keypair
        token = _make_token(sk, der_cert, partitions=["company-a"], tlp=TlpLevel.GREEN)
        rev = RevocationStore(); ded = RequestDeduplicator()

        with pytest.raises(EnforcementDenied):
            await enforce(
                VaultRequest(key="secret", params={},
                             request_id=str(uuid.uuid4()),
                             token=token, peer_der_cert=der_cert),
                vault_items=_vault(), revocation_store=rev,
                verify_key_bytes=vk, deduplicator=ded,
                known_partitions=["company-a"],
            )

        entries = audit_module.query_log(action="vault.enforce")
        denied = [e for e in entries if "denied" in e.get("result", "")]
        assert len(denied) >= 1, "DENY decision must be logged in audit"

    @pytest.mark.asyncio
    async def test_allow_logged_in_audit(self, keypair, der_cert):
        """Every ALLOW decision from enforce() must appear in the audit log."""
        sk, vk = keypair
        token = _make_token(sk, der_cert, partitions=["company-a"], tlp=TlpLevel.RED)
        rev = RevocationStore(); ded = RequestDeduplicator()

        await enforce(
            VaultRequest(key="secret", params={},
                         request_id=str(uuid.uuid4()),
                         token=token, peer_der_cert=der_cert),
            vault_items=_vault(), revocation_store=rev,
            verify_key_bytes=vk, deduplicator=ded,
            known_partitions=["company-a"],
        )

        entries = audit_module.query_log(action="vault.enforce")
        allowed = [e for e in entries if e.get("result") == "success"]
        assert len(allowed) >= 1, "ALLOW decision must be logged in audit"


class TestEnforceAuditChainIntegration:
    """Prove that audit_chain is populated by enforce() decisions."""

    @pytest.mark.asyncio
    async def test_deny_appended_to_audit_chain(self, keypair, der_cert, tmp_path):
        """DENY must be logged to audit_chain when chain is provided."""
        from guardian.audit_chain import AuditChain

        sk, vk = keypair
        token = _make_token(sk, der_cert, partitions=["company-a"], tlp=TlpLevel.GREEN)
        rev = RevocationStore(); ded = RequestDeduplicator()
        chain = AuditChain(tmp_path / "ac.db", hmac_key=b"test_key_enforce_integ_32bytes!!")

        with pytest.raises(EnforcementDenied):
            await enforce(
                VaultRequest(key="secret", params={},
                             request_id=str(uuid.uuid4()),
                             token=token, peer_der_cert=der_cert),
                vault_items=_vault(), revocation_store=rev,
                verify_key_bytes=vk, deduplicator=ded,
                audit_chain=chain,
                known_partitions=["company-a"],
            )

        entries = chain.entries()
        assert len(entries) >= 1
        assert any(e["decision"] == "DENY" for e in entries)

    @pytest.mark.asyncio
    async def test_allow_appended_to_audit_chain(self, keypair, der_cert, tmp_path):
        """ALLOW must be logged to audit_chain when chain is provided."""
        from guardian.audit_chain import AuditChain

        sk, vk = keypair
        token = _make_token(sk, der_cert, partitions=["company-a"], tlp=TlpLevel.RED)
        rev = RevocationStore(); ded = RequestDeduplicator()
        chain = AuditChain(tmp_path / "ac.db", hmac_key=b"test_key_enforce_integ_32bytes!!")

        await enforce(
            VaultRequest(key="secret", params={},
                         request_id=str(uuid.uuid4()),
                         token=token, peer_der_cert=der_cert),
            vault_items=_vault(), revocation_store=rev,
            verify_key_bytes=vk, deduplicator=ded,
            audit_chain=chain,
            known_partitions=["company-a"],
        )

        entries = chain.entries()
        assert len(entries) >= 1
        assert any(e["decision"] == "ALLOW" for e in entries)
