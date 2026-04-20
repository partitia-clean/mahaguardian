"""
Adversarial review fix verification tests (F-01 through F-10).

Each class targets one finding from the Triage Synthesis Report v3.1.
These tests verify the correctness of the blocking fixes and are separate
from the existing Phase 3 test suite to keep diff noise minimal.

F-01 — known_partitions mandatory (ValueError when empty/None)
F-02 — merge_souls() partition scan (SOULLeakError on category/rule match)
F-03 — Renamed helpers are no longer importable under old names
F-08 — format_hash() round-trip and sha256: prefix on audit_chain outputs
F-09 — Pinned test vector for audit_chain._compute_hash()
F-10 — Module-level imports in enforcer.py (smoke test)
"""
from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import guardian.audit as audit_module


# ---------------------------------------------------------------------------
# Common fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_audit(tmp_path):
    audit_module.init_audit_log(tmp_path / "audit.db")
    yield


# ---------------------------------------------------------------------------
# F-01: known_partitions must be non-empty — no vault-derived fallback
# ---------------------------------------------------------------------------

class TestF01KnownPartitionsMandatory:
    """resolve_and_enforce() and enforce() must raise ValueError for empty known_partitions."""

    def test_resolve_and_enforce_empty_list_raises(self):
        from guardian.enforcer import resolve_and_enforce, EnforcementDenied
        from shared.data_item import DataItem
        from shared.types import Classification, TlpLevel

        vault = {
            "item/company-a": DataItem(
                item_id="item",
                owner_partition="company-a",
                classification=Classification.PUBLIC,
                value="v",
            )
        }
        with pytest.raises(ValueError, match="known_partitions"):
            resolve_and_enforce(
                key="item",
                token_partitions=["company-a"],
                tlp_level=TlpLevel.GREEN,
                params={},
                vault_items=vault,
                agent_id="test-agent",
                known_partitions=[],
            )

    def test_resolve_and_enforce_none_raises(self):
        """known_partitions=None should also be caught (falsy check)."""
        from guardian.enforcer import resolve_and_enforce
        from shared.data_item import DataItem
        from shared.types import Classification, TlpLevel

        vault = {
            "item/company-a": DataItem(
                item_id="item",
                owner_partition="company-a",
                classification=Classification.PUBLIC,
                value="v",
            )
        }
        # known_partitions typed as list[str] but falsy None triggers same guard
        with pytest.raises((ValueError, TypeError)):
            resolve_and_enforce(
                key="item",
                token_partitions=["company-a"],
                tlp_level=TlpLevel.GREEN,
                params={},
                vault_items=vault,
                agent_id="test-agent",
                known_partitions=None,  # type: ignore[arg-type]
            )

    @pytest.mark.asyncio
    async def test_enforce_empty_known_partitions_raises(self):
        """enforce() raises ValueError when known_partitions=[]."""
        import nacl.signing
        from guardian.enforcer import VaultRequest, enforce
        from shared.data_item import DataItem
        from shared.token import RequestDeduplicator, RevocationStore, issue_token
        from shared.types import Classification, TlpLevel

        sk = nacl.signing.SigningKey.generate()
        sk_bytes = bytes(sk)
        vk_bytes = bytes(sk.verify_key)
        der_cert = b"test-der-cert"

        now = datetime.now(timezone.utc)
        token = issue_token(
            agent_id="agent-x",
            partitions=["company-a"],
            tlp_level=TlpLevel.RED,
            operations=["vault.read"],
            agent_der_cert=der_cert,
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(hours=1)).isoformat(),
            issuer="test",
            signing_key_bytes=sk_bytes,
        )
        vault = {
            "item/company-a": DataItem(
                item_id="item",
                owner_partition="company-a",
                classification=Classification.PUBLIC,
                value="v",
            )
        }
        with pytest.raises(ValueError, match="known_partitions"):
            await enforce(
                VaultRequest(key="item", params={},
                             request_id=str(uuid.uuid4()),
                             token=token, peer_der_cert=der_cert),
                vault_items=vault,
                revocation_store=RevocationStore(),
                verify_key_bytes=vk_bytes,
                deduplicator=RequestDeduplicator(),
                known_partitions=[],
            )

    def test_zero_item_partition_scanned_by_confused_deputy(self):
        """
        F-01 core security property: a partition with zero vault items must
        still be detected in request params by the confused-deputy scanner.

        'company-z' has no vault items, so a vault-derived known_partitions
        fallback would miss it. With known_partitions from enrollment config,
        the injection is caught.
        """
        from guardian.enforcer import ConfusedDeputyError, resolve_and_enforce
        from shared.data_item import DataItem
        from shared.types import Classification, TlpLevel

        # Vault only contains company-a items — company-z has zero items.
        vault = {
            "item/company-a": DataItem(
                item_id="item",
                owner_partition="company-a",
                classification=Classification.PUBLIC,
                value="v",
            )
        }
        # Enrollment config knows about company-z even though it has no data.
        known = ["company-a", "company-z"]

        # Attacker injects "company-z" into params — should be caught.
        with pytest.raises(ConfusedDeputyError):
            resolve_and_enforce(
                key="item",
                token_partitions=["company-a"],
                tlp_level=TlpLevel.GREEN,
                params={"hint": "company-z"},
                vault_items=vault,
                agent_id="test-agent",
                known_partitions=known,
            )


# ---------------------------------------------------------------------------
# F-02: merge_souls() partition scan
# ---------------------------------------------------------------------------

class TestF02MergeSoulsPartitionScan:
    """merge_souls() must raise SOULLeakError when a partition name appears
    in agent_extensions category names or in agent rule text."""

    def _sign_soul_bytes(self, tmp_path: Path, content: str, keypair) -> bytes:
        """Helper: write TOML, sign it, update hash ledger, return bytes."""
        import guardian.soul as soul_module
        from guardian.soul import sign_soul, update_soul_hash_ledger

        path = tmp_path / f"SOUL-{uuid.uuid4().hex[:8]}.lock"
        path.write_text(content, encoding="utf-8")
        private_key, _ = keypair

        sign_soul(path, private_key)
        update_soul_hash_ledger(path, private_key)
        return path.read_bytes()

    @pytest.fixture
    def keypair(self):
        from guardian.soul import generate_soul_keypair
        return generate_soul_keypair()

    @pytest.fixture
    def soul_hash_path(self, tmp_path, monkeypatch):
        import guardian.soul as soul_module
        p = tmp_path / "SOUL.hash"
        monkeypatch.setattr(soul_module, "SOUL_HASH_PATH", p)
        return p

    def test_category_name_contains_partition_raises(self, tmp_path, keypair, soul_hash_path):
        """agent_extensions category that embeds a partition name raises SOULLeakError."""
        from guardian.soul import SOULLeakError, merge_souls

        # Master allows "company-a-persona" as a category — embeds partition name.
        master_toml = """\
agent_extensions = ["company-a-persona"]

[meta]
version = "1.0"
agent = "master"

[rules]
absolute = ["Always route through Guardian"]

[constraints]
max_token_lifetime_hours = 4
"""
        agent_toml = """\
[meta]
version = "1.0"
agent = "agent"

[rules]
absolute = []

[constraints]
max_token_lifetime_hours = 2
"""
        master_bytes = self._sign_soul_bytes(tmp_path, master_toml, keypair)
        agent_bytes = self._sign_soul_bytes(tmp_path, agent_toml, keypair)

        with pytest.raises(SOULLeakError):
            merge_souls(
                master_bytes,
                agent_bytes,
                known_partitions=["company-a"],
            )

    def test_rule_contains_partition_raises(self, tmp_path, keypair, soul_hash_path):
        """Agent rule that embeds a partition name raises SOULLeakError."""
        from guardian.soul import SOULLeakError, merge_souls

        master_toml = """\
agent_extensions = ["persona"]

[meta]
version = "1.0"
agent = "master"

[rules]
absolute = ["Always route through Guardian"]

[constraints]
max_token_lifetime_hours = 4
"""
        agent_toml = """\
[meta]
version = "1.0"
agent = "agent"

[rules]
absolute = ["[persona] Handle company-b requests carefully"]

[constraints]
max_token_lifetime_hours = 2
"""
        master_bytes = self._sign_soul_bytes(tmp_path, master_toml, keypair)
        agent_bytes = self._sign_soul_bytes(tmp_path, agent_toml, keypair)

        with pytest.raises(SOULLeakError):
            merge_souls(
                master_bytes,
                agent_bytes,
                known_partitions=["company-b"],
            )

    def test_no_partition_names_passes(self, tmp_path, keypair, soul_hash_path):
        """merge_souls() with clean content and known_partitions succeeds."""
        from guardian.soul import merge_souls

        master_toml = """\
agent_extensions = ["persona"]

[meta]
version = "1.0"
agent = "master"

[rules]
absolute = ["Always route through Guardian"]

[constraints]
max_token_lifetime_hours = 4
"""
        agent_toml = """\
[meta]
version = "1.0"
agent = "agent"

[rules]
absolute = ["[persona] Always respond in English"]

[constraints]
max_token_lifetime_hours = 2
"""
        master_bytes = self._sign_soul_bytes(tmp_path, master_toml, keypair)
        agent_bytes = self._sign_soul_bytes(tmp_path, agent_toml, keypair)

        result = merge_souls(
            master_bytes,
            agent_bytes,
            known_partitions=["company-a", "company-b"],
        )
        assert isinstance(result, dict)
        assert "Always route through Guardian" in result["rules"]["absolute"]

    def test_master_rule_duplicate_not_scanned(self, tmp_path, keypair, soul_hash_path):
        """Agent absolute rules that duplicate master rules are not scanned for partition names.

        If master already has the rule, it's safe — the barrier is not new.
        """
        from guardian.soul import merge_souls

        shared_rule = "Always route company-a requests through Guardian"
        master_toml = f"""\
agent_extensions = ["persona"]

[meta]
version = "1.0"
agent = "master"

[rules]
absolute = ["{shared_rule}"]

[constraints]
max_token_lifetime_hours = 4
"""
        agent_toml = f"""\
[meta]
version = "1.0"
agent = "agent"

[rules]
absolute = ["{shared_rule}"]

[constraints]
max_token_lifetime_hours = 2
"""
        master_bytes = self._sign_soul_bytes(tmp_path, master_toml, keypair)
        agent_bytes = self._sign_soul_bytes(tmp_path, agent_toml, keypair)

        # Should NOT raise — it's a master duplicate, not a new rule.
        result = merge_souls(
            master_bytes,
            agent_bytes,
            known_partitions=["company-a"],
        )
        assert isinstance(result, dict)

    def test_no_known_partitions_skips_scan(self, tmp_path, keypair, soul_hash_path):
        """When known_partitions is None/empty, no partition scan is performed."""
        from guardian.soul import merge_souls

        master_toml = """\
agent_extensions = ["company-a-persona"]

[meta]
version = "1.0"
agent = "master"

[rules]
absolute = ["Always route through Guardian"]

[constraints]
max_token_lifetime_hours = 4
"""
        agent_toml = """\
[meta]
version = "1.0"
agent = "agent"

[rules]
absolute = []

[constraints]
max_token_lifetime_hours = 2
"""
        master_bytes = self._sign_soul_bytes(tmp_path, master_toml, keypair)
        agent_bytes = self._sign_soul_bytes(tmp_path, agent_toml, keypair)

        # known_partitions not provided → no SOULLeakError raised.
        result = merge_souls(master_bytes, agent_bytes)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# F-03: Old function names must not be importable
# ---------------------------------------------------------------------------

class TestF03RenamedFunctionsNotImportable:
    """find_items and get_vault_items must not exist under their old names."""

    def test_find_items_not_in_enforcer(self):
        import guardian.enforcer as enforcer_mod
        assert not hasattr(enforcer_mod, "find_items"), (
            "find_items still exists in guardian.enforcer — F-03 rename incomplete"
        )

    def test_find_items_new_name_exists(self):
        import guardian.enforcer as enforcer_mod
        assert hasattr(enforcer_mod, "_find_items_no_tlp_check"), (
            "_find_items_no_tlp_check missing from guardian.enforcer"
        )

    def test_get_vault_items_not_in_vault(self):
        import guardian.vault as vault_mod
        assert not hasattr(vault_mod, "get_vault_items"), (
            "get_vault_items still exists in guardian.vault — F-03 rename incomplete"
        )

    def test_get_vault_items_new_name_exists(self):
        import guardian.vault as vault_mod
        assert hasattr(vault_mod, "_get_vault_items_unfiltered"), (
            "_get_vault_items_unfiltered missing from guardian.vault"
        )

    def test_find_items_not_in_enforcer_all(self):
        """find_items must not appear in enforcer.__all__."""
        from guardian import enforcer
        if hasattr(enforcer, "__all__"):
            assert "find_items" not in enforcer.__all__


# ---------------------------------------------------------------------------
# F-08: format_hash() round-trip and sha256: prefix on audit_chain outputs
# ---------------------------------------------------------------------------

class TestF08FormatHash:
    """format_hash() must produce 'sha256:<64 hex chars>' strings."""

    def test_format_hash_prefix(self):
        from shared.utils import format_hash
        result = format_hash(b"test input")
        assert result.startswith("sha256:"), f"Missing 'sha256:' prefix: {result!r}"

    def test_format_hash_hex_length(self):
        from shared.utils import format_hash
        result = format_hash(b"test input")
        hex_part = result[len("sha256:"):]
        assert len(hex_part) == 64, f"Expected 64 hex chars, got {len(hex_part)}: {hex_part!r}"

    def test_format_hash_lowercase_hex(self):
        from shared.utils import format_hash
        result = format_hash(b"\xff\xee")
        hex_part = result[len("sha256:"):]
        assert hex_part == hex_part.lower()

    def test_format_hash_matches_stdlib(self):
        from shared.utils import format_hash
        data = b"mahaguardian_genesis_v1"
        expected_hex = hashlib.sha256(data).hexdigest()
        assert format_hash(data) == f"sha256:{expected_hex}"

    def test_genesis_hash_has_prefix(self):
        from guardian.audit_chain import GENESIS_HASH
        assert GENESIS_HASH.startswith("sha256:")
        hex_part = GENESIS_HASH[len("sha256:"):]
        assert len(hex_part) == 64

    def test_genesis_hash_correct_value(self):
        from guardian.audit_chain import GENESIS_HASH
        expected = "sha256:" + hashlib.sha256(b"mahaguardian_genesis_v1").hexdigest()
        assert GENESIS_HASH == expected

    def test_params_hash_has_prefix(self):
        from guardian.audit_chain import _params_hash
        result = _params_hash({"key": "val"})
        assert result.startswith("sha256:")
        hex_part = result[len("sha256:"):]
        assert len(hex_part) == 64

    def test_audit_chain_entry_hash_has_prefix(self, tmp_path):
        from guardian.audit_chain import AuditChain
        from shared.types import Decision

        chain = AuditChain(tmp_path / "test.db", hmac_key=b"test_key_for_f08_32bytes_padding!")
        chain.append(
            agent_id="agent-x",
            partition_id="company-a",
            method="vault.read",
            params={"key": "item"},
            decision=Decision.ALLOW,
            reason_code="tlp_allow",
        )
        entries = chain.entries()
        assert len(entries) == 1
        assert entries[0]["entry_hash"].startswith("sha256:")
        assert entries[0]["params_hash"].startswith("sha256:")


# ---------------------------------------------------------------------------
# F-09: Pinned test vector for audit_chain._compute_hash()
# ---------------------------------------------------------------------------

class TestF09ComputeHashPinnedVector:
    """
    Pin the exact output of _compute_hash() for a fixed set of inputs.

    If the encoding scheme ever changes, this test catches it.
    The expected value is computed fresh from the canonical algorithm:
      HMAC-SHA-256 over length-prefixed (4-byte BE) UTF-8 fields.
    """

    _HMAC_KEY = b"pinned_test_key_exactly_32bytes!"
    _INPUTS = dict(
        entry_id="entry-001",
        timestamp="2026-01-01T00:00:00+00:00",
        agent_id="agent-x",
        partition_id="company-a",
        method="vault.read",
        params_hash="sha256:" + "a" * 64,
        decision="ALLOW",
        reason_code="tlp_allow",
        previous_hash="sha256:" + "b" * 64,
    )

    @classmethod
    def _reference_compute(cls) -> str:
        """Reproduce the algorithm from audit_chain._compute_hash() in pure Python."""
        import unicodedata

        def nfc(s: str) -> str:
            return unicodedata.normalize("NFC", s)

        fields = [
            nfc(cls._INPUTS["entry_id"]),
            nfc(cls._INPUTS["timestamp"]),
            nfc(cls._INPUTS["agent_id"]),
            nfc(cls._INPUTS["partition_id"]),
            nfc(cls._INPUTS["method"]),
            nfc(cls._INPUTS["params_hash"]),
            nfc(cls._INPUTS["decision"]),
            nfc(cls._INPUTS["reason_code"]),
            nfc(cls._INPUTS["previous_hash"]),
        ]
        parts = []
        for f in fields:
            encoded = f.encode("utf-8")
            parts.append(len(encoded).to_bytes(4, "big") + encoded)
        payload = b"".join(parts)
        digest = hmac.new(cls._HMAC_KEY, payload, "sha256").hexdigest()
        return "sha256:" + digest

    def test_pinned_vector_matches_implementation(self):
        from guardian.audit_chain import _compute_hash
        expected = self._reference_compute()
        actual = _compute_hash(
            **self._INPUTS,
            hmac_key=self._HMAC_KEY,
        )
        assert actual == expected, (
            f"_compute_hash() output changed!\n"
            f"  expected: {expected}\n"
            f"  actual:   {actual}"
        )

    def test_output_starts_with_sha256_prefix(self):
        from guardian.audit_chain import _compute_hash
        result = _compute_hash(**self._INPUTS, hmac_key=self._HMAC_KEY)
        assert result.startswith("sha256:")

    def test_output_hex_length(self):
        from guardian.audit_chain import _compute_hash
        result = _compute_hash(**self._INPUTS, hmac_key=self._HMAC_KEY)
        hex_part = result[len("sha256:"):]
        assert len(hex_part) == 64

    def test_different_key_produces_different_hash(self):
        from guardian.audit_chain import _compute_hash
        h1 = _compute_hash(**self._INPUTS, hmac_key=self._HMAC_KEY)
        h2 = _compute_hash(**self._INPUTS, hmac_key=b"different_key_32bytes_xxxxxxxxxxx")
        assert h1 != h2

    def test_field_order_matters(self):
        """Swapping any two fields produces a different hash."""
        from guardian.audit_chain import _compute_hash
        original = _compute_hash(**self._INPUTS, hmac_key=self._HMAC_KEY)
        swapped = {**self._INPUTS, "agent_id": self._INPUTS["partition_id"],
                   "partition_id": self._INPUTS["agent_id"]}
        swapped_hash = _compute_hash(**swapped, hmac_key=self._HMAC_KEY)
        assert original != swapped_hash


# ---------------------------------------------------------------------------
# F-10: Module-level imports in enforcer.py
# ---------------------------------------------------------------------------

class TestF10ModuleLevelImports:
    """guardian.enforcer must have shared.token and TlpLevel available at import time."""

    def test_shared_token_importable_at_module_level(self):
        """_shared_token must be bound at module import time — not inside a function."""
        import guardian.enforcer as enforcer_mod
        assert hasattr(enforcer_mod, "_shared_token"), (
            "enforcer._shared_token not found — F-10 module-level import missing"
        )

    def test_tlp_level_importable_at_module_level(self):
        """TlpLevel must be in the enforcer module's global namespace."""
        import guardian.enforcer as enforcer_mod
        assert hasattr(enforcer_mod, "TlpLevel"), (
            "enforcer.TlpLevel not found — F-10 module-level import missing"
        )

    def test_shared_token_is_module_not_function(self):
        """_shared_token should be the module itself, not a specific function."""
        import guardian.enforcer as enforcer_mod
        import types
        assert isinstance(enforcer_mod._shared_token, types.ModuleType), (
            "enforcer._shared_token is not a module object"
        )

    def test_shared_token_has_verify_token_binding(self):
        """_shared_token.verify_token_binding must be accessible as a module attribute."""
        import guardian.enforcer as enforcer_mod
        assert hasattr(enforcer_mod._shared_token, "verify_token_binding"), (
            "verify_token_binding not found on enforcer._shared_token"
        )

    def test_check_tlp_importable_at_module_level(self):
        """check_tlp must also be at module level (it was already, but verify)."""
        import guardian.enforcer as enforcer_mod
        assert hasattr(enforcer_mod, "check_tlp"), (
            "enforcer.check_tlp not found — check_tlp import missing"
        )
