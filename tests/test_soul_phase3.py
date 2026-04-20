"""
Phase 3 SOUL tests — Step 5.

Covers:
  - derive_instruction_set:
      * clean soul → returns instruction string
      * partition name in rule → SOULLeakError
      * partition name in constraint value → SOULLeakError
      * URL-encoded partition name → SOULLeakError
      * NFC-normalised partition name variant → SOULLeakError
      * TLP level in rule → SOULLeakError
      * TLP level case-insensitive match → SOULLeakError
      * custom tlp_levels arg respected
      * multiple partitions — any triggers
      * clean soul never contains partition name or TLP in output
  - verify_soul_integrity:
      * valid SOUL → returns True
      * tampered content → raises SOULTamperError
      * missing sig → raises SOULTamperError
"""
from __future__ import annotations

import urllib.parse
import unicodedata
from pathlib import Path

import pytest

import guardian.audit as audit_module
import guardian.soul as soul_module
from guardian.soul import (
    SOULConflictError,
    SOULLeakError,
    SOULTamperError,
    derive_instruction_set,
    generate_soul_keypair,
    merge_souls,
    sign_soul,
    soul_to_system_prompt,
    update_soul_hash_ledger,
    verify_soul,
    verify_soul_integrity,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_audit(tmp_path):
    audit_module.init_audit_log(tmp_path / "audit.db")
    yield


@pytest.fixture
def keypair():
    return generate_soul_keypair()


_CLEAN_SOUL = {
    "meta": {"agent": "test-agent", "version": "1.0"},
    "rules": {
        "absolute": [
            "Always route data requests through Guardian",
            "Never modify your own SOUL",
        ]
    },
    "constraints": {
        "max_token_lifetime_hours": 4,
    },
}

_KNOWN_PARTITIONS = ["company-a", "company-b"]


# ---------------------------------------------------------------------------
# derive_instruction_set — happy path
# ---------------------------------------------------------------------------

class TestDeriveInstructionSetHappyPath:
    def test_returns_string(self):
        result = derive_instruction_set(_CLEAN_SOUL, known_partitions=_KNOWN_PARTITIONS)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_result_does_not_contain_partition(self):
        result = derive_instruction_set(_CLEAN_SOUL, known_partitions=_KNOWN_PARTITIONS)
        for p in _KNOWN_PARTITIONS:
            assert p not in result

    def test_result_does_not_contain_tlp_level(self):
        from shared.types import TlpLevel
        result = derive_instruction_set(_CLEAN_SOUL, known_partitions=_KNOWN_PARTITIONS)
        for level in TlpLevel:
            assert level.value not in result.upper()

    def test_clean_soul_with_empty_partition_list(self):
        # No partitions to scan for — should always pass
        result = derive_instruction_set(_CLEAN_SOUL, known_partitions=[])
        assert isinstance(result, str)

    def test_custom_tlp_levels_empty_always_passes(self):
        # Empty tlp_levels list: no TLP scan
        result = derive_instruction_set(
            _CLEAN_SOUL,
            known_partitions=_KNOWN_PARTITIONS,
            known_tlp_levels=[],
        )
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# derive_instruction_set — partition name leak detection
# ---------------------------------------------------------------------------

class TestDeriveInstructionSetPartitionLeak:
    def test_partition_name_in_absolute_rule_raises(self):
        soul = {
            "rules": {
                "absolute": ["Always route company-a requests through Guardian"]
            }
        }
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=["company-a"])

    def test_partition_name_in_constraint_value_raises(self):
        soul = {
            "constraints": {
                "scope_note": "This agent handles company-b data only",
            }
        }
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=["company-b"])

    def test_partition_name_in_meta_agent_raises(self):
        soul = {
            "meta": {"agent": "company-a-assistant"},
        }
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=["company-a"])

    def test_url_encoded_partition_raises(self):
        encoded = urllib.parse.quote("company-a")
        soul = {
            "rules": {
                "absolute": [f"Route all {encoded} requests"]
            }
        }
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=["company-a"])

    def test_multiple_partitions_second_triggers(self):
        soul = {
            "rules": {
                "absolute": ["Handle company-b requests carefully"]
            }
        }
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=["company-a", "company-b"])

    def test_soul_leak_error_is_subclass_of_tamper_error(self):
        soul = {"rules": {"absolute": ["Use company-a vault"]}}
        with pytest.raises(SOULTamperError):  # SOULLeakError is a SOULTamperError
            derive_instruction_set(soul, known_partitions=["company-a"])

    # --- SMOLT-003: underscore-bounded partition names ---

    def test_underscore_partition_detected_with_space_boundary(self):
        """_q3_financials_ surrounded by spaces must be detected."""
        soul = {
            "rules": {
                "absolute": ["Handle _q3_financials_ data according to policy"]
            }
        }
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=["_q3_financials_"])

    def test_underscore_partition_detected_adjacent_to_underscore(self):
        """_q3_financials_ preceded/followed by another _ must be detected.

        This is the SMOLT-003 regression: (?<!\\w) treats _ as a word char
        and would MISS the name when the surrounding char is also _.
        The fix uses (?<![a-zA-Z0-9]) so underscore is treated as a separator.
        """
        # Double underscores around the partition name — old (?<!\\w) would fail
        # because the char immediately before/after is _, which is in \\w.
        soul = {
            "rules": {
                "absolute": ["Refer to __q3_financials__ for quarterly data"]
            }
        }
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=["_q3_financials_"])

    def test_embedded_partition_now_detected_fail_closed(self):
        """FIX 1: substring containment replaces word-boundary regex.
        '_q3_financials_' embedded in 'prefix_q3_financials_suffix' MUST now
        be detected — the boundary MUST fail closed even with false positives."""
        soul = {
            "rules": {
                "absolute": ["Use the prefix_q3_financials_suffix key"]
            }
        }
        # FIX 1: fail-closed means embedded names ARE rejected
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=["_q3_financials_"])

    def test_underscore_partition_at_start_of_string_detected(self):
        """_q3_financials_ at the very start of the instruction string is detected."""
        soul = {
            "meta": {"agent": "_q3_financials_"},
        }
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=["_q3_financials_"])


# ---------------------------------------------------------------------------
# derive_instruction_set — TLP level leak detection
# ---------------------------------------------------------------------------

class TestDeriveInstructionSetTlpLeak:
    def test_tlp_level_in_rule_raises(self):
        soul = {
            "rules": {
                "absolute": ["Handle all RED classified items with care"]
            }
        }
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=[])

    def test_tlp_amber_strict_in_rule_raises(self):
        soul = {
            "rules": {
                "absolute": ["AMBER_STRICT data requires human review"]
            }
        }
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=[])

    def test_tlp_level_case_insensitive_match(self):
        soul = {
            "constraints": {"note": "all items are tlp:amber"}
        }
        # "AMBER" from TLP enum will match "amber" case-insensitively
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=[])

    def test_custom_tlp_levels_respected(self):
        # Only checking for "CUSTOM_LEVEL" — "RED" in text should NOT raise
        soul = {
            "rules": {"absolute": ["Handle RED items carefully"]}
        }
        # No raise because we're only checking for "CUSTOM_LEVEL"
        result = derive_instruction_set(
            soul,
            known_partitions=[],
            known_tlp_levels=["CUSTOM_LEVEL"],
        )
        assert isinstance(result, str)

    def test_custom_tlp_level_triggers(self):
        soul = {
            "rules": {"absolute": ["Use CUSTOM_LEVEL for all requests"]}
        }
        with pytest.raises(SOULLeakError):
            derive_instruction_set(
                soul,
                known_partitions=[],
                known_tlp_levels=["CUSTOM_LEVEL"],
            )


# ---------------------------------------------------------------------------
# verify_soul_integrity
# ---------------------------------------------------------------------------

@pytest.fixture
def signed_soul(tmp_path, keypair, monkeypatch):
    """A signed and hash-ledger-registered SOUL.lock."""
    monkeypatch.setattr(soul_module, "SOUL_HASH_PATH", tmp_path / "SOUL.hash")
    path = tmp_path / "agent-SOUL.lock"
    content = '[meta]\nagent = "test"\nversion = "1.0"\n'
    path.write_text(content, encoding="utf-8")
    private_key, _ = keypair
    sign_soul(path, private_key)
    update_soul_hash_ledger(path, private_key)
    return path, keypair


class TestVerifySoulIntegrity:
    def test_valid_soul_returns_true(self, signed_soul):
        path, (private_key, public_key) = signed_soul
        assert verify_soul_integrity(path, public_key) is True

    def test_tampered_content_raises(self, signed_soul):
        path, (private_key, public_key) = signed_soul
        # Tamper with content after signing
        path.write_text('[meta]\nagent = "hacked"\nversion = "1.0"\n', encoding="utf-8")
        with pytest.raises(SOULTamperError):
            verify_soul_integrity(path, public_key)

    def test_missing_sig_raises(self, signed_soul):
        path, (private_key, public_key) = signed_soul
        sig = path.parent / (path.name + ".sig")
        sig.unlink()
        with pytest.raises(SOULTamperError):
            verify_soul_integrity(path, public_key)

    def test_wrong_public_key_raises(self, signed_soul):
        path, _ = signed_soul
        _, wrong_public_key = generate_soul_keypair()
        with pytest.raises(SOULTamperError):
            verify_soul_integrity(path, wrong_public_key)


# ---------------------------------------------------------------------------
# FIX 3: partition name scanner must be case-insensitive
# ---------------------------------------------------------------------------

class TestDeriveInstructionSetCaseInsensitive:
    """FIX 3 — SOUL leak scanner must catch uppercase partition names."""

    def test_uppercase_partition_raises(self):
        """'COMPANY_B_COMMERCIAL' in uppercase must raise SOULLeakError."""
        soul = {
            "rules": {
                "absolute": ["Handle COMPANY_B_COMMERCIAL requests via Guardian"]
            }
        }
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=["company_b_commercial"])

    def test_mixed_case_partition_raises(self):
        """Mixed-case variant must also be detected."""
        soul = {
            "constraints": {"note": "Scope: Company_B_Commercial only"}
        }
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=["company_b_commercial"])


# ---------------------------------------------------------------------------
# FIX 1: substring containment — embedded partition names always detected
# ---------------------------------------------------------------------------

class TestDeriveInstructionSetSubstringContainment:
    """FIX 1 — fail-closed substring containment catches embedded names."""

    def test_corp_in_acorp_data_detected(self):
        """'corp' embedded in 'acorp-data' must be detected."""
        soul = {"rules": {"absolute": ["Route all acorp-data requests"]}}
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=["corp"])

    def test_alpha_in_alphanumeric_detected(self):
        """'alpha' embedded in 'alphanumeric' must be detected."""
        soul = {"constraints": {"note": "Use alphanumeric identifiers only"}}
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=["alpha"])

    def test_test_in_unittest_detected(self):
        """'test' embedded in 'unittest' must be detected."""
        soul = {"rules": {"absolute": ["Run the unittest suite before deploy"]}}
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=["test"])

    def test_url_encoded_partition_in_string_detected(self):
        """URL-encoded partition name embedded in text must be detected."""
        encoded = urllib.parse.quote("data")
        soul = {"rules": {"absolute": [f"Process {encoded} items carefully"]}}
        with pytest.raises(SOULLeakError):
            derive_instruction_set(soul, known_partitions=["data"])

    def test_clean_instruction_no_partition_passes(self):
        """Instruction with no partition names must pass cleanly."""
        soul = {
            "rules": {"absolute": ["Always route requests through Guardian"]},
            "constraints": {"max_token_lifetime_hours": 4},
        }
        result = derive_instruction_set(soul, known_partitions=["corp", "alpha", "test"])
        assert isinstance(result, str)
        assert len(result) > 0


# ---------------------------------------------------------------------------
# FIX 5: merge_souls pre-checks ALL unknown top-level sections
# ---------------------------------------------------------------------------

_MASTER_SOUL_FOR_MERGE = """\
agent_extensions = ["persona"]

[meta]
version = "1.0"
agent = "master"

[rules]
absolute = ["Always be honest"]

[constraints]
max_token_lifetime_hours = 4
"""

_AGENT_SOUL_CONSTRAINTSS_TYPO = """\
[meta]
version = "1.0"
agent = "typo-agent"

[rules]
absolute = []

[constraintss]
max_token_lifetime_hours = 2
"""

_AGENT_SOUL_VALID_SECTIONS = """\
[meta]
version = "1.0"
agent = "good-agent"

[rules]
absolute = ["[persona] Always respond in English"]

[constraints]
max_token_lifetime_hours = 2
"""


class TestMergeSoulsUnknownSections:
    """FIX 5 — pre-check rejects ALL unknown top-level sections before any processing."""

    def _sign_and_bytes(self, path, private_key, hash_path):
        sign_soul(path, private_key)
        update_soul_hash_ledger(path, private_key)
        return path.read_bytes()

    def test_constraintss_typo_raises_conflict_error(self, tmp_path, keypair, monkeypatch):
        """Agent SOUL with [constraintss] (typo) must raise SOULConflictError."""
        monkeypatch.setattr(soul_module, "SOUL_HASH_PATH", tmp_path / "SOUL.hash")
        private_key, _ = keypair

        master_path = tmp_path / "master-SOUL.lock"
        master_path.write_text(_MASTER_SOUL_FOR_MERGE, encoding="utf-8")
        master_bytes = self._sign_and_bytes(master_path, private_key, tmp_path / "SOUL.hash")

        agent_path = tmp_path / "typo-SOUL.lock"
        agent_path.write_text(_AGENT_SOUL_CONSTRAINTSS_TYPO, encoding="utf-8")
        agent_bytes = self._sign_and_bytes(agent_path, private_key, tmp_path / "SOUL.hash")

        with pytest.raises(SOULConflictError, match="unknown top-level sections.*constraintss"):
            merge_souls(master_bytes, agent_bytes)

    def test_unknown_section_audit_logged(self, tmp_path, keypair, monkeypatch):
        """Unknown section rejection must be logged to the audit trail."""
        monkeypatch.setattr(soul_module, "SOUL_HASH_PATH", tmp_path / "SOUL.hash")
        private_key, _ = keypair

        master_path = tmp_path / "master-SOUL.lock"
        master_path.write_text(_MASTER_SOUL_FOR_MERGE, encoding="utf-8")
        master_bytes = self._sign_and_bytes(master_path, private_key, tmp_path / "SOUL.hash")

        agent_path = tmp_path / "typo2-SOUL.lock"
        agent_path.write_text(_AGENT_SOUL_CONSTRAINTSS_TYPO, encoding="utf-8")
        agent_bytes = self._sign_and_bytes(agent_path, private_key, tmp_path / "SOUL.hash")

        with pytest.raises(SOULConflictError):
            merge_souls(master_bytes, agent_bytes)

        entries = audit_module.query_log(action="soul.conflict_detected")
        assert any("constraintss" in e["result"] for e in entries)

    def test_valid_sections_only_passes(self, tmp_path, keypair, monkeypatch):
        """Agent SOUL with only meta/rules/constraints must merge successfully."""
        monkeypatch.setattr(soul_module, "SOUL_HASH_PATH", tmp_path / "SOUL.hash")
        private_key, _ = keypair

        master_path = tmp_path / "master-SOUL.lock"
        master_path.write_text(_MASTER_SOUL_FOR_MERGE, encoding="utf-8")
        master_bytes = self._sign_and_bytes(master_path, private_key, tmp_path / "SOUL.hash")

        agent_path = tmp_path / "good-SOUL.lock"
        agent_path.write_text(_AGENT_SOUL_VALID_SECTIONS, encoding="utf-8")
        agent_bytes = self._sign_and_bytes(agent_path, private_key, tmp_path / "SOUL.hash")

        result = merge_souls(master_bytes, agent_bytes)
        assert isinstance(result, dict)
        assert "Always be honest" in result["rules"]["absolute"]
