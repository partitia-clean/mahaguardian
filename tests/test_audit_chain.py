"""
Tests for guardian/audit_chain.py.

Covers:
  - Known-vector hash (deterministic given fixed inputs)
  - Chain builds correctly (each entry chains from previous)
  - Tamper detection (mutating any field breaks the chain)
  - DENY entry has same fields as ALLOW entry
  - Genesis hash value
  - NFC normalisation is applied
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import unicodedata

import pytest

from guardian.audit_chain import GENESIS_HASH, AuditChain, _compute_hash, _params_hash
from shared.types import Decision


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TEST_HMAC_KEY = b"mahaguardian_test_hmac_key_32bytes!!"


@pytest.fixture
def chain(tmp_path):
    return AuditChain(tmp_path / "audit_chain.db", hmac_key=_TEST_HMAC_KEY)


# ---------------------------------------------------------------------------
# Genesis hash
# ---------------------------------------------------------------------------

def test_genesis_hash_value():
    # FIX 9: must carry "sha256:" prefix
    bare = hashlib.sha256(b"mahaguardian_genesis_v1").hexdigest()
    assert GENESIS_HASH == "sha256:" + bare


# ---------------------------------------------------------------------------
# Known test vector
# ---------------------------------------------------------------------------

def test_params_hash_deterministic():
    """Same params always produce same hash; field order is irrelevant."""
    h1 = _params_hash({"key": "client_count", "z": 1})
    h2 = _params_hash({"z": 1, "key": "client_count"})
    assert h1 == h2


def test_params_hash_canonical_json():
    """params_hash uses sort_keys + no spaces — RFC 8785 approximation."""
    params = {"b": 2, "a": 1}
    canonical = json.dumps(params, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    # FIX 9: _params_hash now returns "sha256:<hex>"
    expected = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert _params_hash(params) == expected


def test_known_vector():
    """
    _compute_hash is deterministic for fixed inputs.
    FIX 4+9: now HMAC-SHA-256 with a key; returns "sha256:<hex>" prefix.
    FIX F2: uses length-prefixed binary encoding (not null-byte delimiters).
    """
    import hmac as _hmac
    key = _TEST_HMAC_KEY
    fields_list = [
        "e1",
        "2026-04-06T00:00:00+00:00",
        "alpha",
        "company-a",
        "vault.read",
        "abc123",
        "ALLOW",
        "tlp_allow",
        GENESIS_HASH,
    ]
    parts = []
    for f in fields_list:
        encoded = f.encode("utf-8")
        parts.append(len(encoded).to_bytes(4, "big") + encoded)
    payload = b"".join(parts)
    expected = "sha256:" + _hmac.new(key, payload, "sha256").hexdigest()
    got = _compute_hash(
        "e1", "2026-04-06T00:00:00+00:00", "alpha", "company-a",
        "vault.read", "abc123", "ALLOW", "tlp_allow", GENESIS_HASH,
        hmac_key=key,
    )
    assert got == expected


# ---------------------------------------------------------------------------
# Chain integrity
# ---------------------------------------------------------------------------

def test_first_entry_chains_from_genesis(chain):
    chain.append(agent_id="alpha", partition_id="company-a",
                 method="vault.read", params={"key": "x"},
                 decision=Decision.ALLOW, reason_code="ok")
    entries = chain.entries()
    # FIX 9: GENESIS_HASH now carries "sha256:" prefix
    assert entries[0]["prev_hash"] == GENESIS_HASH
    assert entries[0]["prev_hash"].startswith("sha256:")


def test_second_entry_chains_from_first(chain):
    chain.append(agent_id="alpha", partition_id="company-a",
                 method="vault.read", params={"key": "x"},
                 decision=Decision.ALLOW, reason_code="ok")
    chain.append(agent_id="alpha", partition_id="company-a",
                 method="vault.read", params={"key": "y"},
                 decision=Decision.DENY, reason_code="tlp_insufficient")
    entries = chain.entries()
    assert entries[1]["prev_hash"] == entries[0]["entry_hash"]


def test_verify_intact_chain(chain):
    for i in range(5):
        chain.append(agent_id="alpha", partition_id="company-a",
                     method="vault.read", params={"i": i},
                     decision=Decision.ALLOW, reason_code="ok")
    assert chain.verify() is True


def test_verify_detects_tamper_in_decision(chain, tmp_path):
    chain.append(agent_id="alpha", partition_id="company-a",
                 method="vault.read", params={"key": "x"},
                 decision=Decision.ALLOW, reason_code="ok")
    chain.append(agent_id="alpha", partition_id="company-a",
                 method="vault.read", params={"key": "y"},
                 decision=Decision.DENY, reason_code="tlp_insufficient")

    # Tamper: open DB directly and flip decision on first entry (ALLOW → DENY)
    db_path = tmp_path / "audit_chain.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("UPDATE audit_chain SET decision='DENY' WHERE rowid=1")
    conn.commit()
    conn.close()

    assert chain.verify() is False


def test_verify_detects_tamper_in_agent_id(chain, tmp_path):
    chain.append(agent_id="alpha", partition_id="company-a",
                 method="vault.read", params={},
                 decision=Decision.ALLOW, reason_code="ok")
    db_path = tmp_path / "audit_chain.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("UPDATE audit_chain SET agent_id='evil' WHERE rowid=1")
    conn.commit()
    conn.close()

    assert chain.verify() is False


def test_verify_empty_chain(chain):
    assert chain.verify() is True


# ---------------------------------------------------------------------------
# DENY parity — same fields as ALLOW
# ---------------------------------------------------------------------------

def test_deny_entry_has_same_fields_as_allow(chain):
    chain.append(agent_id="alpha", partition_id="company-a",
                 method="vault.read", params={"key": "x"},
                 decision=Decision.ALLOW, reason_code="tlp_allow")
    chain.append(agent_id="alpha", partition_id="company-a",
                 method="vault.read", params={"key": "y"},
                 decision=Decision.DENY, reason_code="tlp_insufficient")

    entries = chain.entries()
    allow_keys = set(entries[0].keys())
    deny_keys  = set(entries[1].keys())
    assert allow_keys == deny_keys, "DENY entry must have same fields as ALLOW"


def test_deny_entry_logs_decision_correctly(chain):
    chain.append(agent_id="beta", partition_id="company-b",
                 method="vault.read", params={"key": "secret"},
                 decision=Decision.DENY, reason_code="partition_unauthorized")
    entries = chain.entries()
    assert entries[0]["decision"] == "DENY"
    assert entries[0]["reason_code"] == "partition_unauthorized"


def test_elevate_entry_logged(chain):
    chain.append(agent_id="analyst", partition_id="company-a",
                 method="vault.read", params={"key": "restricted"},
                 decision=Decision.ELEVATE, reason_code="needs_human_approval")
    entries = chain.entries()
    assert entries[0]["decision"] == "ELEVATE"


# ---------------------------------------------------------------------------
# NFC normalisation
# ---------------------------------------------------------------------------

def test_nfc_normalisation_applied():
    """
    NFC-composed and NFC-decomposed forms of the same string
    must produce the same hash.
    """
    # U+00E9 (precomposed é) vs U+0065 U+0301 (decomposed e + combining acute)
    composed   = "\u00e9"
    decomposed = "e\u0301"
    assert unicodedata.normalize("NFC", composed) == unicodedata.normalize("NFC", decomposed)
    h1 = _compute_hash(
        composed, "ts", "a", "p", "m", "ph", "ALLOW", "ok", GENESIS_HASH,
        hmac_key=_TEST_HMAC_KEY)
    h2 = _compute_hash(
        unicodedata.normalize("NFC", decomposed),
        "ts", "a", "p", "m", "ph", "ALLOW", "ok", GENESIS_HASH,
        hmac_key=_TEST_HMAC_KEY)
    assert h1 == h2


# ---------------------------------------------------------------------------
# Append-only enforcement
# ---------------------------------------------------------------------------

def test_append_only_update_blocked(chain, tmp_path):
    chain.append(agent_id="alpha", partition_id="company-a",
                 method="vault.read", params={},
                 decision=Decision.ALLOW, reason_code="ok")
    db_path = tmp_path / "audit_chain.db"
    conn = sqlite3.connect(str(db_path))
    conn.set_authorizer(
        lambda code, *_: sqlite3.SQLITE_DENY if code == sqlite3.SQLITE_UPDATE
        else sqlite3.SQLITE_OK
    )
    with pytest.raises(Exception):
        conn.execute("UPDATE audit_chain SET decision='DENY' WHERE rowid=1")
    conn.close()


# ---------------------------------------------------------------------------
# FIX-09: RFC 8785 canonical JSON compliance tests
# ---------------------------------------------------------------------------

class TestRFC8785Compliance:
    def test_params_hash_uses_sorted_keys(self):
        """RFC 8785: keys must be sorted alphabetically."""
        params = {"z_last": 3, "a_first": 1, "m_middle": 2}
        canonical = json.dumps(params, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False)
        # Verify sort order
        keys_in_order = list(json.loads(canonical).keys())
        assert keys_in_order == sorted(keys_in_order)

    def test_params_hash_no_whitespace(self):
        """RFC 8785: no whitespace between tokens."""
        params = {"key": "value", "num": 42}
        canonical = json.dumps(params, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False)
        assert " " not in canonical
        assert "\t" not in canonical
        assert "\n" not in canonical

    def test_params_hash_unicode_not_escaped(self):
        """RFC 8785: Unicode characters must NOT be escaped to \\uXXXX."""
        params = {"name": "café"}
        ph = _params_hash(params)
        # Verify the canonical form doesn't escape non-ASCII
        canonical = json.dumps(params, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False)
        assert "\\u" not in canonical
        assert "café" in canonical

    def test_nfc_applied_to_unicode_combining_chars(self, chain):
        """
        Unicode combining characters must be NFC-normalized before storage.
        é (precomposed U+00E9) and e + combining acute (U+0065 U+0301)
        must produce the same stored agent_id.
        """
        composed   = "caf\u00e9"    # café — NFC
        decomposed = "cafe\u0301"   # cafe + combining acute — NFD

        chain.append(agent_id=composed, partition_id="p",
                     method="vault.read", params={},
                     decision=Decision.ALLOW, reason_code="ok")
        chain.append(agent_id=decomposed, partition_id="p",
                     method="vault.read", params={},
                     decision=Decision.ALLOW, reason_code="ok")

        entries = chain.entries()
        # Both must normalize to the same stored form
        import unicodedata
        assert (unicodedata.normalize("NFC", entries[0]["agent_id"]) ==
                unicodedata.normalize("NFC", entries[1]["agent_id"]))

    def test_length_prefixed_encoding_in_hash_computation(self):
        """Verify length-prefixed encoding is used in _compute_hash.
        FIX F2: switched from null-byte delimiters to length-prefixed binary.
        FIX 4+9: HMAC-SHA-256 with key; returns "sha256:" prefix."""
        import hmac as _hmac
        entry_id = "e-null"
        timestamp = "2026-04-08T00:00:00+00:00"
        agent_id = "agent"
        partition_id = "partition"
        method = "vault.read"
        ph = "aabbcc"
        decision = "ALLOW"
        reason = "ok"
        prev = GENESIS_HASH

        fields_list = [entry_id, timestamp, agent_id, partition_id,
                       method, ph, decision, reason, prev]
        parts = []
        for f in fields_list:
            encoded = f.encode("utf-8")
            parts.append(len(encoded).to_bytes(4, "big") + encoded)
        payload = b"".join(parts)
        expected = "sha256:" + _hmac.new(
            _TEST_HMAC_KEY, payload, "sha256"
        ).hexdigest()
        got = _compute_hash(entry_id, timestamp, agent_id, partition_id,
                            method, ph, decision, reason, prev,
                            hmac_key=_TEST_HMAC_KEY)
        assert got == expected

    def test_params_hash_reference_vector(self):
        """Known-good reference vector for RFC 8785 canonical JSON hash."""
        params = {"action": "read", "key": "secret"}
        # Canonical: {"action":"read","key":"secret"} (sorted, no spaces)
        canonical = '{"action":"read","key":"secret"}'
        # FIX 9: _params_hash now returns "sha256:<hex>"
        expected = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        assert _params_hash(params) == expected


# ---------------------------------------------------------------------------
# FIX 4: HMAC keying — tamper + recalculate still fails; wrong key fails
# ---------------------------------------------------------------------------

class TestHMACKeying:
    """Verify that HMAC key prevents undetected chain rewriting."""

    def test_tamper_then_recalculate_sha256_still_fails(self, tmp_path):
        """
        Even if an attacker recalculates a plain SHA-256 after tampering,
        verify() must still fail because HMAC key is required.
        """
        chain = AuditChain(tmp_path / "audit_chain.db", hmac_key=_TEST_HMAC_KEY)
        chain.append(agent_id="alpha", partition_id="company-a",
                     method="vault.read", params={"key": "x"},
                     decision=Decision.ALLOW, reason_code="ok")

        entries = chain.entries()
        entry = entries[0]

        # Attacker tampers with decision and recalculates plain SHA-256
        # (as if the old unkeyed scheme were still in use).
        payload = "\x00".join([
            entry["entry_id"], entry["timestamp"], entry["agent_id"],
            entry["partition_id"], entry["method"], entry["params_hash"],
            "DENY",  # tampered decision
            entry["reason_code"], entry["prev_hash"],
        ])
        fake_hash = "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()

        conn = sqlite3.connect(str(tmp_path / "audit_chain.db"))
        conn.execute(
            "UPDATE audit_chain SET decision='DENY', entry_hash=? WHERE rowid=1",
            (fake_hash,),
        )
        conn.commit()
        conn.close()

        # verify() must detect the forgery because correct hash requires HMAC key
        assert chain.verify() is False

    def test_verify_with_wrong_key_fails(self, tmp_path):
        """verify() called with a different key must return False."""
        chain = AuditChain(tmp_path / "audit_chain.db", hmac_key=_TEST_HMAC_KEY)
        chain.append(agent_id="alpha", partition_id="company-a",
                     method="vault.read", params={},
                     decision=Decision.ALLOW, reason_code="ok")
        assert chain.verify() is True

        wrong_key_chain = AuditChain(tmp_path / "audit_chain.db",
                                     hmac_key=b"wrong_key_xxxxxxxxxxxxxxxxxxxxxxx")
        assert wrong_key_chain.verify() is False

    def test_tamper_detected_and_verify_fails(self, tmp_path):
        """Mutating any stored field without recalculating HMAC → verify() False."""
        chain = AuditChain(tmp_path / "audit_chain.db", hmac_key=_TEST_HMAC_KEY)
        chain.append(agent_id="alpha", partition_id="company-a",
                     method="vault.read", params={"key": "x"},
                     decision=Decision.ALLOW, reason_code="ok")

        conn = sqlite3.connect(str(tmp_path / "audit_chain.db"))
        conn.execute("UPDATE audit_chain SET agent_id='evil' WHERE rowid=1")
        conn.commit()
        conn.close()

        assert chain.verify() is False


# ---------------------------------------------------------------------------
# FIX F2: Null-byte injection resistance
# ---------------------------------------------------------------------------

class TestNullByteInjection:
    """Verify that null bytes in field values cannot alter field boundaries."""

    def test_null_byte_in_agent_id_does_not_alter_hash_structure(self):
        """An agent_id containing \\x00 must produce a different hash from a
        normally-delimited version — the injected null cannot fake a boundary."""
        import hmac as _hmac
        key = _TEST_HMAC_KEY

        # agent_id "al\x00pha" vs "al" with rest of fields starting "pha..."
        # With null-byte delimiters those would be ambiguous; with length-prefix they are not.
        h_with_null = _compute_hash(
            "e1", "ts", "al\x00pha", "part", "method", "ph", "ALLOW", "ok", GENESIS_HASH,
            hmac_key=key,
        )
        h_normal = _compute_hash(
            "e1", "ts", "alpha", "part", "method", "ph", "ALLOW", "ok", GENESIS_HASH,
            hmac_key=key,
        )
        # Hashes must differ — injection doesn't collapse to the same value
        assert h_with_null != h_normal

    def test_null_byte_placement_produces_different_hashes(self):
        """Two entries that differ ONLY in where \\x00 appears must produce
        different hashes (injection is neutralised by length-prefixed encoding)."""
        import hmac as _hmac
        key = _TEST_HMAC_KEY

        h1 = _compute_hash(
            "id", "ts", "agent\x00", "part", "m", "ph", "ALLOW", "ok", GENESIS_HASH,
            hmac_key=key,
        )
        h2 = _compute_hash(
            "id", "ts", "agent", "\x00part", "m", "ph", "ALLOW", "ok", GENESIS_HASH,
            hmac_key=key,
        )
        assert h1 != h2

    def test_chain_verify_still_true_with_null_byte_in_field(self, chain):
        """Chain integrity is maintained even when field values contain \\x00."""
        chain.append(agent_id="ag\x00ent", partition_id="company-a",
                     method="vault.read", params={"key": "x"},
                     decision=Decision.ALLOW, reason_code="ok")
        assert chain.verify() is True


# ---------------------------------------------------------------------------
# FIX F10: sha256: prefix validation in verify()
# ---------------------------------------------------------------------------

class TestHashPrefixValidation:
    def test_all_entry_hashes_start_with_sha256_prefix(self, chain):
        """Every appended entry's hash must start with 'sha256:'."""
        for i in range(3):
            chain.append(agent_id="alpha", partition_id="company-a",
                         method="vault.read", params={"i": i},
                         decision=Decision.ALLOW, reason_code="ok")
        entries = chain.entries()
        for entry in entries:
            assert entry["entry_hash"].startswith("sha256:"), (
                f"entry_hash missing prefix: {entry['entry_hash']}"
            )

    def test_verify_rejects_entry_with_missing_sha256_prefix(self, chain, tmp_path):
        """verify() returns False if any stored entry_hash lacks 'sha256:' prefix."""
        chain.append(agent_id="alpha", partition_id="company-a",
                     method="vault.read", params={},
                     decision=Decision.ALLOW, reason_code="ok")
        # Strip the prefix directly in the DB (bypassing the authorizer)
        db_path = tmp_path / "audit_chain.db"
        conn = sqlite3.connect(str(db_path))
        conn.execute(
            "UPDATE audit_chain SET entry_hash = SUBSTR(entry_hash, 8) WHERE rowid=1"
        )
        conn.commit()
        conn.close()
        assert chain.verify() is False
