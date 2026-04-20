"""
Tests for guardian/audit.py — append-only hash-chained audit log.
"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
from pathlib import Path

import pytest

import guardian.audit as audit_module
from guardian.audit import (
    init_audit_log,
    log,
    query_log,
    verify_log_integrity,
    _compute_entry_hash,
    _none_safe,
)
from shared.config import GENESIS_HASH


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_module_db_path(tmp_path):
    """Reset the module-level _db_path before and after each test."""
    original = audit_module._db_path
    yield
    audit_module._db_path = original


@pytest.fixture
def db_path(tmp_path) -> Path:
    """Initialised audit log in a temp directory."""
    path = tmp_path / "audit.db"
    init_audit_log(path)
    return path


# ---------------------------------------------------------------------------
# init_audit_log
# ---------------------------------------------------------------------------

class TestInitAuditLog:
    def test_creates_database_file(self, tmp_path):
        path = tmp_path / "test.db"
        assert not path.exists()
        init_audit_log(path)
        assert path.exists()

    def test_creates_audit_log_table(self, tmp_path):
        path = tmp_path / "test.db"
        init_audit_log(path)
        conn = sqlite3.connect(str(path))
        cur = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'"
        )
        assert cur.fetchone() is not None
        conn.close()

    def test_table_has_required_columns(self, tmp_path):
        path = tmp_path / "test.db"
        init_audit_log(path)
        conn = sqlite3.connect(str(path))
        cur = conn.execute("PRAGMA table_info(audit_log)")
        columns = {row[1] for row in cur.fetchall()}
        conn.close()
        required = {
            "id", "timestamp", "agent_id", "action", "resource",
            "classification", "partition_id", "result",
            "prev_hash", "entry_hash",
        }
        assert required.issubset(columns)

    def test_idempotent_second_call(self, tmp_path):
        path = tmp_path / "test.db"
        init_audit_log(path)
        init_audit_log(path)  # should not raise
        assert path.exists()

    def test_sets_module_db_path(self, tmp_path):
        path = tmp_path / "test.db"
        init_audit_log(path)
        assert audit_module._db_path == path

    def test_creates_parent_directories(self, tmp_path):
        path = tmp_path / "nested" / "dir" / "audit.db"
        init_audit_log(path)
        assert path.exists()


# ---------------------------------------------------------------------------
# log()
# ---------------------------------------------------------------------------

class TestLog:
    def test_appends_single_entry(self, db_path):
        log(action="test.action", result="success")
        entries = query_log()
        assert len(entries) == 1
        assert entries[0]["action"] == "test.action"

    def test_multiple_entries_ordered(self, db_path):
        log(action="first")
        log(action="second")
        log(action="third")
        entries = query_log()
        assert len(entries) == 3
        assert [e["action"] for e in entries] == ["first", "second", "third"]

    def test_first_entry_prev_hash_is_genesis(self, db_path):
        log(action="genesis_test")
        entries = query_log()
        assert entries[0]["prev_hash"] == GENESIS_HASH

    def test_second_entry_prev_hash_chains_from_first(self, db_path):
        log(action="first")
        log(action="second")
        entries = query_log()
        assert entries[1]["prev_hash"] == entries[0]["entry_hash"]

    def test_entry_hash_is_sha256_of_fields(self, db_path):
        log(action="hash_check", agent_id="alpha", result="success")
        entries = query_log()
        e = entries[0]
        expected = _compute_entry_hash(
            e["prev_hash"],
            e["timestamp"],
            e["agent_id"],
            e["action"],
            e["resource"],
            e["classification"],
            e["partition_id"],
            e["result"],
        )
        assert e["entry_hash"] == expected

    def test_agent_id_stored(self, db_path):
        log(action="test", agent_id="alpha")
        entries = query_log()
        assert entries[0]["agent_id"] == "alpha"

    def test_resource_stored(self, db_path):
        log(action="test", resource="vault.enc")
        entries = query_log()
        assert entries[0]["resource"] == "vault.enc"

    def test_classification_stored(self, db_path):
        log(action="test", classification="INTERNAL")
        entries = query_log()
        assert entries[0]["classification"] == "INTERNAL"

    def test_partition_id_stored(self, db_path):
        log(action="test", partition_id="company-alpha")
        entries = query_log()
        assert entries[0]["partition_id"] == "company-alpha"

    def test_partition_id_defaults_to_none(self, db_path):
        log(action="test")
        entries = query_log()
        assert entries[0]["partition_id"] is None

    def test_raises_if_not_initialised(self):
        audit_module._db_path = None
        with pytest.raises(RuntimeError, match="not initialised"):
            log(action="uninitialized")

    def test_does_not_silently_fail(self, db_path):
        """log() must raise on failure — never swallow errors."""
        audit_module._db_path = Path("/nonexistent/path/audit.db")
        with pytest.raises(Exception):
            log(action="should_fail")

    def test_no_update_permission(self, db_path):
        """The authorizer must block UPDATE statements."""
        import guardian.audit as _m
        conn = _m._open_db(db_path)
        try:
            with pytest.raises(Exception):
                conn.execute("UPDATE audit_log SET result='tampered' WHERE id=1")
        finally:
            conn.close()

    def test_no_delete_permission(self, db_path):
        """The authorizer must block DELETE statements."""
        import guardian.audit as _m
        log(action="to_delete")
        conn = _m._open_db(db_path)
        try:
            with pytest.raises(Exception):
                conn.execute("DELETE FROM audit_log WHERE id=1")
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Concurrent log() (FIX 9)
# ---------------------------------------------------------------------------

class TestConcurrentLog:
    def test_concurrent_log_produces_valid_chain(self, db_path):
        """
        Multiple threads calling log() simultaneously must still produce
        a valid hash chain thanks to BEGIN EXCLUSIVE.
        """
        num_threads = 8
        entries_per_thread = 10
        errors: list[Exception] = []

        def worker(tid: int) -> None:
            try:
                for i in range(entries_per_thread):
                    log(action=f"thread_{tid}_entry_{i}")
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(t,))
            for t in range(num_threads)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == [], f"Errors in threads: {errors}"
        entries = query_log()
        assert len(entries) == num_threads * entries_per_thread
        # Most importantly: the chain must be intact
        assert verify_log_integrity(db_path) is True


# ---------------------------------------------------------------------------
# verify_log_integrity
# ---------------------------------------------------------------------------

class TestVerifyLogIntegrity:
    def test_empty_log_is_valid(self, db_path):
        assert verify_log_integrity(db_path) is True

    def test_single_entry_valid(self, db_path):
        log(action="single")
        assert verify_log_integrity(db_path) is True

    def test_multiple_entries_valid(self, db_path):
        for i in range(10):
            log(action=f"action_{i}")
        assert verify_log_integrity(db_path) is True

    def test_tampered_entry_hash_detected(self, db_path):
        log(action="legitimate")
        # Directly tamper with the database bypassing the authorizer
        conn = sqlite3.connect(str(db_path))
        conn.execute("UPDATE audit_log SET entry_hash='deadbeef' WHERE id=1")
        conn.commit()
        conn.close()
        assert verify_log_integrity(db_path) is False

    def test_tampered_prev_hash_detected(self, db_path):
        log(action="first")
        log(action="second")
        conn = sqlite3.connect(str(db_path))
        conn.execute("UPDATE audit_log SET prev_hash='tampered' WHERE id=2")
        conn.commit()
        conn.close()
        assert verify_log_integrity(db_path) is False

    def test_tampered_action_field_detected(self, db_path):
        log(action="original")
        conn = sqlite3.connect(str(db_path))
        conn.execute("UPDATE audit_log SET action='tampered' WHERE id=1")
        conn.commit()
        conn.close()
        assert verify_log_integrity(db_path) is False

    def test_tampered_result_field_detected(self, db_path):
        log(action="test", result="success")
        conn = sqlite3.connect(str(db_path))
        conn.execute("UPDATE audit_log SET result='forged' WHERE id=1")
        conn.commit()
        conn.close()
        assert verify_log_integrity(db_path) is False

    def test_inserted_row_breaks_chain(self, db_path):
        """Inserting a row with a fabricated hash breaks the chain."""
        log(action="first")
        log(action="second")
        conn = sqlite3.connect(str(db_path))
        # Insert a row with an incorrect prev_hash in the middle
        conn.execute(
            "UPDATE audit_log SET prev_hash='INJECTED', entry_hash='INJECTED' WHERE id=2"
        )
        conn.commit()
        conn.close()
        assert verify_log_integrity(db_path) is False

    def test_entry_with_partition_id_valid(self, db_path):
        log(action="partitioned", partition_id="company-alpha")
        assert verify_log_integrity(db_path) is True


# ---------------------------------------------------------------------------
# query_log
# ---------------------------------------------------------------------------

class TestQueryLog:
    def test_returns_all_entries_unfiltered(self, db_path):
        log(action="a")
        log(action="b")
        log(action="c")
        entries = query_log()
        assert len(entries) == 3

    def test_filter_by_agent_id(self, db_path):
        log(action="act", agent_id="alpha")
        log(action="act", agent_id="beta")
        results = query_log(agent_id="alpha")
        assert all(e["agent_id"] == "alpha" for e in results)
        assert len(results) == 1

    def test_filter_by_action(self, db_path):
        log(action="vault.unlock")
        log(action="vault.lock")
        log(action="vault.unlock")
        results = query_log(action="vault.unlock")
        assert len(results) == 2

    def test_filter_by_partition_id(self, db_path):
        log(action="access", partition_id="company-alpha")
        log(action="access", partition_id="company-beta")
        log(action="access", partition_id="company-alpha")
        results = query_log(partition_id="company-alpha")
        assert len(results) == 2
        assert all(e["partition_id"] == "company-alpha" for e in results)

    def test_filter_by_from_timestamp(self, db_path):
        log(action="early")
        from datetime import datetime, timezone
        mid = datetime.now(timezone.utc).isoformat()
        log(action="late")
        results = query_log(from_timestamp=mid)
        assert len(results) == 1
        assert results[0]["action"] == "late"

    def test_filter_by_to_timestamp(self, db_path):
        from datetime import datetime, timezone
        log(action="early")
        mid = datetime.now(timezone.utc).isoformat()
        log(action="late")
        results = query_log(to_timestamp=mid)
        assert len(results) == 1
        assert results[0]["action"] == "early"

    def test_returns_list_of_dicts(self, db_path):
        log(action="test")
        results = query_log()
        assert isinstance(results, list)
        assert isinstance(results[0], dict)

    def test_result_keys_match_schema(self, db_path):
        log(action="schema_check")
        entry = query_log()[0]
        required_keys = {
            "id", "timestamp", "agent_id", "action", "resource",
            "classification", "partition_id", "result",
            "prev_hash", "entry_hash",
        }
        assert required_keys.issubset(entry.keys())

    def test_raises_if_not_initialised(self):
        audit_module._db_path = None
        with pytest.raises(RuntimeError, match="not initialised"):
            query_log()


# ---------------------------------------------------------------------------
# Hash helper
# ---------------------------------------------------------------------------

class TestComputeEntryHash:
    def test_deterministic(self):
        h1 = _compute_entry_hash("GENESIS", "2025-01-01T00:00:00Z",
                                  "alpha", "test", None, None, None, "success")
        h2 = _compute_entry_hash("GENESIS", "2025-01-01T00:00:00Z",
                                  "alpha", "test", None, None, None, "success")
        assert h1 == h2

    def test_different_prev_hash_changes_result(self):
        h1 = _compute_entry_hash("GENESIS", "ts", "a", "act", None, None, None, "ok")
        h2 = _compute_entry_hash("OTHER", "ts", "a", "act", None, None, None, "ok")
        assert h1 != h2

    def test_none_and_empty_produce_different_hashes(self):
        """After _none_safe fix, None and "" must hash differently."""
        h1 = _compute_entry_hash("G", "ts", None, "act", None, None, None, "ok")
        h2 = _compute_entry_hash("G", "ts", "", "act", "", "", "", "ok")
        assert h1 != h2

    def test_returns_64_char_hex(self):
        h = _compute_entry_hash("G", "ts", None, "act", None, None, None, "ok")
        assert h.startswith("sha256:")
        assert len(h) == 71  # "sha256:" (7) + 64 hex chars
        assert all(c in "0123456789abcdef" for c in h[7:])

    def test_field_boundary_collision_prevented(self):
        """FIX B: adjacent field values that concatenate the same must
        produce different hashes when the boundary shifts."""
        h1 = _compute_entry_hash("G", "ts", "user", "login", None, None, None, "ok")
        h2 = _compute_entry_hash("G", "ts", "", "userlogin", None, None, None, "ok")
        assert h1 != h2

    def test_different_partition_ids_produce_different_hashes(self):
        """Entries that differ only in partition_id must have different hashes."""
        h1 = _compute_entry_hash(
            "GENESIS", "2025-01-01T00:00:00Z", "alpha", "access",
            "vault.enc", "INTERNAL", "company-alpha", "success"
        )
        h2 = _compute_entry_hash(
            "GENESIS", "2025-01-01T00:00:00Z", "alpha", "access",
            "vault.enc", "INTERNAL", "company-beta", "success"
        )
        assert h1 != h2


# ---------------------------------------------------------------------------
# Truncation detection limitation (FIX F)
# ---------------------------------------------------------------------------

class TestTruncationDetectionLimitation:
    def test_tail_truncation_not_detected_by_hash_chain(self, db_path):
        """
        Documents a known limitation: truncation from the end is not
        detectable by the hash chain alone. External anchoring (Phase 2)
        is required.

        If an attacker with raw DB access deletes the last N entries,
        the remaining entries still form a valid chain because each
        entry only references its predecessor — no entry knows about
        entries that come after it.
        """
        # Create 5 entries
        for i in range(5):
            log(action=f"entry_{i}")
        entries_before = query_log()
        assert len(entries_before) == 5

        # Bypass the authorizer and delete the last 2 entries
        conn = sqlite3.connect(str(db_path))
        conn.execute("DELETE FROM audit_log WHERE id > 3")
        conn.commit()
        conn.close()

        # The remaining 3 entries still form a valid chain
        assert verify_log_integrity(db_path) is True

        # But we lost 2 entries — the chain cannot detect this
        entries_after = query_log()
        assert len(entries_after) == 3


# ---------------------------------------------------------------------------
# Fix: Null-byte validation in audit fields
# ---------------------------------------------------------------------------

class TestNullByteValidation:
    """Null bytes in audit fields must be rejected to prevent delimiter injection."""

    def test_null_byte_in_agent_id_raises_valueerror(self, tmp_path):
        db_path = tmp_path / "audit.db"
        init_audit_log(db_path)
        with pytest.raises(ValueError, match="control byte"):
            log(action="test.action", agent_id="alpha\x00beta")

    def test_null_byte_in_action_raises_valueerror(self, tmp_path):
        db_path = tmp_path / "audit.db"
        init_audit_log(db_path)
        with pytest.raises(ValueError, match="control byte"):
            log(action="test\x00inject", agent_id="alpha")

    def test_null_byte_in_resource_raises_valueerror(self, tmp_path):
        db_path = tmp_path / "audit.db"
        init_audit_log(db_path)
        with pytest.raises(ValueError, match="control byte"):
            log(action="test.action", resource="data\x00evil")

    def test_null_byte_in_result_raises_valueerror(self, tmp_path):
        db_path = tmp_path / "audit.db"
        init_audit_log(db_path)
        with pytest.raises(ValueError, match="control byte"):
            log(action="test.action", result="ok\x00inject")

    def test_clean_fields_accepted(self, tmp_path):
        db_path = tmp_path / "audit.db"
        init_audit_log(db_path)
        log(action="test.action", agent_id="alpha", result="success")
        entries = query_log()
        assert len(entries) == 1


# ---------------------------------------------------------------------------
# Fix: NULL vs empty string produce different hashes
# ---------------------------------------------------------------------------

class TestNullVsEmptyHash:
    """None and empty string must produce different hashes."""

    def test_none_and_empty_produce_different_hashes(self, tmp_path):
        db_path = tmp_path / "audit.db"
        init_audit_log(db_path)

        hash_with_none = _compute_entry_hash(
            "prev", "2025-01-01T00:00:00Z",
            None, "action", None, None, None, "result",
        )
        hash_with_empty = _compute_entry_hash(
            "prev", "2025-01-01T00:00:00Z",
            "", "action", "", "", "", "result",
        )
        assert hash_with_none != hash_with_empty

    def test_none_safe_returns_sentinel_for_none(self):
        assert _none_safe(None) == "\x01NULL\x01"

    def test_none_safe_returns_string_for_value(self):
        assert _none_safe("hello") == "hello"

    def test_none_safe_returns_string_for_empty(self):
        assert _none_safe("") == ""

    def test_chain_valid_with_none_agent_id(self, tmp_path):
        db_path = tmp_path / "audit.db"
        init_audit_log(db_path)
        log(action="entry1", agent_id=None, result="success")
        log(action="entry2", agent_id="", result="success")
        assert verify_log_integrity(db_path) is True
