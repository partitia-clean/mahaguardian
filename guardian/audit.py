"""
Append-only hash-chained audit log backed by SQLite.

Design guarantees:
  - No UPDATE or DELETE ever issued against the audit_log table.
  - Every entry's entry_hash chains from the previous entry's hash,
    starting from GENESIS_HASH, making any retroactive tampering
    detectable by verify_log_integrity().
  - Secret values are never written; only key paths and metadata.
  - log() never silently swallows failures — it raises a critical
    alert so the caller knows logging is broken.
"""
from __future__ import annotations

import hashlib
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from shared.config import AUDIT_DB_PATH, GENESIS_HASH

# Module-level path used by log() and query_log() whose signatures
# (per spec) carry no db_path argument.
_db_path: Optional[Path] = None


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT NOT NULL,
    agent_id       TEXT,
    action         TEXT NOT NULL,
    resource       TEXT,
    classification TEXT,
    partition_id   TEXT,
    result         TEXT NOT NULL,
    prev_hash      TEXT NOT NULL,
    entry_hash     TEXT NOT NULL
);
"""

# Revoke CREATE/ALTER/DROP at the connection level is not natively supported
# in sqlite3, but we enforce append-only by never calling UPDATE or DELETE
# anywhere in this module and by using a dedicated connection helper that
# sets the authorizer.


def _authorizer(action_code: int, *_args: object) -> int:
    """
    SQLite authorizer callback that blocks UPDATE, DELETE, DROP, and ALTER.
    Permits SELECT, INSERT, CREATE TABLE, and all other read/append ops.
    """
    _BLOCKED = {
        sqlite3.SQLITE_UPDATE,
        sqlite3.SQLITE_DELETE,
        # Python's sqlite3 module does not expose constants for DROP TABLE
        # and ALTER TABLE.  The numeric values below (11 and 26) are defined
        # in the SQLite C header (sqlite3.h) and are stable across versions.
        # If this project ever migrates to a different SQLite binding (e.g.
        # apsw), verify these constants still match the binding's definitions.
        11,  # SQLITE_DROP_TABLE
        26,  # SQLITE_ALTER_TABLE
    }
    if action_code in _BLOCKED:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _open_db(db_path: Path, *, enforce_append_only: bool = True) -> sqlite3.Connection:
    """
    Open the audit database.

    When *enforce_append_only* is True (the default for all runtime paths),
    an authorizer blocks UPDATE, DELETE, DROP TABLE, and ALTER TABLE.
    Set to False only during init_audit_log() so CREATE TABLE can run.
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    if enforce_append_only:
        conn.set_authorizer(_authorizer)
    return conn


# ---------------------------------------------------------------------------
# Hash helpers
# ---------------------------------------------------------------------------

def _validate_audit_field(value, field_name: str) -> None:
    """Reject fields containing control bytes — prevents delimiter injection."""
    if value is None:
        return
    if not isinstance(value, str):
        value = str(value)
    if "\x00" in value or "\x01" in value:
        raise ValueError(
            f"Audit field '{field_name}' contains control byte "
            f"— potential delimiter injection"
        )


def _none_safe(value) -> str:
    """
    Return a non-injectable sentinel for None so NULL != empty string in hashes.

    Uses \\x01NULL\\x01 — the \\x01 control byte is blocked by
    _validate_audit_field(), so this sentinel cannot be injected by an
    attacker.  Changed from \"<NULL>\" during development — existing
    audit.db files will have incompatible hashes.
    """
    if value is None:
        return "\x01NULL\x01"
    return str(value)


def _compute_entry_hash(
    prev_hash: str,
    timestamp: str,
    agent_id: Optional[str],
    action: str,
    resource: Optional[str],
    classification: Optional[str],
    partition_id: Optional[str],
    result: str,
) -> str:
    """
    SHA-256 over the concatenation of prev_hash and all entry fields.
    None fields are represented as the sentinel "\\x01NULL\\x01" so that
    NULL and empty-string values produce different hashes.  The sentinel
    uses a control byte blocked by _validate_audit_field(), making it
    non-injectable.  Existing audit.db files from earlier development
    will have incompatible hashes.
    """
    payload = "\x00".join([
        prev_hash,
        timestamp,
        _none_safe(agent_id),
        action,
        _none_safe(resource),
        _none_safe(classification),
        _none_safe(partition_id),
        result,
    ])
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init_audit_log(db_path: Path) -> None:
    """
    Create the SQLite audit database and audit_log table.

    Sets the module-level _db_path used by log() and query_log().
    Safe to call multiple times — CREATE TABLE IF NOT EXISTS is idempotent.
    """
    global _db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    # Disable authorizer during schema setup so CREATE TABLE is permitted.
    conn = _open_db(db_path, enforce_append_only=False)
    try:
        conn.execute(_CREATE_TABLE_SQL)
        conn.commit()
    finally:
        conn.close()
    _db_path = db_path


def log(
    action: str,
    agent_id: Optional[str] = None,
    resource: Optional[str] = None,
    classification: Optional[str] = None,
    partition_id: Optional[str] = None,
    result: str = "success",
) -> None:
    """
    Append an entry to the audit log with hash chaining.

    APPEND ONLY — no UPDATE or DELETE ever issued.

    The read-last-hash + INSERT is wrapped in a BEGIN EXCLUSIVE
    transaction so that concurrent callers cannot read the same
    prev_hash and break the chain.

    Raises RuntimeError if the audit log has not been initialised
    (init_audit_log not yet called) or if the INSERT fails.
    Never silently swallows errors.
    """
    if _db_path is None:
        raise RuntimeError(
            "Audit log not initialised. Call init_audit_log() first."
        )

    _validate_audit_field(agent_id, "agent_id")
    _validate_audit_field(action, "action")
    _validate_audit_field(resource, "resource")
    _validate_audit_field(classification, "classification")
    _validate_audit_field(partition_id, "partition_id")
    _validate_audit_field(result, "result")

    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        conn = _open_db(_db_path)
        try:
            # BEGIN EXCLUSIVE ensures only one writer at a time — prevents
            # two threads reading the same prev_hash and forking the chain.
            conn.execute("BEGIN EXCLUSIVE")
            try:
                cur = conn.execute(
                    "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1"
                )
                row = cur.fetchone()
                prev_hash = row["entry_hash"] if row else GENESIS_HASH

                entry_hash = _compute_entry_hash(
                    prev_hash, timestamp, agent_id,
                    action, resource, classification,
                    partition_id, result
                )

                conn.execute(
                    """
                    INSERT INTO audit_log
                        (timestamp, agent_id, action, resource,
                         classification, partition_id, result,
                         prev_hash, entry_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (timestamp, agent_id, action, resource,
                     classification, partition_id, result,
                     prev_hash, entry_hash),
                )
                conn.commit()
            except BaseException:
                conn.rollback()
                raise
        finally:
            conn.close()
    except Exception as exc:
        # Per spec: must never raise silently — surface as critical alert.
        print(
            f"CRITICAL: audit log write failed: {exc}",
            file=sys.stderr,
        )
        raise RuntimeError(f"Audit log write failed: {exc}") from exc


def verify_log_integrity(db_path: Path) -> bool:
    """
    Walk all log entries in insertion order and recompute each
    entry_hash, verifying the chain from GENESIS is unbroken.

    Returns True if intact, False if any entry has been tampered with.
    """
    conn = _open_db(db_path)
    try:
        cur = conn.execute(
            """
            SELECT id, timestamp, agent_id, action, resource,
                   classification, partition_id, result,
                   prev_hash, entry_hash
            FROM audit_log
            ORDER BY id ASC
            """
        )
        rows = cur.fetchall()
    finally:
        conn.close()

    expected_prev = GENESIS_HASH
    for row in rows:
        if row["prev_hash"] != expected_prev:
            return False

        recomputed = _compute_entry_hash(
            row["prev_hash"],
            row["timestamp"],
            row["agent_id"],
            row["action"],
            row["resource"],
            row["classification"],
            row["partition_id"],
            row["result"],
        )
        if recomputed != row["entry_hash"]:
            return False

        expected_prev = row["entry_hash"]

    return True


def query_log(
    agent_id: Optional[str] = None,
    action: Optional[str] = None,
    partition_id: Optional[str] = None,
    from_timestamp: Optional[str] = None,
    to_timestamp: Optional[str] = None,
) -> list[dict]:
    """
    Read-only query of the audit log.

    All parameters are optional filters; omitting them returns all entries.
    Returns a list of dicts matching the AuditEntry shape.
    """
    if _db_path is None:
        raise RuntimeError(
            "Audit log not initialised. Call init_audit_log() first."
        )

    clauses: list[str] = []
    params: list[object] = []

    if agent_id is not None:
        clauses.append("agent_id = ?")
        params.append(agent_id)
    if action is not None:
        clauses.append("action = ?")
        params.append(action)
    if partition_id is not None:
        clauses.append("partition_id = ?")
        params.append(partition_id)
    if from_timestamp is not None:
        clauses.append("timestamp >= ?")
        params.append(from_timestamp)
    if to_timestamp is not None:
        clauses.append("timestamp <= ?")
        params.append(to_timestamp)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"""
        SELECT id, timestamp, agent_id, action, resource,
               classification, partition_id, result,
               prev_hash, entry_hash
        FROM audit_log
        {where}
        ORDER BY id ASC
    """

    conn = _open_db(_db_path)
    try:
        cur = conn.execute(sql, params)
        rows = cur.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()
