"""
Cryptographic audit chain for Phase 3 enforcement decisions.

Design:
  - Each entry covers: entry_id, timestamp, agent_id, partition_id,
    method, params_hash, decision, reason_code, previous_hash.
  - params_hash: RFC 8785 canonical JSON (sort_keys=True, no spaces).
  - Fields encoded with 4-byte big-endian length prefix + UTF-8 bytes
    in fixed order (length-prefix encoding, NOT null-byte delimiters).
  - All string fields NFC-normalised before hashing.
  - SHA-256 throughout.
  - Genesis hash: sha256(b"mahaguardian_genesis_v1").
  - DENY entries are logged with exactly the same fields as ALLOW.
  - Backed by SQLite; append-only authorizer blocks UPDATE/DELETE/DROP.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Local imports
from shared.types import Decision
from shared.utils import format_hash  # F-08: canonical sha256:<hex> formatting

# ---------------------------------------------------------------------------
# Genesis
# FIX 9: prefix all hash outputs with "sha256:" so bare hex is never confused
# with a keyed digest.
# ---------------------------------------------------------------------------

GENESIS_HASH: str = format_hash(b"mahaguardian_genesis_v1")  # F-08: via canonical format_hash()

# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS audit_chain (
    entry_id     TEXT PRIMARY KEY,
    timestamp    TEXT NOT NULL,
    agent_id     TEXT NOT NULL,
    partition_id TEXT NOT NULL,
    method       TEXT NOT NULL,
    params_hash  TEXT NOT NULL,
    decision     TEXT NOT NULL,
    reason_code  TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    entry_hash   TEXT NOT NULL
);
"""

_BLOCKED = {
    sqlite3.SQLITE_UPDATE,
    sqlite3.SQLITE_DELETE,
    11,   # SQLITE_DROP_TABLE
    26,   # SQLITE_ALTER_TABLE
}


def _authorizer(action_code: int, *_: object) -> int:
    return sqlite3.SQLITE_DENY if action_code in _BLOCKED else sqlite3.SQLITE_OK


def _open(db_path: Path, *, init: bool = False) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    if not init:
        conn.set_authorizer(_authorizer)
    return conn


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _nfc(s: str) -> str:
    """NFC-normalise a string."""
    return unicodedata.normalize("NFC", s)


def _params_hash(params: Any) -> str:
    """
    RFC 8785 canonical JSON hash of params.
    Uses sort_keys=True and no-space separators — the closest
    pure-Python approximation of RFC 8785 for dict structures.
    FIX 9: returns "sha256:<hex>" prefix.
    """
    canonical = json.dumps(params, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    return format_hash(_nfc(canonical).encode("utf-8"))  # F-08: via canonical format_hash()


def _compute_hash(
    entry_id: str,
    timestamp: str,
    agent_id: str,
    partition_id: str,
    method: str,
    params_hash: str,
    decision: str,
    reason_code: str,
    previous_hash: str,
    *,
    hmac_key: bytes,
) -> str:
    """
    HMAC-SHA-256 over NFC-normalised fields encoded with length-prefixed
    binary encoding in the fixed canonical order defined in the spec.

    FIX 4: keyed with hmac_key so tampered entries cannot be re-hashed
           without knowledge of the secret key.
    FIX 9: returns "sha256:<hex>" prefix.
    FIX F2: length-prefixed encoding (4-byte big-endian length + UTF-8 bytes)
            replaces null-byte delimiters to prevent null-byte injection attacks.
    """
    fields = [
        _nfc(entry_id),
        _nfc(timestamp),
        _nfc(agent_id),
        _nfc(partition_id),
        _nfc(method),
        _nfc(params_hash),
        _nfc(decision),
        _nfc(reason_code),
        _nfc(previous_hash),
    ]
    parts = []
    for f in fields:
        encoded = f.encode("utf-8")
        parts.append(len(encoded).to_bytes(4, "big") + encoded)
    payload = b"".join(parts)
    digest = hmac.new(hmac_key, payload, "sha256").hexdigest()
    return "sha256:" + digest


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class AuditChain:
    """
    Append-only audit chain instance backed by a SQLite file.

    FIX 4: hmac_key is required. Loaded from the encrypted vault at
    Guardian startup (generate and store in vault if absent). All entry
    hashes are HMAC-SHA-256 so that filesystem access alone cannot
    allow history rewriting.

    Usage:
        chain = AuditChain(db_path, hmac_key=key_bytes)
        chain.append(agent_id="alpha", partition_id="company-a",
                     method="vault.read", params={"key": "client_count"},
                     decision=Decision.ALLOW, reason_code="tlp_allow")
    """

    def __init__(self, db_path: Path, *, hmac_key: bytes) -> None:
        self._db_path = db_path
        self._hmac_key = hmac_key
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = _open(db_path, init=True)
        try:
            conn.execute(_DDL)
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def append(
        self,
        *,
        agent_id: str,
        partition_id: str,
        method: str,
        params: Any,
        decision: Decision,
        reason_code: str,
        entry_id: Optional[str] = None,
    ) -> str:
        """
        Append one entry to the chain.

        DENY and ALLOW entries are logged with identical fidelity.
        Returns the entry_id of the appended record.
        """
        entry_id = entry_id or str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()
        ph = _params_hash(params)
        decision_str = decision.value if isinstance(decision, Decision) else str(decision)

        conn = _open(self._db_path)
        try:
            conn.execute("BEGIN EXCLUSIVE")
            cur = conn.execute(
                "SELECT entry_hash FROM audit_chain ORDER BY rowid DESC LIMIT 1"
            )
            row = cur.fetchone()
            prev_hash = row["entry_hash"] if row else GENESIS_HASH

            entry_hash = _compute_hash(
                entry_id, timestamp, agent_id, partition_id,
                method, ph, decision_str, reason_code, prev_hash,
                hmac_key=self._hmac_key,
            )

            conn.execute(
                """
                INSERT INTO audit_chain
                    (entry_id, timestamp, agent_id, partition_id,
                     method, params_hash, decision, reason_code,
                     prev_hash, entry_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (entry_id, timestamp, agent_id, partition_id,
                 method, ph, decision_str, reason_code,
                 prev_hash, entry_hash),
            )
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

        return entry_id

    # ------------------------------------------------------------------
    # Read / verify
    # ------------------------------------------------------------------

    def verify(self) -> bool:
        """
        Walk all entries in insertion order and recompute each entry_hash.
        Returns True if the chain is intact, False if any entry is tampered.
        """
        conn = _open(self._db_path)
        try:
            rows = conn.execute(
                """
                SELECT entry_id, timestamp, agent_id, partition_id,
                       method, params_hash, decision, reason_code,
                       prev_hash, entry_hash
                FROM audit_chain ORDER BY rowid ASC
                """
            ).fetchall()
        finally:
            conn.close()

        expected_prev = GENESIS_HASH
        for row in rows:
            # FIX F10: reject entries whose stored hash lacks the "sha256:" prefix
            if not row["entry_hash"].startswith("sha256:"):
                return False
            if row["prev_hash"] != expected_prev:
                return False
            recomputed = _compute_hash(
                row["entry_id"], row["timestamp"], row["agent_id"],
                row["partition_id"], row["method"], row["params_hash"],
                row["decision"], row["reason_code"], row["prev_hash"],
                hmac_key=self._hmac_key,
            )
            if recomputed != row["entry_hash"]:
                return False
            expected_prev = row["entry_hash"]

        return True

    def entries(self) -> list[dict]:
        """Return all entries as dicts, ordered by insertion."""
        conn = _open(self._db_path)
        try:
            rows = conn.execute(
                "SELECT * FROM audit_chain ORDER BY rowid ASC"
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
