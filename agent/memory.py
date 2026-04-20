"""
MEMORY.db management for agent on droplet.
SQLite database for agent conversation memory.
Encrypted at rest in production (Phase 2).
"""
from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import Optional

_db_path: Optional[Path] = None

_SCHEMA = """
CREATE TABLE IF NOT EXISTS memory (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    role      TEXT NOT NULL,
    content   TEXT NOT NULL,
    session_id TEXT
);
"""

def init_memory(db_path: Path) -> None:
    global _db_path
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.execute(_SCHEMA)
        conn.commit()
    finally:
        conn.close()
    _db_path = db_path

def store_message(role: str, content: str, session_id: str = "", timestamp: str = "") -> None:
    if _db_path is None:
        raise RuntimeError("Memory not initialised.")
    from datetime import datetime, timezone
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()
    conn = sqlite3.connect(str(_db_path))
    try:
        conn.execute(
            "INSERT INTO memory (timestamp, role, content, session_id) VALUES (?, ?, ?, ?)",
            (timestamp, role, content, session_id),
        )
        conn.commit()
    finally:
        conn.close()

def get_history(session_id: str = "", limit: int = 50) -> list[dict]:
    if _db_path is None:
        raise RuntimeError("Memory not initialised.")
    conn = sqlite3.connect(str(_db_path))
    conn.row_factory = sqlite3.Row
    try:
        if session_id:
            cur = conn.execute(
                "SELECT * FROM memory WHERE session_id = ? ORDER BY id DESC LIMIT ?",
                (session_id, limit),
            )
        else:
            cur = conn.execute("SELECT * FROM memory ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

def clear_memory() -> None:
    if _db_path is None:
        raise RuntimeError("Memory not initialised.")
    conn = sqlite3.connect(str(_db_path))
    try:
        conn.execute("DELETE FROM memory")
        conn.commit()
    finally:
        conn.close()
