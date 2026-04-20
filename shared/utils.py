"""Shared utility helpers — canonical formats for hashes and timestamps."""
from __future__ import annotations
import hashlib
import re
from datetime import datetime, timezone


_HASH_RE = re.compile(r'^sha256:[a-f0-9]{64}$')
_TS_RE   = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|\+\d{2}:\d{2})$')


def format_hash(digest: bytes) -> str:
    """Return SHA-256 hash in canonical 'sha256:<lowercase_hex>' format."""
    return "sha256:" + hashlib.sha256(digest).hexdigest()


def utc_now() -> str:
    """Return current UTC time as ISO 8601 string with +00:00 suffix."""
    return datetime.now(timezone.utc).isoformat()


def is_valid_hash_format(s: str) -> bool:
    """Return True if s matches sha256:<64 hex chars>."""
    return bool(_HASH_RE.match(s))


def is_valid_timestamp(s: str) -> bool:
    """Return True if s is an ISO 8601 UTC timestamp."""
    return bool(_TS_RE.match(s))
