"""
Guardian Access Token issuing and verification.

Security guarantees:
  - ed25519 signed using PyNaCl — NOT HMAC.
  - Includes expiry timestamp — checked on every verification.
  - Includes agent cert fingerprint — verified against presenting agent.
  - Revocation list in SQLite — checked on every verification.
  - Never grants vault keys — permissions only.
  - Token signing key is separate from the SOUL signing key.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import nacl.encoding
import nacl.exceptions
import nacl.signing

import guardian.audit as audit
from shared.config import TOKEN_LIFETIME_HOURS

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TokenError(Exception):
    """Base exception for token errors."""


class TokenExpiredError(TokenError):
    """Raised when a token has expired."""


class TokenInvalidError(TokenError):
    """Raised when a token signature is invalid or token is malformed."""


class TokenAgentMismatchError(TokenError):
    """Raised when the agent cert does not match the token fingerprint."""


class TokenRevokedError(TokenError):
    """Raised when a token or its agent has been revoked."""


# ---------------------------------------------------------------------------
# Strict JSON decoder — rejects duplicate keys
# ---------------------------------------------------------------------------

class _StrictDecoder(json.JSONDecoder):
    """JSON decoder that rejects duplicate keys in objects."""

    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            object_pairs_hook=self._check_duplicates,
            **kwargs,
        )

    @staticmethod
    def _check_duplicates(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise TokenInvalidError(
                    f"Duplicate key '{k}' in token JSON"
                )
            d[k] = v
        return d


# Known fields that issue_token() produces — reject anything else
_KNOWN_TOKEN_FIELDS = {
    "token_id", "agent_id", "issued_at", "expires_at",
    "permissions", "agent_cert_fingerprint", "sig",
}


# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_signing_key: Optional[nacl.signing.SigningKey] = None
_verify_key: Optional[nacl.signing.VerifyKey] = None
_db_path: Optional[Path] = None

_REVOCATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS revoked_tokens (
    token_id   TEXT PRIMARY KEY,
    agent_id   TEXT,
    revoked_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS revoked_agents (
    agent_id   TEXT PRIMARY KEY,
    revoked_at TEXT NOT NULL
);
"""


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def generate_token_keypair() -> tuple[bytes, bytes]:
    """
    Generate an ed25519 keypair for token signing.
    Returns (private_key_bytes, public_key_bytes).
    Uses PyNaCl — not HMAC, not pycryptodome.
    """
    signing_key = nacl.signing.SigningKey.generate()
    return bytes(signing_key), bytes(signing_key.verify_key)


def init_tokens(
    signing_key_bytes: bytes,
    verify_key_bytes: bytes,
    db_path: Path,
) -> None:
    """
    Initialise the token module.

    Sets module-level signing key, verify key, and revocation DB path.
    Creates the revocation database and tables if they don't exist.
    Must be called before issue_token / verify_token / revoke_*.
    """
    global _signing_key, _verify_key, _db_path

    _signing_key = nacl.signing.SigningKey(signing_key_bytes)
    _verify_key = nacl.signing.VerifyKey(verify_key_bytes)

    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(_REVOCATION_SCHEMA)
        conn.commit()
    finally:
        conn.close()
    _db_path = db_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_AGENT_ID_RE = re.compile(r'^[a-zA-Z0-9_-]+$')


def _validate_agent_id(agent_id: str) -> None:
    """Validate agent_id contains only safe characters."""
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError(
            f"Invalid agent_id '{agent_id}': must be "
            f"alphanumeric, hyphens, or underscores only."
        )


def _cert_fingerprint(agent_cert: bytes) -> str:
    """SHA-256 fingerprint of the agent's TLS certificate bytes."""
    return "sha256:" + hashlib.sha256(agent_cert).hexdigest()


def _canonical_payload(token_dict: dict) -> bytes:
    """
    Produce a deterministic JSON representation of the token
    for signing/verification.  The 'sig' field is excluded.
    """
    d = {k: v for k, v in token_dict.items() if k != "sig"}
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _is_token_revoked(token_id: str, agent_id: str) -> bool:
    """Check both the token and agent revocation lists."""
    if _db_path is None:
        raise RuntimeError("Token module not initialised. Call init_tokens() first.")
    conn = sqlite3.connect(str(_db_path))
    try:
        cur = conn.execute(
            "SELECT 1 FROM revoked_tokens WHERE token_id = ?", (token_id,)
        )
        if cur.fetchone():
            return True
        cur = conn.execute(
            "SELECT 1 FROM revoked_agents WHERE agent_id = ?", (agent_id,)
        )
        if cur.fetchone():
            return True
        return False
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def issue_token(
    agent_id: str,
    agent_cert: bytes,
    permissions: dict,
    lifetime_hours: int = TOKEN_LIFETIME_HOURS,
) -> str:
    """
    Issue a signed Guardian Access Token.

    Sign with Guardian's ed25519 token signing key (PyNaCl).
    Include agent cert fingerprint to bind token to agent.
    Return token as signed JSON string.
    Log issuance to audit.log.
    """
    if _signing_key is None:
        raise RuntimeError("Token module not initialised. Call init_tokens() first.")

    _validate_agent_id(agent_id)

    now = datetime.now(timezone.utc)
    token_dict = {
        "token_id": str(uuid.uuid4()),
        "agent_id": agent_id,
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(hours=lifetime_hours)).isoformat(),
        "permissions": permissions,
        "agent_cert_fingerprint": _cert_fingerprint(agent_cert),
    }

    # Sign canonical payload (without sig field)
    payload = _canonical_payload(token_dict)
    signed = _signing_key.sign(payload)
    token_dict["sig"] = base64.b64encode(signed.signature).decode("ascii")

    token_str = json.dumps(token_dict, sort_keys=True, separators=(",", ":"))

    audit.log(
        action="token.issue",
        agent_id=agent_id,
        resource=token_dict["token_id"],
        result="success",
    )
    return token_str


def verify_token(token_str: str, agent_cert: bytes) -> dict:
    """
    Verify Guardian Access Token.

    Check ed25519 signature.
    Check expiry timestamp.
    Check agent cert fingerprint matches presenting agent.
    Check revocation list.

    Returns the full verified token payload dict including
    token_id, agent_id, permissions, issued_at, expires_at.
    All fields are from the cryptographically verified
    canonical JSON — safe to trust.

    Raise TokenExpiredError, TokenInvalidError,
    TokenAgentMismatchError, or TokenRevokedError as appropriate.
    Log verification result to audit.log.
    """
    if _verify_key is None or _db_path is None:
        raise RuntimeError("Token module not initialised. Call init_tokens() first.")

    # --- Parse (strict: reject duplicate keys) ---
    try:
        token_dict = json.loads(token_str, cls=_StrictDecoder)
    except TokenInvalidError:
        audit.log(action="token.verify", result="failure:duplicate_key")
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        audit.log(action="token.verify", result="failure:malformed")
        raise TokenInvalidError("Token is not valid JSON.") from exc

    # --- Reject unknown fields ---
    unknown = set(token_dict.keys()) - _KNOWN_TOKEN_FIELDS
    if unknown:
        audit.log(action="token.verify", result=f"failure:unknown_fields:{unknown}")
        raise TokenInvalidError(f"Unknown fields in token: {unknown}")

    sig_b64 = token_dict.get("sig")
    if not sig_b64:
        audit.log(action="token.verify", result="failure:missing_sig")
        raise TokenInvalidError("Token has no signature.")

    unverified_token_id = token_dict.get("token_id", "unknown")
    unverified_agent_id = token_dict.get("agent_id", "unknown")

    # --- Signature ---
    try:
        signature = base64.b64decode(sig_b64)
        payload = _canonical_payload(token_dict)
        _verify_key.verify(payload, signature)
    except (nacl.exceptions.BadSignatureError, Exception) as exc:
        audit.log(
            action="token.verify",
            agent_id=f"unverified:{unverified_agent_id}",
            resource=unverified_token_id,
            result="failure:bad_signature",
        )
        raise TokenInvalidError("Token signature verification failed.") from exc

    token_id = token_dict.get("token_id", "unknown")
    agent_id = token_dict.get("agent_id", "unknown")

    # --- Expiry ---
    try:
        expires_at = datetime.fromisoformat(token_dict["expires_at"])
    except (KeyError, ValueError) as exc:
        audit.log(
            action="token.verify",
            agent_id=agent_id,
            resource=token_id,
            result="failure:bad_expiry",
        )
        raise TokenInvalidError("Token has invalid expiry timestamp.") from exc

    if datetime.now(timezone.utc) >= expires_at:
        audit.log(
            action="token.verify",
            agent_id=agent_id,
            resource=token_id,
            result="failure:expired",
        )
        raise TokenExpiredError(
            f"Token {token_id} expired at {expires_at.isoformat()}."
        )

    # --- Agent cert fingerprint ---
    expected_fp = _cert_fingerprint(agent_cert)
    actual_fp = token_dict.get("agent_cert_fingerprint", "")
    if expected_fp != actual_fp:
        audit.log(
            action="token.verify",
            agent_id=agent_id,
            resource=token_id,
            result="failure:agent_mismatch",
        )
        raise TokenAgentMismatchError(
            "Agent certificate does not match token fingerprint."
        )

    # --- Revocation ---
    if _is_token_revoked(token_id, agent_id):
        audit.log(
            action="token.verify",
            agent_id=agent_id,
            resource=token_id,
            result="failure:revoked",
        )
        raise TokenRevokedError(f"Token {token_id} or agent {agent_id} is revoked.")

    audit.log(
        action="token.verify",
        agent_id=agent_id,
        resource=token_id,
        result="success",
    )
    return {
        "token_id": token_dict["token_id"],
        "agent_id": token_dict["agent_id"],
        "permissions": token_dict["permissions"],
        "issued_at": token_dict["issued_at"],
        "expires_at": token_dict["expires_at"],
    }


def revoke_all_tokens(agent_id: str) -> None:
    """
    Add agent_id to revocation list in SQLite.
    All subsequent verify_token calls for this agent fail.
    Log revocation to audit.log.
    """
    if _db_path is None:
        raise RuntimeError("Token module not initialised. Call init_tokens() first.")

    conn = sqlite3.connect(str(_db_path))
    try:
        conn.execute(
            "INSERT OR REPLACE INTO revoked_agents (agent_id, revoked_at) VALUES (?, ?)",
            (agent_id, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()

    audit.log(
        action="token.revoke_all",
        agent_id=agent_id,
        result="success",
    )


def revoke_token(token_id: str, agent_id: str = "") -> None:
    """
    Revoke specific token by ID.
    Add to revocation list in SQLite.
    Log to audit.log.
    """
    if _db_path is None:
        raise RuntimeError("Token module not initialised. Call init_tokens() first.")

    conn = sqlite3.connect(str(_db_path))
    try:
        conn.execute(
            "INSERT OR REPLACE INTO revoked_tokens (token_id, agent_id, revoked_at) "
            "VALUES (?, ?, ?)",
            (token_id, agent_id, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
    finally:
        conn.close()

    audit.log(
        action="token.revoke",
        resource=token_id,
        result="success",
    )
