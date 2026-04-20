"""
Phase 3 AccessToken schema and verification.

This module is SEPARATE from guardian/tokens.py (which handles
the Phase 1/2 GuardianAccessToken). shared/token.py introduces
the richer Phase 3 schema that adds:
  - partitions[]          — explicit partition scope
  - tlp_level             — TlpLevel enum
  - cert_fingerprint      — "sha256:<hex of DER cert>"
  - nonce                 — per-token random nonce
  - issuer                — signing authority identifier
  - operations[]          — explicit method allowlist

Revocation store:
  - In-memory dict.
  - Persisted on every mutation (caller supplies persist callback).
  - Checked on EVERY request (no caching).

Request deduplication:
  - Tracks request_id for 60 seconds.
  - Rejects duplicate request_id within the window.
  - Prunes expired entries every 60 seconds.
"""
from __future__ import annotations

import base64
import hashlib
import json
import threading
import time
import unicodedata
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import nacl.encoding
import nacl.exceptions
import nacl.signing

from shared.types import TlpLevel


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class TokenVerifyError(Exception):
    """Base for all token verification failures."""


class TokenExpiredError(TokenVerifyError):
    """Token has passed its expires_at timestamp."""


class TokenRevokedError(TokenVerifyError):
    """Token or its issuing agent has been revoked."""


class TokenSignatureError(TokenVerifyError):
    """Ed25519 signature verification failed."""


class TokenBindingError(TokenVerifyError):
    """cert_fingerprint or agent_id does not match the presenting certificate."""


class DuplicateRequestError(TokenVerifyError):
    """request_id seen within the 60-second deduplication window."""


# ---------------------------------------------------------------------------
# AccessToken dataclass (plain dict-backed; no Pydantic to keep it lean)
# ---------------------------------------------------------------------------

class AccessToken:
    """
    Phase 3 access token.

    Fields:
      token_id          — UUID4
      agent_id          — alphanumeric/hyphens/underscores
      partitions        — list of partition IDs this token covers
      tlp_level         — TlpLevel enum value
      operations        — list of allowed method strings
      cert_fingerprint  — "sha256:<lowercase hex of DER cert>"
      issued_at         — ISO 8601 UTC
      expires_at        — ISO 8601 UTC
      nonce             — random hex string (per-issuance)
      issuer            — signing authority identifier
      signature         — base64url ed25519 over canonical payload
    """

    __slots__ = (
        "token_id", "agent_id", "partitions", "tlp_level",
        "operations", "cert_fingerprint", "issued_at", "expires_at",
        "nonce", "issuer", "signature",
    )

    def __init__(
        self,
        token_id: str,
        agent_id: str,
        partitions: list[str],
        tlp_level: TlpLevel,
        operations: list[str],
        cert_fingerprint: str,
        issued_at: str,
        expires_at: str,
        nonce: str,
        issuer: str,
        signature: str,
    ) -> None:
        self.token_id         = token_id
        self.agent_id         = agent_id
        self.partitions       = partitions
        self.tlp_level        = tlp_level
        self.operations       = operations
        self.cert_fingerprint = cert_fingerprint
        self.issued_at        = issued_at
        self.expires_at       = expires_at
        self.nonce            = nonce
        self.issuer           = issuer
        self.signature        = signature

    def to_dict(self) -> dict:
        return {
            "token_id":         self.token_id,
            "agent_id":         self.agent_id,
            "partitions":       self.partitions,
            "tlp_level":        self.tlp_level.value if isinstance(self.tlp_level, TlpLevel)
                                else str(self.tlp_level),
            "operations":       self.operations,
            "cert_fingerprint": self.cert_fingerprint,
            "issued_at":        self.issued_at,
            "expires_at":       self.expires_at,
            "nonce":            self.nonce,
            "issuer":           self.issuer,
            "signature":        self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "AccessToken":
        return cls(
            token_id         = d["token_id"],
            agent_id         = d["agent_id"],
            partitions       = d["partitions"],
            tlp_level        = TlpLevel(d["tlp_level"]),
            operations       = d["operations"],
            cert_fingerprint = d["cert_fingerprint"],
            issued_at        = d["issued_at"],
            expires_at       = d["expires_at"],
            nonce            = d["nonce"],
            issuer           = d["issuer"],
            signature        = d["signature"],
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Fingerprint helpers
# ---------------------------------------------------------------------------

def cert_fingerprint(der_bytes: bytes) -> str:
    """Return 'sha256:<lowercase hex>' of the DER-encoded certificate."""
    return "sha256:" + hashlib.sha256(der_bytes).hexdigest()


def _canonical_payload(token: AccessToken) -> bytes:
    """Canonical JSON of the token without the signature field."""
    d = token.to_dict()
    d.pop("signature", None)
    return json.dumps(d, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# Revocation store
# ---------------------------------------------------------------------------

class RevocationStore:
    """
    In-memory revocation store for token_id and agent_id.

    Persist callback: called with the current revocation dict after
    every mutation so callers can write it to the vault.

    Checked on EVERY verification call — no caching.
    """

    def __init__(
        self, persist_callback: Optional[Any] = None
    ) -> None:
        self._revoked_tokens: dict[str, str] = {}   # token_id → revoked_at
        self._revoked_agents: dict[str, str] = {}   # agent_id → revoked_at
        self._lock = threading.RLock()              # reentrant: revoke → _notify → snapshot
        self._persist = persist_callback

    def revoke_token(self, token_id: str) -> None:
        with self._lock:
            self._revoked_tokens[token_id] = datetime.now(timezone.utc).isoformat()
            self._notify()

    def revoke_agent(self, agent_id: str) -> None:
        with self._lock:
            self._revoked_agents[agent_id] = datetime.now(timezone.utc).isoformat()
            self._notify()

    def is_revoked(self, token_id: str, agent_id: str) -> bool:
        with self._lock:
            return (token_id in self._revoked_tokens
                    or agent_id in self._revoked_agents)

    def load(self, state: dict) -> None:
        """Restore from a previously persisted dict."""
        with self._lock:
            self._revoked_tokens = dict(state.get("revoked_tokens", {}))
            self._revoked_agents = dict(state.get("revoked_agents", {}))

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "revoked_tokens": dict(self._revoked_tokens),
                "revoked_agents": dict(self._revoked_agents),
            }

    def _notify(self) -> None:
        if self._persist:
            self._persist(self.snapshot())


# ---------------------------------------------------------------------------
# Request deduplication
# ---------------------------------------------------------------------------

_DEDUP_WINDOW_SECONDS = 60


class RequestDeduplicator:
    """
    Tracks request_id values for 60 seconds.
    Rejects any duplicate within the window.
    Prunes expired entries every 60 seconds.
    """

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}   # request_id → expiry (monotonic)
        self._lock = threading.Lock()
        self._last_prune = time.monotonic()

    def check_and_register(self, request_id: str) -> None:
        """
        Raise DuplicateRequestError if request_id was seen within the window.
        Otherwise register it.
        """
        now = time.monotonic()
        with self._lock:
            self._maybe_prune(now)
            # FIX F8: check expiry explicitly so boundary behaviour is deterministic
            # regardless of when _maybe_prune last ran.
            if request_id in self._seen and self._seen[request_id] > now:
                raise DuplicateRequestError(
                    f"Duplicate request_id '{request_id}' within "
                    f"{_DEDUP_WINDOW_SECONDS}s window."
                )
            self._seen[request_id] = now + _DEDUP_WINDOW_SECONDS

    def _maybe_prune(self, now: float) -> None:
        if now - self._last_prune >= _DEDUP_WINDOW_SECONDS:
            self._seen = {k: v for k, v in self._seen.items() if v > now}
            self._last_prune = now


# ---------------------------------------------------------------------------
# Token issuance
# ---------------------------------------------------------------------------

def issue_token(
    *,
    agent_id: str,
    partitions: list[str],
    tlp_level: TlpLevel,
    operations: list[str],
    agent_der_cert: bytes,
    issued_at: str,
    expires_at: str,
    issuer: str,
    signing_key_bytes: bytes,
) -> AccessToken:
    """
    Issue a signed Phase 3 AccessToken.

    signing_key_bytes: 32-byte ed25519 private key (PyNaCl format).
    cert_fingerprint is computed as 'sha256:<hex of DER cert>'.
    """
    token_id = str(uuid.uuid4())
    nonce    = uuid.uuid4().hex
    fp       = cert_fingerprint(agent_der_cert)

    token = AccessToken(
        token_id         = token_id,
        agent_id         = agent_id,
        partitions       = partitions,
        tlp_level        = tlp_level,
        operations       = operations,
        cert_fingerprint = fp,
        issued_at        = issued_at,
        expires_at       = expires_at,
        nonce            = nonce,
        issuer           = issuer,
        signature        = "",   # placeholder before signing
    )

    signing_key = nacl.signing.SigningKey(signing_key_bytes)
    payload = _canonical_payload(token)
    signed  = signing_key.sign(payload)
    token.signature = base64.b64encode(signed.signature).decode("ascii")
    return token


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_token_binding(
    token: AccessToken,
    peer_der_cert: bytes,
    revocation_store: RevocationStore,
    verify_key_bytes: bytes,
    *,
    request_id: Optional[str] = None,
    deduplicator: Optional[RequestDeduplicator] = None,
) -> None:
    """
    Verify all binding properties of the token against the presenting cert.

    Steps (in order):
      1. Ed25519 signature verification.
      2. Expiry check (ISO comparison against UTC now).
      3. Revocation check (token_id and agent_id).
      4. cert_fingerprint match: sha256(peer_der_cert) == token.cert_fingerprint.
      5. agent_id match: token.agent_id == CN extracted from cert (not done here —
         CN extraction is handled by the mTLS layer; caller passes verified bytes).
      6. Request deduplication (if request_id and deduplicator provided).

    Raises one of the TokenVerifyError subclasses on failure.
    All failures are distinct and unambiguous (no generic errors).
    """
    # Step 1 — Ed25519 signature
    try:
        vk = nacl.signing.VerifyKey(verify_key_bytes)
        payload = _canonical_payload(token)
        sig = base64.b64decode(token.signature)
        vk.verify(payload, sig)
    except (nacl.exceptions.BadSignatureError, Exception) as exc:
        raise TokenSignatureError("Ed25519 signature verification failed.") from exc

    # Step 2 — Expiry
    try:
        expires_at = datetime.fromisoformat(token.expires_at)
    except ValueError as exc:
        raise TokenVerifyError("Invalid expires_at timestamp.") from exc
    if datetime.now(timezone.utc) >= expires_at:
        raise TokenExpiredError(
            f"Token {token.token_id} expired at {token.expires_at}."
        )

    # Step 3 — Revocation
    if revocation_store.is_revoked(token.token_id, token.agent_id):
        raise TokenRevokedError(
            f"Token {token.token_id} or agent {token.agent_id} is revoked."
        )

    # Step 4 — cert_fingerprint
    expected_fp = cert_fingerprint(peer_der_cert)
    if unicodedata.normalize("NFC", token.cert_fingerprint) != expected_fp:
        raise TokenBindingError(
            "Certificate fingerprint does not match token binding."
        )

    # Step 6 — Request deduplication
    if request_id is not None and deduplicator is not None:
        deduplicator.check_and_register(request_id)
