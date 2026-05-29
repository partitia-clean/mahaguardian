"""
Partition access enforcer — the information barrier choke point.

Phase 3 additions:
  - Partition-resolving: Guardian resolves the partition from the data key.
    Agents NEVER supply a partition name in their requests.
  - Anti-probing: "key not found" returns the SAME error format and
    code as "access denied". An attacker cannot distinguish whether a
    key exists outside their partition from a key that does not exist.
  - Anti-confused-deputy scanner: scans application params (NOT token,
    NOT signature) recursively up to depth 10, checking for partition
    names in direct, URL-encoded, and unicode-escaped forms.
  - TLP matrix enforcement via shared/tlp_matrix.py.
  - When an audit_chain is provided, DENY decisions log to both
    guardian/audit.py and guardian/audit_chain.py with matching semantics.

All enforcement MUST go through enforce() or resolve_and_enforce().
"""
# NOTE: Legacy Phase 1/2 functions removed per security review SM-001/SM-005.
# All enforcement MUST go through enforce() or resolve_and_enforce().  # FIX: SM-001/SM-005
from __future__ import annotations

import asyncio
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Optional

# Local imports
import guardian.audit as audit
from guardian.shared.encoding import decode_variants  # FIX: SM-004
from shared.data_item import DataItem
from shared.tlp_matrix import check_tlp
from shared.types import Decision, TlpLevel
import shared.token as _shared_token  # F-10: module-level import (use shared.token.X so patches work)


__all__ = [
    # Public enforcement API
    "resolve_and_enforce",
    "enforce",
    "scan_params",
    "VaultRequest",
    # Public exception types
    "EnforcementDenied",
    "AmbiguousKeyError",
    "ConfusedDeputyError",
    "ElevateTimeoutError",
]

# ---------------------------------------------------------------------------
# Phase 3: Errors
# ---------------------------------------------------------------------------

class EnforcementDenied(Exception):
    """
    Raised when any enforcement check rejects the request.

    The message is always "access_denied" — callers must not leak
    reason codes, partition names, classification levels, or TLP
    labels in responses sent to agents.
    """
    def __init__(self, reason_code: str, *, safe_message: str = "access_denied") -> None:
        self.reason_code  = reason_code   # internal audit use only
        self.safe_message = safe_message  # what the agent sees
        super().__init__(reason_code)


class AmbiguousKeyError(EnforcementDenied):
    """Key exists in more than one of the agent's authorized partitions."""
    def __init__(self) -> None:
        super().__init__(
            "ambiguous_key",           # internal reason (for logs only)
            safe_message="access_denied"  # FIX SM-003: uniform error to agent
        )


class ConfusedDeputyError(EnforcementDenied):
    """Partition name detected in application params — possible injection."""
    def __init__(self) -> None:
        super().__init__("confused_deputy_detected", safe_message="access_denied")


class ElevateTimeoutError(EnforcementDenied):
    """Human approval was required but timed out — fail closed."""
    def __init__(self) -> None:
        super().__init__("elevate_timeout", safe_message="access_denied")


# ---------------------------------------------------------------------------
# Phase 3: Item resolution
# ---------------------------------------------------------------------------

def _find_items_no_tlp_check(
    key: str,
    token_partitions: list[str],
    vault_items: dict[str, DataItem],
) -> list[DataItem]:
    """
    Search for *key* across *token_partitions* in the vault item store.

    PRIVATE — callers outside this module must use enforce() or
    resolve_and_enforce(), which apply the full TLP + partition pipeline.
    Using this function directly bypasses TLP enforcement.

    Returns a list of matching DataItems.
    - Empty list  → key not found (caller must treat as access_denied).
    - Length > 1  → ambiguous key (same item_id in multiple partitions).
    - Length == 1 → unique match; caller still must verify
                    item.owner_partition is in token_partitions.
    """
    results: list[DataItem] = []
    for item in vault_items.values():
        if item.item_id == key and item.owner_partition in token_partitions:
            results.append(item)
    return results


# ---------------------------------------------------------------------------
# Phase 3: Confused-deputy scanner
# ---------------------------------------------------------------------------

_MAX_SCAN_DEPTH = 20  # FIX F5: increased from 10; exceeding this REJECTS (not silently passes)
_ELEVATE_TIMEOUT_SECONDS = 300  # FIX 6: fail closed if human approval hangs
_MIN_RESPONSE_TIME = 0.05  # FIX F7/FIX 3: 50ms floor applied to all enforcement paths


def _nfc(s: str) -> str:
    return unicodedata.normalize("NFC", s)


def _matches_partition(value: str, partition_name: str) -> bool:
    """
    True if *value* — in any of the checked forms — equals *partition_name*.

    Checked forms:
      1. Exact (NFC-normalised)
      2. URL-decoded (urllib.parse.unquote)
      3. URL-decoded then NFC-normalised
    """
    p = _nfc(partition_name)
    v_nfc      = _nfc(value)
    v_urldec   = urllib.parse.unquote(value)
    v_url_nfc  = _nfc(v_urldec)
    return v_nfc == p or v_urldec == p or v_url_nfc == p


def scan_params(
    params: object,
    known_partitions: list[str],
    *,
    depth: int = 0,
    max_depth: int = _MAX_SCAN_DEPTH,
) -> None:
    """
    Recursively scan *params* for partition names.

    Raises ConfusedDeputyError immediately on first match.

    Rules:
      - Only application params — NEVER pass the token or signature here.
      - Recursive; stops at max_depth=10 to prevent DoS via deeply nested input.
      - Checks string values (not keys) for direct, URL-encoded, and
        NFC-normalised variants of every known partition name.
    """
    if depth > max_depth:
        # FIX F5: reject (not silently pass) when nesting exceeds max depth
        raise ConfusedDeputyError()

    if isinstance(params, str):
        # FIX 1: substring containment with casefold — catches embedded partition
        # names like "access company_b_commercial now", not just exact matches.
        value_variants = decode_variants(params)
        for pname in known_partitions:
            pname_variants = decode_variants(pname)
            for vv in value_variants:
                vv_folded = vv.casefold()
                for pv in pname_variants:
                    if pv and pv.casefold() in vv_folded:
                        raise ConfusedDeputyError()

    elif isinstance(params, dict):
        for k, v in params.items():
            # FIX SM-006: scan keys too, not just values
            scan_params(k, known_partitions, depth=depth + 1, max_depth=max_depth)
            scan_params(v, known_partitions, depth=depth + 1, max_depth=max_depth)

    elif isinstance(params, (int, float, bool)):
        # FIX 4: numeric → string conversion is not a depth increment;
        # delegate at the SAME depth so the full decode_variants pipeline runs.
        scan_params(str(params), known_partitions, depth=depth, max_depth=max_depth)

    elif isinstance(params, (list, tuple, set, frozenset)):
        for item in params:
            scan_params(item, known_partitions, depth=depth + 1, max_depth=max_depth)

    else:
        # FIX F5: unknown type — convert to string and scan that
        scan_params(str(params), known_partitions, depth=depth + 1, max_depth=max_depth)


# ---------------------------------------------------------------------------
# Phase 3: TLP + partition enforcement (core logic, sync)
# ---------------------------------------------------------------------------

def resolve_and_enforce(
    key: str,
    token_partitions: list[str],
    tlp_level: object,           # TlpLevel enum
    params: dict,
    vault_items: dict[str, DataItem],
    agent_id: str,
    *,
    known_partitions: list[str],
    audit_chain: Optional[object] = None,
) -> DataItem:
    """
    Resolve which DataItem *key* refers to, then enforce TLP.

    Args:
        key               — the data key from the agent request
        token_partitions  — partitions the agent token is scoped to
        tlp_level         — TlpLevel from the agent token
        params            — raw application params (for confused-deputy scan)
        vault_items       — dict[item_id -> DataItem] for ALL partitions
        agent_id          — for audit logging only
        known_partitions  — REQUIRED. ALL partition IDs in the system
                            (for confused-deputy scan). Must be derived from
                            the enrollment config, NOT from vault_items keys,
                            so that partitions with zero vault items are also
                            scanned. MUST include partitions beyond
                            token_partitions — a confused-deputy attack uses
                            unauthorized partition names that would never
                            appear in token_partitions.

    Returns the DataItem if all checks pass.

    Raises:
        ConfusedDeputyError   — partition name detected in params
        EnforcementDenied     — not found OR partition check OR TLP deny
                                (not-found returns same error as denied
                                 to prevent probing attacks)
        AmbiguousKeyError     — key matches items in more than one partition
        ElevateTimeoutError   — ELEVATE decision and approval timed out

    DENY messages are always "access_denied" — never contain partition
    names, classification levels, TLP labels, or existence hints.
    """
    # FIX F7: capture start time for timing normalisation
    _start = time.monotonic()
    try:
        return _resolve_and_enforce_inner(
            key, token_partitions, tlp_level, params, vault_items, agent_id,
            known_partitions=known_partitions,
            audit_chain=audit_chain,
        )
    finally:
        elapsed = time.monotonic() - _start
        if elapsed < _MIN_RESPONSE_TIME:
            time.sleep(_MIN_RESPONSE_TIME - elapsed)


def _resolve_and_enforce_inner(
    key: str,
    token_partitions: list[str],
    tlp_level: object,
    params: dict,
    vault_items: dict[str, DataItem],
    agent_id: str,
    *,
    known_partitions: list[str],
    audit_chain: Optional[object] = None,
) -> DataItem:
    """Inner implementation of resolve_and_enforce (without timing wrapper)."""
    # F-01: known_partitions is required — no vault-derived fallback.
    # The caller must supply the full system partition list from enrollment
    # config so that zero-item partitions are also scanned.
    if not known_partitions:
        raise ValueError(
            "known_partitions must be a non-empty list of all system partition IDs. "
            "Derive it from enrollment config, not from vault_items keys."
        )
    # Step: scan params before touching vault data
    scan_params(params, known_partitions)

    # Step: find items (anti-probing: not-found == denied)
    items = _find_items_no_tlp_check(key, token_partitions, vault_items)

    if len(items) == 0:
        # SAME error as access_denied — agent cannot distinguish
        audit.log(
            action="vault.read",
            agent_id=agent_id,
            result="denied:access_denied",
        )
        if audit_chain is not None:
            audit_chain.append(
                agent_id=agent_id, partition_id="",
                method="vault.read", params=params,
                decision=Decision.DENY, reason_code="not_found",
            )
        raise EnforcementDenied("not_found")  # reason_code internal; safe_message="access_denied"

    if len(items) > 1:
        audit.log(
            action="vault.read",
            agent_id=agent_id,
            result="denied:ambiguous_key",
        )
        if audit_chain is not None:
            audit_chain.append(
                agent_id=agent_id, partition_id="",
                method="vault.read", params=params,
                decision=Decision.DENY, reason_code="ambiguous_key",
            )
        raise AmbiguousKeyError()

    item = items[0]

    # Partition check (belt-and-suspenders after find_items)
    if item.owner_partition not in token_partitions:
        audit.log(
            action="vault.read",
            agent_id=agent_id,
            result="denied:access_denied",
        )
        if audit_chain is not None:
            audit_chain.append(
                agent_id=agent_id, partition_id="[redacted]",
                method="vault.read", params=params,
                decision=Decision.DENY, reason_code="partition_unauthorized",
            )
        raise EnforcementDenied("partition_unauthorized")

    # TLP matrix
    tlp = tlp_level if isinstance(tlp_level, TlpLevel) else TlpLevel(str(tlp_level))
    decision = check_tlp(tlp, item.classification)

    if decision == Decision.DENY:
        # FIX F3: redact partition name from TLP denial entries
        audit.log(
            action="vault.read",
            agent_id=agent_id,
            partition_id="[redacted]",
            result="denied:tlp_insufficient",
        )
        if audit_chain is not None:
            audit_chain.append(
                agent_id=agent_id, partition_id="[redacted]",
                method="vault.read", params=params,
                decision=Decision.DENY, reason_code="tlp_insufficient",
            )
        raise EnforcementDenied("tlp_insufficient")

    if decision == Decision.ELEVATE:
        # Synchronous path: raises ElevateTimeoutError.
        # The async 8-step enforce() overrides this with await.
        # FIX F3: redact partition name from ELEVATE entries
        audit.log(
            action="vault.read",
            agent_id=agent_id,
            partition_id="[redacted]",
            result="pending:elevate_required",
        )
        if audit_chain is not None:
            audit_chain.append(
                agent_id=agent_id, partition_id="[redacted]",
                method="vault.read", params=params,
                decision=Decision.DENY, reason_code="elevate_required",
            )
        raise EnforcementDenied("elevate_required",
                                safe_message="access_denied")

    # ALLOW
    audit.log(
        action="vault.read",
        agent_id=agent_id,
        partition_id=item.owner_partition,
        result="success",
    )
    if audit_chain is not None:
        audit_chain.append(
            agent_id=agent_id, partition_id=item.owner_partition,
            method="vault.read", params=params,
            decision=Decision.ALLOW, reason_code="allow",
        )
    return item


# ---------------------------------------------------------------------------
# Phase 3: 8-step async enforce()
# ---------------------------------------------------------------------------

@dataclass
class VaultRequest:
    """
    Typed container for an agent's vault data request.

    Fields:
      key           — data key to look up (NO partition — Guardian resolves it)
      params        — application parameters (scanned for confused-deputy)
      request_id    — per-request UUID for replay protection
      token         — Phase 3 AccessToken (partitions[], tlp_level, etc.)
      peer_der_cert — DER-encoded TLS peer cert for token binding check
    """
    key:          str
    params:       dict
    request_id:   str
    token:        object        # shared.token.AccessToken (imported lazily)
    peer_der_cert: bytes


async def enforce(
    request: VaultRequest,
    *,
    vault_items: dict[str, DataItem],
    revocation_store: object,            # shared.token.RevocationStore
    verify_key_bytes: bytes,
    deduplicator: object,                # shared.token.RequestDeduplicator
    elevate_callback: Optional[Callable[[DataItem], Awaitable[bool]]] = None,
    audit_chain: Optional[object] = None,  # guardian.audit_chain.AuditChain
    known_partitions: list[str],
) -> DataItem:
    """
    8-step async enforcement pipeline.

    Steps:
      1.    Ed25519 token signature verification.
      2.    Token expiry check.
      2b.   Replay protection: duplicate request_id within 60 s → deny.
      3.    Revocation check (token_id + agent_id).
      4.    Partition-resolving: find DataItem by key across token partitions.
            Agents NEVER supply a partition name.
      5.    Confused-deputy scan: scan params for ALL known partition names
            (not just token_partitions — a confused-deputy attack uses
            unauthorized partition names the agent should never know).
      6.    TLP matrix decision.
      7.    ELEVATE → await elevate_callback; timeout or denial → ElevateTimeoutError.
      8.    ALLOW → return DataItem.

    Args:
      known_partitions — REQUIRED. ALL partition IDs in the system for step 5
                         scan. Must be derived from enrollment config so that
                         partitions with zero vault items are still scanned.

    All DENY paths raise EnforcementDenied(reason_code, safe_message="access_denied").
    The caller MUST use safe_message when communicating with the agent.

    Raises:
      EnforcementDenied    — any denial (not-found, token invalid, TLP, etc.)
      AmbiguousKeyError    — key matches items in multiple authorized partitions
      ConfusedDeputyError  — partition name detected in params
      ElevateTimeoutError  — ELEVATE required but callback absent/timed out/denied
    """
    # F-01: validate known_partitions before anything else
    if not known_partitions:
        raise ValueError(
            "known_partitions must be a non-empty list of all system partition IDs. "
            "Derive it from enrollment config, not from vault_items keys."
        )

    # FIX 3: capture start time for timing normalization (mirrors resolve_and_enforce)
    _enforce_start = time.monotonic()
    try:
        return await _enforce_inner(
            request,
            vault_items=vault_items,
            revocation_store=revocation_store,
            verify_key_bytes=verify_key_bytes,
            deduplicator=deduplicator,
            elevate_callback=elevate_callback,
            audit_chain=audit_chain,
            known_partitions=known_partitions,
        )
    finally:
        elapsed = time.monotonic() - _enforce_start
        if elapsed < _MIN_RESPONSE_TIME:
            await asyncio.sleep(_MIN_RESPONSE_TIME - elapsed)


async def _enforce_inner(
    request: VaultRequest,
    *,
    vault_items: dict,
    revocation_store: object,
    verify_key_bytes: bytes,
    deduplicator: object,
    elevate_callback,
    audit_chain,
    known_partitions,
) -> DataItem:
    """Inner implementation of enforce() without the timing wrapper."""
    # -----------------------------------------------------------------------
    # Steps 1 + 2 + 3: Token binding (signature, expiry, revocation, cert)
    # -----------------------------------------------------------------------
    try:
        _shared_token.verify_token_binding(
            request.token,
            request.peer_der_cert,
            revocation_store,
            verify_key_bytes,
        )
    except _shared_token.TokenVerifyError as exc:
        unverified_agent_id = getattr(request.token, "agent_id", "unknown")
        log_agent_id = f"unverified:{unverified_agent_id}"
        audit.log(
            action="vault.enforce",
            agent_id=log_agent_id,
            result=f"denied:token_invalid:{type(exc).__name__}",
        )
        if audit_chain is not None:
            audit_chain.append(
                agent_id=log_agent_id, partition_id="",
                method="vault.enforce", params=request.params,
                decision=Decision.DENY, reason_code="token_invalid",
            )
        raise EnforcementDenied("token_invalid") from exc

    agent_id = request.token.agent_id  # type: ignore[union-attr]

    # -----------------------------------------------------------------------
    # Step 2b: Replay protection
    # -----------------------------------------------------------------------
    try:
        deduplicator.check_and_register(request.request_id)  # type: ignore[union-attr]
    except _shared_token.DuplicateRequestError:
        audit.log(
            action="vault.enforce",
            agent_id=agent_id,
            result="denied:duplicate_request",
        )
        if audit_chain is not None:
            audit_chain.append(
                agent_id=agent_id, partition_id="",
                method="vault.enforce", params=request.params,
                decision=Decision.DENY, reason_code="duplicate_request",
            )
        raise EnforcementDenied("duplicate_request")

    # -----------------------------------------------------------------------
    # Step 5: Confused-deputy scan (before touching vault data)
    # Scan against ALL known partitions — not just token_partitions.
    # A confused-deputy attack embeds an unauthorized partition name in
    # params; that name would never appear in token_partitions.
    # -----------------------------------------------------------------------
    token_partitions: list[str] = request.token.partitions  # type: ignore[union-attr]
    scan_params(request.params, known_partitions)

    # -----------------------------------------------------------------------
    # Step 4: Partition-resolving (anti-probing: not-found == denied)
    # -----------------------------------------------------------------------
    items = _find_items_no_tlp_check(request.key, token_partitions, vault_items)

    if len(items) == 0:
        audit.log(
            action="vault.enforce",
            agent_id=agent_id,
            result="denied:access_denied",
        )
        if audit_chain is not None:
            audit_chain.append(
                agent_id=agent_id, partition_id="",
                method="vault.enforce", params=request.params,
                decision=Decision.DENY, reason_code="not_found",
            )
        raise EnforcementDenied("not_found")

    if len(items) > 1:
        audit.log(
            action="vault.enforce",
            agent_id=agent_id,
            result="denied:ambiguous_key",
        )
        if audit_chain is not None:
            audit_chain.append(
                agent_id=agent_id, partition_id="",
                method="vault.enforce", params=request.params,
                decision=Decision.DENY, reason_code="ambiguous_key",
            )
        raise AmbiguousKeyError()

    item = items[0]

    # Belt-and-suspenders partition check
    if item.owner_partition not in token_partitions:
        audit.log(
            action="vault.enforce",
            agent_id=agent_id,
            result="denied:access_denied",
        )
        if audit_chain is not None:
            audit_chain.append(
                agent_id=agent_id, partition_id="[redacted]",
                method="vault.enforce", params=request.params,
                decision=Decision.DENY, reason_code="partition_unauthorized",
            )
        raise EnforcementDenied("partition_unauthorized")

    # -----------------------------------------------------------------------
    # Step 6: TLP matrix
    # -----------------------------------------------------------------------
    tlp = (request.token.tlp_level  # type: ignore[union-attr]
           if isinstance(request.token.tlp_level, TlpLevel)  # type: ignore[union-attr]
           else TlpLevel(str(request.token.tlp_level)))  # type: ignore[union-attr]

    decision = check_tlp(tlp, item.classification)

    if decision == Decision.DENY:
        # FIX F3: redact partition name from TLP denial entries
        audit.log(
            action="vault.enforce",
            agent_id=agent_id,
            partition_id="[redacted]",
            result="denied:tlp_insufficient",
        )
        if audit_chain is not None:
            audit_chain.append(
                agent_id=agent_id, partition_id="[redacted]",
                method="vault.enforce", params=request.params,
                decision=Decision.DENY, reason_code="tlp_insufficient",
            )
        raise EnforcementDenied("tlp_insufficient")

    # -----------------------------------------------------------------------
    # Step 7: ELEVATE — await human approval
    # -----------------------------------------------------------------------
    if decision == Decision.ELEVATE:
        # FIX F3: redact partition name from ELEVATE entries
        audit.log(
            action="vault.enforce",
            agent_id=agent_id,
            partition_id="[redacted]",
            result="pending:elevate_required",
        )

        if elevate_callback is None:
            if audit_chain is not None:
                audit_chain.append(
                    agent_id=agent_id, partition_id="[redacted]",
                    method="vault.enforce", params=request.params,
                    decision=Decision.DENY, reason_code="elevate_timeout",
                )
            raise ElevateTimeoutError()

        try:
            # FIX 6: enforce timeout so a hung callback cannot block forever.
            approved: bool = await asyncio.wait_for(
                elevate_callback(item),
                timeout=_ELEVATE_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            audit.log(
                action="vault.enforce",
                agent_id=agent_id,
                partition_id="[redacted]",
                result="denied:elevate_timeout",
            )
            if audit_chain is not None:
                audit_chain.append(
                    agent_id=agent_id, partition_id="[redacted]",
                    method="vault.enforce", params=request.params,
                    decision=Decision.DENY, reason_code="elevate_timeout",
                )
            raise ElevateTimeoutError()

        if not approved:
            audit.log(
                action="vault.enforce",
                agent_id=agent_id,
                partition_id="[redacted]",
                result="denied:elevate_rejected",
            )
            if audit_chain is not None:
                audit_chain.append(
                    agent_id=agent_id, partition_id="[redacted]",
                    method="vault.enforce", params=request.params,
                    decision=Decision.DENY, reason_code="elevate_rejected",
                )
            raise ElevateTimeoutError()

        if audit_chain is not None:
            audit_chain.append(
                agent_id=agent_id, partition_id=item.owner_partition,
                method="vault.enforce", params=request.params,
                decision=Decision.ELEVATE, reason_code="elevate_approved",
            )

    # -----------------------------------------------------------------------
    # Step 8: ALLOW
    # -----------------------------------------------------------------------
    audit.log(
        action="vault.enforce",
        agent_id=agent_id,
        partition_id=item.owner_partition,
        result="success",
    )
    if audit_chain is not None:
        audit_chain.append(
            agent_id=agent_id, partition_id=item.owner_partition,
            method="vault.enforce", params=request.params,
            decision=Decision.ALLOW, reason_code="allow",
        )
    return item
