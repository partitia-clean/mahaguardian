"""
SOUL.lock signing and verification.

Security guarantees:
  - ed25519 via PyNaCl — NOT pycryptodome.
  - verify_soul() checks BOTH the ed25519 signature AND the SHA-256 hash
    in the SOUL.hash integrity ledger. Both must pass.
  - The SOUL.hash ledger is itself signed; verify_soul_hash_ledger()
    checks that signature before trusting the ledger contents.
  - Any tampering raises SOULTamperError immediately.
  - Merge conflicts use a whitelist (agent_extensions) rather than
    keyword heuristics; master rules always win.
  - The SOUL.lock file itself is never sent to the agent — only the
    system prompt string derived from soul_to_system_prompt().
  - set_immutable() sets OS-level immutable flag (chattr +i / chflags uchg)
    and degrades gracefully when permissions are insufficient.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import platform
import re
import subprocess
import sys
import unicodedata
import urllib.parse
import uuid
from pathlib import Path
from typing import Optional

import nacl.encoding
import nacl.exceptions
import nacl.signing

import guardian.audit as audit
from guardian.shared.encoding import decode_variants  # FIX: SM-004
from shared.config import SOUL_HASH_PATH

try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # type: ignore[no-reuse-def]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class SOULTamperError(Exception):
    """Raised when a SOUL.lock signature or hash check fails."""


class SOULConflictError(Exception):
    """Raised when an agent SOUL contains a rule that conflicts with master."""


class SOULLeakError(SOULTamperError):
    """
    Raised when the derived instruction set contains classified metadata —
    partition names or TLP classification levels — that must never reach
    the agent.  Treated as a tamper event because it means SOUL content
    violates the information barrier.
    """


class SOULSchemaError(SOULTamperError):
    """Raised when a SOUL.lock does not conform to the canonical schema."""


def _soul_tamper_error(detail: str, action: str = "soul.error") -> SOULTamperError:
    """
    FIX F4: Log detail server-side with a correlation ID, return a generic
    SOULTamperError whose message contains only the corr_id — no file paths,
    partition names, field names, or hash values.
    """
    corr_id = str(uuid.uuid4())[:8]
    audit.log(action=action, result=f"corr_id={corr_id} {detail}")
    return SOULTamperError(f"SOUL.lock validation failed [corr:{corr_id}]")


# ---------------------------------------------------------------------------
# SOUL.lock schema validation
# ---------------------------------------------------------------------------

# Known top-level sections for the TOML SOUL.lock format.
_SOUL_ALLOWED_TOP_KEYS: frozenset[str] = frozenset({
    "meta", "rules", "constraints", "agent_extensions",
})

# Required fields within [meta].
_SOUL_META_REQUIRED: frozenset[str] = frozenset({"agent"})


def _validate_soul_schema(soul_dict: dict, source: str = "SOUL.lock", *, strict: bool = False) -> None:
    """
    Validate *soul_dict* against the canonical SOUL.lock TOML schema.

    Security properties:
    - Rejects missing required fields.
    - Rejects wrong types for known fields.
    - When strict=True: also rejects unknown top-level keys (used for
      standalone SOUL.lock verification; merge_souls() enforces its own
      section allowlist and should use strict=False).
    - Error messages are GENERIC — field names are logged internally but
      not exposed to callers (prevents schema probing by adversarial agents).

    Raises SOULSchemaError on any violation.
    """
    if not isinstance(soul_dict, dict):
        audit.log(action="soul.schema_validation", result="denied:not_a_dict")
        raise SOULSchemaError("SOUL.lock failed schema validation.")

    # --- Unknown top-level keys (strict mode only) ---
    if strict:
        unknown = set(soul_dict.keys()) - _SOUL_ALLOWED_TOP_KEYS
        if unknown:
            # FIX F4: do not enumerate unknown field names in audit log (schema probing)
            corr_id = str(uuid.uuid4())[:8]
            audit.log(
                action="soul.schema_validation",
                result=f"denied:unknown_top_keys corr_id={corr_id} count={len(unknown)}",
            )
            raise SOULSchemaError("SOUL.lock failed schema validation.")

    # --- [meta] section ---
    meta = soul_dict.get("meta")
    if meta is not None:
        if not isinstance(meta, dict):
            audit.log(action="soul.schema_validation", result="denied:meta_not_dict")
            raise SOULSchemaError("SOUL.lock failed schema validation.")
        for field in _SOUL_META_REQUIRED:
            if field not in meta:
                audit.log(
                    action="soul.schema_validation",
                    result=f"denied:meta_missing_{field}",
                )
                raise SOULSchemaError("SOUL.lock failed schema validation.")
        if not isinstance(meta.get("agent", ""), str):
            audit.log(action="soul.schema_validation", result="denied:meta.agent_not_str")
            raise SOULSchemaError("SOUL.lock failed schema validation.")

    # --- [rules] section ---
    rules = soul_dict.get("rules")
    if rules is not None:
        if not isinstance(rules, dict):
            audit.log(action="soul.schema_validation", result="denied:rules_not_dict")
            raise SOULSchemaError("SOUL.lock failed schema validation.")
        absolutes = rules.get("absolute")
        if absolutes is not None:
            if not isinstance(absolutes, list):
                audit.log(action="soul.schema_validation", result="denied:rules.absolute_not_list")
                raise SOULSchemaError("SOUL.lock failed schema validation.")
            for item in absolutes:
                if not isinstance(item, str):
                    audit.log(action="soul.schema_validation", result="denied:rules.absolute_item_not_str")
                    raise SOULSchemaError("SOUL.lock failed schema validation.")

    # --- agent_extensions (top-level list) ---
    exts = soul_dict.get("agent_extensions")
    if exts is not None:
        if not isinstance(exts, list):
            audit.log(action="soul.schema_validation", result="denied:agent_extensions_not_list")
            raise SOULSchemaError("SOUL.lock failed schema validation.")
        for item in exts:
            if not isinstance(item, str):
                audit.log(action="soul.schema_validation", result="denied:agent_extensions_item_not_str")
                raise SOULSchemaError("SOUL.lock failed schema validation.")

    # --- [constraints] section ---
    constraints = soul_dict.get("constraints")
    if constraints is not None:
        if not isinstance(constraints, dict):
            audit.log(action="soul.schema_validation", result="denied:constraints_not_dict")
            raise SOULSchemaError("SOUL.lock failed schema validation.")

    audit.log(action="soul.schema_validation", result="success")


# ---------------------------------------------------------------------------
# Keypair generation
# ---------------------------------------------------------------------------

def generate_soul_keypair() -> tuple[bytes, bytes]:
    """
    Generate an ed25519 keypair for SOUL signing.

    Returns (private_key_bytes, public_key_bytes).

    The private key must be stored encrypted in vault under
    signing_keys.soul_private_key.
    The public key is stored in the SOUL.hash file.
    Uses PyNaCl — not pycryptodome.
    """
    signing_key = nacl.signing.SigningKey.generate()
    private_key_bytes = bytes(signing_key)
    public_key_bytes = bytes(signing_key.verify_key)
    return private_key_bytes, public_key_bytes


# ---------------------------------------------------------------------------
# Signing
# ---------------------------------------------------------------------------

def sign_soul(soul_path: Path, private_key: bytes) -> bytes:
    """
    Sign SOUL.lock file content with ed25519.

    Reads soul_path as canonical UTF-8 bytes.
    Returns signature bytes.
    Writes signature to soul_path.with_suffix('.lock.sig') — i.e. replaces
    the last suffix with '.lock.sig' so master-SOUL.lock → master-SOUL.lock.sig.

    Uses PyNaCl SigningKey.
    """
    soul_bytes = soul_path.read_bytes()
    signing_key = nacl.signing.SigningKey(private_key)
    signed = signing_key.sign(soul_bytes)
    # signed.signature is the raw 64-byte signature
    signature = signed.signature

    sig_path = _sig_path(soul_path)
    sig_path.write_bytes(signature)

    audit.log(
        action="soul.sign",
        resource=str(soul_path),
        result="success",
    )
    return signature


# ---------------------------------------------------------------------------
# SOUL.hash ledger signing / verification
# ---------------------------------------------------------------------------

def _ledger_sig_path() -> Path:
    """Return the signature path for the SOUL.hash ledger itself."""
    return SOUL_HASH_PATH.parent / (SOUL_HASH_PATH.name + ".sig")


def sign_soul_hash_ledger(private_key: bytes) -> bytes:
    """
    Sign the SOUL.hash ledger file with ed25519.
    Returns signature bytes.  Writes to SOUL.hash.sig.
    """
    ledger_bytes = SOUL_HASH_PATH.read_bytes()
    signing_key = nacl.signing.SigningKey(private_key)
    signed = signing_key.sign(ledger_bytes)
    sig = signed.signature

    sig_path = _ledger_sig_path()
    sig_path.write_bytes(sig)
    return sig


def verify_soul_hash_ledger(
    public_key: bytes,
    ledger_bytes: Optional[bytes] = None,
) -> bytes:
    """
    Verify the ed25519 signature of the SOUL.hash ledger.
    If *ledger_bytes* is not provided, reads from disk.
    Returns the verified ledger bytes so callers can reuse them
    without a second read (avoiding TOCTOU).
    Raises SOULTamperError on failure.
    """
    sig_path = _ledger_sig_path()

    if ledger_bytes is None:
        if not SOUL_HASH_PATH.exists():
            # FIX F4: generic message — do not leak ledger path
            raise _soul_tamper_error(
                f"ledger_not_found path={SOUL_HASH_PATH}",
                action="soul.verify_ledger",
            )
        ledger_bytes = SOUL_HASH_PATH.read_bytes()

    if not sig_path.exists():
        # FIX F4: generic message — do not leak signature path
        raise _soul_tamper_error(
            f"ledger_sig_not_found path={sig_path}",
            action="soul.verify_ledger",
        )

    signature = sig_path.read_bytes()
    verify_key = nacl.signing.VerifyKey(public_key)
    try:
        verify_key.verify(ledger_bytes, signature)
    except nacl.exceptions.BadSignatureError as exc:
        # FIX F4: generic message — no internal detail exposed
        raise _soul_tamper_error(
            "ledger_sig_invalid", action="soul.verify_ledger"
        ) from exc

    return ledger_bytes


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_soul(soul_path: Path, public_key: bytes) -> bytes:
    """
    Verify SOUL.lock signature and hash ledger entry.

    Returns the verified file bytes (not just True/False).
    Callers MUST use the returned bytes instead of re-reading
    the file, to prevent TOCTOU attacks.

    Raises SOULTamperError if any check fails.
    Logs verification attempt to audit.log.
    """
    # --- 0. Read ledger ONCE and verify its signature ---
    # Reading once prevents TOCTOU: an attacker cannot swap the file
    # between the signature check and the hash lookup.
    ledger_bytes = verify_soul_hash_ledger(public_key)
    ledger_text = ledger_bytes.decode("utf-8")

    soul_bytes = soul_path.read_bytes()
    sig_path = _sig_path(soul_path)

    # --- 1. Signature check ---
    if not sig_path.exists():
        audit.log(
            action="soul.verify",
            resource=str(soul_path),
            result="failure:missing_sig",
        )
        # FIX F4: generic message — do not leak sig_path to callers
        raise _soul_tamper_error(
            f"sig_not_found path={sig_path}", action="soul.verify"
        )

    signature = sig_path.read_bytes()
    verify_key = nacl.signing.VerifyKey(public_key)
    try:
        verify_key.verify(soul_bytes, signature)
    except nacl.exceptions.BadSignatureError as exc:
        audit.log(
            action="soul.verify",
            resource=str(soul_path),
            result="failure:bad_signature",
        )
        # FIX F4: generic message — do not leak soul_path to callers
        raise _soul_tamper_error(
            f"sig_invalid path={soul_path}", action="soul.verify"
        ) from exc

    # --- 2. Hash ledger check (uses the same bytes we already verified) ---
    actual_hash = hashlib.sha256(soul_bytes).hexdigest()
    _check_soul_hash_ledger(soul_path, actual_hash, ledger_text)

    # --- 3. Schema validation (strict: no unknown top-level keys) ---
    soul_dict = _load_toml(soul_bytes)
    _validate_soul_schema(soul_dict, source=str(soul_path), strict=True)

    audit.log(
        action="soul.verify",
        resource=str(soul_path),
        result="success",
    )
    return soul_bytes


def _check_soul_hash_ledger(
    soul_path: Path, actual_hex: str, ledger_text: str
) -> None:
    """
    Verify that actual_hex matches the entry for soul_path in the ledger.

    *ledger_text* is the already-verified content of SOUL.hash — callers
    must pass the same bytes that were signature-checked by
    verify_soul_hash_ledger() to avoid TOCTOU.

    The ledger has lines of the form:
        <label>: sha256:<hex>
    where label is derived from the filename stem (e.g. "master", "alpha").

    Raises SOULTamperError if:
      - no entry for this SOUL file exists,
      - or the recorded hash does not match.
    """
    label = _soul_label(soul_path)
    recorded_hash: Optional[str] = None

    for line in ledger_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Expected format: "master: sha256:<hex>"
        m = re.match(r"^(\S+):\s+sha256:([0-9a-f]{64})$", line, re.IGNORECASE)
        if m and m.group(1) == label:
            recorded_hash = m.group(2).lower()
            break

    if recorded_hash is None:
        # FIX F4: generic message — do not leak label or ledger path
        raise _soul_tamper_error(
            f"hash_entry_not_found label={label}", action="soul.verify_hash"
        )

    if actual_hex.lower() != recorded_hash:
        # FIX F4: generic message — do not leak label
        raise _soul_tamper_error(
            f"hash_mismatch label={label}", action="soul.verify_hash"
        )


# ---------------------------------------------------------------------------
# SOUL.hash ledger management
# ---------------------------------------------------------------------------

def update_soul_hash_ledger(
    soul_path: Path, private_key: Optional[bytes] = None
) -> None:
    """
    Compute the SHA-256 of soul_path and upsert its entry in SOUL.hash.

    Called after sign_soul() so the ledger stays in sync.
    The ledger file is re-written atomically.

    If *private_key* is provided the ledger is re-signed with
    sign_soul_hash_ledger().  When omitted the ledger is left unsigned
    (callers that need signing should pass the key explicitly).
    """
    SOUL_HASH_PATH.parent.mkdir(parents=True, exist_ok=True)

    label = _soul_label(soul_path)
    new_hash = hashlib.sha256(soul_path.read_bytes()).hexdigest()
    new_line = f"{label}: sha256:{new_hash}"

    existing_lines: list[str] = []
    if SOUL_HASH_PATH.exists():
        existing_lines = SOUL_HASH_PATH.read_text(encoding="utf-8").splitlines()

    # Replace existing entry or append
    updated = False
    result_lines: list[str] = []
    for line in existing_lines:
        m = re.match(r"^(\S+):\s+sha256:", line.strip())
        if m and m.group(1) == label:
            result_lines.append(new_line)
            updated = True
        else:
            result_lines.append(line)

    if not updated:
        result_lines.append(new_line)

    SOUL_HASH_PATH.write_text("\n".join(result_lines) + "\n", encoding="utf-8")

    # Re-sign the ledger if a private key was provided
    if private_key is not None:
        sign_soul_hash_ledger(private_key)


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

def merge_souls(
    master_soul_bytes: bytes,
    agent_soul_bytes: bytes,
    master_name: str = "master",
    agent_name: str = "agent",
    *,
    known_partitions: Optional[list[str]] = None,
) -> dict:
    """
    Merge master SOUL with agent-specific SOUL.

    SECURITY: Only accepts bytes (not Path) to prevent TOCTOU attacks.
    Callers MUST pass bytes returned by verify_soul().  This is an
    intentional API restriction — passing Path objects will raise
    TypeError.

    Master rules always win.  Agent absolute rules are only accepted if
    they belong to a category listed in the master's [agent_extensions]
    section.  If no [agent_extensions] section exists, agents cannot add
    any absolute rules at all (secure default).

    Any rejected rule:
      - raises SOULConflictError,
      - logs to audit.log,
      - (caller is responsible for alerting the user).

    Args:
      known_partitions — F-02: if provided, agent_extensions category names
                         and rule category tags are scanned against this list.
                         A match raises SOULLeakError — partition names must
                         never appear in SOUL metadata that flows into prompts.

    Returns merged soul as dict for system prompt injection.
    """
    if isinstance(master_soul_bytes, Path) or isinstance(agent_soul_bytes, Path):
        raise TypeError(
            "merge_souls() requires bytes from verify_soul(), "
            "not file paths. This prevents TOCTOU attacks."
        )

    master_soul = _load_toml(master_soul_bytes)
    agent_soul = _load_toml(agent_soul_bytes)

    # Schema validation before any processing
    _validate_soul_schema(master_soul, source=master_name)
    _validate_soul_schema(agent_soul, source=agent_name)

    # FIX 8: deep copy so nested lists/dicts are independent
    merged: dict = copy.deepcopy(master_soul)

    # Determine which extension categories agents may contribute to
    allowed_categories: list[str] = master_soul.get("agent_extensions", [])

    # F-02: scan agent_extensions category names against known_partitions.
    # A partition name embedded in a category string would flow into the
    # system prompt via soul_to_system_prompt(), leaking the barrier topology.
    if known_partitions:
        for category in allowed_categories:
            for pname in known_partitions:
                if pname and pname.casefold() in category.casefold():
                    audit.log(
                        action="soul.merge",
                        resource=f"agent={agent_name}",
                        result="denied:agent_extensions_contains_partition",
                    )
                    raise SOULLeakError(
                        "agent_extensions category contains a partition name. "
                        "SOUL metadata must not embed partition identifiers."
                    )

    # Sections an agent SOUL is allowed to contain.  Any section not in
    # this set is rejected — preventing prompt injection via novel
    # top-level sections that would flow into soul_to_system_prompt().
    allowed_agent_sections = {"meta", "rules", "constraints"}
    # Also permit sections explicitly listed in master's agent_extensions
    for cat in allowed_categories:
        allowed_agent_sections.add(cat.lower())

    # FIX 5: pre-check ALL top-level keys before processing any section.
    # This catches typos like [constraintss] that would silently drop
    # constraints if only caught per-section during the merge loop.
    unknown_sections = {
        k for k in agent_soul
        if k not in allowed_agent_sections
    }
    if unknown_sections:
        audit.log(
            action="soul.conflict_detected",
            resource=f"agent={agent_name}",
            result=f"conflict:unknown_sections={sorted(unknown_sections)}",
        )
        raise SOULConflictError(
            f"Agent SOUL contains unknown top-level sections: "
            f"{sorted(unknown_sections)}. "
            f"Allowed sections: {sorted(allowed_agent_sections)}."
        )

    # Overlay agent sections — master wins on any overlap
    for section, agent_value in agent_soul.items():
        if section not in allowed_agent_sections:
            audit.log(
                action="soul.conflict_detected",
                resource=f"agent={agent_name}",
                result=f"conflict:disallowed_section='{section}'",
            )
            raise SOULConflictError(
                f"Agent SOUL contains disallowed section '{section}'.\n"
                f"Agents may only use sections: {sorted(allowed_agent_sections)}.\n"
                f"Fix {agent_name} or add '{section}' to master "
                f"[agent_extensions]."
            )

        if section == "meta":
            # Keep master meta; agent meta is informational only
            continue

        if section == "rules":
            master_absolutes: list[str] = master_soul.get("rules", {}).get(
                "absolute", []
            )
            agent_absolutes: list[str] = agent_value.get("absolute", [])

            # F-02: scan each agent rule for embedded partition names before
            # any other processing — catches injection via rule text.
            if known_partitions:
                for rule in agent_absolutes:
                    if rule in master_absolutes:
                        continue  # master duplicates are safe; checked already
                    for pname in known_partitions:
                        if pname and pname.casefold() in rule.casefold():
                            audit.log(
                                action="soul.merge",
                                resource=f"agent={agent_name}",
                                result="denied:rule_contains_partition",
                            )
                            raise SOULLeakError(
                                "Agent SOUL rule contains a partition name. "
                                "Rules must not embed partition identifiers."
                            )

            # Validate each agent absolute rule against the whitelist
            safe_agent_rules: list[str] = []
            for rule in agent_absolutes:
                if rule in master_absolutes:
                    # Duplicate of a master rule — harmless, skip
                    continue
                _validate_agent_value(rule, "rules.absolute", agent_name)
                _validate_agent_rule(
                    rule, allowed_categories, agent_name
                )
                safe_agent_rules.append(rule)

            merged.setdefault("rules", {})
            merged["rules"]["absolute"] = list(master_absolutes) + safe_agent_rules

            # Merge non-conflicting sub-keys (e.g. conditional rules)
            # Only allow rule sub-keys from approved categories
            for k, v in agent_value.items():
                if k != "absolute":
                    if k not in merged.get("rules", {}):
                        if k.lower() not in [c.lower() for c in allowed_categories]:
                            audit.log(
                                action="soul.conflict_detected",
                                resource=f"agent={agent_name}",
                                result=f"conflict:disallowed_rule_key='{k}'",
                            )
                            raise SOULConflictError(
                                f"Agent SOUL rule key '{k}' not in allowed "
                                f"categories: {allowed_categories}. "
                                f"Fix {agent_name}."
                            )
                        _validate_agent_value(v, f"rules.{k}", agent_name)
                        merged["rules"][k] = v
            continue

        if section == "constraints":
            # Master constraints always win; only add keys master lacks
            if isinstance(agent_value, dict) and isinstance(merged.get(section), dict):
                for k, v in agent_value.items():
                    if k not in merged[section]:
                        _validate_agent_value(v, f"constraints.{k}", agent_name)
                        merged[section][k] = v
            continue

    audit.log(
        action="soul.merge",
        resource=f"master={master_name},agent={agent_name}",
        result="success",
    )
    return merged


def _validate_agent_rule(
    rule: str,
    allowed_categories: list[str],
    agent_name: str,
) -> None:
    """
    Validate an agent absolute rule against the whitelist of allowed
    extension categories.

    Agent rules must be formatted as ``[category] rule text`` where
    *category* is one of the categories in the master SOUL's
    [agent_extensions] list.

    If no categories are allowed (empty list or missing section),
    ALL agent absolute rules are rejected.

    Raises SOULConflictError if the rule is not in an allowed category.
    """
    if not allowed_categories:
        audit.log(
            action="soul.conflict_detected",
            resource=f"agent={agent_name}",
            result=f"conflict:rule='{rule}' (no agent_extensions permitted)",
        )
        raise SOULConflictError(
            f"Agent SOUL rule rejected: {rule!r}\n"
            f"Master SOUL has no [agent_extensions] section — "
            f"agents cannot add absolute rules.\n"
            f"Fix {agent_name} or add [agent_extensions] to master."
        )

    # Parse category tag from rule:  "[persona] Always respond in English"
    m = re.match(r"^\[(\w+)\]\s+", rule)
    if not m:
        audit.log(
            action="soul.conflict_detected",
            resource=f"agent={agent_name}",
            result=f"conflict:rule='{rule}' (missing category tag)",
        )
        raise SOULConflictError(
            f"Agent SOUL rule rejected: {rule!r}\n"
            f"Rule must be prefixed with a category tag, e.g. "
            f"'[persona] {rule}'.\n"
            f"Allowed categories: {allowed_categories}"
        )

    category = m.group(1).lower()
    normalised_allowed = [c.lower() for c in allowed_categories]

    if category not in normalised_allowed:
        audit.log(
            action="soul.conflict_detected",
            resource=f"agent={agent_name}",
            result=f"conflict:rule='{rule}' (category '{category}' not allowed)",
        )
        raise SOULConflictError(
            f"Agent SOUL rule rejected: {rule!r}\n"
            f"Category '{category}' is not in allowed agent_extensions: "
            f"{allowed_categories}.\n"
            f"Fix {agent_name} or add '{category}' to master [agent_extensions]."
        )


def _validate_agent_value(value: object, path: str, agent_name: str) -> None:
    """
    Validate a value from an agent SOUL before merging.
    Rejects values that could be used for prompt injection
    or policy bypass.
    """
    if isinstance(value, str):
        if len(value) > 500:
            raise SOULConflictError(
                f"Agent SOUL value too long at '{path}' "
                f"({len(value)} chars, max 500). Fix {agent_name}."
            )
        # Block attempts to inject prompt structure
        if any(line.strip().startswith("#") for line in value.split("\n")):
            raise SOULConflictError(
                f"Agent SOUL value at '{path}' contains markdown "
                f"headers (prompt injection risk). Fix {agent_name}."
            )
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _validate_agent_value(item, f"{path}[{i}]", agent_name)
    elif isinstance(value, dict):
        for k, v in value.items():
            _validate_agent_value(v, f"{path}.{k}", agent_name)
    # int, float, bool are safe — no validation needed


# ---------------------------------------------------------------------------
# Content sanitization for prompt rendering
# ---------------------------------------------------------------------------

def _sanitize_prompt_value(value: str, max_length: int = 500) -> str:
    """Sanitize a value before rendering into system prompt."""
    import unicodedata

    # Remove null bytes
    cleaned = value.replace("\x00", "")

    # Remove all Unicode control characters except \n and \t
    cleaned = "".join(
        ch for ch in cleaned
        if ch in ("\n", "\t") or (
            not unicodedata.category(ch).startswith("C")
        )
    )

    # Remove Unicode direction override characters
    direction_overrides = {
        "\u200b", "\u200c", "\u200d", "\u200e", "\u200f",
        "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
        "\u2066", "\u2067", "\u2068", "\u2069", "\ufeff",
    }
    cleaned = "".join(
        ch for ch in cleaned if ch not in direction_overrides
    )

    # Strip XML/HTML tags
    cleaned = re.sub(r'<[^>]+>', '', cleaned)

    # Strip code fences (used in some prompt injection patterns)
    cleaned = cleaned.replace("```", "")

    # Strip role-prefix patterns that some LLMs interpret as
    # instruction boundaries
    cleaned = re.sub(
        r'(?im)^(SYSTEM|DEVELOPER|ASSISTANT|USER)\s*:',
        '[BLOCKED_ROLE_PREFIX]',
        cleaned,
    )

    # Truncate
    truncated = cleaned[:max_length]

    # Strip lines that look like prompt structure injection
    lines = truncated.split("\n")
    safe_lines = [
        line for line in lines
        if not line.strip().startswith("#")
    ]
    return "\n".join(safe_lines)


# ---------------------------------------------------------------------------
# System prompt generation
# ---------------------------------------------------------------------------

def soul_to_system_prompt(merged_soul: dict) -> str:
    """
    Convert merged SOUL dict to a system prompt string.

    This is what gets injected into the agent's context.
    The SOUL.lock file itself is never sent to the agent.

    Defense-in-depth: only sections in RENDERABLE_SECTIONS are rendered.
    Even if merge_souls() has a bug that lets an unexpected section
    through, the renderer will not include it.  All string values are
    sanitized via _sanitize_prompt_value() before rendering.
    """
    # Only render sections we explicitly understand.
    # This is defense-in-depth against prompt injection:
    # even if merge_souls() has a bug that lets an unknown
    # section through, the renderer will not include it.
    RENDERABLE_SECTIONS = {"meta", "rules", "constraints"}

    lines: list[str] = [
        "# MahaGuardian Agent Identity and Constraints",
        "",
    ]

    # --- meta ---
    meta = merged_soul.get("meta", {})
    if meta.get("agent"):
        lines.append(
            f"You are agent: **{_sanitize_prompt_value(str(meta['agent']))}**"
        )
    if meta.get("created"):
        lines.append(
            f"Identity established: {_sanitize_prompt_value(str(meta['created']))}"
        )
    lines.append("")

    # --- rules ---
    rules = merged_soul.get("rules", {})
    absolutes = rules.get("absolute", [])
    if absolutes:
        lines.append("## Absolute Rules (non-negotiable, cannot be overridden)")
        for rule in absolutes:
            lines.append(f"- {_sanitize_prompt_value(str(rule))}")
        lines.append("")

    for key, value in rules.items():
        if key == "absolute":
            continue
        lines.append(f"## {_sanitize_prompt_value(key.replace('_', ' ').title())}")
        if isinstance(value, list):
            for item in value:
                lines.append(f"- {_sanitize_prompt_value(str(item))}")
        else:
            lines.append(_sanitize_prompt_value(str(value)))
        lines.append("")

    # --- constraints ---
    constraints = merged_soul.get("constraints", {})
    if constraints:
        lines.append("## Operational Constraints")
        for k, v in constraints.items():
            lines.append(
                f"- {_sanitize_prompt_value(k.replace('_', ' '))}: "
                f"{_sanitize_prompt_value(str(v))}"
            )
        lines.append("")

    # Any section NOT in RENDERABLE_SECTIONS is silently skipped.
    # This includes agent_extensions (internal config) and any
    # section that might have leaked through a merge bug.
    for section in merged_soul:
        if section not in RENDERABLE_SECTIONS:
            continue  # already handled above or not renderable

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Immutable flag
# ---------------------------------------------------------------------------

def set_immutable(soul_path: Path) -> None:
    """
    Set OS-level immutable flag on SOUL.lock.

    Linux:  subprocess call to ``chattr +i <path>``
    macOS:  subprocess call to ``chflags uchg <path>``
    Windows: sets the read-only attribute as the closest available
             equivalent (true immutability requires ACL changes).

    Degrades gracefully: on Linux without root chattr +i will fail;
    a warning is logged rather than raising an exception.

    Logs action to audit.log.
    """
    system = platform.system()
    try:
        if system == "Linux":
            subprocess.run(
                ["chattr", "+i", str(soul_path)],
                check=True,
                capture_output=True,
            )
        elif system == "Darwin":
            subprocess.run(
                ["chflags", "uchg", str(soul_path)],
                check=True,
                capture_output=True,
            )
        elif system == "Windows":
            import stat
            soul_path.chmod(stat.S_IREAD)
            # Windows read-only attribute is the best available protection
            # but is NOT equivalent to true immutability.  Any user with
            # write permission to the directory can remove the flag.
            audit.log(
                action="soul.set_immutable",
                resource=str(soul_path),
                result="success:windows_readonly_only",
            )
            return
        else:
            # Fallback: read-only
            import stat
            soul_path.chmod(stat.S_IREAD)
    except subprocess.CalledProcessError as exc:
        # chattr +i / chflags uchg requires root/elevated privileges.
        # Degrade gracefully: warn but do not abort.
        audit.log(
            action="soul.set_immutable",
            resource=str(soul_path),
            result=(
                f"warning:immutability not enforced "
                f"({system} requires elevated privileges). "
                f"Run 'sudo chattr +i {soul_path}' manually."
            ),
        )
        return

    audit.log(
        action="soul.set_immutable",
        resource=str(soul_path),
        result="success",
    )


# ---------------------------------------------------------------------------
# Phase 3: derive_instruction_set + verify_soul_integrity
# ---------------------------------------------------------------------------

def derive_instruction_set(
    merged_soul: dict,
    *,
    known_partitions: list[str],
    known_tlp_levels: Optional[list[str]] = None,
) -> str:
    """
    Derive the agent instruction string from the merged SOUL dict and
    verify it contains no classified metadata before delivery.

    Steps:
      1. Render via soul_to_system_prompt().
      2. Scan for any partition name (direct, URL-decoded, NFC-normalised).
      3. Scan for any TLP level value (exact match, case-insensitive).
      4. On first match: audit-log and raise SOULLeakError.
      5. On clean: audit-log success and return the instruction string.

    Args:
        merged_soul       — from merge_souls(); NOT raw TOML bytes.
        known_partitions  — all partition IDs that must never reach the agent.
        known_tlp_levels  — TLP level strings to scan for; defaults to all
                            TlpLevel enum values when None.

    Raises:
        SOULLeakError — instruction string would expose classified metadata.
    """
    instruction_str = soul_to_system_prompt(merged_soul)

    # Default: all TLP enum values
    if known_tlp_levels is None:
        from shared.types import TlpLevel
        known_tlp_levels = [level.value for level in TlpLevel]

    # --- Strip zero-width characters before scanning ---
    _ZWC_RE = re.compile(r'[\u200b\u200c\u200d\ufeff\u2060]')
    instruction_str_clean = _ZWC_RE.sub('', instruction_str)

    # --- Scan for partition names ---
    # FIX: SM-004 / FIX-2 — use word-boundary regex instead of substring matching
    # to prevent false positives (e.g. "admin" matching "administrator").
    # Also strip zero-width characters and apply casefold before comparison.
    inst_variants = decode_variants(instruction_str_clean)

    # FIX 1: use casefold substring containment instead of word-boundary regex.
    # Word-boundary lookbehind/lookahead misses embedded partition names
    # (e.g. "corp" inside "acorp-data"). This boundary MUST fail closed.
    for partition in known_partitions:
        p_variants = decode_variants(_ZWC_RE.sub('', partition))
        for p_v in p_variants:
            if not p_v:
                continue
            p_v_folded = p_v.casefold()
            if any(p_v_folded in inst_v.casefold() for inst_v in inst_variants):
                audit.log(
                    action="soul.derive_instruction_set",
                    result="denied:partition_leak_detected",
                )
                raise SOULLeakError(
                    "Instruction set contains a partition name. "
                    "Agent instructions must not include partition identifiers."
                )

    # --- Scan for TLP levels ---
    # FIX 1: same casefold substring containment for TLP levels.
    for level in known_tlp_levels:
        level_variants = decode_variants(_ZWC_RE.sub('', level))
        for lv in level_variants:
            if not lv:
                continue
            lv_folded = lv.casefold()
            if any(lv_folded in inst_v.casefold() for inst_v in inst_variants):
                audit.log(
                    action="soul.derive_instruction_set",
                    result="denied:tlp_leak_detected",
                )
                raise SOULLeakError(
                    "Instruction set contains a TLP classification level. "
                    "Agent instructions must not include TLP labels."
                )

    audit.log(
        action="soul.derive_instruction_set",
        result="success",
    )
    return instruction_str


def verify_soul_integrity(soul_path: Path, public_key: bytes) -> bool:
    """
    Verify signature + hash-ledger integrity of a SOUL.lock file.

    A thin, boolean-returning wrapper around verify_soul().  Callers that
    only need a pass/fail result use this; callers that need the verified
    bytes use verify_soul() directly.

    Returns True if all checks pass.
    Raises SOULTamperError (from verify_soul) on any failure.
    """
    verify_soul(soul_path, public_key)  # raises SOULTamperError on failure
    return True


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sig_path(soul_path: Path) -> Path:
    """
    Return the companion .sig path for a given SOUL.lock path.
    master-SOUL.lock  →  master-SOUL.lock.sig
    """
    return soul_path.parent / (soul_path.name + ".sig")


def _soul_label(soul_path: Path) -> str:
    """
    Derive the SOUL.hash label from the file name.
    master-SOUL.lock  →  master
    alpha-SOUL.lock   →  alpha
    """
    name = soul_path.name  # e.g. "master-SOUL.lock" or "alpha-SOUL.lock"
    # Strip known suffixes
    for suffix in ("-SOUL.lock", ".lock"):
        if name.endswith(suffix):
            name = name[: -len(suffix)]
            break
    return name


def _load_toml(data: bytes) -> dict:
    """Load TOML from bytes, returning a dict."""
    return tomllib.loads(data.decode("utf-8"))
