"""
Guardian FastAPI application -- the central control plane.

Binds to 127.0.0.1 ONLY (never 0.0.0.0).
All endpoints use the enforcer for access control.
Startup lifecycle: audit -> vault -> SOUL verify -> tokens -> tools -> payments -> llm_keys.
Shutdown lifecycle: stop heartbeats -> lock vault -> close audit.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

import guardian.audit as audit
import guardian.vault as vault
from guardian.audit_chain import AuditChain
from guardian.enforcer import (  # FIX: SM-001 — legacy functions removed
    EnforcementDenied,
    VaultRequest,
    enforce as _enforce,
)
from guardian.heartbeat import start_heartbeat, stop_heartbeat
from guardian.llm_keys import init_llm_keys, stop_rotation
from guardian.payments import (
    PaymentDeniedError,
    PaymentTimeoutError,
    execute_payment,
    init_payments,
)
from guardian.skills import (
    SkillVerificationError,
    load_verified_skills,
    verify_skill,
)
from guardian.soul import (
    SOULConflictError,
    SOULLeakError,
    SOULTamperError,
    derive_instruction_set,
    merge_souls,
    verify_soul,
)
from shared.token import (
    AccessToken,
    issue_token as _phase3_issue_token,
    verify_token_binding,
    RevocationStore,
    RequestDeduplicator,
    TokenVerifyError,
)
from guardian.tools import ToolNotPermittedError, execute_tool_call, init_tools
from guardian.middleware import PeerCertMiddleware
from guardian.mtls import verify_peer_agent_id_from_der
from shared.config import (
    AGENTS_SOUL_DIR,
    AUDIT_DB_PATH,
    CA_CERT_PATH,
    CORE_DIR,
    GUARDIAN_CERT_PATH,
    GUARDIAN_HOST,
    GUARDIAN_KEY_PATH,
    GUARDIAN_PORT,
    LOGS_DIR,
    SKILLS_DIR,
    TOKEN_LIFETIME_HOURS,
)
from shared.models import PaymentRequest
from shared.types import Decision, TlpLevel


# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_vault_dict: Optional[dict] = None
_audit_chain: Optional[AuditChain] = None
_active_agents: set[str] = set()
_revoke_timestamps: dict[str, list[float]] = {}  # rate limiting
_ws_clients: dict = {}  # agent_id -> GuardianWSClient (Phase 2)

# Phase 3 token state
_signing_key_bytes: Optional[bytes] = None
_verify_key_bytes: Optional[bytes] = None
_revocation_store: Optional[RevocationStore] = None
_deduplicator: Optional[RequestDeduplicator] = None


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class TokenIssueRequest(BaseModel):
    agent_id: str
    # Permissions are derived from Guardian's local vault config,
    # NEVER from the agent's request. The agent must not dictate
    # its own permissions — this breaks the split-trust model.


class TokenVerifyRequest(BaseModel):
    token_str: str


class TokenRevokeRequest(BaseModel):
    agent_id: str
    token_str: str            # the token TO BE REVOKED (not a separate auth token)


class ToolCallRequest(BaseModel):
    agent_id: str
    token_str: str            # signed JSON token string
    tool_name: str
    action: str
    params: dict = {}
    partition_id: str = ""


class PartitionAccessRequest(BaseModel):
    token_str: str            # Phase 3 AccessToken JSON string
    key: str                  # data key — Guardian resolves the partition; agents never supply partition names
    agent_id: str
    action: str = "data.request"


class TokenRevokeAllRequest(BaseModel):
    agent_id: str
    admin_passphrase: str  # raw passphrase (hashed server-side)


class HeartbeatStartRequest(BaseModel):
    agent_id: str
    interval_minutes: int = 15
    provider: str = "anthropic"


class HeartbeatStopRequest(BaseModel):
    agent_id: str


class SkillVerifyRequest(BaseModel):
    skill_path: str
    manifest_path: str
    token_str: str
    agent_id: str


class SkillLoadRequest(BaseModel):
    agent_id: str
    token_str: str


class PaymentExecuteRequest(BaseModel):
    agent_id: str
    token_str: str            # signed JSON token string
    payment_request: PaymentRequest


class AuditQueryRequest(BaseModel):
    agent_id: Optional[str] = None
    action: Optional[str] = None
    partition_id: Optional[str] = None
    from_timestamp: Optional[str] = None
    to_timestamp: Optional[str] = None
    token_str: str
    requesting_agent_id: str


class AuditIntegrityRequest(BaseModel):
    token_str: str
    agent_id: str


class SessionStartRequest(BaseModel):
    agent_id: str
    # Permissions and lifetime are derived from Guardian's local vault
    # config, NEVER from the agent's request.


# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

def _get_agent_cert(request: Request) -> bytes:
    """
    Get agent certificate bytes from the mTLS session.
    This is the only trusted source of peer identity.
    """
    peer_cert = getattr(request.state, "peer_cert_der", None)
    if peer_cert is None:
        audit.log(
            action="cert.missing_from_mtls",
            result="critical:no_peer_cert",
        )
        raise HTTPException(
            status_code=500,
            detail="No TLS peer certificate found in request state.",
        )
    return peer_cert


def _verify_cert_and_agent_id(agent_cert: bytes, expected_agent_id: str) -> None:
    """Fail closed unless the mTLS peer certificate matches expected_agent_id."""
    try:
        verify_peer_agent_id_from_der(agent_cert, expected_agent_id)
    except Exception as exc:
        audit.log(
            action="cert.identity_verification",
            agent_id=expected_agent_id,
            result=f"failure:{type(exc).__name__}",
        )
        raise HTTPException(
            status_code=403,
            detail="Certificate identity verification failed.",
        ) from exc


def _parse_token(token_str: str) -> AccessToken:
    """Parse a Phase 3 AccessToken from its JSON representation."""
    try:
        return AccessToken.from_dict(json.loads(token_str))
    except Exception as exc:
        raise TokenVerifyError(f"Invalid token format: {exc}") from exc


def _verify_token_from_str(token_str: str, agent_cert: bytes) -> AccessToken:
    """Parse and verify a Phase 3 AccessToken string (signature + cert binding)."""
    token = _parse_token(token_str)
    verify_token_binding(token, agent_cert, _revocation_store, _verify_key_bytes)
    return token


def _get_agent_tlp_level(agent_id: str) -> TlpLevel:
    """Load TLP level for agent from vault config; default GREEN."""
    try:
        agent_perms = vault.get_secret(_vault_dict, f"agent_permissions.{agent_id}")
        if isinstance(agent_perms, str):
            agent_perms = json.loads(agent_perms)
        if isinstance(agent_perms, dict):
            level_str = agent_perms.get("tlp_level", "GREEN")
            return TlpLevel(level_str)
    except (KeyError, ValueError, RuntimeError):
        pass
    return TlpLevel.GREEN


def _check_agent_id_match(
    req_agent_id: str,
    token: AccessToken,
) -> str:
    """
    Verify that the agent_id in the request matches the
    agent_id in the cryptographically verified token.
    Returns the verified agent_id. Raises TokenVerifyError on mismatch.

    This is transport-agnostic (no HTTPException) so it can be
    called from both HTTP endpoints and WebSocket handlers.

    IMPORTANT: token must come from _verify_token_from_str(),
    not from _parse_token() alone — to stay inside the cryptographic boundary.
    """
    token_agent_id = token.agent_id
    if req_agent_id != token_agent_id:
        audit.log(
            action="agent_id_mismatch",
            agent_id=req_agent_id,
            result=f"failure:claimed={req_agent_id},"
                   f"token={token_agent_id}",
        )
        raise TokenVerifyError(
            f"Agent ID mismatch: claimed={req_agent_id}, "
            f"token={token_agent_id}"
        )
    return token_agent_id


def _verify_agent_identity(
    req_agent_id: str,
    token: AccessToken,
) -> str:
    """HTTP-layer wrapper that converts TokenVerifyError to HTTPException."""
    try:
        return _check_agent_id_match(req_agent_id, token)
    except TokenVerifyError:
        raise HTTPException(
            status_code=403,
            detail="Agent ID does not match token",
        )


def _get_agent_permissions(agent_id: str) -> dict:
    """
    Load agent permissions from the Guardian's local vault config.
    Permissions are NEVER taken from the agent's request — this is
    the core split-trust guarantee.
    """
    default_permissions = {
        "data_classifications": ["PUBLIC"],
        "vault_read": [],
        "vault_write": [],
        "tool_calls": [],
        "payment_execute": False,
    }

    try:
        agent_perms = vault.get_secret(
            _vault_dict, f"agent_permissions.{agent_id}",
        )
        if isinstance(agent_perms, str):
            return json.loads(agent_perms)
        elif isinstance(agent_perms, dict):
            return agent_perms
        return default_permissions
    except KeyError:
        audit.log(
            action="permissions.lookup",
            agent_id=agent_id,
            result="warning:no_configured_permissions,using_defaults",
        )
        return default_permissions


def _check_revoke_rate_limit(agent_id: str) -> None:
    """
    Simple in-memory rate limit: max 5 revocation requests per minute
    per agent_id. Raises HTTPException 429 if exceeded.
    """
    import time
    now = time.time()

    # Prevent memory DoS from many distinct agent_ids
    if len(_revoke_timestamps) > 10000:
        _revoke_timestamps.clear()

    timestamps = _revoke_timestamps.get(agent_id, [])
    timestamps = [t for t in timestamps if now - t < 60]
    if len(timestamps) >= 5:
        audit.log(
            action="revoke.rate_limited",
            agent_id=agent_id,
            result="failure:rate_limit_exceeded",
        )
        raise HTTPException(
            status_code=429,
            detail="Revocation rate limit exceeded",
        )
    timestamps.append(now)
    _revoke_timestamps[agent_id] = timestamps


def _append_audit_chain(
    *,
    agent_id: str,
    method: str,
    decision: Decision,
    reason_code: str,
    partition_id: str = "",
    params: Optional[dict] = None,
) -> None:
    """Best-effort wrapper for writing to the cryptographic audit chain."""
    if _audit_chain is None:
        return
    _audit_chain.append(
        agent_id=agent_id,
        partition_id=partition_id,
        method=method,
        params=params or {},
        decision=decision,
        reason_code=reason_code,
    )


def _persist_revocation_state(state: dict, passphrase: str) -> None:
    """Persist revocation state into the unlocked vault."""
    if _vault_dict is None:
        raise RuntimeError("Vault is not unlocked.")
    if "revocation_state" not in _vault_dict:
        _vault_dict["revocation_state"] = "{}"
    vault.rotate_secret(
        _vault_dict,
        "revocation_state",
        json.dumps(state, sort_keys=True),
        passphrase,
    )


async def _invalidate_existing_session(agent_id: str) -> None:
    """
    Revoke session-issued tokens, stop any WS connection, and remove the session.
    If any step fails, abort new session creation (fail closed).
    """
    from guardian.session_state import get_session, remove_session

    existing = get_session(agent_id)
    if existing is None or not existing.active:
        return

    try:
        for token_id in sorted(existing.token_ids):
            _revocation_store.revoke_token(token_id)
        audit.log(
            action="session.replace",
            agent_id=agent_id,
            result=f"revoked_tokens:{len(existing.token_ids)}",
        )
        _append_audit_chain(
            agent_id=agent_id,
            method="session.replace",
            decision=Decision.DENY,
            reason_code="revoked_prior_session_tokens",
            params={"count": len(existing.token_ids)},
        )

        ws_client = _ws_clients.pop(agent_id, None)
        if ws_client:
            await ws_client.stop()
            audit.log(
                action="session.replace",
                agent_id=agent_id,
                result="ws_closed",
            )
            _append_audit_chain(
                agent_id=agent_id,
                method="session.replace",
                decision=Decision.DENY,
                reason_code="prior_session_ws_closed",
            )

        remove_session(agent_id)
        audit.log(
            action="session.replaced",
            agent_id=agent_id,
            result="previous_session_closed",
        )
        _append_audit_chain(
            agent_id=agent_id,
            method="session.replace",
            decision=Decision.DENY,
            reason_code="prior_session_removed",
        )
    except Exception as exc:
        audit.log(
            action="session.replace",
            agent_id=agent_id,
            result=f"failure:{type(exc).__name__}:{exc}",
        )
        _append_audit_chain(
            agent_id=agent_id,
            method="session.replace",
            decision=Decision.DENY,
            reason_code="prior_session_invalidation_failed",
        )
        raise HTTPException(
            status_code=500,
            detail="Existing session invalidation failed.",
        ) from exc


# ---------------------------------------------------------------------------
# Internal functions — shared by HTTP and WebSocket handlers
# ---------------------------------------------------------------------------

async def _execute_tool_internal(
    token_str: str,
    agent_cert: bytes,
    agent_id: str,
    tool_name: str,
    action: str,
    params: dict,
    partition_id: str = "",
) -> dict:
    """
    Execute a tool call with Phase 3 authorization.
    Transport-agnostic: called by both HTTP endpoint and WS router.
    Raises TokenVerifyError, ToolNotPermittedError, or Exception.
    """
    token = _verify_token_from_str(token_str, agent_cert)
    _check_agent_id_match(agent_id, token)
    return await execute_tool_call(
        agent_id=agent_id,
        token=token,
        tool_name=tool_name,
        action=action,
        params=params,
        partition_id=partition_id,
    )


async def _check_partition_internal(
    token_str: str,
    agent_cert: bytes,
    agent_id: str,
    key: str,
    action: str = "data.request",
) -> dict:
    """
    Check partition access using Phase 3 enforcement.
    Guardian resolves the partition from the key — agents never supply partition names.
    Transport-agnostic: called by both HTTP endpoint and WS router.
    Raises EnforcementDenied if the agent is not authorized.
    """
    token = _verify_token_from_str(token_str, agent_cert)
    _check_agent_id_match(agent_id, token)

    vault_items = vault._get_vault_items_unfiltered(_vault_dict)
    all_partitions = list({item.owner_partition for item in vault_items.values()})

    request = VaultRequest(
        key=key,
        params={},
        request_id=str(uuid.uuid4()),
        token=token,
        peer_der_cert=agent_cert,
    )
    item = await _enforce(
        request,
        vault_items=vault_items,
        revocation_store=_revocation_store,
        verify_key_bytes=_verify_key_bytes,
        deduplicator=_deduplicator,
        audit_chain=_audit_chain,
        known_partitions=all_partitions,
    )
    return {
        "allowed": True,
        "partition": item.owner_partition,
        "agent_id": agent_id,
    }


async def _execute_payment_internal(
    token_str: str,
    agent_cert: bytes,
    agent_id: str,
    payment_request: PaymentRequest,
) -> dict:
    """
    Execute a payment with Phase 3 authorization.
    Transport-agnostic: called by both HTTP endpoint and WS router.
    Raises TokenVerifyError, PaymentDeniedError, PaymentTimeoutError, ValueError.
    """
    token = _verify_token_from_str(token_str, agent_cert)
    _check_agent_id_match(agent_id, token)
    # Build a compatible permissions dict for the payments module
    permissions = {
        "payment_execute": "payment.execute" in token.operations,
        "vault_read": token.partitions,
        "tool_calls": token.operations,
    }
    result = await execute_payment(agent_id, permissions, payment_request)
    return result.model_dump()


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup and shutdown lifecycle for the Guardian.

    Startup order:
      1. Initialise audit log
      2. Unlock vault (passphrase from environment or prompt)
      2b. Verify master SOUL.lock (and any agent SOULs)
      3. Initialise token module
      4. Initialise tools module
      5. Initialise payments module
      6. Initialise LLM keys module

    Shutdown order:
      1. Stop all heartbeats
      2. Lock vault
    """
    global _vault_dict, _audit_chain
    global _signing_key_bytes, _verify_key_bytes, _revocation_store, _deduplicator

    # --- STARTUP ---
    # 1. Audit log
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    audit.init_audit_log(AUDIT_DB_PATH)
    audit.log(action="guardian.startup", result="audit_initialised")

    # 1b. Audit chain (append-only cryptographic chain for ALLOW/DENY/ELEVATE)
    # FIX 4: load or generate HMAC key for the chain from the environment/vault.
    # The key is kept in memory and never written to the audit DB itself.
    _audit_chain_key_hex = os.environ.get("MAHAGUARDIAN_AUDIT_HMAC_KEY", "")
    if _audit_chain_key_hex:
        _audit_chain_key = bytes.fromhex(_audit_chain_key_hex)
    else:
        import secrets as _secrets
        _audit_chain_key = _secrets.token_bytes(32)
        audit.log(action="guardian.startup",
                  result="warning:audit_hmac_key_not_set:generated_ephemeral")
    _audit_chain = AuditChain(AUDIT_DB_PATH.parent / "audit_chain.db",
                              hmac_key=_audit_chain_key)
    audit.log(action="guardian.startup", result="audit_chain_initialised")

    # 2. Vault
    passphrase = os.environ.get("MAHAGUARDIAN_PASSPHRASE", "")
    if not passphrase:
        # Phase 1: allow empty passphrase for development
        # Production will require passphrase from secure input
        audit.log(
            action="guardian.startup",
            result="warning:no_passphrase_set",
        )
    try:
        _vault_dict = vault.unlock_vault(passphrase)
        audit.log(action="guardian.startup", result="vault_unlocked")
    except Exception as exc:
        audit.log(
            action="guardian.startup",
            result=f"failure:vault_unlock_failed:{exc}",
        )
        sys.exit(1)

    # 2b. Verify SOUL.lock signatures
    # Guardian MUST NOT start without a verified master SOUL.
    master_soul_path = CORE_DIR / "master-SOUL.lock"
    if not master_soul_path.exists():
        audit.log(
            action="guardian.startup",
            result="failure:master_soul_not_found",
        )
        print(
            "FATAL: master-SOUL.lock not found. "
            "Run 'mahaguardian init' first."
        )
        sys.exit(1)

    try:
        soul_pubkey_b64 = vault.get_secret(
            _vault_dict, "signing_keys.soul_public_key",
            allow_protected=True,
        )
        soul_pubkey = base64.b64decode(soul_pubkey_b64)

        # Verify master SOUL
        verify_soul(master_soul_path, soul_pubkey)
        audit.log(
            action="guardian.startup",
            result="soul_master_verified",
        )

        # Verify all agent SOULs
        if AGENTS_SOUL_DIR.exists():
            for agent_soul in AGENTS_SOUL_DIR.glob("*-SOUL.lock"):
                verify_soul(agent_soul, soul_pubkey)
                audit.log(
                    action="guardian.startup",
                    result=f"soul_agent_verified:{agent_soul.name}",
                )
    except (SOULTamperError, KeyError) as exc:
        audit.log(
            action="guardian.startup",
            result=f"failure:soul_verification_failed:{exc}",
        )
        sys.exit(1)

    # 3. Token module (Phase 3 — shared.token)
    try:
        token_signing = _vault_dict.get("signing_keys", {}) if _vault_dict else {}
        sk_hex = token_signing.get("token_signing_key", "")
        vk_hex = token_signing.get("token_verify_key", "")
        if sk_hex and vk_hex:
            _signing_key_bytes = bytes.fromhex(sk_hex)
            _verify_key_bytes = bytes.fromhex(vk_hex)
        else:
            # Generate ephemeral keypair for this session
            import nacl.signing as _nacl_signing
            _sk_obj = _nacl_signing.SigningKey.generate()
            _signing_key_bytes = bytes(_sk_obj)
            _verify_key_bytes = bytes(_sk_obj.verify_key)
            audit.log(action="guardian.startup",
                      result="warning:token_keypair_ephemeral:no_keys_in_vault")
        try:
            raw_revocation_state = vault.get_secret(_vault_dict, "revocation_state")
            if isinstance(raw_revocation_state, str):
                revocation_state = json.loads(raw_revocation_state)
            else:
                revocation_state = raw_revocation_state
        except KeyError:
            revocation_state = {
                "revoked_tokens": {},
                "revoked_agents": {},
            }
            audit.log(
                action="guardian.startup",
                result="revocation_store_initialised_empty",
            )

        _revocation_store = RevocationStore(
            persist_callback=lambda state: _persist_revocation_state(state, passphrase)
        )
        _revocation_store.load(revocation_state)
        _deduplicator = RequestDeduplicator()
        audit.log(action="guardian.startup", result="tokens_initialised")
    except Exception as exc:
        audit.log(
            action="guardian.startup",
            result=f"failure:tokens_init_failed:{exc}",
        )
        sys.exit(1)

    # 4. Tools module
    init_tools(_vault_dict)
    audit.log(action="guardian.startup", result="tools_initialised")

    # 4b. MCP client manager
    from guardian.mcp_client import init_mcp
    init_mcp(_vault_dict)
    audit.log(action="guardian.startup", result="mcp_initialised")

    # 5. Payments module
    init_payments(_vault_dict)
    audit.log(action="guardian.startup", result="payments_initialised")

    # 6. LLM keys module
    init_llm_keys(_vault_dict)
    audit.log(action="guardian.startup", result="llm_keys_initialised")

    audit.log(action="guardian.startup", result="complete")

    yield

    # --- SHUTDOWN ---
    audit.log(action="guardian.shutdown", result="initiated")

    # 1. Stop all WebSocket connections
    for agent_id, ws_client in list(_ws_clients.items()):
        try:
            await ws_client.stop()
        except Exception:
            pass
    _ws_clients.clear()

    # 2. Stop all heartbeats
    for agent_id in list(_active_agents):
        try:
            stop_heartbeat(agent_id)
        except Exception:
            pass
    _active_agents.clear()

    # 2b. Close MCP connections
    from guardian.mcp_client import close_mcp
    await close_mcp()

    # 2c. Clear session state
    from guardian.session_state import clear_all as _clear_sessions
    _clear_sessions()

    # 3. Lock vault
    if _vault_dict is not None:
        vault.lock_vault(_vault_dict)
        _vault_dict = None

    audit.log(action="guardian.shutdown", result="complete")


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="MahaGuardian Guardian",
    description="Central control plane for MahaGuardian agent security.",
    version="0.4.0",
    lifespan=lifespan,
)

app.add_middleware(PeerCertMiddleware)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "vault_unlocked": _vault_dict is not None,
        "active_agents": len(_active_agents),
    }


# ---------------------------------------------------------------------------
# Session endpoint
# ---------------------------------------------------------------------------

@app.post("/session/start")
async def api_start_session(req: SessionStartRequest, request: Request):
    """
    Start agent session.

    1. Verify master SOUL signature and hash
    2. Verify agent SOUL signature and hash
    3. Merge SOULs (using verified bytes — TOCTOU safe)
    4. Generate system prompt
    5. Issue Guardian Access Token
    6. Return session_id, token, and system prompt
    """
    await _invalidate_existing_session(req.agent_id)

    agent_cert = _get_agent_cert(request)
    _verify_cert_and_agent_id(agent_cert, req.agent_id)

    # Get SOUL public key from vault
    try:
        soul_pubkey_b64 = vault.get_secret(
            _vault_dict, "signing_keys.soul_public_key",
            allow_protected=True,
        )
        soul_pubkey = base64.b64decode(soul_pubkey_b64)
    except (KeyError, RuntimeError) as exc:
        raise HTTPException(
            status_code=500,
            detail=f"SOUL public key not available: {exc}",
        )

    master_soul_path = CORE_DIR / "master-SOUL.lock"
    agent_soul_path = AGENTS_SOUL_DIR / f"{req.agent_id}-SOUL.lock"

    # Verify and get bytes (TOCTOU safe — returns verified bytes)
    try:
        master_bytes = verify_soul(master_soul_path, soul_pubkey)
        agent_bytes = verify_soul(agent_soul_path, soul_pubkey)
    except FileNotFoundError as exc:
        audit.log(
            action="session.start",
            agent_id=req.agent_id,
            result=f"failure:soul_not_found:{exc}",
        )
        raise HTTPException(
            status_code=404,
            detail=f"SOUL file not found: {exc}",
        )
    except SOULTamperError as exc:
        audit.log(
            action="session.start",
            agent_id=req.agent_id,
            result=f"failure:soul_tampered:{exc}",
        )
        raise HTTPException(status_code=403, detail=str(exc))

    # Merge using verified bytes (not re-reading from disk)
    try:
        merged = merge_souls(
            master_bytes, agent_bytes,
            master_name="master", agent_name=req.agent_id,
        )
    except SOULConflictError as exc:
        audit.log(
            action="session.start",
            agent_id=req.agent_id,
            result=f"failure:soul_conflict:{exc}",
        )
        raise HTTPException(status_code=403, detail=str(exc))

    # FIX 2: route through derive_instruction_set so the SOUL leak scanner
    # (partition names, TLP labels) is enforced on every session start.
    _all_partitions = list({
        item.owner_partition
        for item in vault._get_vault_items_unfiltered(_vault_dict).values()
    })
    try:
        system_prompt = derive_instruction_set(
            merged,
            known_partitions=_all_partitions,
        )
    except SOULLeakError as exc:
        audit.log(
            action="session.start",
            agent_id=req.agent_id,
            result=f"failure:soul_leak:{exc}",
        )
        raise HTTPException(status_code=403, detail="SOUL integrity check failed")

    # Derive permissions from Guardian's local vault config
    # NEVER from the agent's request
    granted_permissions = _get_agent_permissions(req.agent_id)

    # Issue Phase 3 token
    try:
        _now = datetime.now(timezone.utc)
        _partitions = granted_permissions.get("vault_read", [])
        _operations = list(granted_permissions.get("tool_calls", []))
        if granted_permissions.get("payment_execute"):
            _operations.append("payment.execute")
        _token_obj = _phase3_issue_token(
            agent_id=req.agent_id,
            partitions=_partitions,
            tlp_level=_get_agent_tlp_level(req.agent_id),
            operations=_operations,
            agent_der_cert=agent_cert,
            issued_at=_now.isoformat(),
            expires_at=(_now + timedelta(hours=TOKEN_LIFETIME_HOURS)).isoformat(),
            issuer="guardian",
            signing_key_bytes=_signing_key_bytes,
        )
        token_str = _token_obj.to_json()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    session_id = f"sess-{uuid.uuid4().hex[:12]}"

    # Retrieve LLM key from vault (NEVER log the key value)
    llm_provider = "anthropic"
    llm_key = None
    rotation_id = None
    try:
        llm_key = vault.get_secret(
            _vault_dict, f"llm_api_keys.{llm_provider}",
        )
        rotation_id = str(uuid.uuid4())
    except KeyError:
        pass  # No LLM key configured — session starts without one

    # Determine if agent is primary or external from vault
    is_primary = True
    try:
        external_list = vault.get_secret(_vault_dict, "external_agents")
        if isinstance(external_list, str):
            external_list = json.loads(external_list)
        if isinstance(external_list, list):
            is_primary = req.agent_id not in external_list
    except KeyError:
        pass  # No external_agents configured — Phase 1 single-agent

    # Register session in state registry
    from guardian.session_state import SessionInfo, register_session
    register_session(SessionInfo(
        agent_id=req.agent_id,
        session_id=session_id,
        llm_provider=llm_provider,
        is_primary=is_primary,
        token_ids={_token_obj.token_id},
    ))

    if not is_primary:
        audit.log(
            action="session.start",
            agent_id=req.agent_id,
            result="registered_as_external_agent",
        )

    # Start WS-based key rotation if agent has a WebSocket connection
    if llm_key and req.agent_id in _ws_clients:
        from guardian.llm_keys import schedule_ws_rotation
        try:
            await schedule_ws_rotation(
                agent_id=req.agent_id,
                ws_client=_ws_clients[req.agent_id],
                provider=llm_provider,
            )
        except Exception:
            pass  # Rotation scheduling failure is non-fatal

    # SECURITY: llm_key MUST NOT appear in audit log
    audit.log(
        action="session.start",
        agent_id=req.agent_id,
        result=f"success:session={session_id}",
    )

    response = {
        "session_id": session_id,
        "system_prompt": system_prompt,
        "token": token_str,
    }

    # Include LLM key only if retrieved from vault
    if llm_key:
        response["llm_key"] = llm_key
        response["llm_provider"] = llm_provider
        response["rotation_id"] = rotation_id

    return response


# ---------------------------------------------------------------------------
# Token endpoints
# ---------------------------------------------------------------------------

@app.post("/tokens/issue")
async def api_issue_token(req: TokenIssueRequest, request: Request):
    """Issue a new Guardian Access Token for an agent."""
    agent_cert = _get_agent_cert(request)
    _verify_cert_and_agent_id(agent_cert, req.agent_id)

    # Derive permissions from Guardian's local vault config
    # NEVER from the agent's request
    granted_permissions = _get_agent_permissions(req.agent_id)

    try:
        _now = datetime.now(timezone.utc)
        _partitions = granted_permissions.get("vault_read", [])
        _operations = list(granted_permissions.get("tool_calls", []))
        if granted_permissions.get("payment_execute"):
            _operations.append("payment.execute")
        _token_obj = _phase3_issue_token(
            agent_id=req.agent_id,
            partitions=_partitions,
            tlp_level=_get_agent_tlp_level(req.agent_id),
            operations=_operations,
            agent_der_cert=agent_cert,
            issued_at=_now.isoformat(),
            expires_at=(_now + timedelta(hours=TOKEN_LIFETIME_HOURS)).isoformat(),
            issuer="guardian",
            signing_key_bytes=_signing_key_bytes,
        )
        token_str = _token_obj.to_json()
        from guardian.session_state import add_token_id
        add_token_id(req.agent_id, _token_obj.token_id)
        return {"token": token_str}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/tokens/verify")
async def api_verify_token(req: TokenVerifyRequest, request: Request):
    """Verify a Phase 3 Guardian Access Token."""
    agent_cert = _get_agent_cert(request)
    try:
        token = _verify_token_from_str(req.token_str, agent_cert)
        return {
            "valid": True,
            "partitions": token.partitions,
            "operations": token.operations,
            "tlp_level": token.tlp_level.value if hasattr(token.tlp_level, "value") else str(token.tlp_level),
        }
    except TokenVerifyError as exc:
        return {"valid": False, "error": str(exc)}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/tokens/revoke")
async def api_revoke_token(req: TokenRevokeRequest, request: Request):
    """
    Revoke a specific token.

    Requires a valid signed token for the SAME agent — you can
    revoke your own tokens but not another agent's.

    NOTE: Agents can only revoke tokens they can present.
    If a token is suspected leaked but the agent no longer
    has it, use the bulk revoke-all endpoint with admin
    passphrase to revoke all tokens for that agent.
    """
    agent_cert = _get_agent_cert(request)
    try:
        token = _verify_token_from_str(req.token_str, agent_cert)
    except TokenVerifyError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    # Verify agent identity from crypto boundary
    _verify_agent_identity(req.agent_id, token)

    # Extract token_id from VERIFIED token, not request body
    target_token_id = token.token_id

    _check_revoke_rate_limit(req.agent_id)
    _revocation_store.revoke_token(target_token_id)
    from guardian.session_state import discard_token_id
    discard_token_id(req.agent_id, target_token_id)

    return {"revoked": True, "token_id": target_token_id}


@app.post("/tokens/revoke-all")
async def api_revoke_all_tokens(req: TokenRevokeAllRequest):
    """
    Revoke all tokens for an agent.

    Requires admin passphrase authentication — bulk revocation
    is a privileged operation.
    """
    import hashlib as _hl
    import hmac as _hmac

    _check_revoke_rate_limit(req.agent_id)

    # Verify admin passphrase against stored hash
    try:
        expected_hash = vault.get_secret(
            _vault_dict, "admin_passphrase_hash",
        )
    except (KeyError, RuntimeError):
        audit.log(
            action="tokens.revoke_all",
            agent_id=req.agent_id,
            result="failure:no_admin_hash_configured",
        )
        raise HTTPException(
            status_code=500,
            detail="Admin passphrase hash not configured in vault",
        )

    # Hash once — timing-safe compare against stored hash
    provided_hash = _hl.sha256(
        req.admin_passphrase.encode("utf-8")
    ).hexdigest()
    if not _hmac.compare_digest(provided_hash, expected_hash):
        audit.log(
            action="tokens.revoke_all",
            agent_id=req.agent_id,
            result="failure:invalid_admin_auth",
        )
        raise HTTPException(
            status_code=403,
            detail="Admin authentication failed",
        )

    try:
        _revocation_store.revoke_agent(req.agent_id)
        audit.log(
            action="tokens.revoke_all",
            agent_id=req.agent_id,
            result="success",
        )
        return {"revoked": True, "agent_id": req.agent_id}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ---------------------------------------------------------------------------
# Enforcer endpoints
# ---------------------------------------------------------------------------

@app.post("/enforce/partition")
async def api_enforce_partition(req: PartitionAccessRequest, request: Request):
    """Check partition access for an agent token. Guardian resolves the partition from the key."""
    agent_cert = _get_agent_cert(request)
    try:
        return await _check_partition_internal(
            req.token_str, agent_cert, req.agent_id,
            req.key, req.action,
        )
    except TokenVerifyError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    except EnforcementDenied as exc:
        raise HTTPException(status_code=403, detail=exc.safe_message)


# ---------------------------------------------------------------------------
# Tool endpoints
# ---------------------------------------------------------------------------

@app.post("/tools/execute")
async def api_execute_tool(req: ToolCallRequest, request: Request):
    """Execute a tool call with authorization enforcement."""
    agent_cert = _get_agent_cert(request)
    try:
        return await _execute_tool_internal(
            req.token_str, agent_cert, req.agent_id,
            req.tool_name, req.action, req.params,
            req.partition_id,
        )
    except TokenVerifyError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    except ToolNotPermittedError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Payment endpoints
# ---------------------------------------------------------------------------

@app.post("/payments/execute")
async def api_execute_payment(req: PaymentExecuteRequest, request: Request):
    """Execute a payment with policy enforcement and approval flow."""
    agent_cert = _get_agent_cert(request)
    try:
        return await _execute_payment_internal(
            req.token_str, agent_cert, req.agent_id,
            req.payment_request,
        )
    except TokenVerifyError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    except PaymentTimeoutError as exc:
        raise HTTPException(status_code=408, detail=str(exc))
    except PaymentDeniedError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Heartbeat endpoints
# ---------------------------------------------------------------------------

@app.post("/heartbeat/start")
async def api_start_heartbeat(req: HeartbeatStartRequest):
    """Start LLM key rotation heartbeat for an agent."""
    try:
        # Phase 1: mtls_connection is not available via HTTP API.
        # This endpoint is called internally by the Guardian session manager
        # which passes the real mTLS connection. For the HTTP API,
        # we return an error explaining this.
        raise HTTPException(
            status_code=501,
            detail=(
                "Heartbeat start requires an mTLS connection object. "
                "Use the internal Guardian session manager."
            ),
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/heartbeat/stop")
async def api_stop_heartbeat(req: HeartbeatStopRequest):
    """Stop LLM key rotation heartbeat for an agent."""
    try:
        stop_heartbeat(req.agent_id)
        _active_agents.discard(req.agent_id)
        return {"stopped": True, "agent_id": req.agent_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Skills endpoints
# ---------------------------------------------------------------------------

@app.post("/skills/verify")
async def api_verify_skill(req: SkillVerifyRequest, request: Request):
    """Verify a skill file against its manifest."""
    agent_cert = _get_agent_cert(request)
    try:
        token = _verify_token_from_str(req.token_str, agent_cert)
    except TokenVerifyError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    _verify_agent_identity(req.agent_id, token)

    # Validate paths don't traverse outside skills directory
    if ".." in req.skill_path or ".." in req.manifest_path:
        raise HTTPException(
            status_code=400,
            detail="Path traversal not permitted",
        )

    # Block absolute paths and ensure resolution stays within SKILLS_DIR
    skills_root = SKILLS_DIR.resolve()
    resolved_skill = (SKILLS_DIR / req.skill_path).resolve()
    if not resolved_skill.is_relative_to(skills_root):
        audit.log(
            action="skills.path_traversal_blocked",
            agent_id=req.agent_id,
            result=f"failure:path_escape:{req.skill_path}",
        )
        raise HTTPException(
            status_code=400,
            detail="Skill path must be within the skills directory",
        )

    resolved_manifest = (SKILLS_DIR / req.manifest_path).resolve()
    if not resolved_manifest.is_relative_to(skills_root):
        audit.log(
            action="skills.path_traversal_blocked",
            agent_id=req.agent_id,
            result=f"failure:path_escape:{req.manifest_path}",
        )
        raise HTTPException(
            status_code=400,
            detail="Manifest path must be within the skills directory",
        )

    try:
        valid = verify_skill(Path(req.skill_path), Path(req.manifest_path))
        return {"verified": valid}
    except SkillVerificationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/skills/load")
async def api_load_skills(req: SkillLoadRequest, request: Request):
    """Load all verified skills for an agent."""
    agent_cert = _get_agent_cert(request)
    try:
        token = _verify_token_from_str(req.token_str, agent_cert)
    except TokenVerifyError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    _verify_agent_identity(req.agent_id, token)

    try:
        skills = load_verified_skills(req.agent_id)
        return {"skills": skills, "count": len(skills)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Audit endpoints
# ---------------------------------------------------------------------------

@app.post("/audit/query")
async def api_query_audit(req: AuditQueryRequest, request: Request):
    """Query the audit log. Agents can only query their own logs."""
    agent_cert = _get_agent_cert(request)
    try:
        token = _verify_token_from_str(req.token_str, agent_cert)
    except TokenVerifyError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    _verify_agent_identity(req.requesting_agent_id, token)

    # Agents can only query their own logs unless they
    # have audit_read_all permission
    if "audit_read_all" not in token.operations:
        if req.agent_id and req.agent_id != req.requesting_agent_id:
            audit.log(
                action="audit.query_blocked",
                agent_id=req.requesting_agent_id,
                result=f"failure:cross_agent_query:{req.agent_id}",
            )
            raise HTTPException(
                status_code=403,
                detail="Cannot query other agents' logs",
            )
        req.agent_id = req.requesting_agent_id

    try:
        entries = audit.query_log(
            agent_id=req.agent_id,
            action=req.action,
            partition_id=req.partition_id,
            from_timestamp=req.from_timestamp,
            to_timestamp=req.to_timestamp,
        )
        # FIX 5: normalize all denial reasons to "denied" so agents cannot
        # distinguish "not_found" from "tlp_insufficient" by probing audit.
        for entry in entries:
            if isinstance(entry.get("result"), str) and entry["result"].startswith("denied:"):
                entry["result"] = "denied"
        return {"entries": entries, "count": len(entries)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/audit/integrity")
async def api_verify_audit_integrity(req: AuditIntegrityRequest, request: Request):
    """Verify audit log hash chain integrity. Requires audit_read_all."""
    agent_cert = _get_agent_cert(request)
    try:
        token = _verify_token_from_str(req.token_str, agent_cert)
    except TokenVerifyError as exc:
        raise HTTPException(status_code=401, detail=str(exc))

    _verify_agent_identity(req.agent_id, token)

    if "audit_read_all" not in token.operations:
        raise HTTPException(
            status_code=403,
            detail="audit_read_all permission required for integrity scans",
        )

    try:
        intact = audit.verify_log_integrity(AUDIT_DB_PATH)
        return {"intact": intact}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _build_guardian_ssl_context():
    """
    Build SSL context for Guardian's local HTTPS server.
    Requires client certificate for mTLS.
    Returns None if cert files don't exist.
    """
    import ssl as _ssl
    if not GUARDIAN_CERT_PATH.exists() or not GUARDIAN_KEY_PATH.exists():
        return None
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    passphrase = os.environ.get("MAHAGUARDIAN_PASSPHRASE", "")
    pw = passphrase.encode("utf-8") if passphrase else None
    ctx.load_cert_chain(
        certfile=str(GUARDIAN_CERT_PATH),
        keyfile=str(GUARDIAN_KEY_PATH),
        password=pw,
    )
    if CA_CERT_PATH.exists():
        ctx.load_verify_locations(cafile=str(CA_CERT_PATH))
    ctx.verify_mode = _ssl.CERT_REQUIRED
    ctx.check_hostname = False  # we verify CN manually
    return ctx


def main() -> None:
    """Run the Guardian server. Binds to 127.0.0.1 ONLY."""
    import uvicorn
    ssl_ctx = _build_guardian_ssl_context()
    kwargs = {
        "host": GUARDIAN_HOST,  # 127.0.0.1 -- NEVER 0.0.0.0
        "port": GUARDIAN_PORT,
        "log_level": "info",
    }
    if ssl_ctx:
        kwargs["ssl"] = ssl_ctx
    uvicorn.run(app, **kwargs)


if __name__ == "__main__":
    main()
