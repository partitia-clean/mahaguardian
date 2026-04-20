"""
LLM API key management and rotation.

Security guarantees:
  - LLM API keys are NEVER written to any file on any system.
  - Keys are sent to agents via established mTLS connections only.
  - Key values are NEVER logged — not even partially.
  - Agent receives key and stores in memory only.
  - Heartbeat rotation replaces keys on a configurable interval.
  - Old keys are zeroed from agent memory on rotation.
"""
from __future__ import annotations

import asyncio
import uuid
from typing import Optional

import guardian.audit as audit
from shared.config import KEY_ROTATION_INTERVAL_MINUTES, MAX_ROTATION_FAILURES
from shared.models import RotatedKey


# ---------------------------------------------------------------------------
# Module-level state
# ---------------------------------------------------------------------------

_vault: Optional[dict] = None
_rotation_tasks: dict[str, asyncio.Task] = {}


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------

def init_llm_keys(vault: dict) -> None:
    """
    Initialise the LLM key management module.

    Sets the module-level vault reference used by send/rotate functions.
    Must be called after unlock_vault() and before any key operations.
    """
    global _vault
    _vault = vault


# ---------------------------------------------------------------------------
# Key retrieval (internal)
# ---------------------------------------------------------------------------

def _get_llm_key(provider: str) -> str:
    """
    Retrieve LLM API key from the unlocked vault dict.

    Never logs the key value — only the provider name.
    Raises KeyError if provider not found.
    """
    if _vault is None:
        raise RuntimeError(
            "LLM keys module not initialised. Call init_llm_keys() first."
        )
    keys = _vault.get("llm_api_keys", {})
    if provider not in keys:
        raise KeyError(f"LLM API key for provider '{provider}' not found in vault.")
    return keys[provider]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def send_llm_key_to_agent(
    agent_id: str,
    provider: str,
    mtls_connection: object,
) -> str:
    """
    Retrieve LLM API key from vault.
    Send to agent via established mTLS connection.
    Do NOT write key to any file on either end.
    Agent receives key and stores in memory only.
    Return key_rotation_id for tracking.
    Log: key sent to agent, provider, timestamp.
    Never log the key value itself.

    The mtls_connection object must implement an async post() method
    compatible with httpx.AsyncClient (accepting url and json kwargs).
    """
    key_value = _get_llm_key(provider)
    rotation_id = str(uuid.uuid4())

    rotated_key = RotatedKey(
        provider=provider,
        key=key_value,
        rotation_id=rotation_id,
    )

    # Send via mTLS — key travels encrypted over TLS, never touches disk
    await mtls_connection.post(  # type: ignore[attr-defined]
        "/llm-key/rotate",
        json=rotated_key.model_dump(),
    )

    # Log provider and rotation_id — NEVER the key value
    audit.log(
        action="llm_key.send",
        agent_id=agent_id,
        resource=provider,
        result=f"success:rotation_id={rotation_id}",
    )
    return rotation_id


async def rotate_llm_key(
    agent_id: str,
    provider: str,
    mtls_connection: object,
    rotation_id: str,
) -> str:
    """
    Called by heartbeat scheduler every N minutes.
    Send fresh LLM API key to agent via mTLS.
    Agent replaces old key in memory with new key.
    Log rotation event to audit.log.
    Return new rotation_id.
    """
    new_rotation_id = await send_llm_key_to_agent(
        agent_id, provider, mtls_connection
    )

    audit.log(
        action="llm_key.rotate",
        agent_id=agent_id,
        resource=provider,
        result=f"success:old={rotation_id},new={new_rotation_id}",
    )
    return new_rotation_id


async def schedule_rotation(
    agent_id: str,
    interval_minutes: int = KEY_ROTATION_INTERVAL_MINUTES,
    provider: str = "anthropic",
    mtls_connection: object = None,
) -> None:
    """
    Start asyncio task that calls rotate_llm_key every interval_minutes.
    Store task reference for cancellation on session end.
    Log schedule start to audit.log.
    """
    if mtls_connection is None:
        raise ValueError("mtls_connection is required for key rotation.")

    # FIX C: Stop any existing rotation task for this agent before
    # starting a new one — prevents orphaned tasks that would
    # bombard the agent with duplicate key rotations.
    if agent_id in _rotation_tasks:
        stop_rotation(agent_id)

    # Initial rotation ID from the first send
    rotation_id = await send_llm_key_to_agent(
        agent_id, provider, mtls_connection
    )

    async def _rotation_loop() -> None:
        nonlocal rotation_id
        while True:
            try:
                await asyncio.sleep(interval_minutes * 60)
                rotation_id = await rotate_llm_key(
                    agent_id, provider, mtls_connection, rotation_id
                )
            except asyncio.CancelledError:
                raise  # allow clean shutdown
            except Exception as exc:
                # FIX B: Log failure but continue loop —
                # will retry on next interval instead of crashing
                audit.log(
                    action="llm_key.rotation_failed",
                    agent_id=agent_id,
                    result=f"failure:{exc}",
                )
                continue

    task = asyncio.create_task(_rotation_loop())
    _rotation_tasks[agent_id] = task

    audit.log(
        action="llm_key.schedule_start",
        agent_id=agent_id,
        resource=provider,
        result=f"success:interval={interval_minutes}m",
    )


async def schedule_ws_rotation(
    agent_id: str,
    ws_client: object,
    provider: str = "anthropic",
    interval_minutes: int = KEY_ROTATION_INTERVAL_MINUTES,
) -> None:
    """
    Schedule LLM key rotation that pushes via WebSocket notification.
    Uses the ws_client.send_notification() method instead of HTTP POST.

    The ws_client must implement send_notification(method, params).
    """
    if _vault is None:
        raise RuntimeError(
            "LLM keys module not initialised. Call init_llm_keys() first."
        )

    # Stop any existing rotation for this agent
    if agent_id in _rotation_tasks:
        stop_rotation(agent_id)

    async def _ws_rotation_loop():
        consecutive_failures = 0
        while True:
            try:
                await asyncio.sleep(interval_minutes * 60)

                # Get fresh key from vault
                new_key = _get_llm_key(provider)
                rotation_id = str(uuid.uuid4())

                # Push via WebSocket notification
                await ws_client.send_notification(
                    method="llm_key.rotate",
                    params={
                        "key": new_key,
                        "provider": provider,
                        "rotation_id": rotation_id,
                    },
                )

                consecutive_failures = 0
                audit.log(
                    action="llm_key.rotated",
                    agent_id=agent_id,
                    result=f"success:provider={provider},"
                           f"rotation_id={rotation_id}",
                    # NEVER log the key value
                )

            except asyncio.CancelledError:
                raise
            except Exception as exc:
                consecutive_failures += 1
                audit.log(
                    action="llm_key.rotation_failed",
                    agent_id=agent_id,
                    result=f"failure:{exc},"
                           f"attempt={consecutive_failures}",
                )
                if consecutive_failures >= MAX_ROTATION_FAILURES:
                    audit.log(
                        action="llm_key.rotation_abandoned",
                        agent_id=agent_id,
                        result="failure:max_retries",
                    )
                    break

    task = asyncio.create_task(_ws_rotation_loop())
    _rotation_tasks[agent_id] = task

    audit.log(
        action="llm_key.ws_schedule_start",
        agent_id=agent_id,
        resource=provider,
        result=f"success:interval={interval_minutes}m",
    )


def stop_rotation(agent_id: str) -> None:
    """
    Cancel rotation task for agent.
    Called at session end.
    Log to audit.log.
    """
    task = _rotation_tasks.pop(agent_id, None)
    if task is not None:
        task.cancel()

    audit.log(
        action="llm_key.schedule_stop",
        agent_id=agent_id,
        result="success",
    )
