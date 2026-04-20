"""
Heartbeat wrapper around LLM key rotation.

Provides a clean start/stop interface for the Guardian main loop.
Delegates to llm_keys.schedule_rotation / stop_rotation which
already handle:
  - Crash recovery (retry on next interval)
  - Duplicate prevention (stops existing task before starting new)

This module exists as the public API surface so that main.py does
not need to know about llm_keys internals, and so that heartbeat
semantics (health checks, etc.) can be extended in Phase 2 without
changing main.py.
"""
from __future__ import annotations

import guardian.audit as audit
from guardian.llm_keys import schedule_rotation, stop_rotation
from shared.config import KEY_ROTATION_INTERVAL_MINUTES


async def start_heartbeat(
    agent_id: str,
    interval_minutes: int = KEY_ROTATION_INTERVAL_MINUTES,
    provider: str = "anthropic",
    mtls_connection: object = None,
) -> None:
    """
    Start the heartbeat for an agent session.

    Initiates LLM key rotation on the given interval.
    Delegates to llm_keys.schedule_rotation which handles:
      - Stopping any existing rotation for the same agent (no duplicates)
      - Sending initial key immediately
      - Scheduling periodic rotation
      - Crash-resilient retry on rotation failure

    Parameters
    ----------
    agent_id : str
        The agent to start heartbeat for.
    interval_minutes : int
        Minutes between key rotations.
    provider : str
        LLM provider name (must match a vault key).
    mtls_connection : object
        Established mTLS connection to the agent.
    """
    if mtls_connection is None:
        raise ValueError("mtls_connection is required for heartbeat.")

    await schedule_rotation(
        agent_id=agent_id,
        interval_minutes=interval_minutes,
        provider=provider,
        mtls_connection=mtls_connection,
    )

    audit.log(
        action="heartbeat.start",
        agent_id=agent_id,
        result=f"success:interval={interval_minutes}m,provider={provider}",
    )


def stop_heartbeat(agent_id: str) -> None:
    """
    Stop the heartbeat for an agent session.

    Cancels the LLM key rotation task.
    Called during session teardown / agent disconnect.
    """
    stop_rotation(agent_id)

    audit.log(
        action="heartbeat.stop",
        agent_id=agent_id,
        result="success",
    )
