"""
In-memory session state registry.

Tracks active agent sessions, their connection details, and
whether they are primary or external agents. Used by:
- /session/start to register sessions
- payments module to determine payment source
- heartbeat to look up agent connection info
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass
class SessionInfo:
    agent_id: str
    session_id: str
    agent_host: str = ""
    agent_port: int = 8443
    llm_provider: str = "anthropic"
    is_primary: bool = True  # False for external agents
    active: bool = True


_sessions: dict[str, SessionInfo] = {}


def register_session(info: SessionInfo) -> None:
    """Register or update an agent session."""
    _sessions[info.agent_id] = info


def get_session(agent_id: str) -> Optional[SessionInfo]:
    """Get session info for an agent, or None if not registered."""
    return _sessions.get(agent_id)


def remove_session(agent_id: str) -> None:
    """Remove an agent session."""
    _sessions.pop(agent_id, None)


def is_external_agent(agent_id: str) -> bool:
    """
    Check if agent is external based on session state.
    Unknown agents default to external (secure default).
    """
    session = _sessions.get(agent_id)
    if session is None:
        return True  # Secure default: unknown = external
    return not session.is_primary


def clear_all() -> None:
    """Clear all sessions. Used during shutdown."""
    _sessions.clear()
