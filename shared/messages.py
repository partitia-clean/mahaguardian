"""
JSON-RPC message protocol for Guardian ↔ Agent WebSocket communication.

Guardian initiates an outbound mTLS WebSocket connection to the agent.
Agent sends JSON-RPC requests over the WebSocket (tool calls, data
requests, payments). Guardian routes them through the enforcer and
responds over the same channel. Guardian pushes notifications (key
rotation, session termination) without expecting a response.
"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel


class WSRequest(BaseModel):
    """Agent → Guardian request over WebSocket."""
    jsonrpc: str = "2.0"
    method: str          # e.g. "tools.execute", "partition.check",
                         #      "payment.execute"
    params: dict = {}    # method-specific parameters
    id: str              # REQUIRED — requests without an id are rejected
                         # as parse errors. The agent must generate an id
                         # for every request to match responses.


class WSResponse(BaseModel):
    """Guardian → Agent response over WebSocket."""
    jsonrpc: str = "2.0"
    id: str              # matches request id
    result: Optional[Any] = None
    error: Optional[dict] = None  # {"code": int, "message": str}


class WSNotification(BaseModel):
    """Guardian → Agent push notification (no response expected)."""
    jsonrpc: str = "2.0"
    method: str          # e.g. "llm_key.rotate", "session.terminate"
    params: dict = {}
    # No id field — notifications don't get responses


# Error codes (JSON-RPC standard + MahaGuardian extensions)
ERR_PARSE = -32700
ERR_INVALID_REQUEST = -32600
ERR_METHOD_NOT_FOUND = -32601
ERR_INVALID_PARAMS = -32602
ERR_INTERNAL = -32603
ERR_UNAUTHORIZED = -40100      # token verification failed
ERR_FORBIDDEN = -40300         # enforcer denied access
ERR_PARTITION_DENIED = -40301  # cross-partition access
ERR_PAYMENT_DENIED = -40302    # payment policy denied
ERR_PAYMENT_TIMEOUT = -40800   # approval timeout
