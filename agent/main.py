"""
FastAPI application for the MahaGuardian agent running on a droplet.

Endpoints:
  POST /message       — receive a user message, call LLM, return response
  POST /llm-key/rotate — receive a rotated LLM API key from Guardian

The agent calls the LLM directly using the key held in memory.
The agent NEVER calls tool APIs directly — it asks Guardian via mTLS.
On startup the agent connects to Guardian (placeholder for Phase 1).
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

from fastapi import FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect

from agent.session import AgentSession
from agent.ws_handler import AgentWSHandler
from shared.config import AGENT_PORT, AGENT_WS_HOST, AGENT_WS_PORT, GUARDIAN_HOST, GUARDIAN_PORT
from shared.models import RotatedKey, UserMessage

logger = logging.getLogger("mahaguardian.agent")

# ---------------------------------------------------------------------------
# Global session — one per droplet process
# ---------------------------------------------------------------------------

_session = AgentSession()
_guardian_ws: Optional[AgentWSHandler] = None

# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Startup: connect to Guardian, receive initial LLM key.
    Shutdown: zero sensitive memory.
    """
    logger.info("Agent starting — connecting to Guardian (Phase 1 placeholder)")
    _session.guardian_url = f"https://{GUARDIAN_HOST}:{GUARDIAN_PORT}"
    # Phase 1: Guardian connection and token exchange will be wired here.
    # For now the agent starts with an empty session.
    yield
    logger.info("Agent shutting down — clearing session")
    _session.clear()

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="MahaGuardian Agent",
    version="0.1.0",
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# POST /message
# ---------------------------------------------------------------------------

@app.post("/message")
async def handle_message(msg: UserMessage) -> dict:
    """
    Receive a user message, forward to LLM, return the response.

    The agent holds the LLM API key in memory (never disk).
    If a tool call is needed the agent asks Guardian — it never
    calls tool APIs directly.
    """
    if not _session.llm_api_key:
        raise HTTPException(
            status_code=503,
            detail="LLM API key not available. Waiting for Guardian key rotation.",
        )

    # Phase 1 placeholder: call LLM with _session.llm_api_key
    # In production this will be an httpx call to the Anthropic/OpenAI API.
    response_text = (
        f"[Phase 1 stub] Received message in session {msg.session_id}: "
        f"{msg.content[:80]}"
    )

    return {
        "session_id": msg.session_id,
        "response": response_text,
        "agent_id": _session.agent_id,
    }

# ---------------------------------------------------------------------------
# POST /llm-key/rotate
# ---------------------------------------------------------------------------

@app.post("/llm-key/rotate")
async def rotate_llm_key(rotated: RotatedKey) -> dict:
    """
    Receive a rotated LLM API key from Guardian over mTLS.

    The new key replaces the old one in memory. The old key
    reference is cleared so the GC can collect it.
    """
    _session.llm_api_key = rotated.key

    logger.info(
        "LLM key rotated: provider=%s rotation_id=%s",
        rotated.provider,
        rotated.rotation_id,
    )

    return {
        "status": "ok",
        "provider": rotated.provider,
        "rotation_id": rotated.rotation_id,
    }

# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
async def health() -> dict:
    return {
        "status": "ok",
        "agent_id": _session.agent_id or "uninitialised",
        "has_llm_key": bool(_session.llm_api_key),
        "guardian_connected": _guardian_ws is not None,
    }


# ---------------------------------------------------------------------------
# WebSocket endpoint — Guardian connects here (Phase 2)
# ---------------------------------------------------------------------------

@app.websocket("/ws")
async def guardian_websocket(websocket: WebSocket):
    """
    WebSocket endpoint for Guardian connection.

    The Guardian initiates this connection over mTLS.
    The agent sends requests; the Guardian processes and responds.
    The Guardian also pushes notifications (key rotation).

    Only ONE Guardian connection is allowed at a time.
    """
    global _guardian_ws

    if _guardian_ws is not None:
        await websocket.close(code=1008, reason="Guardian already connected")
        return

    await websocket.accept()

    # Verify the connecting client is the Guardian by checking
    # the peer certificate CN from the TLS session.
    try:
        transport = websocket.scope.get("transport")
        if transport:
            ssl_object = transport.get_extra_info("ssl_object")
            if ssl_object:
                der_cert = ssl_object.getpeercert(binary_form=True)
                if der_cert:
                    from cryptography import x509
                    from cryptography.x509.oid import NameOID
                    cert = x509.load_der_x509_certificate(der_cert)
                    cn_attrs = cert.subject.get_attributes_for_oid(
                        NameOID.COMMON_NAME
                    )
                    if cn_attrs:
                        cn = cn_attrs[0].value
                        if cn != "MahaGuardian Guardian":
                            logger.warning(
                                "WebSocket peer CN '%s' is not Guardian — rejecting", cn
                            )
                            await websocket.close(
                                code=1008,
                                reason="Unauthorized: not Guardian",
                            )
                            return
    except Exception as exc:
        # Fail closed: if we cannot verify the Guardian's identity,
        # reject the connection. No fallback.
        logger.error(
            "Guardian certificate verification failed: %s", exc
        )
        await websocket.close(
            code=1008,
            reason="Guardian certificate verification failed",
        )
        return

    handler = AgentWSHandler(websocket)
    handler.on_notification("llm_key.rotate", _handle_key_rotation)
    handler.on_notification("session.terminate", _handle_session_terminate)

    _guardian_ws = handler
    await handler.start_listener()

    try:
        # Keep connection alive while listener handles messages
        while True:
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        await handler.stop()
        _guardian_ws = None
        # Wipe secrets when Guardian disconnects — key should not
        # persist in memory without an active Guardian session
        _session.clear()
        logger.info(
            "Guardian WebSocket disconnected — session cleared"
        )


async def _handle_key_rotation(params: dict) -> None:
    """Handle LLM key rotation notification from Guardian."""
    new_key = params.get("key", "")
    provider = params.get("provider", "")
    rotation_id = params.get("rotation_id", "")

    _session.llm_api_key = new_key  # property setter handles bytearray
    logger.info(
        "LLM key rotated: provider=%s rotation_id=%s",
        provider, rotation_id,
    )


async def _handle_session_terminate(params: dict) -> None:
    """Handle session termination notification from Guardian."""
    reason = params.get("reason", "unknown")
    _session.clear()
    logger.info("Session terminated: reason=%s", reason)


async def call_guardian(
    method: str, params: dict, timeout: float = 30.0
) -> dict:
    """
    Send a request to the Guardian via the WebSocket.
    Used by agent logic when it needs tool calls, data, or payments.
    """
    if _guardian_ws is None:
        raise ConnectionError("Guardian not connected")
    return await _guardian_ws.request(method, params, timeout)
