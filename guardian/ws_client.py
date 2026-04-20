"""
Guardian WebSocket Client.

Initiates an outbound mTLS WebSocket connection to a remote agent.
Routes incoming JSON-RPC messages from the agent through the
message router. Pushes notifications (key rotation, session
termination) to the agent.

The Guardian controls the connection lifecycle:
- Guardian initiates the connection (outbound only)
- Guardian can disconnect at any time
- If the agent drops, Guardian reconnects with exponential backoff
- After max_retries consecutive failures, Guardian gives up and
  marks the session as degraded
"""
from __future__ import annotations

import asyncio
import json
import logging
import ssl
from typing import Optional

import guardian.audit as audit
from guardian.message_router import route_message
from shared.config import (
    WS_MAX_RETRIES,
    WS_RECONNECT_BASE_SECONDS,
    WS_RECONNECT_MAX_SECONDS,
)
from shared.messages import WSNotification, WSRequest, WSResponse

logger = logging.getLogger(__name__)


class GuardianWSClient:
    """
    Manages a persistent WebSocket connection to one agent.
    One instance per agent session.
    """

    def __init__(
        self,
        agent_id: str,
        agent_host: str,       # from deployment records, NOT from agent
        agent_port: int,       # from deployment records, NOT from agent
        agent_cert_der: bytes, # extracted from mTLS handshake
        ssl_context: ssl.SSLContext,
    ):
        self.agent_id = agent_id
        self.agent_host = agent_host
        self.agent_port = agent_port
        self.agent_cert_der = agent_cert_der
        self.ssl_context = ssl_context
        self._ws = None
        self._task: Optional[asyncio.Task] = None
        self._consecutive_failures = 0
        self._running = False

    async def connect(self) -> None:
        """
        Establish WebSocket connection to the agent.
        Uses the websockets library with the mTLS SSL context.
        """
        import websockets

        uri = f"wss://{self.agent_host}:{self.agent_port}/ws"
        self._ws = await websockets.connect(
            uri,
            ssl=self.ssl_context,
            ping_interval=30,
            ping_timeout=10,
            close_timeout=5,
        )

        # Verify peer cert CN matches expected agent_id
        transport = self._ws.transport
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
                    if cn != self.agent_id:
                        await self._ws.close()
                        raise ValueError(
                            f"Peer cert CN '{cn}' does not match "
                            f"expected agent_id '{self.agent_id}'"
                        )
                # Store the real cert from the TLS session
                self.agent_cert_der = der_cert

        # Do NOT reset _consecutive_failures here. A rogue agent can
        # accept the TLS handshake then immediately drop, trapping
        # Guardian in rapid reconnections. Failures are reset only
        # after successfully processing a real message in listen_loop.
        audit.log(
            action="ws.connected",
            agent_id=self.agent_id,
            result="success",
        )

    async def listen_loop(self) -> None:
        """
        Main loop: listen for agent messages, route them,
        send responses. Handles reconnection with exponential backoff.
        """
        self._running = True
        while self._running:
            try:
                if self._ws is None or self._ws.closed:
                    await self.connect()

                async for raw_message in self._ws:
                    # Reset failure counter only after real communication
                    self._consecutive_failures = 0

                    try:
                        data = json.loads(raw_message)
                        request = WSRequest(**data)
                    except (json.JSONDecodeError, Exception) as exc:
                        error_resp = WSResponse(
                            id="unknown",
                            error={"code": -32700,
                                   "message": f"Parse error: {exc}"},
                        )
                        await self._ws.send(
                            error_resp.model_dump_json()
                        )
                        continue

                    response = await route_message(
                        request,
                        agent_cert_der=self.agent_cert_der,
                        session_agent_id=self.agent_id,
                    )

                    await self._ws.send(response.model_dump_json())

            except asyncio.CancelledError:
                self._running = False
                break
            except Exception as exc:
                self._consecutive_failures += 1
                audit.log(
                    action="ws.disconnected",
                    agent_id=self.agent_id,
                    result=f"failure:{exc},"
                           f"attempt={self._consecutive_failures}",
                )

                if self._consecutive_failures >= WS_MAX_RETRIES:
                    audit.log(
                        action="ws.abandoned",
                        agent_id=self.agent_id,
                        result="failure:max_retries_exceeded",
                    )
                    self._running = False
                    break

                delay = min(
                    WS_RECONNECT_BASE_SECONDS
                    * (2 ** (self._consecutive_failures - 1)),
                    WS_RECONNECT_MAX_SECONDS,
                )
                logger.warning(
                    "Agent %s disconnected. Reconnecting in %ds "
                    "(attempt %d/%d)",
                    self.agent_id, delay,
                    self._consecutive_failures, WS_MAX_RETRIES,
                )
                await asyncio.sleep(delay)

        if self._ws and not self._ws.closed:
            await self._ws.close()

    async def send_notification(
        self, method: str, params: dict
    ) -> None:
        """
        Push a notification to the agent (no response expected).
        Used for key rotation, session termination, etc.
        """
        if self._ws is None or self._ws.closed:
            raise ConnectionError(
                f"No active connection to agent {self.agent_id}"
            )
        notification = WSNotification(method=method, params=params)
        await self._ws.send(notification.model_dump_json())

    async def start(self) -> None:
        """Start the listen loop as a background task."""
        self._task = asyncio.create_task(self.listen_loop())

    async def stop(self) -> None:
        """Stop the connection and clean up."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._ws and not self._ws.closed:
            await self._ws.close()
        audit.log(
            action="ws.stopped",
            agent_id=self.agent_id,
            result="success",
        )
