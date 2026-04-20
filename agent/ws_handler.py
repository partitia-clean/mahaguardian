"""
Agent WebSocket Handler.

Accepts an inbound WebSocket connection from the Guardian.
Sends JSON-RPC requests to the Guardian for tool calls,
data access, and payments. Receives responses and
notifications (key rotation, session termination).
"""
from __future__ import annotations

import asyncio
import json
import uuid
from typing import Callable, Optional

from shared.messages import WSNotification, WSRequest, WSResponse


class AgentWSHandler:
    """
    Manages the WebSocket connection to the Guardian.
    Provides async methods for sending requests and
    receiving responses.
    """

    def __init__(self, websocket):
        self._ws = websocket
        self._pending: dict[str, asyncio.Future] = {}
        self._notification_handlers: dict[str, Callable] = {}
        self._listener_task: Optional[asyncio.Task] = None

    def on_notification(
        self, method: str, handler: Callable
    ) -> None:
        """Register a handler for Guardian notifications."""
        self._notification_handlers[method] = handler

    async def start_listener(self) -> None:
        """Start background listener for Guardian messages."""
        self._listener_task = asyncio.create_task(
            self._listen_loop()
        )

    async def _listen_loop(self) -> None:
        """Listen for responses and notifications from Guardian."""
        try:
            async for raw_message in self._ws:
                try:
                    data = json.loads(raw_message)
                except json.JSONDecodeError:
                    continue

                if "id" in data and ("result" in data or "error" in data):
                    # Response to one of our requests
                    msg_id = data["id"]
                    if msg_id in self._pending:
                        self._pending[msg_id].set_result(data)
                elif "method" in data and "id" not in data:
                    # Notification from Guardian
                    notification = WSNotification(**data)
                    handler = self._notification_handlers.get(
                        notification.method
                    )
                    if handler:
                        asyncio.create_task(
                            handler(notification.params)
                        )
        except asyncio.CancelledError:
            pass

    async def request(
        self,
        method: str,
        params: dict,
        timeout: float = 30.0,
    ) -> dict:
        """
        Send a JSON-RPC request and wait for the response.
        Returns the result dict or raises on error.
        """
        req = WSRequest(method=method, params=params, id=str(uuid.uuid4()))
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self._pending[req.id] = future

        await self._ws.send(req.model_dump_json())

        try:
            response_data = await asyncio.wait_for(
                future, timeout=timeout
            )
        finally:
            self._pending.pop(req.id, None)

        if "error" in response_data and response_data["error"]:
            error = response_data["error"]
            raise RuntimeError(
                f"Guardian error {error.get('code')}: "
                f"{error.get('message')}"
            )

        return response_data.get("result", {})

    async def stop(self) -> None:
        """Stop the listener and clean up pending requests."""
        if self._listener_task:
            self._listener_task.cancel()
            try:
                await self._listener_task
            except asyncio.CancelledError:
                pass
        for future in self._pending.values():
            if not future.done():
                future.cancel()
        self._pending.clear()
