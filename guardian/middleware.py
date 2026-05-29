"""
ASGI middleware for extracting client certificates from TLS sessions.

Stores peer_cert_der in request.state for use by endpoint handlers.
This is the only trusted source for endpoint certificate identity.
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class PeerCertMiddleware(BaseHTTPMiddleware):
    """
    Extract client certificate from TLS session and store
    in request.state.peer_cert_der.

    If no TLS session or no peer cert (e.g., TestClient without TLS),
    peer_cert_der is set to None and endpoint handlers reject the request.
    """

    async def dispatch(self, request: Request, call_next):
        peer_cert_der = None

        # Try to extract from ASGI transport
        transport = request.scope.get("transport")
        if transport:
            ssl_object = transport.get_extra_info("ssl_object")
            if ssl_object:
                peer_cert_der = ssl_object.getpeercert(
                    binary_form=True
                )

        request.state.peer_cert_der = peer_cert_der
        return await call_next(request)
