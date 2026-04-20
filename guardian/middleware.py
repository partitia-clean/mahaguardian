"""
ASGI middleware for extracting client certificates from TLS sessions.

Stores peer_cert_der in request.state for use by endpoint handlers.
This is the foundation for real mTLS transport binding — replacing
the Phase 1 pattern of trusting agent_cert_b64 from request bodies.
"""
from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request


class PeerCertMiddleware(BaseHTTPMiddleware):
    """
    Extract client certificate from TLS session and store
    in request.state.peer_cert_der.

    If no TLS session or no peer cert (e.g., TestClient without TLS),
    peer_cert_der is set to None. Endpoint handlers decide whether
    to fall back to request-body certs (Phase 1) or reject (Phase 3).
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
