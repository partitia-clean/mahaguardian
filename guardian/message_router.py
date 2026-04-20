"""
WebSocket message router for Guardian.

Routes incoming JSON-RPC messages from agents to the same internal
functions used by the HTTP endpoints. The enforcer, token verification,
and partition checks are identical regardless of transport.

agent_cert_der and session_agent_id come from the mTLS session —
NEVER from the message payload.
"""
from __future__ import annotations

import guardian.audit as audit
from guardian.enforcer import EnforcementDenied  # FIX: SM-001 — PartitionAccessDenied removed
from guardian.main import (
    _check_partition_internal,
    _execute_payment_internal,
    _execute_tool_internal,
)
from guardian.payments import PaymentDeniedError, PaymentTimeoutError
from shared.token import TokenVerifyError
from guardian.tools import ToolNotPermittedError
from shared.messages import (
    ERR_FORBIDDEN,
    ERR_INTERNAL,
    ERR_INVALID_PARAMS,
    ERR_METHOD_NOT_FOUND,
    ERR_PARTITION_DENIED,
    ERR_PAYMENT_DENIED,
    ERR_PAYMENT_TIMEOUT,
    ERR_UNAUTHORIZED,
    WSRequest,
    WSResponse,
)
from shared.models import PaymentRequest

# ---------------------------------------------------------------------------
# Method registry
# ---------------------------------------------------------------------------

_METHODS: dict[str, object] = {}


def method(name: str):
    """Decorator to register a JSON-RPC method handler."""
    def decorator(func):
        _METHODS[name] = func
        return func
    return decorator


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

async def route_message(
    request: WSRequest,
    agent_cert_der: bytes,
    session_agent_id: str,
) -> WSResponse:
    """
    Route a JSON-RPC request to the appropriate handler.

    agent_cert_der comes from the TLS session — NEVER from the
    message payload. session_agent_id was verified at WebSocket
    connect time via cert CN match.
    """
    handler = _METHODS.get(request.method)
    if handler is None:
        return WSResponse(
            id=request.id,
            error={"code": ERR_METHOD_NOT_FOUND,
                   "message": f"Unknown method: {request.method}"},
        )

    try:
        result = await handler(
            request.params,
            agent_cert_der=agent_cert_der,
            session_agent_id=session_agent_id,
        )
        return WSResponse(id=request.id, result=result)
    except TokenVerifyError as exc:
        return WSResponse(
            id=request.id,
            error={"code": ERR_UNAUTHORIZED, "message": str(exc)},
        )
    except EnforcementDenied as exc:  # FIX: SM-001 — catch Phase 3 enforcement errors
        return WSResponse(
            id=request.id,
            error={"code": ERR_PARTITION_DENIED, "message": exc.safe_message},
        )
    except NotImplementedError as exc:  # FIX: SM-001 — legacy path removed
        return WSResponse(
            id=request.id,
            error={"code": ERR_METHOD_NOT_FOUND, "message": str(exc)},
        )
    except ToolNotPermittedError as exc:
        return WSResponse(
            id=request.id,
            error={"code": ERR_FORBIDDEN, "message": str(exc)},
        )
    except PaymentTimeoutError as exc:
        return WSResponse(
            id=request.id,
            error={"code": ERR_PAYMENT_TIMEOUT, "message": str(exc)},
        )
    except PaymentDeniedError as exc:
        return WSResponse(
            id=request.id,
            error={"code": ERR_PAYMENT_DENIED, "message": str(exc)},
        )
    except ValueError as exc:
        return WSResponse(
            id=request.id,
            error={"code": ERR_INVALID_PARAMS, "message": str(exc)},
        )
    except Exception as exc:
        audit.log(
            action="ws.internal_error",
            agent_id=session_agent_id,
            result=f"failure:{type(exc).__name__}:{exc}",
        )
        return WSResponse(
            id=request.id,
            error={"code": ERR_INTERNAL, "message": "Internal error"},
        )


# ---------------------------------------------------------------------------
# Method handlers
# ---------------------------------------------------------------------------

@method("tools.execute")
async def handle_tool_execute(
    params: dict,
    agent_cert_der: bytes,
    session_agent_id: str,
) -> dict:
    """Execute a tool call with full authorization."""
    return await _execute_tool_internal(
        token_str=params.get("token_str", ""),
        agent_cert=agent_cert_der,
        agent_id=session_agent_id,
        tool_name=params.get("tool_name", ""),
        action=params.get("action", ""),
        params=params.get("params", {}),
        partition_id=params.get("partition_id", ""),
    )


@method("partition.check")
async def handle_partition_check(
    params: dict,
    agent_cert_der: bytes,
    session_agent_id: str,
) -> dict:
    """Check partition access."""
    return await _check_partition_internal(
        token_str=params.get("token_str", ""),
        agent_cert=agent_cert_der,
        agent_id=session_agent_id,
        key=params.get("key", ""),
        action=params.get("action", "data.request"),
    )


@method("payment.execute")
async def handle_payment_execute(
    params: dict,
    agent_cert_der: bytes,
    session_agent_id: str,
) -> dict:
    """Execute a payment with full policy enforcement."""
    payment_data = params.get("payment_request", {})
    payment_request = PaymentRequest(**payment_data)
    return await _execute_payment_internal(
        token_str=params.get("token_str", ""),
        agent_cert=agent_cert_der,
        agent_id=session_agent_id,
        payment_request=payment_request,
    )
