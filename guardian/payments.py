"""
Payment execution with human-in-the-loop approval.

Security guarantees:
  - Every payment is logged to the audit trail.
  - Payments above auto-approve threshold require explicit user approval.
  - External agent payments check trusted agent list and use a separate
    (typically zero) auto-approve threshold.
  - Daily spend limit is enforced via audit log aggregation.
  - Timeout on user approval prompt = automatic rejection.
  - Payment credentials (Stripe keys etc.) never leave Guardian.
  - _execute_payment_request() is separated from rules so it can be
    replaced independently.
"""
from __future__ import annotations

import asyncio
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Optional

import guardian.audit as audit
import guardian.vault as vault
from shared.config import PAYMENT_APPROVAL_TIMEOUT_SECONDS
from shared.models import PaymentRequest, PaymentResult


class PaymentDeniedError(Exception):
    """Raised when a payment is denied by policy or user."""


class PaymentTimeoutError(PaymentDeniedError):
    """Raised when user approval times out."""


_AGENT_ID_RE = re.compile(r'^[a-zA-Z0-9_-]+$')

# Module-level vault reference
_vault: Optional[dict] = None

# Limit concurrent approval prompts to 1, with max queue depth of 5
_approval_semaphore = asyncio.Semaphore(1)
_pending_approvals: int = 0
_MAX_PENDING_APPROVALS: int = 5


def init_payments(vault_dict: dict) -> None:
    """
    Initialise the payments module with an unlocked vault dict.
    Must be called after unlock_vault() and before execute_payment().
    """
    global _vault
    _vault = vault_dict


def _validate_agent_id(agent_id: str) -> None:
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError(f"Invalid agent_id '{agent_id}'")


def _get_payment_rules() -> dict:
    """Retrieve payment rules from the vault."""
    if _vault is None:
        raise RuntimeError(
            "Payments module not initialised. Call init_payments() first."
        )
    return _vault.get("payment_rules", {})


def _is_external_agent(agent_id: str) -> bool:
    """
    Check if agent_id is a known external agent.

    Priority:
    1. Session state registry (if agent has an active session)
    2. Vault external_agents list (fallback for pre-session checks)
    3. Secure default: unknown = external if vault has external list,
       primary if no external list (single-agent Phase 1)

    The agent cannot self-declare its own classification.
    """
    # Try session state first (authoritative when session exists)
    try:
        from guardian.session_state import is_external_agent as _session_check
        from guardian.session_state import get_session
        if get_session(agent_id) is not None:
            return _session_check(agent_id)
    except ImportError:
        pass

    # Fallback to vault lookup
    if _vault is None:
        return True  # Secure default: unknown = external
    try:
        external_list = vault.get_secret(_vault, "external_agents")
        if isinstance(external_list, list):
            return agent_id in external_list
        if isinstance(external_list, str):
            return agent_id in json.loads(external_list)
        return True  # Secure default
    except KeyError:
        # No external_agents key in vault — treat all as
        # primary (single-agent Phase 1 deployment)
        return False


def _get_daily_spend(agent_id: str) -> float:
    """
    Query audit log for today's successful payments and sum amounts.

    Relies on audit.query_log to find payment.execute entries with
    result starting with 'success' for the given agent.
    """
    today_start = datetime.now(timezone.utc).replace(
        hour=0, minute=0, second=0, microsecond=0,
    ).isoformat()

    entries = audit.query_log(
        agent_id=agent_id,
        action="payment.execute",
        from_timestamp=today_start,
    )

    total = 0.0
    for entry in entries:
        result = entry.get("result", "")
        if not result.startswith("success"):
            continue
        resource = entry.get("resource", "")
        try:
            resource_data = json.loads(resource)
            total += float(resource_data.get("amount", 0))
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    return total


async def notify_user_for_approval(payment_request: PaymentRequest) -> bool:
    """
    Present payment details to user and wait for approval.

    Phase 1: prints to terminal and reads stdin via asyncio.
    Phase 2+: sends push notification / UI prompt.

    Returns True if approved, False if rejected.
    Raises PaymentTimeoutError if no response within timeout.
    Raises PaymentDeniedError if approval queue is full.
    """
    global _pending_approvals

    # Reject if too many approvals are already queued
    if _pending_approvals >= _MAX_PENDING_APPROVALS:
        audit.log(
            action="payment.execute",
            result="failure:approval_queue_full",
        )
        return False

    _pending_approvals += 1
    try:
        async with _approval_semaphore:
            source_info = ""
            if payment_request.payment_source == "external_agent":
                source_info = (
                    f"\n  External agent: {payment_request.external_agent_id}"
                    f"\n  Service: {payment_request.service_status}"
                )

            prompt = (
                f"\n{'='*60}"
                f"\n  PAYMENT APPROVAL REQUIRED"
                f"\n{'='*60}"
                f"\n  Amount:    {payment_request.amount_gbp:.2f} GBP"
                f"\n  To:        {payment_request.recipient}"
                f"\n  Reason:    {payment_request.description}"
                f"\n  Method:    {payment_request.payment_method}"
                f"\n  Source:    {payment_request.payment_source}"
                f"{source_info}"
                f"\n{'='*60}"
                f"\n  Approve? [y/N] (timeout: {PAYMENT_APPROVAL_TIMEOUT_SECONDS}s): "
            )

            loop = asyncio.get_event_loop()

            try:
                print(prompt, end="", flush=True)
                response = await asyncio.wait_for(
                    loop.run_in_executor(None, input),
                    timeout=PAYMENT_APPROVAL_TIMEOUT_SECONDS,
                )
                return response.strip().lower() in ("y", "yes")
            except asyncio.TimeoutError:
                print("\n  ** Approval timed out -- payment rejected **")
                raise PaymentTimeoutError(
                    f"User did not respond within {PAYMENT_APPROVAL_TIMEOUT_SECONDS}s"
                )
    finally:
        _pending_approvals -= 1


async def execute_payment(
    agent_id: str,
    token: dict,
    payment_request: PaymentRequest,
) -> PaymentResult:
    """
    Execute a payment with full policy enforcement.

    Flow:
      1. Check token permits payment_execute.
      2. If external_agent: check trusted list, apply external threshold.
      3. If agent: apply standard auto_approve_below_gbp.
      4. Check daily limit via audit log sum.
      5. If above threshold: notify_user_for_approval (with timeout).
      6. Execute payment via _execute_payment_request.
      7. Log to audit.
    """
    _validate_agent_id(agent_id)

    # Determine payment source from Guardian's own vault records,
    # not from the request payload. The agent cannot self-declare
    # as "agent" vs "external_agent".
    # The external_agent_id field in PaymentRequest is informational
    # metadata only — it does NOT influence authorization decisions.
    if _is_external_agent(agent_id):
        actual_source = "external_agent"
    else:
        actual_source = "agent"

    # Override whatever the request claimed
    if actual_source != payment_request.payment_source:
        audit.log(
            action="payment.source_override",
            agent_id=agent_id,
            result=f"request claimed '{payment_request.payment_source}' "
                   f"but actual is '{actual_source}'",
        )
    payment_request.payment_source = actual_source

    # Reject non-positive amounts immediately
    if payment_request.amount_gbp <= 0:
        audit.log(
            action="payment.rejected",
            agent_id=agent_id,
            result="failure:non_positive_amount",
        )
        raise ValueError(
            f"Payment amount must be positive, got "
            f"{payment_request.amount_gbp}"
        )

    # Reject recipients with delimiter characters (audit log injection)
    if any(c in payment_request.recipient for c in ",=\n\r"):
        raise ValueError("Recipient contains invalid characters")

    if _vault is None:
        raise RuntimeError(
            "Payments module not initialised. Call init_payments() first."
        )

    # Check token permits payments
    permissions = token if isinstance(token, dict) else {}
    if not permissions.get("payment_execute", False):
        audit.log(
            action="payment.execute",
            agent_id=agent_id,
            result="denied:payment_not_permitted",
        )
        raise PaymentDeniedError(
            f"Agent '{agent_id}' token does not permit payment execution."
        )

    rules = _get_payment_rules()
    auto_approve_limit = rules.get("auto_approve_below_gbp", 0)
    daily_limit = rules.get("daily_limit_gbp", 0)
    trusted_external = rules.get("trusted_external_agents", [])
    external_auto_limit = rules.get("external_agent_auto_approve_below_gbp", 0)

    # --- External agent checks ---
    if payment_request.payment_source == "external_agent":
        # Use verified agent_id (not request payload) for trust check
        if agent_id not in trusted_external:
            audit.log(
                action="payment.execute",
                agent_id=agent_id,
                resource=json.dumps({"external_agent": agent_id}),
                result="denied:untrusted_external_agent",
            )
            raise PaymentDeniedError(
                f"External agent '{agent_id}' is not in the trusted list."
            )
        # External agents use their own (typically stricter) threshold
        auto_approve_limit = external_auto_limit

    # --- Daily limit check ---
    daily_spend = _get_daily_spend(agent_id)
    if daily_spend + payment_request.amount_gbp > daily_limit:
        audit.log(
            action="payment.execute",
            agent_id=agent_id,
            resource=json.dumps({"amount": payment_request.amount_gbp, "daily_spend": daily_spend}),
            result=f"denied:daily_limit_exceeded:{daily_limit}",
        )
        raise PaymentDeniedError(
            f"Daily spending limit exceeded. "
            f"Current: {daily_spend:.2f}, requested: {payment_request.amount_gbp:.2f}, "
            f"limit: {daily_limit:.2f} GBP."
        )

    # --- Approval logic ---
    approved_by: str
    if payment_request.amount_gbp < auto_approve_limit:
        approved_by = "auto"
    else:
        # Human-in-the-loop
        try:
            approved = await notify_user_for_approval(payment_request)
        except PaymentTimeoutError:
            audit.log(
                action="payment.execute",
                agent_id=agent_id,
                resource=json.dumps({"amount": payment_request.amount_gbp, "recipient": payment_request.recipient}),
                result="denied:approval_timeout",
            )
            raise
        if not approved:
            audit.log(
                action="payment.execute",
                agent_id=agent_id,
                resource=json.dumps({"amount": payment_request.amount_gbp, "recipient": payment_request.recipient}),
                result="denied:user_rejected",
            )
            raise PaymentDeniedError("Payment rejected by user.")
        approved_by = "user"

    # --- Execute payment ---
    credentials = vault.get_secret(
        _vault, f"tool_api_keys.{payment_request.payment_method}"
    )
    txn = await _execute_payment_request(payment_request, credentials)

    now = datetime.now(timezone.utc).isoformat()
    reference = txn.get("reference", f"TXN-{uuid.uuid4().hex[:8].upper()}")

    result = PaymentResult(
        success=True,
        reference=reference,
        amount_gbp=payment_request.amount_gbp,
        recipient=payment_request.recipient,
        timestamp=now,
        payment_source=payment_request.payment_source,
        approved_by=approved_by,
    )

    audit.log(
        action="payment.execute",
        agent_id=agent_id,
        resource=json.dumps({
            "amount": payment_request.amount_gbp,
            "recipient": payment_request.recipient,
            "method": payment_request.payment_method,
            "source": payment_request.payment_source,
        }),
        result=f"success:ref={reference},approved_by={approved_by}",
    )
    return result


async def _execute_payment_request(
    payment_request: PaymentRequest,
    credentials: str,
) -> dict:
    """
    Execute the actual payment API call.

    Separated from rules so it can be replaced independently.
    In Phase 1: returns simulated response.
    In production: calls Stripe / bank transfer API using credentials.

    The credentials parameter is the API key string -- it must
    NEVER be logged or returned to the agent.
    """
    # In production, this would use httpx to call Stripe/bank API
    # using the credentials. For Phase 1, we simulate.
    return {
        "reference": f"TXN-{uuid.uuid4().hex[:8].upper()}",
        "status": "completed",
        "amount": payment_request.amount_gbp,
        "recipient": payment_request.recipient,
        "method": payment_request.payment_method,
    }
