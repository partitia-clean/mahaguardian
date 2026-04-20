"""
All Pydantic models used across Guardian, Agent, and CLI.
Import from here — do not redefine elsewhere.
"""
from __future__ import annotations

import warnings
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator


class PaymentRequest(BaseModel):
    amount_gbp: float

    @field_validator("amount_gbp")
    @classmethod
    def amount_must_be_positive(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("Payment amount must be positive")
        return v
    recipient: str                    # e.g. "Ottolenghi restaurant"
    description: str
    payment_method: Literal["stripe", "bank_transfer"]
    payment_source: Literal["agent", "external_agent"] = "agent"
    # "agent"          — user's own MahaGuardian agent initiated this payment
    # "external_agent" — a third-party agent/service is requesting payment
    external_agent_id: Optional[str] = None
    # Required when payment_source == "external_agent".
    # Must match a verified agent identity — not free text.
    service_status: Literal["already_provided", "to_be_provided"] = "to_be_provided"
    # Shown to user in approval prompt so they know whether
    # they are paying for something received or in advance.


class PaymentResult(BaseModel):
    success: bool
    reference: str                    # e.g. "TXN-4821"
    amount_gbp: float
    recipient: str
    timestamp: str                    # ISO 8601
    payment_source: str               # echoed from request
    approved_by: Literal["auto", "user"]
    # "auto" — within auto-approve threshold
    # "user" — user explicitly confirmed


class TokenPermissions(BaseModel):
    """Deprecated: Phase 1/2 permissions model. Use shared.token.AccessToken instead."""
    data_classifications: list[str]   # e.g. ["PUBLIC", "INTERNAL"]
    vault_read: list[str]             # e.g. ["personal"]
    vault_write: list[str]            # e.g. []
    tool_calls: list[str]             # e.g. ["google_calendar", "ft_news"]
    payment_execute: bool
    # payment_auto_approve_limit_gbp removed — lives in vault config only
    # (Guardian-local policy, never in token)

    def model_post_init(self, __context: Any) -> None:
        warnings.warn(
            "TokenPermissions is deprecated and will be removed. "
            "Use shared.token.AccessToken instead.",
            DeprecationWarning,
            stacklevel=2,
        )


class GuardianAccessToken(BaseModel):
    """Deprecated: Phase 1/2 token model. Use shared.token.AccessToken instead."""
    token_id: str                     # UUID4
    agent_id: str
    issued_at: str                    # ISO 8601
    expires_at: str                   # ISO 8601 — 4 hours from issue
    permissions: TokenPermissions
    agent_cert_fingerprint: str       # SHA-256 of agent TLS cert
    sig: str                          # base64 ed25519 signature

    def model_post_init(self, __context: Any) -> None:
        warnings.warn(
            "GuardianAccessToken is deprecated and will be removed. "
            "Use shared.token.AccessToken instead.",
            DeprecationWarning,
            stacklevel=2,
        )


class UserMessage(BaseModel):
    content: str
    session_id: str


class RotatedKey(BaseModel):
    provider: Literal["anthropic", "openai"]
    key: str = Field(repr=False)      # NEVER show in repr/logs
    rotation_id: str


class AuditEntry(BaseModel):
    id: int
    timestamp: str
    agent_id: Optional[str]
    action: str
    resource: Optional[str]
    classification: Optional[str]
    partition_id: Optional[str]
    result: str
    prev_hash: str
    entry_hash: str


class SkillPermissions(BaseModel):
    name: str
    version: str
    author_sig: str
    registry_sig: str
    permissions: dict                 # network, filesystem, system_calls
    checksum: str                     # SHA-256 of skill file
