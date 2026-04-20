"""
Vault partitioning data models — information barrier architecture.

MahaGuardian enforces cryptographic information barriers between client
engagements. Each partition represents one client, company, or
engagement whose data must be isolated from all others.

This is the same concept as "Chinese walls" or "information barriers"
in investment banking, law, consulting, and audit — but enforced by
architecture rather than policy.

Cross-partition access is denied by default and requires explicit
user approval with full audit logging.

Regulatory context: EU Market Abuse Regulation (MAR), MiFID II,
attorney-client privilege, audit independence rules.

Phase 1: data models only. Implementation in Phase 2.
"""
from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator


class VaultPartition(BaseModel):
    partition_id: str              # e.g. "company-alpha"
    display_name: str              # e.g. "Alpha Industries Board"
    created_at: str                # ISO 8601
    classification: str            # e.g. "CONFIDENTIAL"
    regulatory_framework: Optional[str] = None
    # e.g. "MAR", "MiFID II", "attorney-client privilege"
    # Informational — displayed in audit reports and approval
    # prompts so the user sees WHY isolation matters.
    allowed_agent_ids: list[str]   # which agents can access
    data_categories: list[str]     # e.g. ["financials", "board_minutes"]

    @field_validator("allowed_agent_ids")
    @classmethod
    def at_least_one_agent(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("Partition must have at least one allowed agent.")
        return v


class PartitionedTokenPermissions(BaseModel):
    """
    Extends token permissions with partition scope.

    An agent with a token scoped to ["company-alpha"] CANNOT access
    data in "company-beta" partition. This is the core isolation
    guarantee — the cryptographic information barrier.
    """
    partition_ids: list[str]

    @field_validator("partition_ids")
    @classmethod
    def at_least_one_partition(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError(
                "Token must be scoped to at least one partition. "
                "Empty partition_ids would grant no data access."
            )
        return v

    data_classifications: list[str] = Field(default_factory=list)
    vault_read: list[str] = Field(default_factory=list)
    vault_write: list[str] = Field(default_factory=list)
    tool_calls: list[str] = Field(default_factory=list)
    payment_execute: bool = False


class CrossPartitionRequest(BaseModel):
    """
    Logged when an agent attempts to access data outside its
    permitted partitions.

    Cross-partition access is ALWAYS denied or escalated to the
    user for explicit approval. There is no auto-approve for
    cross-partition access. This is non-negotiable — it is the
    information barrier.
    """
    agent_id: str
    token_id: str
    requested_partition: str
    permitted_partitions: list[str]
    timestamp: str
    result: Literal["denied", "escalated_to_user"]
    user_decision: Optional[Literal["approved", "rejected"]] = None
    # Only populated when result == "escalated_to_user"
    regulatory_note: Optional[str] = None
    # e.g. "Cross-partition access between MAR-regulated entities
    # requires compliance officer approval"

    # Timeout behaviour: if the user does not respond within
    # PAYMENT_APPROVAL_TIMEOUT_SECONDS, the result is "denied".
    # Cross-partition access is NEVER auto-approved on timeout.
    # There is no code path anywhere that produces
    # result="auto_approved" — this value must not exist.


class SharedKnowledgeBase(BaseModel):
    """
    Represents the common knowledge pool that ALL partitions can
    access. Contains only generalized, non-confidential information.

    Example: public market data, regulatory reference material,
    general industry knowledge — but NEVER client-specific data.

    Client-specific data must be vectorized and stored WITHIN
    the relevant partition, not in the shared knowledge base.
    """
    knowledge_base_id: str = "shared"
    description: str = "Public and general knowledge — no client-specific data"
    allowed_data_sources: list[str] = Field(
        default_factory=lambda: ["public_markets", "regulatory_reference", "general_industry"]
    )
    # Any data entering the shared knowledge base must be reviewed
    # to ensure it contains no material non-public information.
    requires_review_before_ingestion: bool = True
