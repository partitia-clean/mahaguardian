"""
Tests for shared/partitions.py — vault partitioning data model.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from shared.partitions import (
    CrossPartitionRequest,
    PartitionedTokenPermissions,
    SharedKnowledgeBase,
    VaultPartition,
)


# ---------------------------------------------------------------------------
# VaultPartition
# ---------------------------------------------------------------------------

class TestVaultPartition:
    def test_valid_partition(self):
        p = VaultPartition(
            partition_id="company-alpha",
            display_name="Alpha Industries Board",
            created_at="2025-06-01T00:00:00Z",
            classification="CONFIDENTIAL",
            allowed_agent_ids=["alpha"],
            data_categories=["financials", "board_minutes"],
        )
        assert p.partition_id == "company-alpha"
        assert p.classification == "CONFIDENTIAL"
        assert p.data_categories == ["financials", "board_minutes"]

    def test_empty_allowed_agents_rejected(self):
        with pytest.raises(ValidationError, match="at least one allowed agent"):
            VaultPartition(
                partition_id="company-beta",
                display_name="Beta Corp",
                created_at="2025-06-01T00:00:00Z",
                classification="INTERNAL",
                allowed_agent_ids=[],
                data_categories=["reports"],
            )

    def test_missing_required_field_raises(self):
        with pytest.raises(ValidationError):
            VaultPartition(
                partition_id="company-alpha",
                # missing display_name, created_at, etc.
            )

    def test_regulatory_framework_optional(self):
        p = VaultPartition(
            partition_id="company-gamma",
            display_name="Gamma LLC",
            created_at="2025-06-01T00:00:00Z",
            classification="CONFIDENTIAL",
            regulatory_framework="MAR",
            allowed_agent_ids=["alpha"],
            data_categories=["financials"],
        )
        assert p.regulatory_framework == "MAR"


# ---------------------------------------------------------------------------
# PartitionedTokenPermissions
# ---------------------------------------------------------------------------

class TestPartitionedTokenPermissions:
    def _base_kwargs(self, **overrides):
        defaults = dict(
            partition_ids=["company-alpha"],
        )
        defaults.update(overrides)
        return defaults

    def test_valid_partitioned_permissions(self):
        p = PartitionedTokenPermissions(**self._base_kwargs())
        assert p.partition_ids == ["company-alpha"]

    def test_default_fields(self):
        p = PartitionedTokenPermissions(**self._base_kwargs())
        assert p.data_classifications == []
        assert p.payment_execute is False

    def test_empty_partition_ids_rejected(self):
        with pytest.raises(ValidationError, match="no data access"):
            PartitionedTokenPermissions(**self._base_kwargs(partition_ids=[]))

    def test_multiple_partitions_allowed(self):
        p = PartitionedTokenPermissions(
            **self._base_kwargs(partition_ids=["company-alpha", "company-beta"])
        )
        assert len(p.partition_ids) == 2


# ---------------------------------------------------------------------------
# CrossPartitionRequest
# ---------------------------------------------------------------------------

class TestCrossPartitionRequest:
    def _base_kwargs(self, **overrides):
        defaults = dict(
            agent_id="alpha",
            token_id="tok-123",
            requested_partition="company-beta",
            permitted_partitions=["company-alpha"],
            timestamp="2025-06-01T12:00:00Z",
            result="denied",
        )
        defaults.update(overrides)
        return defaults

    def test_denied_result(self):
        r = CrossPartitionRequest(**self._base_kwargs(result="denied"))
        assert r.result == "denied"

    def test_escalated_result(self):
        r = CrossPartitionRequest(**self._base_kwargs(result="escalated_to_user"))
        assert r.result == "escalated_to_user"

    def test_invalid_result_rejected(self):
        with pytest.raises(ValidationError):
            CrossPartitionRequest(**self._base_kwargs(result="auto_approved"))

    def test_missing_required_field_raises(self):
        with pytest.raises(ValidationError):
            CrossPartitionRequest(
                agent_id="alpha",
                # missing other required fields
            )

    def test_user_decision_optional(self):
        r = CrossPartitionRequest(
            **self._base_kwargs(result="escalated_to_user", user_decision="approved")
        )
        assert r.user_decision == "approved"


# ---------------------------------------------------------------------------
# SharedKnowledgeBase
# ---------------------------------------------------------------------------

class TestSharedKnowledgeBase:
    def test_defaults_require_review(self):
        kb = SharedKnowledgeBase()
        assert kb.requires_review_before_ingestion is True

    def test_default_knowledge_base_id(self):
        kb = SharedKnowledgeBase()
        assert kb.knowledge_base_id == "shared"

    def test_default_data_sources(self):
        kb = SharedKnowledgeBase()
        assert "public_markets" in kb.allowed_data_sources
        assert "regulatory_reference" in kb.allowed_data_sources
