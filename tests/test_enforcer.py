"""
Tests for guardian/enforcer.py — Phase 3 enforcement pipeline.

NOTE: Legacy Phase 1/2 test classes (TestEnforcePartitionAccess,
TestEnforceToolAccess) removed per SM-001/SM-005. Those functions no longer
exist. All enforcement goes through enforce() or resolve_and_enforce().
"""
from __future__ import annotations

from pathlib import Path

import pytest

import guardian.audit as audit_module
from guardian.enforcer import (
    AmbiguousKeyError,
    ConfusedDeputyError,
    EnforcementDenied,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def setup_audit(tmp_path):
    audit_db = tmp_path / "audit.db"
    audit_module.init_audit_log(audit_db)
    yield


# ---------------------------------------------------------------------------
# SM-001: Verify legacy API is gone
# ---------------------------------------------------------------------------

class TestLegacyAPIRemoved:
    """Confirm the removed functions raise AttributeError on import attempt."""

    def test_enforce_partition_access_does_not_exist(self):
        import guardian.enforcer as m
        assert not hasattr(m, "enforce_partition_access")  # FIX: SM-001

    def test_enforce_tool_access_does_not_exist(self):
        import guardian.enforcer as m
        assert not hasattr(m, "enforce_tool_access")  # FIX: SM-001

    def test_partition_access_denied_does_not_exist(self):
        import guardian.enforcer as m
        assert not hasattr(m, "PartitionAccessDenied")  # FIX: SM-001


# ---------------------------------------------------------------------------
# SM-003: AmbiguousKeyError safe_message is always "access_denied"
# ---------------------------------------------------------------------------

class TestAmbiguousKeyError:
    def test_safe_message_is_access_denied(self):
        exc = AmbiguousKeyError()
        assert exc.safe_message == "access_denied"  # FIX: SM-003

    def test_internal_reason_code_is_ambiguous_key(self):
        exc = AmbiguousKeyError()
        assert exc.reason_code == "ambiguous_key"
