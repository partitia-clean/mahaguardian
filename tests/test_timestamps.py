"""
FIX-11: Standardize timestamps to ISO 8601 UTC.

Tests that:
  - utc_now() returns an ISO 8601 UTC timestamp
  - All timestamp generation points in the codebase produce valid timestamps
"""
from __future__ import annotations

import re
from datetime import timezone

import pytest

from shared.utils import is_valid_timestamp, utc_now

_TS_RE = re.compile(
    r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|\+\d{2}:\d{2})$'
)


class TestUtcNow:
    def test_utc_now_returns_string(self):
        ts = utc_now()
        assert isinstance(ts, str)

    def test_utc_now_matches_iso8601_pattern(self):
        ts = utc_now()
        assert _TS_RE.match(ts), f"utc_now() = {ts!r} does not match ISO 8601 UTC pattern"

    def test_utc_now_has_utc_offset(self):
        """Must end with +00:00 or Z (UTC offset required)."""
        ts = utc_now()
        assert ts.endswith("+00:00") or ts.endswith("Z"), (
            f"utc_now() = {ts!r} missing UTC offset"
        )

    def test_is_valid_timestamp_accepts_utc_plus(self):
        assert is_valid_timestamp("2026-04-08T12:00:00+00:00")

    def test_is_valid_timestamp_accepts_microseconds(self):
        assert is_valid_timestamp("2026-04-08T12:00:00.123456+00:00")

    def test_is_valid_timestamp_accepts_z_suffix(self):
        assert is_valid_timestamp("2026-04-08T12:00:00Z")

    def test_is_valid_timestamp_rejects_naive(self):
        assert not is_valid_timestamp("2026-04-08T12:00:00")

    def test_is_valid_timestamp_rejects_date_only(self):
        assert not is_valid_timestamp("2026-04-08")

    def test_audit_timestamps_are_valid(self, tmp_path):
        """All timestamps produced by guardian/audit.py must be ISO 8601 UTC."""
        import guardian.audit as audit
        audit.init_audit_log(tmp_path / "audit.db")
        audit.log(action="test.ts", result="ok")
        entries = audit.query_log(action="test.ts")
        assert len(entries) >= 1
        for entry in entries:
            ts = entry.get("timestamp", "")
            assert is_valid_timestamp(ts), f"Audit timestamp {ts!r} not ISO 8601 UTC"

    def test_audit_chain_timestamps_are_valid(self, tmp_path):
        """All timestamps produced by guardian/audit_chain.py must be ISO 8601 UTC."""
        from guardian.audit_chain import AuditChain
        from shared.types import Decision
        chain = AuditChain(tmp_path / "chain.db", hmac_key=b"test_key_timestamps_32bytes!!!!!")
        chain.append(agent_id="a", partition_id="p", method="m",
                     params={}, decision=Decision.ALLOW, reason_code="ok")
        entries = chain.entries()
        for entry in entries:
            ts = entry.get("timestamp", "")
            assert is_valid_timestamp(ts), f"Chain timestamp {ts!r} not ISO 8601 UTC"
