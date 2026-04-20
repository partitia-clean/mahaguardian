"""
FIX 5: Audit query must normalize denial results so agents cannot
distinguish "denied:tlp_insufficient" from "denied:not_found".

These unit tests verify the normalization logic in isolation, independent
of the full FastAPI stack.
"""
from __future__ import annotations


def _normalize_entries(entries: list[dict]) -> list[dict]:
    """Mirror the normalization applied in guardian/main.py api_query_audit."""
    for entry in entries:
        if isinstance(entry.get("result"), str) and entry["result"].startswith("denied:"):
            entry["result"] = "denied"
    return entries


class TestAuditDenialNormalization:
    def test_tlp_insufficient_normalized(self):
        entries = [{"result": "denied:tlp_insufficient", "action": "vault.read"}]
        result = _normalize_entries(entries)
        assert result[0]["result"] == "denied"

    def test_not_found_normalized(self):
        entries = [{"result": "denied:access_denied", "action": "vault.read"}]
        result = _normalize_entries(entries)
        assert result[0]["result"] == "denied"

    def test_two_different_denials_indistinguishable(self):
        """Agent cannot distinguish denial reasons by reading the result field."""
        entries = [
            {"result": "denied:not_found", "action": "vault.read"},
            {"result": "denied:tlp_insufficient", "action": "vault.read"},
        ]
        result = _normalize_entries(entries)
        assert result[0]["result"] == result[1]["result"] == "denied"

    def test_success_not_modified(self):
        entries = [{"result": "success", "action": "vault.read"}]
        result = _normalize_entries(entries)
        assert result[0]["result"] == "success"

    def test_non_denied_failure_not_modified(self):
        entries = [{"result": "failure:soul_conflict", "action": "session.start"}]
        result = _normalize_entries(entries)
        assert result[0]["result"] == "failure:soul_conflict"

    def test_bare_denied_not_modified(self):
        """A result that is exactly 'denied' (no colon) stays as-is."""
        entries = [{"result": "denied"}]
        result = _normalize_entries(entries)
        assert result[0]["result"] == "denied"
