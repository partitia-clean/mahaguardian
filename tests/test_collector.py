"""Tests for orchestrator/collector.py — FIX-7: base_branch validation."""
from __future__ import annotations

import pytest

from orchestrator.collector import get_changed_files, read_files, assemble_review_context


class TestGetChangedFiles:
    """get_changed_files() returns the fixed allowlist — no git required."""

    def test_returns_list(self):
        result = get_changed_files()
        assert isinstance(result, list)

    def test_only_py_files(self):
        result = get_changed_files()
        for f in result:
            assert f.endswith(".py"), f"Non-.py file in result: {f}"

    def test_no_test_files(self):
        result = get_changed_files()
        for f in result:
            assert not f.startswith("tests/"), f"Test file leaked into result: {f}"

    def test_allowlist_paths_are_expected(self):
        from orchestrator.collector import _REVIEW_ALLOWLIST
        result = get_changed_files()
        # Every returned file must come from the allowlist
        for f in result:
            assert f in _REVIEW_ALLOWLIST, f"Unexpected file: {f}"

    def test_base_branch_arg_accepted(self):
        """base_branch parameter is accepted without error (ignored)."""
        get_changed_files("main~8")
        get_changed_files("main")
        get_changed_files("some-branch")


class TestReadFiles:
    def test_missing_file_placeholder(self, tmp_path):
        result = read_files([str(tmp_path / "nonexistent.py")])
        assert "FILE NOT FOUND" in list(result.values())[0]

    def test_existing_file_read(self, tmp_path):
        f = tmp_path / "hello.py"
        f.write_text("x = 1", encoding="utf-8")
        result = read_files([str(f)])
        assert result[str(f)] == "x = 1"


class TestAssembleReviewContext:
    def test_contains_file_headers(self):
        context = assemble_review_context({"foo.py": "code here"})
        assert "foo.py" in context
        assert "code here" in context
