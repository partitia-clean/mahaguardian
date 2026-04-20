"""
Tests for guardian/tools.py — FIX 8: execute_tool_call enforcement.

Covers:
  - Missing token → ToolNotPermittedError (deny)
  - Empty token dict → ToolNotPermittedError
  - Token agent_id mismatch → ToolNotPermittedError
  - Valid token with matching agent_id → executes and returns result
"""
from __future__ import annotations

import pytest

import guardian.audit as audit_module
from guardian.tools import ToolNotPermittedError, execute_tool_call, init_tools


@pytest.fixture(autouse=True)
def setup_audit_and_tools(tmp_path):
    audit_module.init_audit_log(tmp_path / "audit.db")
    # Provide a minimal vault dict so get_vault_items works.
    init_tools({"data_items": []})
    yield


@pytest.mark.asyncio
async def test_tool_call_without_token_raises():
    """Empty token dict → ToolNotPermittedError."""
    with pytest.raises(ToolNotPermittedError):
        await execute_tool_call("agent1", {}, "some_tool", "read", {})


@pytest.mark.asyncio
async def test_tool_call_with_none_token_raises():
    """None token → ToolNotPermittedError."""
    with pytest.raises(ToolNotPermittedError):
        await execute_tool_call("agent1", None, "some_tool", "read", {})


@pytest.mark.asyncio
async def test_tool_call_with_mismatched_agent_id_raises():
    """Token agent_id != caller agent_id → ToolNotPermittedError."""
    token = {"agent_id": "other_agent", "partitions": []}
    with pytest.raises(ToolNotPermittedError):
        await execute_tool_call("agent1", token, "some_tool", "read", {})


@pytest.mark.asyncio
async def test_tool_call_with_valid_token_executes():
    """Valid token with matching agent_id → executes and returns a result dict."""
    from types import SimpleNamespace
    token = SimpleNamespace(agent_id="agent1", partitions=[], operations=["some_tool"])
    result = await execute_tool_call("agent1", token, "some_tool", "read", {})
    assert isinstance(result, dict)
    assert result.get("tool") == "some_tool"
    assert result.get("status") == "success"
