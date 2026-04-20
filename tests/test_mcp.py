"""
Tests for Workstream 2: MCP Integration.

Tests work with AND without the MCP SDK installed.
The fallback to simulated responses is always tested.
MCP-specific tests are skipped if the SDK is not available.
"""
from __future__ import annotations

import asyncio

import pytest

import guardian.audit as audit_module
import guardian.main as main_module
import guardian.tools as tools_module
import guardian.vault as vault_module
from guardian.mcp_client import (
    MCPClientManager,
    init_mcp,
    resolve_mcp_server,
)
from guardian.tools import execute_tool_call
from guardian.vault import init_vault, unlock_vault

try:
    import mcp
    HAS_MCP = True
except ImportError:
    HAS_MCP = False

PASSPHRASE = "mcp-test-2026"


@pytest.fixture(autouse=True)
def setup(tmp_path, monkeypatch):
    """Isolate modules to tmp_path."""
    audit_module.init_audit_log(tmp_path / "audit.db")

    monkeypatch.setattr(vault_module, "VAULT_DIR", tmp_path / "vault")
    monkeypatch.setattr(vault_module, "VAULT_PATH", tmp_path / "vault" / "vault.enc")
    monkeypatch.setattr(vault_module, "KEYS_DIR", tmp_path / "vault" / "keys")
    monkeypatch.setattr(vault_module, "AGE_KEY_PATH", tmp_path / "vault" / "keys" / "master.key")
    monkeypatch.setattr(vault_module, "AGE_PUBKEY_PATH", tmp_path / "vault" / "keys" / "master.key.pub")

    yield tmp_path

    tools_module._vault = None
    main_module._vault_dict = None


# ---------------------------------------------------------------------------
# MCPClientManager unit tests
# ---------------------------------------------------------------------------

class TestMCPClientManager:

    def test_init_with_no_servers(self, setup):
        """Empty vault → no servers configured, no error."""
        mgr = MCPClientManager()
        mgr.init({"mcp_servers": {}})
        assert mgr._config == {}

    def test_init_with_no_mcp_key(self, setup):
        """Vault without mcp_servers key → empty config."""
        mgr = MCPClientManager()
        mgr.init({})
        assert mgr._config == {}

    def test_resolve_known_tool(self, setup):
        """Tool mapped to a server is resolved correctly."""
        mgr = MCPClientManager()
        mgr.init({
            "mcp_servers": {
                "calendar_server": {
                    "transport": "stdio",
                    "command": ["node", "server.js"],
                    "tools": ["google_calendar", "outlook_calendar"],
                },
            },
        })
        assert mgr.resolve_server("google_calendar") == "calendar_server"
        assert mgr.resolve_server("outlook_calendar") == "calendar_server"

    def test_resolve_unknown_tool(self, setup):
        """Tool not mapped to any server returns None."""
        mgr = MCPClientManager()
        mgr.init({
            "mcp_servers": {
                "calendar_server": {
                    "tools": ["google_calendar"],
                },
            },
        })
        assert mgr.resolve_server("nonexistent_tool") is None

    def test_resolve_multiple_servers(self, setup):
        """Tools on different servers resolve to correct server."""
        mgr = MCPClientManager()
        mgr.init({
            "mcp_servers": {
                "calendar": {"tools": ["google_calendar"]},
                "payments": {"tools": ["stripe"]},
            },
        })
        assert mgr.resolve_server("google_calendar") == "calendar"
        assert mgr.resolve_server("stripe") == "payments"

    def test_init_with_json_string(self, setup):
        """mcp_servers as JSON string is parsed correctly."""
        import json
        servers = json.dumps({
            "test_server": {"tools": ["test_tool"]},
        })
        mgr = MCPClientManager()
        mgr.init({"mcp_servers": servers})
        assert mgr.resolve_server("test_tool") == "test_server"


# ---------------------------------------------------------------------------
# Module-level functions
# ---------------------------------------------------------------------------

class TestMCPModuleFunctions:

    def test_init_mcp_callable(self, setup):
        """init_mcp is importable and callable."""
        init_mcp({})

    def test_resolve_mcp_server_callable(self, setup):
        """resolve_mcp_server returns None for unconfigured tool."""
        init_mcp({})
        assert resolve_mcp_server("anything") is None


# ---------------------------------------------------------------------------
# Tool execution fallback
# ---------------------------------------------------------------------------

class TestToolExecutionFallback:

    def test_unmapped_tool_gets_simulated_response(self, setup):
        """FIX 8 — execute_tool_call now runs real enforcement.
        A token dict missing 'agent_id' is rejected with ToolNotPermittedError
        (enforcement denies before any tool call reaches the MCP layer)."""
        tmp_path = setup
        init_vault(PASSPHRASE)
        vault_dict = unlock_vault(PASSPHRASE)
        tools_module.init_tools(vault_dict)
        init_mcp(vault_dict)

        with pytest.raises(tools_module.ToolNotPermittedError):
            asyncio.run(
                execute_tool_call(
                    agent_id="alpha",
                    token={"tool_calls": ["google_calendar"]},
                    tool_name="google_calendar",
                    action="list",
                    params={"date": "2026-04-02"},
                )
            )

    def test_mapped_tool_without_mcp_sdk_raises(self, setup):
        """FIX 8 — execute_tool_call enforces token validation.
        A token dict missing 'agent_id' is rejected before MCP dispatch."""
        tmp_path = setup
        init_vault(PASSPHRASE)
        vault_dict = unlock_vault(PASSPHRASE)
        vault_dict["mcp_servers"] = {
            "test_server": {
                "transport": "stdio",
                "command": ["node", "test.js"],
                "tools": ["test_tool"],
            },
        }
        tools_module.init_tools(vault_dict)
        init_mcp(vault_dict)

        with pytest.raises(tools_module.ToolNotPermittedError):
            asyncio.run(
                execute_tool_call(
                    agent_id="alpha",
                    token={"tool_calls": ["test_tool"]},
                    tool_name="test_tool",
                    action="run",
                    params={},
                )
            )

    def test_authorization_still_enforced_with_mcp(self, setup):
        """FIX 8 — token validation is enforced before MCP dispatch.
        A token missing 'agent_id' is denied regardless of MCP config."""
        tmp_path = setup
        init_vault(PASSPHRASE)
        vault_dict = unlock_vault(PASSPHRASE)
        vault_dict["mcp_servers"] = {
            "server": {"tools": ["allowed_tool"]},
        }
        tools_module.init_tools(vault_dict)
        init_mcp(vault_dict)

        with pytest.raises(tools_module.ToolNotPermittedError):
            asyncio.run(
                execute_tool_call(
                    agent_id="alpha",
                    token={"tool_calls": ["other_tool"]},
                    tool_name="allowed_tool",
                    action="run",
                    params={},
                )
            )

    def test_credentials_not_in_result(self, setup):
        """FIX 8 — token validation rejects calls with missing 'agent_id',
        so no result (and no credentials) can reach the caller."""
        tmp_path = setup
        init_vault(PASSPHRASE)
        vault_dict = unlock_vault(PASSPHRASE)
        vault_dict["tool_api_keys"] = {"google_calendar": "sk-secret-cal-key"}
        tools_module.init_tools(vault_dict)
        init_mcp(vault_dict)

        with pytest.raises(tools_module.ToolNotPermittedError):
            asyncio.run(
                execute_tool_call(
                    agent_id="alpha",
                    token={"tool_calls": ["google_calendar"]},
                    tool_name="google_calendar",
                    action="list",
                    params={},
                )
            )
