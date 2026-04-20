"""
MCP Client Manager.

Manages connections to MCP servers configured in the vault.
Credentials are injected from vault at connection time and
never exposed to callers or agents.

The split-trust boundary is preserved: the agent sends a tool
request to Guardian, Guardian authorizes it via the enforcer,
then Guardian executes it via MCP using credentials the agent
never sees.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

import guardian.audit as audit

logger = logging.getLogger(__name__)

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    HAS_MCP = True
except ImportError:
    HAS_MCP = False


class MCPClientManager:
    """
    Manages lazy connections to configured MCP servers.
    Async-native.
    """

    def __init__(self):
        self._config: dict = {}    # server_name -> config dict
        self._sessions: dict = {}  # server_name -> ClientSession
        self._vault = None

    def init(self, vault_dict: dict) -> None:
        """
        Initialize from vault config.
        Reads mcp_servers from vault.
        """
        self._vault = vault_dict
        try:
            servers = vault_dict.get("mcp_servers", {})
            if isinstance(servers, str):
                servers = json.loads(servers)
            self._config = servers
        except (json.JSONDecodeError, TypeError):
            self._config = {}
            logger.warning("No MCP servers configured in vault")

        audit.log(
            action="mcp.init",
            result=f"success:servers={list(self._config.keys())}",
        )

    def resolve_server(self, tool_name: str) -> Optional[str]:
        """
        Look up which MCP server handles this tool.
        Returns server name or None if not mapped.
        """
        for server_name, config in self._config.items():
            tools = config.get("tools", [])
            if tool_name in tools:
                return server_name
        return None

    async def call_tool(
        self,
        server_name: str,
        tool_name: str,
        arguments: dict,
    ) -> dict:
        """
        Call a tool on the named MCP server.

        Connects lazily on first call. Credentials injected
        from vault. Never exposed to callers.
        """
        if not HAS_MCP:
            raise RuntimeError(
                "MCP SDK not installed. Install with: pip install mcp"
            )

        config = self._config.get(server_name)
        if config is None:
            raise ValueError(f"Unknown MCP server: {server_name}")

        session = await self._get_or_create_session(server_name)

        try:
            result = await session.call_tool(tool_name, arguments)
            return {"status": "success", "data": result.content}
        except Exception as exc:
            # NEVER log raw exception — may contain credentials
            safe_error = type(exc).__name__
            audit.log(
                action="mcp.call_failed",
                result=f"failure:server={server_name},"
                       f"tool={tool_name},"
                       f"error_type={safe_error}",
            )
            raise RuntimeError(
                f"MCP tool call failed: {safe_error}"
            ) from None

    async def _get_or_create_session(self, server_name: str):
        """Lazy connection to MCP server."""
        if server_name in self._sessions:
            return self._sessions[server_name]

        config = self._config[server_name]
        transport = config.get("transport", "stdio")

        if transport == "stdio":
            session = await self._connect_stdio(server_name, config)
        elif transport == "sse":
            session = await self._connect_sse(server_name, config)
        else:
            raise ValueError(f"Unknown MCP transport: {transport}")

        self._sessions[server_name] = session
        return session

    async def _connect_stdio(self, server_name: str, config: dict):
        """Connect to a local MCP server via stdio."""
        command = config["command"]
        env = config.get("env", {})

        # Resolve vault: references in env
        resolved_env = {}
        for k, v in env.items():
            if isinstance(v, str) and v.startswith("vault:"):
                vault_key = v[6:]  # strip "vault:" prefix
                from guardian import vault as vault_mod
                resolved_env[k] = vault_mod.get_secret(
                    self._vault, vault_key
                )
            else:
                resolved_env[k] = v

        params = StdioServerParameters(
            command=command[0],
            args=command[1:] if len(command) > 1 else [],
            env=resolved_env,
        )

        try:
            transport = await stdio_client(params)
            session = ClientSession(*transport)
            await session.initialize()
        except Exception as exc:
            safe_error = type(exc).__name__
            audit.log(
                action="mcp.connect_failed",
                result=f"failure:server={server_name},"
                       f"transport=stdio,error_type={safe_error}",
            )
            raise RuntimeError(
                f"MCP stdio connect failed: {safe_error}"
            ) from None

        audit.log(
            action="mcp.connected",
            result=f"success:server={server_name},transport=stdio",
        )
        return session

    async def _connect_sse(self, server_name: str, config: dict):
        """Connect to a remote MCP server via SSE."""
        from mcp.client.sse import sse_client

        url = config["url"]
        auth_header = config.get("auth_header", "")
        vault_key = config.get("vault_key", "")

        headers = {}
        if auth_header and vault_key:
            from guardian import vault as vault_mod
            api_key = vault_mod.get_secret(self._vault, vault_key)
            headers[auth_header] = api_key

        try:
            transport = await sse_client(url, headers=headers)
            session = ClientSession(*transport)
            await session.initialize()
        except Exception as exc:
            safe_error = type(exc).__name__
            audit.log(
                action="mcp.connect_failed",
                result=f"failure:server={server_name},"
                       f"transport=sse,error_type={safe_error}",
            )
            raise RuntimeError(
                f"MCP SSE connect failed: {safe_error}"
            ) from None

        audit.log(
            action="mcp.connected",
            result=f"success:server={server_name},transport=sse",
        )
        return session

    async def close_all(self) -> None:
        """Close all MCP server connections."""
        for name, session in list(self._sessions.items()):
            try:
                await session.close()
            except Exception:
                pass
        self._sessions.clear()


# Module-level singleton
_manager = MCPClientManager()


def init_mcp(vault_dict: dict) -> None:
    """Initialize MCP client manager from vault config."""
    _manager.init(vault_dict)


def resolve_mcp_server(tool_name: str) -> Optional[str]:
    """Look up which MCP server handles a tool."""
    return _manager.resolve_server(tool_name)


async def call_mcp_tool(
    server_name: str, tool_name: str, arguments: dict
) -> dict:
    """Call a tool on the named MCP server."""
    return await _manager.call_tool(server_name, tool_name, arguments)


async def close_mcp() -> None:
    """Close all MCP connections."""
    await _manager.close_all()
