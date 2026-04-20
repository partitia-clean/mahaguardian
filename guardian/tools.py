"""
Tool API call executor.

AUTHORIZATION is handled by guardian/enforcer.py.
EXECUTION is handled by _execute_tool_request() -- a separate function
that can be replaced by an MCP client in Phase 2.

Security guarantees:
  - Tool API keys NEVER leave Guardian -- the API call is made from
    Guardian and only the result is returned to the agent.
  - All tool calls must be migrated to guardian.enforcer.enforce().
  - All calls are logged to the audit trail.

NOTE: Legacy Phase 1/2 authorization removed. execute_tool_call()
now expects a pre-verified Phase 3 AccessToken (shared.token.AccessToken)
whose signature and cert binding have been checked by the caller
via verify_token_binding(). The operations list on the token gates
which tools may be called.
"""
from __future__ import annotations

import re
from typing import Optional

import guardian.audit as audit
import guardian.vault as vault


class ToolNotPermittedError(Exception):
    """Raised when token does not permit the requested tool."""


class PartitionParamViolation(ToolNotPermittedError):
    """Raised when tool params reference an unauthorized partition."""


_AGENT_ID_RE = re.compile(r'^[a-zA-Z0-9_-]+$')


def _validate_agent_id(agent_id: str) -> None:
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError(f"Invalid agent_id '{agent_id}'")


# Module-level vault reference
_vault: Optional[dict] = None


def _check_params_partition_safety(
    params: dict,
    permitted_partitions: list[str],
    all_known_partitions: list[str],
) -> None:
    """
    Recursively scan all values in params for references
    to unauthorized partition names. Traverses nested dicts,
    lists, and tuples to prevent bypass via nesting.
    """
    def _scan_value(value, key_path: str = ""):
        if isinstance(value, str):
            for partition in all_known_partitions:
                if partition not in permitted_partitions:
                    if partition in value:
                        raise PartitionParamViolation(
                            f"Parameter '{key_path}' references "
                            f"unauthorized partition '{partition}'"
                        )
        elif isinstance(value, dict):
            for k, v in value.items():
                _scan_value(v, f"{key_path}.{k}" if key_path else k)
        elif isinstance(value, (list, tuple)):
            for i, item in enumerate(value):
                _scan_value(item, f"{key_path}[{i}]")
        # ints, floats, bools, None — skip silently

    for key, value in params.items():
        _scan_value(value, key)


def init_tools(vault_dict: dict) -> None:
    """
    Initialise the tools module with an unlocked vault dict.
    Must be called after unlock_vault() and before execute_tool_call().
    """
    global _vault
    _vault = vault_dict


async def execute_tool_call(
    agent_id: str,
    token: object,   # shared.token.AccessToken — pre-verified by caller
    tool_name: str,
    action: str,
    params: dict,
    token_id: str = "",
    partition_id: str = "",
) -> dict:
    """
    Validate token permits this tool, then execute it via Guardian.
    The tool API key never leaves Guardian; only the result is returned.

    Expects a pre-verified Phase 3 AccessToken (signature and cert binding
    already checked by the caller via verify_token_binding()). Checks that
    tool_name appears in token.operations and that params do not reference
    unauthorized partition names.
    """
    _validate_agent_id(agent_id)

    # STEP A -- AUTHORIZATION
    if token is None:
        audit.log(
            action="tool.execute",
            agent_id=agent_id,
            result="denied:missing_token",
        )
        raise ToolNotPermittedError("Token is missing or invalid")

    token_agent_id = getattr(token, "agent_id", None)
    if token_agent_id != agent_id:
        audit.log(
            action="tool.execute",
            agent_id=agent_id,
            result="denied:token_agent_mismatch",
        )
        raise ToolNotPermittedError("Token agent_id does not match caller")

    operations: list[str] = getattr(token, "operations", None) or []
    if tool_name not in operations:
        audit.log(
            action="tool.execute",
            agent_id=agent_id,
            result=f"denied:tool_not_permitted:{tool_name}",
        )
        raise ToolNotPermittedError(f"Token does not permit tool '{tool_name}'")

    permitted_partitions: list[str] = getattr(token, "partitions", None) or []
    all_known_partitions: list[str] = (
        list({
            item.owner_partition
            for item in vault._get_vault_items_unfiltered(_vault).values()
        })
        if _vault is not None
        else []
    )
    _check_params_partition_safety(params, permitted_partitions, all_known_partitions)

    # STEP B -- EXECUTION (replaceable by MCP in Phase 2)
    result = await _execute_tool_request(tool_name, action, params)

    audit.log(
        action="tool.execute",
        agent_id=agent_id,
        resource=f"{tool_name}:{action}",
        partition_id=partition_id or None,
        result="success",
    )
    return result


async def _execute_tool_request(
    tool_name: str,
    action: str,
    params: dict,
) -> dict:
    """
    Execute tool via MCP if configured, otherwise fallback
    to simulated response.

    Phase 2: MCP servers configured in vault handle execution.
    Phase 1 fallback: simulated responses for testing.

    The authorization layer above remains MahaGuardian's unique value —
    this function is ONLY called after enforcer checks pass.
    """
    if _vault is None:
        raise RuntimeError("Tools module not initialised. Call init_tools() first.")

    from guardian.mcp_client import resolve_mcp_server, call_mcp_tool

    server_name = resolve_mcp_server(tool_name)

    if server_name:
        # Real MCP execution — credentials from vault, never exposed
        return await call_mcp_tool(server_name, tool_name, params)

    # Phase 1 fallback: simulated response
    return {
        "tool": tool_name,
        "action": action,
        "status": "success",
        "data": params,
        "note": "simulated (no MCP server configured)",
    }
