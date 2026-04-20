"""
HEARTBEAT.md task runner for agent on droplet.
Manages scheduled tasks defined in HEARTBEAT.md.
"""
from __future__ import annotations
import asyncio
from typing import Optional

_tasks: dict[str, asyncio.Task] = {}

async def start_heartbeat_runner(agent_id: str, tasks_config: list[dict]) -> None:
    """Start scheduled tasks from HEARTBEAT.md config."""
    for task_cfg in tasks_config:
        name = task_cfg.get("name", "unknown")
        interval = task_cfg.get("interval_seconds", 300)

        async def _run(n: str = name, iv: int = interval) -> None:
            try:
                while True:
                    await asyncio.sleep(iv)
                    # Phase 1: log heartbeat. Phase 2: execute task.
            except asyncio.CancelledError:
                pass

        task = asyncio.create_task(_run())
        _tasks[f"{agent_id}:{name}"] = task

def stop_heartbeat_runner(agent_id: str) -> None:
    """Stop all heartbeat tasks for agent."""
    keys_to_remove = [k for k in _tasks if k.startswith(f"{agent_id}:")]
    for key in keys_to_remove:
        task = _tasks.pop(key)
        task.cancel()
