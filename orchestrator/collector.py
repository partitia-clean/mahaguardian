"""Collect files for review from git diff or explicit list."""
from __future__ import annotations

from pathlib import Path


_REVIEW_ALLOWLIST: list[str] = [
    "guardian/enforcer.py",
    "guardian/soul.py",
    "guardian/vault.py",
    "guardian/audit_chain.py",
    "shared/token.py",
    "shared/types.py",
    "shared/tlp_matrix.py",
    "shared/data_item.py",
    "shared/utils.py",
]


def get_changed_files(base_branch: str = "main~8") -> list[str]:
    """Return the fixed allowlist of files to review."""
    return [f for f in _REVIEW_ALLOWLIST if Path(f).exists()]


# Directories whose contents are never sent for review.
_EXCLUDED_PREFIXES = (
    "tests/",
    "deploy/scenarios/",
    "experiments/results/",
    "docs/",
    "review_results/",
    ".claude/",
)

# Only .py files from these directory roots are included.
_INCLUDED_PREFIXES = (
    "guardian/",
    "shared/",
    "orchestrator/",
    "agent/",
)


def _include(path: str) -> bool:
    """Return True if *path* should be sent to the reviewer."""
    if not path.endswith(".py"):
        return False
    for excl in _EXCLUDED_PREFIXES:
        if path.startswith(excl):
            return False
    # deploy/*.py — top-level only, no subdirectories
    if path.startswith("deploy/"):
        return "/" not in path[len("deploy/"):]
    # experiments/*.py — top-level only, no subdirectories
    if path.startswith("experiments/"):
        return "/" not in path[len("experiments/"):]
    # guardian/, shared/, orchestrator/, agent/ — all .py files
    for incl in _INCLUDED_PREFIXES:
        if path.startswith(incl):
            return True
    return False


def read_files(file_paths: list[str]) -> dict[str, str]:
    """Read file contents into a dict."""
    contents = {}
    for path in file_paths:
        try:
            contents[path] = Path(path).read_text(encoding="utf-8")
        except FileNotFoundError:
            contents[path] = f"# FILE NOT FOUND: {path}"
    return contents


def assemble_review_context(files: dict[str, str]) -> str:
    """Concatenate files into a single review context string."""
    parts = []
    for path, content in files.items():
        parts.append(f"\n{'='*60}\n=== {path} ===\n{'='*60}\n{content}")
    return "\n".join(parts)
