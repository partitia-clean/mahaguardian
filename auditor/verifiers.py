"""
Verify extracted and static claims against the actual codebase.

Two verification strategies:
  1. Static registry — deterministic checks against known claims (claims.py)
  2. Dynamic extraction — verify claims parsed from doc files (extractors.py)
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Static claim verification
# ---------------------------------------------------------------------------

def verify_static_claims(claims: list[dict], repo_path: str) -> list[dict]:
    """
    Verify each claim in the static registry against the live codebase.

    Returns a list of result dicts:
      id, claim_text, source, status, evidence

    status values: CONFIRMED | CONTRADICTED | UNVERIFIABLE
    """
    repo = Path(repo_path)
    results = []

    for claim in claims:
        check = claim.get("check", {})
        check_type = check.get("type")

        try:
            if check_type == "file_exists":
                result = _check_file_exists(repo, check["path"], claim)

            elif check_type == "dir_exists":
                result = _check_dir_exists(repo, check["path"], claim)

            elif check_type == "all_contains":
                result = _check_all_contains(
                    repo, check["file"], check["symbol"], claim
                )

            elif check_type == "regex_in_file":
                result = _check_regex_in_file(
                    repo, check["file"], check["pattern"], claim
                )

            elif check_type == "constant_value":
                result = _check_constant_value(
                    repo, check["file"], check["name"], check["expected"], claim
                )

            else:
                result = _unverifiable(claim, f"unknown check type: {check_type!r}")

        except Exception as exc:  # noqa: BLE001
            result = _unverifiable(claim, f"check raised {type(exc).__name__}: {exc}")

        results.append(result)

    return results


# ---------------------------------------------------------------------------
# Dynamic claim verification (from extractors output)
# ---------------------------------------------------------------------------

def verify_dynamic_claims(
    claims: list[dict], repo_path: str, *, check_tests: bool = False
) -> list[dict]:
    """
    Verify dynamically extracted claims.

    Handles file references and test-count statistics.
    Test-count statistics require running pytest (slow, ~3 min).
    Pass check_tests=True to enable that check; by default it is
    skipped and test-count claims are left UNVERIFIED.
    """
    results = []
    repo = Path(repo_path)

    for claim in claims:
        text = claim.get("text", "")
        result = {
            "claim": text,
            "source": claim.get("source", ""),
            "status": "UNVERIFIED",
            "evidence": None,
        }

        # File reference: "in X.py" or "docs/X.md"
        file_match = re.search(r'([a-zA-Z0-9_/.-]+\.(py|md|txt))', text)
        if file_match:
            ref = file_match.group(1)
            candidate = repo / ref
            if candidate.exists():
                result["status"] = "CONFIRMED"
                result["evidence"] = f"file exists: {ref}"
            else:
                # Only flag as CONTRADICTED if it looks like a deliberate reference
                if "/" in ref or ref.endswith(".py"):
                    result["status"] = "CONTRADICTED"
                    result["evidence"] = f"file NOT found: {ref}"

        # Test statistics (only verified when check_tests=True)
        stat_match = re.search(
            r'(\d+)\s+(?:tests?|assertions?)\s+(?:pass(?:ing)?|in\s+CI)',
            text, re.IGNORECASE
        )
        if stat_match:
            claimed = int(stat_match.group(1))
            if check_tests:
                actual = _run_test_count(repo_path)
                if actual is not None:
                    if actual == claimed:
                        result["status"] = "CONFIRMED"
                        result["evidence"] = f"test count matches: {actual}"
                    else:
                        result["status"] = "STALE"
                        result["evidence"] = (
                            f"docs claim {claimed} tests; actual: {actual}"
                        )
                else:
                    result["status"] = "UNVERIFIABLE"
                    result["evidence"] = "pytest run failed or timed out"
            else:
                result["status"] = "UNVERIFIED"
                result["evidence"] = (
                    f"test count claim ({claimed}) not checked "
                    "(pass --check-tests to verify)"
                )

        results.append(result)

    return results


# ---------------------------------------------------------------------------
# Individual check helpers
# ---------------------------------------------------------------------------

def _check_file_exists(repo: Path, rel_path: str, claim: dict) -> dict:
    target = repo / rel_path
    if target.is_file():
        return _confirmed(claim, f"file exists: {rel_path}")
    return _contradicted(claim, f"file NOT found: {rel_path}")


def _check_dir_exists(repo: Path, rel_path: str, claim: dict) -> dict:
    target = repo / rel_path
    if target.is_dir():
        return _confirmed(claim, f"directory exists: {rel_path}")
    return _contradicted(claim, f"directory NOT found: {rel_path}")


def _check_all_contains(
    repo: Path, rel_file: str, symbol: str, claim: dict
) -> dict:
    src = repo / rel_file
    if not src.is_file():
        return _unverifiable(claim, f"source file not found: {rel_file}")

    text = src.read_text(encoding="utf-8", errors="replace")
    # Match symbol inside __all__ = [...] block
    all_block = re.search(
        r'__all__\s*=\s*\[([^\]]*)\]', text, re.DOTALL
    )
    if all_block:
        if f'"{symbol}"' in all_block.group(1) or f"'{symbol}'" in all_block.group(1):
            return _confirmed(claim, f"'{symbol}' present in {rel_file}:__all__")
        return _contradicted(claim, f"'{symbol}' absent from {rel_file}:__all__")

    # Fallback: bare string search
    if f'"{symbol}"' in text or f"'{symbol}'" in text:
        return _confirmed(claim, f"'{symbol}' found in {rel_file} (no __all__ block found)")
    return _unverifiable(claim, f"no __all__ block found in {rel_file}")


def _check_regex_in_file(
    repo: Path, rel_file: str, pattern: str, claim: dict
) -> dict:
    src = repo / rel_file
    if not src.is_file():
        return _unverifiable(claim, f"source file not found: {rel_file}")

    text = src.read_text(encoding="utf-8", errors="replace")
    match = re.search(pattern, text, re.DOTALL)
    if match:
        # Show a brief excerpt (first 80 chars of match)
        snippet = match.group(0)[:80].replace("\n", " ")
        return _confirmed(claim, f"pattern matched in {rel_file}: {snippet!r}")
    return _contradicted(claim, f"pattern not found in {rel_file}: {pattern!r}")


def _check_constant_value(
    repo: Path, rel_file: str, name: str, expected: Any, claim: dict
) -> dict:
    src = repo / rel_file
    if not src.is_file():
        return _unverifiable(claim, f"source file not found: {rel_file}")

    text = src.read_text(encoding="utf-8", errors="replace")
    pattern = rf'{re.escape(name)}\s*=\s*({re.escape(str(expected))})'
    if re.search(pattern, text):
        return _confirmed(claim, f"{name} = {expected!r} in {rel_file}")
    return _contradicted(claim, f"{name} != {expected!r} in {rel_file}")


# ---------------------------------------------------------------------------
# Result constructors
# ---------------------------------------------------------------------------

def _confirmed(claim: dict, evidence: str) -> dict:
    return {
        "id": claim.get("id", "?"),
        "claim": claim.get("text", claim.get("claim", "")),
        "source": claim.get("source", ""),
        "status": "CONFIRMED",
        "evidence": evidence,
    }


def _contradicted(claim: dict, evidence: str) -> dict:
    return {
        "id": claim.get("id", "?"),
        "claim": claim.get("text", claim.get("claim", "")),
        "source": claim.get("source", ""),
        "status": "CONTRADICTED",
        "evidence": evidence,
    }


def _unverifiable(claim: dict, evidence: str) -> dict:
    return {
        "id": claim.get("id", "?"),
        "claim": claim.get("text", claim.get("claim", "")),
        "source": claim.get("source", ""),
        "status": "UNVERIFIABLE",
        "evidence": evidence,
    }


# ---------------------------------------------------------------------------
# Test suite helpers
# ---------------------------------------------------------------------------

def _run_test_count(repo_path: str) -> int | None:
    """Run pytest and return the number of passing tests."""
    try:
        proc = subprocess.run(
            ["python", "-m", "pytest", "tests/", "-q", "--tb=no", "--no-header"],
            capture_output=True,
            text=True,
            cwd=repo_path,
            timeout=300,
        )
        match = re.search(r'(\d+) passed', proc.stdout)
        return int(match.group(1)) if match else None
    except Exception:  # noqa: BLE001
        return None
