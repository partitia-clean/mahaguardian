"""
MahaGuardian Documentation Auditor — verifies doc/code consistency.

Phases:
  1. Load static claim registry + extract dynamic claims from docs
  2. Verify claims locally (deterministic, no LLM required)
  3. Multi-LLM cross-audit (optional — requires orchestrator module)
  4. Triage findings (optional — requires orchestrator module)
  5. Generate AUDIT_REPORT.md and fix prompts

Usage:
  # Local-only audit (no LLM keys required)
  py -3 -m auditor.main [--repo PATH]

  # Full audit with LLM reviewers
  py -3 -m auditor.main [--repo PATH] --llm
"""
from __future__ import annotations

import asyncio
import sys
import argparse
from datetime import datetime, timezone
from pathlib import Path

from auditor.extractors import load_static_claims, extract_claims_from_docs
from auditor.verifiers import verify_static_claims, verify_dynamic_claims
from auditor.report import generate_report

# orchestrator is a sibling package in the same repo.
# Import succeeds when running `py -3 -m auditor.main` from the mahaguardian root.
try:
    from orchestrator.reviewers import (
        review_with_gemini,
        review_with_gpt52,
        review_with_codex,
        triage_with_opus,
    )
    _HAS_REVIEWERS = True
except ImportError:
    _HAS_REVIEWERS = False

from auditor.prompts import GEMINI_AUDIT_PROMPT, GPT_AUDIT_PROMPT, CODEX_AUDIT_PROMPT

RESULTS_DIR = Path("audit_results")


# ---------------------------------------------------------------------------
# Main audit loop
# ---------------------------------------------------------------------------

async def run_audit(
    repo_path: str = ".", *, use_llm: bool = False, check_tests: bool = False
) -> None:
    """Run full documentation audit cycle."""
    print("MahaGuardian Documentation Auditor")
    print(f"Started:  {datetime.now(timezone.utc).isoformat()}")
    print(f"Repo:     {repo_path}")
    print(f"LLM mode: {'enabled' if use_llm and _HAS_REVIEWERS else 'disabled'}")

    # ------------------------------------------------------------------
    # Phase 1: Load claims
    # ------------------------------------------------------------------
    print("\nPhase 1: Loading claims...")
    static_claims = load_static_claims()
    dynamic_claims = extract_claims_from_docs(repo_path)
    print(f"  Static registry:  {len(static_claims)} claims")
    n_sources = len({c["source"] for c in dynamic_claims})
    print(f"  Dynamic (scanned): {len(dynamic_claims)} claims from {n_sources} files")

    # ------------------------------------------------------------------
    # Phase 2: Local verification
    # ------------------------------------------------------------------
    print("\nPhase 2: Local verification...")
    static_results = verify_static_claims(static_claims, repo_path)
    dynamic_results = verify_dynamic_claims(
        dynamic_claims, repo_path, check_tests=check_tests
    )

    confirmed = sum(1 for r in static_results if r["status"] == "CONFIRMED")
    contradicted = [r for r in static_results if r["status"] == "CONTRADICTED"]
    unverifiable = sum(1 for r in static_results if r["status"] == "UNVERIFIABLE")
    stale = [r for r in dynamic_results if r.get("status") == "STALE"]

    print(f"  Static:  {confirmed} confirmed, "
          f"{len(contradicted)} contradicted, "
          f"{unverifiable} unverifiable")
    print(f"  Dynamic: {len(stale)} stale claims found")

    if contradicted:
        print("\n  CONTRADICTED claims:")
        for r in contradicted:
            print(f"    [{r['id']}] {r['claim']}")
            print(f"           {r['evidence']}")

    if stale:
        print("\n  STALE claims:")
        for r in stale:
            print(f"    {r['source']}: {r['claim']}")
            print(f"           {r['evidence']}")

    # ------------------------------------------------------------------
    # Phase 3: Multi-LLM cross-audit (optional)
    # ------------------------------------------------------------------
    triage_text: str | None = None

    if use_llm and _HAS_REVIEWERS:
        print("\nPhase 3: Sending to LLM reviewers...")
        context = _format_audit_context(
            static_claims, static_results, dynamic_claims, repo_path
        )

        gemini_res, gpt_res = await asyncio.gather(
            review_with_gemini(context, GEMINI_AUDIT_PROMPT),
            review_with_gpt52(context, GPT_AUDIT_PROMPT),
            return_exceptions=True,
        )

        for name, res in [("Gemini", gemini_res), ("GPT", gpt_res)]:
            if isinstance(res, Exception):
                print(f"  WARNING: {name} failed: {res}")
                if name == "Gemini":
                    gemini_res = f"REVIEWER ERROR: {res}"
                else:
                    gpt_res = f"REVIEWER ERROR: {res}"

        print("  Waiting 60s for rate limits...")
        await asyncio.sleep(60)

        codex_res = await review_with_codex(context, CODEX_AUDIT_PROMPT)
        if isinstance(codex_res, Exception):
            print(f"  WARNING: Codex failed: {codex_res}")
            codex_res = f"REVIEWER ERROR: {codex_res}"

        # ------------------------------------------------------------------
        # Phase 4: Triage
        # ------------------------------------------------------------------
        print("\nPhase 4: Triage with Opus...")
        triage_text = await triage_with_opus(
            str(gemini_res), str(gpt_res), str(codex_res)
        )
    elif use_llm and not _HAS_REVIEWERS:
        print("\nERROR: --llm requested but orchestrator.reviewers could not be imported.")
        print("  Run from the mahaguardian repo root: py -3 -m auditor.main --llm")
        sys.exit(2)

    # ------------------------------------------------------------------
    # Phase 5: Report + fix prompts
    # ------------------------------------------------------------------
    print("\nPhase 5: Generating report...")
    RESULTS_DIR.mkdir(exist_ok=True)
    run_dir = RESULTS_DIR / datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    report_path = generate_report(
        static_results, dynamic_results, triage_text, run_dir
    )
    print(f"  Report: {report_path}")
    print(f"  Fix prompts in: {run_dir}/")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print()
    if contradicted:
        print(f"RESULT: {len(contradicted)} CONTRADICTED claim(s). "
              "Fix documentation before next release.")
        sys.exit(1)
    elif stale:
        print(f"RESULT: {len(stale)} stale claim(s). "
              "Update documentation to match current test count.")
        sys.exit(1)
    else:
        print("RESULT: All local checks passed. Documentation is consistent with code.")


# ---------------------------------------------------------------------------
# Context formatter for LLM reviewers
# ---------------------------------------------------------------------------

def _format_audit_context(
    static_claims: list[dict],
    static_results: list[dict],
    dynamic_claims: list[dict],
    repo_path: str,
) -> str:
    parts = [
        "# MahaGuardian Documentation Audit Context",
        "",
        "## Static Claim Results",
        "",
    ]

    result_by_id = {r["id"]: r for r in static_results}
    for claim in static_claims:
        cid = claim.get("id", "?")
        result = result_by_id.get(cid, {})
        status = result.get("status", "UNVERIFIED")
        evidence = result.get("evidence", "")
        parts.append(f"[{status}] {cid}: {claim['text']}")
        parts.append(f"  Source: {claim['source']}")
        if evidence:
            parts.append(f"  Evidence: {evidence}")
        parts.append("")

    parts += [
        "## Dynamic Claims (from doc scan)",
        "",
    ]
    for c in dynamic_claims[:50]:  # cap at 50 to avoid token overflow
        parts.append(f"  [{c['label']}] {c['source']}:{c['line']}: {c['text'][:120]}")

    # Include key source files
    repo = Path(repo_path)
    parts += ["", "## Key Source Files", ""]
    for rel in [
        "guardian/enforcer.py",
        "guardian/audit_chain.py",
        "shared/types.py",
        "shared/tlp_matrix.py",
        "shared/utils.py",
        "shared/token.py",
    ]:
        src = repo / rel
        if src.is_file():
            parts.append(f"### {rel}")
            parts.append("```python")
            parts.append(src.read_text(encoding="utf-8", errors="replace")[:3000])
            parts.append("```")
            parts.append("")

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="MahaGuardian Documentation Auditor"
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Path to repo root (default: current directory)",
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        default=False,
        help="Enable multi-LLM cross-audit (requires orchestrator module)",
    )
    parser.add_argument(
        "--check-tests",
        action="store_true",
        default=False,
        help="Run pytest to verify test-count claims (adds ~3 min)",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    asyncio.run(run_audit(args.repo, use_llm=args.llm, check_tests=args.check_tests))
