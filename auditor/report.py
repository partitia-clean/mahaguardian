"""
Generate audit report and fix prompts from verified results.

Output structure:
  <run_dir>/
    AUDIT_REPORT.md          — human-readable report
    fix_prompt_clean_repo.md — fix prompt for documentation corrections
    fix_prompt_working_repo.md — fix prompt for code and documentation corrections
"""
from __future__ import annotations

from pathlib import Path


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

def generate_report(
    static_results: list[dict],
    dynamic_results: list[dict],
    triage: str | None,
    output_dir: Path,
) -> Path:
    """
    Write AUDIT_REPORT.md and fix prompts to output_dir.

    Returns path to AUDIT_REPORT.md.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    contradicted = [r for r in static_results if r["status"] == "CONTRADICTED"]
    stale = [r for r in dynamic_results if r.get("status") == "STALE"]
    unverifiable = [r for r in static_results if r["status"] == "UNVERIFIABLE"]
    confirmed = [r for r in static_results if r["status"] == "CONFIRMED"]

    lines = [
        "# MahaGuardian Documentation Audit Report",
        "",
        f"Static claims checked:  {len(static_results)}",
        f"  CONFIRMED:      {len(confirmed)}",
        f"  CONTRADICTED:   {len(contradicted)}",
        f"  UNVERIFIABLE:   {len(unverifiable)}",
        f"Dynamic claims checked: {len(dynamic_results)}",
        f"  STALE:          {len(stale)}",
        "",
    ]

    if contradicted:
        lines += [
            "## CONTRADICTED Claims",
            "",
            "These claims in the documentation are factually wrong:",
            "",
        ]
        for r in contradicted:
            lines += [
                f"### [{r['id']}] {r['claim']}",
                f"- **Source**: {r['source']}",
                f"- **Evidence**: {r['evidence']}",
                "",
            ]

    if stale:
        lines += [
            "## STALE Claims",
            "",
            "These claims were once true but the code has changed:",
            "",
        ]
        for r in stale:
            lines += [
                f"- **{r['source']}**: {r['claim']}",
                f"  - {r['evidence']}",
                "",
            ]

    if unverifiable:
        lines += [
            "## UNVERIFIABLE Claims (manual review needed)",
            "",
        ]
        for r in unverifiable:
            lines += [
                f"- [{r['id']}] {r['claim']}: {r['evidence']}",
            ]
        lines.append("")

    if triage:
        lines += [
            "## LLM Triage",
            "",
            triage,
            "",
        ]

    report_text = "\n".join(lines)
    report_path = output_dir / "AUDIT_REPORT.md"
    report_path.write_text(report_text, encoding="utf-8")

    _write_fix_prompts(contradicted, stale, triage, output_dir)

    return report_path


# ---------------------------------------------------------------------------
# Fix prompt writers
# ---------------------------------------------------------------------------

def _write_fix_prompts(
    contradicted: list[dict],
    stale: list[dict],
    triage: str | None,
    output_dir: Path,
) -> None:
    issues = contradicted + stale
    if not issues:
        _write_text(
            output_dir / "fix_prompt_clean_repo.md",
            "# Fix Prompt — Clean Repo\n\nNo contradicted or stale claims found.\n",
        )
        _write_text(
            output_dir / "fix_prompt_working_repo.md",
            "# Fix Prompt — Working Repo\n\nNo contradicted or stale claims found.\n",
        )
        return

    issue_block = _format_issues(issues)

    clean_prompt = (
        "# Fix Prompt — Documentation Corrections\n\n"
        "Apply these documentation corrections to the repository.\n\n"
        "**Rules:**\n"
        "- Fix docs to match code. Do NOT modify code behavior.\n"
        "- If a referenced file does not exist, either create a stub or remove "
        "the reference — do not leave a broken link.\n\n"
        "## Issues to Fix\n\n"
        f"{issue_block}\n"
    )
    if triage:
        clean_prompt += f"\n## LLM Triage Detail\n\n{triage}\n"

    working_prompt = (
        "# Fix Prompt — Code and Documentation Corrections\n\n"
        "Apply these documentation AND code comment corrections to the repository.\n\n"
        "**Rules:**\n"
        "- Fix docs to match code.\n"
        "- Also update any matching code comments that repeat the stale claim.\n"
        "- If a code behavior is wrong (not just the doc), flag for manual review "
        "rather than silently changing behavior.\n\n"
        "## Issues to Fix\n\n"
        f"{issue_block}\n"
    )
    if triage:
        working_prompt += f"\n## LLM Triage Detail\n\n{triage}\n"

    _write_text(output_dir / "fix_prompt_clean_repo.md", clean_prompt)
    _write_text(output_dir / "fix_prompt_working_repo.md", working_prompt)


def _format_issues(issues: list[dict]) -> str:
    lines = []
    for r in issues:
        cid = r.get("id", "?")
        status = r.get("status", "?")
        claim = r.get("claim", r.get("text", ""))
        source = r.get("source", "")
        evidence = r.get("evidence", "")
        lines.append(f"### [{cid}] {status}: {claim}")
        lines.append(f"- Source: `{source}`")
        lines.append(f"- Evidence: {evidence}")
        lines.append("")
    return "\n".join(lines)


def _write_text(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8")
