"""Main orchestration loop for multi-LLM review."""
from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from orchestrator.collector import (
    assemble_review_context,
    get_changed_files,
    read_files,
)
from orchestrator.prompts import CODEX_PROMPT, GEMINI_PROMPT, GPT52_PROMPT
from orchestrator.reviewers import (
    review_with_codex,
    review_with_gemini,
    review_with_gpt52,
    triage_with_opus,
)


RESULTS_DIR = Path("review_results")
MAX_ROUNDS = 5

_RETRIAGE_DONE_MARKER = "manual_retriage_complete.txt"

# Reviewer names whose outputs the orchestrator tracks
_REVIEWERS = ["gemini", "gpt52", "codex"]

# Human-readable display name per reviewer (for failure messages)
_REVIEWER_DISPLAY: dict[str, str] = {
    "gemini": "Gemini",
    "gpt52":  "GPT-5.2",
    "codex":  "Codex",
}

# Prompt sent to each reviewer (needed to build manual paste files)
_REVIEWER_PROMPTS: dict[str, str] = {
    "gemini": GEMINI_PROMPT,
    "gpt52":  GPT52_PROMPT,
    "codex":  CODEX_PROMPT,
}


def _next_round_num(results_dir: Path) -> int:
    """Return the next round number, continuing after any existing round_N folders."""
    if not results_dir.exists():
        return 1
    existing = [
        int(d.name.split("_")[1])
        for d in results_dir.iterdir()
        if d.is_dir()
        and d.name.startswith("round_")
        and d.name.split("_")[1].isdigit()
    ]
    return max(existing) + 1 if existing else 1


# ---------------------------------------------------------------------------
# Manual-Gemini helpers
# ---------------------------------------------------------------------------

def _load_manual_reviewer(round_dir: Path, reviewer: str) -> Optional[str]:
    """
    Return content of round_dir/{reviewer}.md if the user has placed a real
    (non-error) manual response there.  Returns None otherwise.
    Convention: manual files are plain  e.g. gemini.md / gpt52.md / codex.md
    (no timestamp), to distinguish them from API-generated timestamped files).
    """
    manual_path = round_dir / f"{reviewer}.md"
    if not manual_path.exists():
        return None
    content = manual_path.read_text(encoding="utf-8").strip()
    if not content or content.startswith("REVIEWER ERROR:"):
        return None
    return content


def _find_pending_triage_round(results_dir: Path) -> Optional[int]:
    """
    Return the round_num of a round where:
      1. At least one reviewer had an API failure  (*_manual_paste.txt present)
      2. ALL failed reviewers now have manual responses  ({reviewer}.md present)
      3. Triage has NOT yet been re-run  (_RETRIAGE_DONE_MARKER absent)

    Returns None if no such round exists.  When multiple qualify, the
    lowest (oldest) pending round is returned first.
    """
    if not results_dir.exists():
        return None
    candidates = []
    for d in results_dir.iterdir():
        if not d.is_dir() or not d.name.startswith("round_"):
            continue
        n_str = d.name.split("_")[1]
        if not n_str.isdigit():
            continue
        n = int(n_str)
        paste_files = list(d.glob("*_manual_paste.txt"))
        if not paste_files:
            continue                          # no API failures in this round
        if (d / _RETRIAGE_DONE_MARKER).exists():
            continue                          # already completed
        # All failed reviewers must have placed manual responses
        all_responded = all(
            _load_manual_reviewer(d, p.stem.replace("_manual_paste", "")) is not None
            for p in paste_files
            if p.stem.replace("_manual_paste", "") in _REVIEWERS
        )
        if not all_responded:
            continue
        candidates.append(n)
    return min(candidates) if candidates else None


def _save_manual_pastes(
    failed_reviewers: list[str],
    context: str,
    round_dir: Path,
) -> None:
    """
    For every failed reviewer save {reviewer}_manual_paste.txt with the
    prompt + context, then print unified instructions covering all failures.
    """
    paste_paths:    list[Path] = []
    response_paths: list[Path] = []

    for reviewer in failed_reviewers:
        prompt     = _REVIEWER_PROMPTS.get(reviewer, "")
        paste_path = round_dir / f"{reviewer}_manual_paste.txt"
        paste_path.write_text(f"{prompt}\n\n{context}", encoding="utf-8")
        paste_paths.append(paste_path)
        response_paths.append(round_dir / f"{reviewer}.md")

    print(f"\n{'='*60}")
    for reviewer, paste_path in zip(failed_reviewers, paste_paths):
        display = _REVIEWER_DISPLAY.get(reviewer, reviewer)
        print(f"  {display} API failed. Review context saved to:")
        print(f"    {paste_path}")
        print()
    print("  Paste each file into the respective GUI, then save")
    print("  responses to:")
    for response_path in response_paths:
        print(f"    {response_path}")
    print()
    print("  Re-run orchestrator to pick up manual responses.")
    print(f"{'='*60}")


# ---------------------------------------------------------------------------
# Per-round previous-round manual-input check
# ---------------------------------------------------------------------------

def _prev_round_manual_inputs(round_num: int) -> dict[str, str]:
    """
    Check whether the round immediately before *round_num* has any reviewer
    file that contains 'REVIEWER ERROR:' AND a plain manual replacement file
    (e.g. gemini.md, gpt52.md, codex.md) placed by the user.

    Returns a dict mapping reviewer name → manual content for every such
    reviewer.  Returns an empty dict if nothing needs re-triaging (including
    the case where the retriage has already been done for that round).
    """
    if round_num <= 1:
        return {}

    prev_dir = RESULTS_DIR / f"round_{round_num - 1}"
    if not prev_dir.exists():
        return {}

    # Don't re-triage a round that's already been retried
    if (prev_dir / _RETRIAGE_DONE_MARKER).exists():
        return {}

    manual_inputs: dict[str, str] = {}
    for reviewer in _REVIEWERS:
        # Find the latest timestamped file for this reviewer
        candidates = sorted(prev_dir.glob(f"{reviewer}_*.md"))
        if not candidates:
            continue
        latest = candidates[-1].read_text(encoding="utf-8")
        if not latest.startswith("REVIEWER ERROR:"):
            continue  # this reviewer succeeded — nothing to replace
        # Check if the user placed a manual replacement
        manual = _load_manual_reviewer(prev_dir, reviewer)
        if manual is not None:
            manual_inputs[reviewer] = manual

    return manual_inputs


async def _retriage_prev_round(round_num: int, manual_inputs: dict[str, str]) -> dict:
    """
    Re-run Opus triage for round *round_num - 1* substituting *manual_inputs*
    (reviewer → content) for the reviewers that previously had errors.

    For reviewers not in *manual_inputs* the latest timestamped file is used.
    Saves a new triage_{ts}.md and writes _RETRIAGE_DONE_MARKER.
    Returns a result dict compatible with run_review_round().
    """
    prev_round = round_num - 1
    prev_dir   = RESULTS_DIR / f"round_{prev_round}"
    ts         = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    results: dict[str, str] = {}
    for reviewer in _REVIEWERS:
        if reviewer in manual_inputs:
            results[reviewer] = manual_inputs[reviewer]
        else:
            candidates = sorted(prev_dir.glob(f"{reviewer}_*.md"))
            if candidates:
                results[reviewer] = candidates[-1].read_text(encoding="utf-8")
            else:
                results[reviewer] = f"REVIEWER ERROR: no file found for {reviewer}"

    print("  Sending to Opus for triage...")
    triage = await triage_with_opus(
        results["gemini"], results["gpt52"], results["codex"]
    )
    (prev_dir / f"triage_{ts}.md").write_text(triage, encoding="utf-8")
    print(f"  Triage saved to {prev_dir}/triage_{ts}.md")

    (prev_dir / _RETRIAGE_DONE_MARKER).write_text(
        f"Manual retriage completed at {datetime.now(timezone.utc).isoformat()}\n"
        f"Reviewers with manual input: {', '.join(manual_inputs)}\n",
        encoding="utf-8",
    )

    return {
        "round":  prev_round,
        "ts":     ts,
        "gemini": results["gemini"],
        "gpt52":  results["gpt52"],
        "codex":  results["codex"],
        "triage": triage,
    }


# ---------------------------------------------------------------------------
# One review round
# ---------------------------------------------------------------------------

async def run_review_round(round_num: int, context: str) -> dict:
    """Run one review round with all three reviewers + Opus triage."""

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # Create round_dir early so manual-Gemini check and paste save can use it
    round_dir = RESULTS_DIR / f"round_{round_num}"
    round_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  Review Round {round_num}  [{ts}]")
    print(f"{'='*60}")

    def _coerce(name: str, result: object) -> str:
        if isinstance(result, Exception):
            print(f"  WARNING: {name} failed: {type(result).__name__}: {result}")
            return f"REVIEWER ERROR: {result}"
        return result  # type: ignore[return-value]

    # Use manual responses for any reviewer whose API previously failed
    gemini_manual = _load_manual_reviewer(round_dir, "gemini")
    gpt52_manual  = _load_manual_reviewer(round_dir, "gpt52")

    if gemini_manual:
        print(f"  Using manual Gemini response from {round_dir / 'gemini.md'}")
        gemini_result = gemini_manual
    if gpt52_manual:
        print(f"  Using manual GPT-5.2 response from {round_dir / 'gpt52.md'}")
        gpt52_result = gpt52_manual

    if gemini_manual and gpt52_manual:
        pass  # both already loaded; nothing to fetch
    elif gemini_manual:
        print("  Sending to GPT-5.2...")
        try:
            gpt52_result = await review_with_gpt52(context, GPT52_PROMPT)
        except Exception as exc:
            gpt52_result = _coerce("GPT-5.2", exc)
    elif gpt52_manual:
        print("  Sending to Gemini...")
        try:
            gemini_result = await review_with_gemini(context, GEMINI_PROMPT)
        except Exception as exc:
            gemini_result = _coerce("Gemini", exc)
    else:
        print("  Sending to Gemini + GPT-5.2 (parallel)...")
        gemini_result, gpt52_result = await asyncio.gather(
            review_with_gemini(context, GEMINI_PROMPT),
            review_with_gpt52(context, GPT52_PROMPT),
            return_exceptions=True,
        )
        gemini_result = _coerce("Gemini", gemini_result)
        gpt52_result  = _coerce("GPT-5.2", gpt52_result)

    print("  Waiting 60 s before Codex call (OpenAI TPM limit)...")
    await asyncio.sleep(60)

    codex_manual = _load_manual_reviewer(round_dir, "codex")
    if codex_manual:
        print(f"  Using manual Codex response from {round_dir / 'codex.md'}")
        codex_result = codex_manual
    else:
        print("  Sending to Codex...")
        try:
            codex_result = await review_with_codex(context, CODEX_PROMPT)
        except Exception as exc:
            codex_result = _coerce("Codex", exc)

    # Save paste files for every reviewer that failed
    failed = [
        r for r, result in [("gemini", gemini_result), ("gpt52", gpt52_result), ("codex", codex_result)]
        if result.startswith("REVIEWER ERROR:")
    ]
    if failed:
        _save_manual_pastes(failed, context, round_dir)

    # --- Save raw outputs (methodology v3.1: human MUST see these) ---
    (round_dir / f"gemini_{ts}.md").write_text(gemini_result, encoding="utf-8")
    (round_dir / f"gpt52_{ts}.md").write_text(gpt52_result,  encoding="utf-8")
    (round_dir / f"codex_{ts}.md").write_text(codex_result,  encoding="utf-8")

    print("  Raw outputs saved. Sending to Opus for triage...")

    # --- Triage ---
    triage = await triage_with_opus(gemini_result, gpt52_result, codex_result)
    (round_dir / f"triage_{ts}.md").write_text(triage, encoding="utf-8")
    print(f"  Triage saved to {round_dir}/triage_{ts}.md")

    return {
        "round":  round_num,
        "ts":     ts,
        "gemini": gemini_result,
        "gpt52":  gpt52_result,
        "codex":  codex_result,
        "triage": triage,
    }


# ---------------------------------------------------------------------------
# Manual-Gemini pending triage completion
# ---------------------------------------------------------------------------

async def _complete_pending_triage(round_num: int) -> dict:
    """
    Complete triage for a round where one or more reviewers previously failed
    and the user has since placed manual responses for all of them.

    For each reviewer: prefer the manual response ({reviewer}.md) when present,
    otherwise load the latest timestamped file from the round directory.
    Runs Opus triage and saves the result.
    Returns a result dict identical in shape to run_review_round().
    """
    round_dir = RESULTS_DIR / f"round_{round_num}"
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # Determine which reviewers have paste files (i.e. previously failed)
    manual_reviewers = [
        p.stem.replace("_manual_paste", "")
        for p in round_dir.glob("*_manual_paste.txt")
        if p.stem.replace("_manual_paste", "") in _REVIEWERS
    ]

    print(f"\n{'='*60}")
    print(f"  Completing triage for round {round_num}")
    print(f"  Manual responses provided for: {', '.join(manual_reviewers)}")
    print(f"{'='*60}")

    results: dict[str, str] = {}
    for reviewer in _REVIEWERS:
        manual = _load_manual_reviewer(round_dir, reviewer)
        if manual is not None:
            print(f"  Loaded manual {reviewer} from {round_dir / f'{reviewer}.md'}")
            results[reviewer] = manual
        else:
            files = sorted(round_dir.glob(f"{reviewer}_*.md"))
            if not files:
                raise RuntimeError(
                    f"round_{round_num}: no file found for reviewer '{reviewer}'. "
                    "Cannot complete triage without all three reviewers."
                )
            print(f"  Loaded {reviewer} from: {files[-1].name}")
            results[reviewer] = files[-1].read_text(encoding="utf-8")

    print("  Sending to Opus for triage...")
    triage = await triage_with_opus(results["gemini"], results["gpt52"], results["codex"])
    (round_dir / f"triage_{ts}.md").write_text(triage, encoding="utf-8")
    print(f"  Triage saved to {round_dir}/triage_{ts}.md")

    (round_dir / _RETRIAGE_DONE_MARKER).write_text(
        f"Manual retriage completed at {datetime.now(timezone.utc).isoformat()}\n"
        f"Reviewers with manual input: {', '.join(manual_reviewers)}\n",
        encoding="utf-8",
    )

    return {
        "round":  round_num,
        "ts":     ts,
        "gemini": results["gemini"],
        "gpt52":  results["gpt52"],
        "codex":  results["codex"],
        "triage": triage,
    }


# ---------------------------------------------------------------------------
# Triage analysis helpers
# ---------------------------------------------------------------------------

def is_cosmetic_only(triage: str) -> bool:
    """True when Opus says remaining issues are cosmetic-only or none."""
    t = triage.lower()
    if "cosmetic" in t and "blocking" not in t:
        return True
    if "code is ready" in t:
        return True
    if "none" in t and "remaining improvements" in t:
        return True
    return False


def extract_claude_code_prompt(triage: str) -> str:
    """Extract the Claude Code implementation prompt from triage output."""
    markers = [
        "Claude Code prompt:",
        "Claude Code implementation prompt:",
        "Implementation prompt:",
        "Fixes to apply:",
    ]
    for marker in markers:
        if marker.lower() in triage.lower():
            idx = triage.lower().index(marker.lower())
            return triage[idx:]
    # Fallback: return full triage if no explicit section found
    return triage


def _handle_round_result(result: dict, end_round: int) -> bool:
    """
    Print triage outcome for one round and decide whether to continue.

    Returns True if the loop should break (cosmetic-only or human action needed),
    False if the loop should proceed to the next round.
    """
    round_num = result["round"]
    ts        = result["ts"]

    if is_cosmetic_only(result["triage"]):
        print(f"\n  Round {round_num}: COSMETIC ONLY — ready to merge.")
        return True  # break

    cc_prompt   = extract_claude_code_prompt(result["triage"])
    prompt_path = RESULTS_DIR / f"round_{round_num}" / f"claude_code_prompt_{ts}.md"
    prompt_path.write_text(cc_prompt, encoding="utf-8")

    # Print the full prompt to stdout so it can be piped directly to Claude Code
    print(f"\n{'='*60}")
    print("  CLAUDE CODE IMPLEMENTATION PROMPT")
    print(f"  (also saved to {prompt_path})")
    print(f"{'='*60}")
    print(cc_prompt)
    print(f"{'='*60}")

    if round_num < end_round:
        print(f"\n  Round {round_num}: BLOCKING findings exist.")
        print(f"\n  ACTION REQUIRED:")
        print(f"  1. Review {RESULTS_DIR}/round_{round_num}/triage_{ts}.md")
        print(f"  2. Apply the prompt above with Claude Code")
        print(f"  3. After fixes, re-run this script for round {round_num + 1}")
        return True  # break — human reviews between rounds
    else:
        print(f"\n  Round {end_round} reached. Manual review required.")
        return False


# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------

def generate_final_report(results_dir: Path = RESULTS_DIR) -> str:
    """Generate a summary report of all completed review rounds."""
    report = [
        "# MahaGuardian Multi-LLM Review Report",
        f"Date: {datetime.now(timezone.utc).isoformat()}",
        "",
    ]

    for round_dir in sorted(results_dir.glob("round_*")):
        round_num = round_dir.name.split("_")[1]
        report.append(f"## Round {round_num}")
        report.append("")

        for reviewer in ["gemini", "gpt52", "codex", "triage"]:
            # Support both plain (legacy) and timestamped filenames; pick latest.
            candidates = sorted(round_dir.glob(f"{reviewer}_*.md"))
            if not candidates:
                candidates = [round_dir / f"{reviewer}.md"]
            path = candidates[-1]
            if path.exists():
                content = path.read_text(encoding="utf-8")
                p1 = content.lower().count("[p1]")
                p2 = content.lower().count("[p2]")
                p3 = content.lower().count("[p3]")
                report.append(f"### {reviewer.title()}")
                report.append(f"Findings: {p1} P1, {p2} P2, {p3} P3")
                report.append("")

        report.append("---")
        report.append("")

    return "\n".join(report)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main() -> None:
    print("MahaGuardian Multi-LLM Review Orchestrator")
    print(f"Started: {datetime.now(timezone.utc).isoformat()}")

    # --- Verify API keys ---
    required_keys = ["GOOGLE_API_KEY", "OPENAI_API_KEY"]
    missing = [k for k in required_keys if not os.environ.get(k)]
    if missing:
        print(f"ERROR: Missing API keys: {', '.join(missing)}")
        print("Set them as environment variables before running.")
        sys.exit(1)

    # --- Collect files ---
    print("\nCollecting files for review...")
    changed_files = get_changed_files()
    if not changed_files:
        print("No files found in the review allowlist. Nothing to review.")
        sys.exit(0)

    # Verify allowlist: only .py files from approved directories
    approved_prefixes = ("guardian/", "shared/", "orchestrator/", "agent/",
                         "deploy/", "experiments/")
    for f in changed_files:
        assert f.endswith(".py"), f"Non-.py file in allowlist: {f}"
        assert any(f.startswith(p) for p in approved_prefixes), (
            f"File outside approved directories: {f}"
        )

    print(f"  {len(changed_files)} files:")
    for f in changed_files:
        print(f"    {f}")

    file_contents = read_files(changed_files)
    context = assemble_review_context(file_contents)

    total_chars  = sum(len(c) for c in file_contents.values())
    token_est    = total_chars // 4
    print(f"\n  Total: ~{total_chars:,} chars  |  ~{token_est:,} tokens estimated")
    if token_est > 30_000:
        print(f"  WARNING: estimated token count {token_est:,} exceeds 30K limit.")
        print("  Consider trimming the allowlist in collector.py.")

    # --- Setup ---
    RESULTS_DIR.mkdir(exist_ok=True)

    # --- Check for pending manual-Gemini triage from a previous run ---
    pending_round = _find_pending_triage_round(RESULTS_DIR)
    if pending_round is not None:
        print(f"\n  Found pending round {pending_round} with manual Gemini response.")
        start_round = _next_round_num(RESULTS_DIR)
        end_round   = start_round + MAX_ROUNDS - 1

        result = await _complete_pending_triage(pending_round)
        if _handle_round_result(result, end_round):
            # If cosmetic-only or human action required, stop here
            _finish(RESULTS_DIR)
            return
        # Otherwise fall through to normal rounds

    # --- Review loop ---
    start_round = _next_round_num(RESULTS_DIR)
    if start_round > 1:
        print(f"\n  Resuming: existing rounds detected, starting at round {start_round}.")
    end_round = start_round + MAX_ROUNDS - 1  # inclusive cap for this run

    for round_num in range(start_round, end_round + 1):
        # Before running this round, check if the previous round had any
        # reviewer errors that the user has since replaced manually.
        manual_inputs = _prev_round_manual_inputs(round_num)
        if manual_inputs:
            prev = round_num - 1
            for rev in manual_inputs:
                print(f"  Found manual {rev} input for round {prev}, re-triaging...")
            prev_result = await _retriage_prev_round(round_num, manual_inputs)
            if _handle_round_result(prev_result, end_round):
                break  # cosmetic-only or blocking — let human act before continuing

        result = await run_review_round(round_num, context)

        if _handle_round_result(result, end_round):
            break

    _finish(RESULTS_DIR)


def _finish(results_dir: Path) -> None:
    """Write final report and print closing banner."""
    report      = generate_final_report(results_dir)
    report_path = results_dir / "FINAL_REPORT.md"
    report_path.write_text(report, encoding="utf-8")
    print(f"\n  Final report: {report_path}")

    print("\n" + "=" * 60)
    print("  REVIEW COMPLETE")
    print("  All results in review_results/")
    print("  Ready to push to GitHub.")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
