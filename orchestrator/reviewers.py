"""API clients for each reviewer model."""
from __future__ import annotations

import asyncio
import os
import re


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _strip_test_files(context: str) -> str:
    """Remove test-file sections from the assembled context string.

    Sections whose path starts with 'tests/' are dropped so GPT and Codex
    receive only source files.  This keeps input tokens under 30K TPM.

    assemble_review_context() produces two sep-delimited fragments per file:
      sep + "=== path ===" + sep + content
    So when a test-file header is found, the immediately following content
    fragment is also skipped.
    """
    sep = "\n" + "=" * 60 + "\n"
    parts = context.split(sep)
    filtered = []
    skip_next = False
    for part in parts:
        if skip_next:
            skip_next = False
            continue
        if part.startswith("=== tests/") or part.startswith("=== tests\\"):
            skip_next = True   # drop this header AND the content fragment that follows
            continue
        filtered.append(part)
    return sep.join(filtered)


async def _with_retry(name: str, call_fn) -> str:
    """Await call_fn(); on any exception wait 60 s and retry once.

    The second failure propagates to the caller unchanged.
    """
    try:
        return await call_fn()
    except Exception as exc:
        print(f"  {name} failed ({type(exc).__name__}: {exc}), retrying in 60 s...")
        await asyncio.sleep(60)
        return await call_fn()


# ---------------------------------------------------------------------------
# Gemini
# ---------------------------------------------------------------------------

async def review_with_gemini(context: str, prompt: str) -> str:
    """Send to Gemini 2.5 Pro via Google GenAI SDK."""
    from google import genai

    client = genai.Client(api_key=os.environ["GOOGLE_API_KEY"])

    async def _call() -> str:
        response = await asyncio.to_thread(
            client.models.generate_content,
            model="gemini-2.5-pro",
            contents=f"{prompt}\n\n{context}",
        )
        return response.text

    return await _with_retry("Gemini", _call)


# ---------------------------------------------------------------------------
# GPT-5.2
# ---------------------------------------------------------------------------

async def review_with_gpt52(context: str, prompt: str) -> str:
    """Send to GPT-4o via OpenAI API (source files only)."""
    import openai

    source_context = _strip_test_files(context)
    client = openai.AsyncOpenAI(api_key=os.environ["OPENAI_API_KEY"])

    async def _call() -> str:
        response = await client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": f"{prompt}\n\n{source_context}"}],
            max_completion_tokens=2000,
        )
        return response.choices[0].message.content

    return await _with_retry("GPT-5.2", _call)


# ---------------------------------------------------------------------------
# Codex
# ---------------------------------------------------------------------------

async def review_with_codex(context: str, prompt: str) -> str:
    """Send to GPT-4o (code-focused persona) via OpenAI API (source files only)."""
    import openai

    source_context = _strip_test_files(context)
    client = openai.AsyncOpenAI(api_key=os.environ["OPENAI_API_KEY"])

    async def _call() -> str:
        response = await client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a code-focused security and correctness reviewer. "
                        "Concentrate on implementation bugs, unsafe patterns, test coverage gaps, "
                        "and deviations from the stated specification. Be precise and cite line numbers."
                    ),
                },
                {"role": "user", "content": f"{prompt}\n\n{source_context}"},
            ],
            max_completion_tokens=2000,
        )
        return response.choices[0].message.content

    return await _with_retry("Codex", _call)


# ---------------------------------------------------------------------------
# Claude Opus (triage) — via Anthropic Python SDK
# ---------------------------------------------------------------------------

async def triage_with_opus(
    gemini_findings: str,
    gpt52_findings: str,
    codex_findings: str,
) -> str:
    """Send all findings to Claude Opus for triage via the Anthropic Python SDK.

    Requires ANTHROPIC_API_KEY environment variable to be set.
    """
    import anthropic

    triage_prompt = f"""You are the triage synthesizer for MahaGuardian's
multi-LLM adversarial review process (Methodology v3.1).

You have received findings from three independent reviewers.
Your job:
1. Deduplicate findings across reviewers
2. Rank by severity (P1 > P2 > P3)
3. Flag disagreements between reviewers as highest priority
4. For each finding: ACCEPT, REJECT (with reason), or DEFER
5. Produce a consolidated Claude Code implementation prompt
   for all ACCEPTED findings
6. State clearly whether remaining improvements are:
   a) BLOCKING (must fix before merge)
   b) COSMETIC (nice to have, can merge now)
   c) NONE (code is ready)

=== GEMINI FINDINGS ===
{gemini_findings}

=== GPT-5.2 FINDINGS ===
{gpt52_findings}

=== CODEX FINDINGS ===
{codex_findings}
"""

    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    async def _call() -> str:
        response = await asyncio.to_thread(
            client.messages.create,
            model="claude-opus-4-6",
            max_tokens=8000,
            messages=[{"role": "user", "content": triage_prompt}],
        )
        return response.content[0].text

    return await _with_retry("Opus", _call)
