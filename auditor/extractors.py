"""
Extract factual claims from MahaGuardian documentation files.

Two extraction modes:
  1. Static registry  — import CLAIMS from auditor.claims
  2. Dynamic scanning — regex-based extraction from .md files

The static registry is preferred for security-critical claims because
it is deterministic and audit-reproducible. Dynamic scanning catches
claims that may have been added since the registry was last updated.
"""
from __future__ import annotations

import re
from pathlib import Path

from auditor.claims import CLAIMS


# ---------------------------------------------------------------------------
# Static claim loader
# ---------------------------------------------------------------------------

def load_static_claims() -> list[dict]:
    """Return the static claim registry."""
    return list(CLAIMS)


# ---------------------------------------------------------------------------
# Dynamic extraction from documentation
# ---------------------------------------------------------------------------

# Patterns that suggest a line contains a factual claim worth checking.
# Each entry is (label, compiled_regex).
_CLAIM_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Algorithm / crypto claims
    ("algorithm", re.compile(
        r'(?:uses?|implements?|based on|powered by)\s+'
        r'([A-Z][A-Za-z0-9\-_]+(?:-\d+)?)',
        re.IGNORECASE,
    )),
    # Negative security claims ("no X", "does not X", "never X")
    ("negative", re.compile(
        r'(?:no\s+|does\s+not\s+|doesn\'t\s+|never\s+|without\s+|cannot\s+)'
        r'(?:receive|store|use|have|access|leak|expose|expose)\s+\S+',
        re.IGNORECASE,
    )),
    # Statistics: "N tests", "N assertions", etc.
    ("statistic", re.compile(
        r'\b(\d+)\s+(?:tests?|assertions?|agents?|droplets?|findings?|rounds?)\b',
        re.IGNORECASE,
    )),
    # File / module references: "in X.py", "docs/X.md"
    ("file_reference", re.compile(
        r'(?:in\s+|file\s+|implemented\s+in\s+|see\s+|from\s+)'
        r'([a-z][a-z0-9_/.-]+\.(?:py|md|txt))',
        re.IGNORECASE,
    )),
    # Architecture / data-flow claims
    ("architecture", re.compile(
        r'Guardian\s+(?:verifies?|validates?|resolves?|applies?|mediates?|records?'
        r'|holds?|proxies?)\s+\S+',
        re.IGNORECASE,
    )),
    # "X does not receive Y" (agent isolation claims)
    ("isolation", re.compile(
        r'agents?\s+(?:do(?:es)?\s+not|never)\s+\S+',
        re.IGNORECASE,
    )),
]

# Documentation files to scan (relative globs)
_DOC_GLOBS = [
    "*.md",
    "docs/**/*.md",
    "docs/**/*.txt",
]


def extract_claims_from_docs(repo_path: str) -> list[dict]:
    """
    Scan documentation files and extract lines containing factual claims.

    Returns a list of dicts:
      text    - full line text (stripped)
      match   - the specific matched substring
      label   - claim category label
      source  - relative path to the source file
      line    - 1-based line number
    """
    repo = Path(repo_path)
    claims: list[dict] = []
    seen: set[tuple[str, int]] = set()

    doc_files: list[Path] = []
    for glob in _DOC_GLOBS:
        doc_files.extend(repo.glob(glob))

    for filepath in sorted(set(doc_files)):
        try:
            text = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel = str(filepath.relative_to(repo)).replace("\\", "/")

        for line_num, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue  # skip blank lines and markdown headings only if pure #

            for label, pattern in _CLAIM_PATTERNS:
                for m in pattern.finditer(stripped):
                    key = (rel, line_num)
                    if key in seen:
                        break
                    seen.add(key)
                    claims.append({
                        "text": stripped,
                        "match": m.group(0),
                        "label": label,
                        "source": rel,
                        "line": line_num,
                    })
                    break  # one claim per line

    return claims


# ---------------------------------------------------------------------------
# Statistics extractor
# ---------------------------------------------------------------------------

def extract_statistics(repo_path: str) -> dict[str, list[dict]]:
    """
    Extract all numeric statistics from documentation.

    Returns mapping from statistic noun (singular) to list of occurrences:
      {
          "test": [{"value": 962, "source": "README.md", "line": 42}],
          ...
      }
    """
    repo = Path(repo_path)
    stats: dict[str, list[dict]] = {}
    pattern = re.compile(
        r'\b(\d+)\s+(tests?|assertions?|agents?|droplets?|findings?)\b',
        re.IGNORECASE,
    )

    doc_files: list[Path] = []
    for glob in _DOC_GLOBS:
        doc_files.extend(repo.glob(glob))

    for filepath in sorted(set(doc_files)):
        try:
            text = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel = str(filepath.relative_to(repo)).replace("\\", "/")

        for line_num, line in enumerate(text.splitlines(), start=1):
            for m in pattern.finditer(line):
                noun = m.group(2).rstrip("s").lower()
                stats.setdefault(noun, []).append({
                    "value": int(m.group(1)),
                    "source": rel,
                    "line": line_num,
                    "context": line.strip(),
                })

    return stats
