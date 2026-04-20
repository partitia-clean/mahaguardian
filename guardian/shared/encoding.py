"""
Encoding normalisation utilities for confused-deputy scanner and SOUL metadata stripper.

FIX: SM-004 — centralises all decode/normalise variants so every scanner
covers the same attack surface without duplication.
"""
from __future__ import annotations

import base64
import html
import unicodedata
import urllib.parse


def decode_variants(raw: str) -> set[str]:
    """Return a set of all plausible decoded forms of `raw`.

    Used by confused-deputy scanner (guardian/enforcer.py) and SOUL metadata
    stripper (guardian/soul.py) to detect partition names or TLP labels that
    have been obfuscated via encoding.

    FIX: SM-004 — covers Base64, double-URL, hex, HTML entities, NFC, NFKC,
    and zero-width character stripping.
    """
    variants: set[str] = set()

    # Raw input
    variants.add(raw)

    # Unicode normalisation
    variants.add(unicodedata.normalize("NFC", raw))
    variants.add(unicodedata.normalize("NFKC", raw))

    # URL decode — single and double
    url1 = urllib.parse.unquote(raw)
    variants.add(url1)
    variants.add(urllib.parse.unquote(url1))  # double decode

    # HTML entity decode
    variants.add(html.unescape(raw))

    # Base64 — attempt decode; ignore non-base64 input silently
    try:
        decoded = base64.b64decode(raw, validate=True).decode("utf-8")
        variants.add(decoded)
    except Exception:
        pass

    # Strip zero-width characters
    zwc_stripped = raw.translate(
        {0x200B: None, 0x200C: None, 0x200D: None, 0xFEFF: None}
    )
    variants.add(zwc_stripped)

    # FIX F5: strip null bytes (\x00) — commonly injected to bypass substring matching
    null_stripped = raw.replace("\x00", "")
    if null_stripped != raw:
        variants.add(null_stripped)
        variants.add(unicodedata.normalize("NFC", null_stripped))

    return variants
