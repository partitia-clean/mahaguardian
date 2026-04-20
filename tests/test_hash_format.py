"""
FIX-10: Standardize hash format to sha256:<hex>.

Tests that:
  - format_hash() returns the correct canonical format
  - All hash-generating functions in the codebase use this format
  - Hash matches regex ^sha256:[a-f0-9]{64}$
"""
from __future__ import annotations

import hashlib
import re

import pytest

from shared.utils import format_hash, is_valid_hash_format

_HASH_RE = re.compile(r'^sha256:[a-f0-9]{64}$')


class TestFormatHash:
    def test_format_hash_produces_sha256_prefix(self):
        result = format_hash(b"test data")
        assert result.startswith("sha256:")

    def test_format_hash_produces_64_hex_chars(self):
        result = format_hash(b"test data")
        hex_part = result[len("sha256:"):]
        assert len(hex_part) == 64
        assert all(c in "0123456789abcdef" for c in hex_part)

    def test_format_hash_matches_canonical_regex(self):
        for data in [b"", b"hello", b"\x00\xff" * 100]:
            result = format_hash(data)
            assert _HASH_RE.match(result), f"format_hash({data!r}) = {result!r} doesn't match regex"

    def test_format_hash_matches_manual_sha256(self):
        data = b"mahaguardian test vector"
        expected = "sha256:" + hashlib.sha256(data).hexdigest()
        assert format_hash(data) == expected

    def test_format_hash_lowercase(self):
        result = format_hash(b"case test")
        hex_part = result[len("sha256:"):]
        assert hex_part == hex_part.lower()

    def test_is_valid_hash_format_accepts_valid(self):
        valid = "sha256:" + "a" * 64
        assert is_valid_hash_format(valid)

    def test_is_valid_hash_format_rejects_bare_hex(self):
        bare = "a" * 64
        assert not is_valid_hash_format(bare)

    def test_is_valid_hash_format_rejects_uppercase(self):
        upper = "sha256:" + "A" * 64
        assert not is_valid_hash_format(upper)

    def test_is_valid_hash_format_rejects_wrong_length(self):
        short = "sha256:" + "a" * 32
        assert not is_valid_hash_format(short)

    def test_tokens_cert_fingerprint_uses_sha256_prefix(self):
        """guardian/tokens.py _cert_fingerprint() must return sha256:<hex>."""
        from guardian.tokens import _cert_fingerprint
        fp = _cert_fingerprint(b"test-cert-bytes")
        assert is_valid_hash_format(fp), f"cert fingerprint {fp!r} is not in canonical format"

    def test_shared_token_cert_fingerprint_uses_sha256_prefix(self):
        """shared/token.py cert_fingerprint() must return sha256:<hex>."""
        from shared.token import cert_fingerprint
        fp = cert_fingerprint(b"test-cert-bytes")
        assert is_valid_hash_format(fp), f"cert fingerprint {fp!r} is not in canonical format"

    def test_genesis_hash_has_sha256_prefix(self):
        """
        FIX 9: GENESIS_HASH in audit_chain.py now carries the 'sha256:' prefix
        for consistency with all other hash outputs in the chain.
        """
        from guardian.audit_chain import GENESIS_HASH
        assert GENESIS_HASH.startswith("sha256:")
        bare = GENESIS_HASH[len("sha256:"):]
        assert len(bare) == 64
        assert all(c in "0123456789abcdef" for c in bare)
