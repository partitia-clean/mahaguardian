"""
Tests for SM-004: encoding coverage in decode_variants, scan_params,
and derive_instruction_set.

Verifies that Base64, double-URL, HTML-entity, and zero-width-character
obfuscation are all caught by the confused-deputy scanner and SOUL metadata
stripper via the shared decode_variants() utility.
"""
from __future__ import annotations

import base64
import html
import urllib.parse

import pytest

from guardian.enforcer import ConfusedDeputyError, scan_params
from guardian.shared.encoding import decode_variants


# ---------------------------------------------------------------------------
# decode_variants unit tests
# ---------------------------------------------------------------------------

class TestDecodeVariants:
    def test_base64_encoded_partition_is_decoded(self):
        """decode_variants must return the Base64-decoded form."""
        partition = "company-a"
        encoded = base64.b64encode(partition.encode()).decode()
        assert partition in decode_variants(encoded)

    def test_double_url_encoded_partition_is_decoded(self):
        """decode_variants must return the double-URL-decoded form."""
        partition = "company-a"
        single = urllib.parse.quote(partition)
        double = urllib.parse.quote(single)
        variants = decode_variants(double)
        assert partition in variants

    def test_html_entity_tlp_level_is_decoded(self):
        """decode_variants must HTML-unescape encoded TLP level strings."""
        # HTML-entity encode 'TLP:WHITE' using numeric entities
        encoded = "&#84;&#76;&#80;:WHITE"   # T, L, P → numeric HTML entities
        variants = decode_variants(encoded)
        assert html.unescape(encoded) in variants   # "TLP:WHITE"

    def test_zero_width_char_stuffed_partition_is_decoded(self):
        """decode_variants must strip zero-width characters."""
        partition = "company-a"
        stuffed = "comp\u200bany-a"    # U+200B ZERO WIDTH SPACE
        variants = decode_variants(stuffed)
        assert partition in variants

    def test_raw_string_is_always_included(self):
        variants = decode_variants("hello")
        assert "hello" in variants

    def test_nfc_normalised_form_is_included(self):
        import unicodedata
        raw = "caf\u0065\u0301"          # 'e' + combining acute
        nfc = unicodedata.normalize("NFC", raw)
        assert nfc in decode_variants(raw)

    def test_invalid_base64_is_silently_ignored(self):
        """Non-base64 strings must not raise — just return other variants."""
        variants = decode_variants("not-base64!!!")
        assert "not-base64!!!" in variants    # raw form still present


# ---------------------------------------------------------------------------
# scan_params encoding tests — FIX: SM-004
# ---------------------------------------------------------------------------

_PARTITIONS = ["company-a", "company-b"]


class TestScanParamsEncoding:
    def test_plain_partition_name_detected(self):
        with pytest.raises(ConfusedDeputyError):
            scan_params({"key": "company-a"}, _PARTITIONS)

    def test_base64_encoded_partition_detected(self):
        """Base64-encoded partition name in params must raise ConfusedDeputyError."""
        encoded = base64.b64encode(b"company-a").decode()
        with pytest.raises(ConfusedDeputyError):
            scan_params({"key": encoded}, _PARTITIONS)

    def test_double_url_encoded_partition_detected(self):
        """Double-URL-encoded partition name must raise ConfusedDeputyError."""
        single = urllib.parse.quote("company-a")
        double = urllib.parse.quote(single)
        with pytest.raises(ConfusedDeputyError):
            scan_params({"payload": double}, _PARTITIONS)

    def test_html_entity_encoded_partition_detected(self):
        """HTML-entity-encoded partition name must raise ConfusedDeputyError."""
        # Encode the hyphen as an HTML entity: company&#x2D;a
        encoded = "company&#x2D;a"
        with pytest.raises(ConfusedDeputyError):
            scan_params({"field": encoded}, _PARTITIONS)

    def test_zero_width_char_partition_detected(self):
        """Zero-width-character-stuffed partition name must raise ConfusedDeputyError."""
        stuffed = "comp\u200bany-a"    # U+200B in the middle
        with pytest.raises(ConfusedDeputyError):
            scan_params({"field": stuffed}, _PARTITIONS)

    def test_partition_in_dict_key_detected(self):
        """FIX SM-006: partition name in a dict KEY must be caught."""
        with pytest.raises(ConfusedDeputyError):
            scan_params({"company-a": "some_value"}, _PARTITIONS)

    def test_clean_params_do_not_raise(self):
        """Params with no partition references must not raise."""
        scan_params({"action": "read", "limit": 10, "tags": ["public"]}, _PARTITIONS)

    def test_nested_encoded_partition_detected(self):
        """Encoded partition nested inside a list must be caught."""
        encoded = base64.b64encode(b"company-b").decode()
        with pytest.raises(ConfusedDeputyError):
            scan_params({"filters": [{"value": encoded}]}, _PARTITIONS)
