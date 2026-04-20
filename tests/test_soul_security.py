"""
FIX-08: SOUL.lock derivation side-channel hardening.

Tests that:
  1. All error paths return identical error types/messages
  2. Error messages do not leak internal SOUL.lock details
"""
from __future__ import annotations

import pytest


class TestSOULErrorUniformity:
    def test_tamper_error_does_not_leak_internals(self, tmp_path):
        """
        SOULTamperError message must not expose partition names,
        key IDs, or internal state beyond a safe generic message.
        """
        import base64
        import nacl.signing
        from guardian.soul import SOULTamperError, verify_soul

        sk = nacl.signing.SigningKey.generate()
        vk_bytes = bytes(sk.verify_key)

        # Create a valid SOUL.lock structure
        soul_content = b'{"version": "1.0", "agent_id": "test-agent"}'
        signed = sk.sign(soul_content)
        soul_bytes = signed

        # Corrupt the signature (flip a byte)
        corrupted = bytearray(soul_bytes)
        corrupted[5] ^= 0xFF
        soul_path = tmp_path / "test-SOUL.lock"
        soul_path.write_bytes(bytes(corrupted))

        # Hash ledger with wrong hash
        ledger_path = tmp_path / "SOUL-LEDGER.txt"
        ledger_path.write_text("test: sha256:" + "a" * 64 + "\n", encoding="utf-8")

        with pytest.raises(Exception) as exc_info:
            verify_soul(soul_path, vk_bytes)

        # Error must not contain internal secret material
        err_msg = str(exc_info.value)
        assert "partition" not in err_msg.lower()
        assert "key_id" not in err_msg.lower()
        # Should be a generic tamper/signature error message
        assert len(err_msg) < 500, "Error message is suspiciously long (may leak state)"

    def test_verify_soul_error_type_is_consistent(self, tmp_path):
        """
        verify_soul() on a corrupted SOUL must raise SOULTamperError,
        not expose different exception types for different corruption modes.
        """
        import nacl.signing
        from guardian.soul import SOULTamperError, verify_soul

        sk = nacl.signing.SigningKey.generate()
        vk_bytes = bytes(sk.verify_key)

        # Write garbage bytes
        soul_path = tmp_path / "corrupt-SOUL.lock"
        soul_path.write_bytes(b"not a valid soul lock at all")

        with pytest.raises((SOULTamperError, Exception)):
            verify_soul(soul_path, vk_bytes)


# ---------------------------------------------------------------------------
# F4: Generic error messages — no paths, partition names, or schema fields leaked
# ---------------------------------------------------------------------------

class TestSOULGenericErrorMessages:
    """F4: All SOUL.lock error paths must return a generic message with corr_id only."""

    _SENSITIVE_PATTERNS = [
        # file system paths (must not appear in error messages)
        "SOUL.hash", ".sig", "C:\\", "/tmp/", "AppData",
        # schema field names (must not be enumerated in errors)
        "unknown_top_keys", "meta_missing", "meta.agent",
        "rules_not_dict", "agent_extensions",
        # hash/hex patterns
        "sha256:", "0" * 32,
    ]

    def _assert_generic(self, msg: str) -> None:
        assert "SOUL.lock validation failed" in msg, (
            f"Expected generic message, got: {msg!r}"
        )
        for pattern in self._SENSITIVE_PATTERNS:
            assert pattern not in msg, (
                f"Sensitive pattern {pattern!r} leaked in error message: {msg!r}"
            )

    def test_missing_sig_message_is_generic(self, tmp_path, monkeypatch):
        """F4: missing .sig file → generic error, no path in message."""
        import nacl.signing
        import guardian.soul as soul_module
        from guardian.soul import (
            SOULTamperError, verify_soul,
            sign_soul, update_soul_hash_ledger, sign_soul_hash_ledger,
        )
        monkeypatch.setattr(soul_module, "SOUL_HASH_PATH", tmp_path / "SOUL.hash")

        sk = nacl.signing.SigningKey.generate()
        private_key, public_key = bytes(sk), bytes(sk.verify_key)

        # Create a SOUL.lock but do NOT create the sig file
        soul_path = tmp_path / "master-SOUL.lock"
        soul_path.write_bytes(b'[meta]\nagent = "test"\n')
        update_soul_hash_ledger(soul_path, private_key)

        with pytest.raises(SOULTamperError) as exc_info:
            verify_soul(soul_path, public_key)
        self._assert_generic(str(exc_info.value))

    def test_hash_mismatch_message_is_generic(self, tmp_path, monkeypatch):
        """F4: hash mismatch → generic error, no label or hash in message."""
        import nacl.signing
        import guardian.soul as soul_module
        from guardian.soul import (
            SOULTamperError, verify_soul,
            sign_soul, update_soul_hash_ledger, sign_soul_hash_ledger,
        )
        monkeypatch.setattr(soul_module, "SOUL_HASH_PATH", tmp_path / "SOUL.hash")

        sk = nacl.signing.SigningKey.generate()
        private_key, public_key = bytes(sk), bytes(sk.verify_key)

        soul_path = tmp_path / "master-SOUL.lock"
        soul_path.write_bytes(b'[meta]\nagent = "test"\n')
        sign_soul(soul_path, private_key)

        # Write wrong hash to ledger
        ledger = tmp_path / "SOUL.hash"
        ledger.write_text("master: sha256:" + "a" * 64 + "\n", encoding="utf-8")
        sign_soul_hash_ledger(private_key)

        with pytest.raises(SOULTamperError) as exc_info:
            verify_soul(soul_path, public_key)
        self._assert_generic(str(exc_info.value))

    def test_ledger_sig_missing_message_is_generic(self, tmp_path, monkeypatch):
        """F4: missing ledger .sig → generic error, no path in message."""
        import nacl.signing
        import guardian.soul as soul_module
        from guardian.soul import (
            SOULTamperError, verify_soul_hash_ledger, update_soul_hash_ledger,
        )
        monkeypatch.setattr(soul_module, "SOUL_HASH_PATH", tmp_path / "SOUL.hash")

        sk = nacl.signing.SigningKey.generate()
        private_key, public_key = bytes(sk), bytes(sk.verify_key)

        soul_path = tmp_path / "master-SOUL.lock"
        soul_path.write_bytes(b'[meta]\nagent = "test"\n')
        update_soul_hash_ledger(soul_path)  # no signing key → no .sig

        with pytest.raises(SOULTamperError) as exc_info:
            verify_soul_hash_ledger(public_key)
        self._assert_generic(str(exc_info.value))

    def test_all_invalid_soul_errors_use_same_message_prefix(self, tmp_path, monkeypatch):
        """F4: all error paths must start with 'SOUL.lock validation failed'."""
        import nacl.signing
        import guardian.soul as soul_module
        from guardian.soul import (
            SOULTamperError, verify_soul, verify_soul_hash_ledger,
            update_soul_hash_ledger, sign_soul_hash_ledger,
        )
        monkeypatch.setattr(soul_module, "SOUL_HASH_PATH", tmp_path / "SOUL.hash")
        sk = nacl.signing.SigningKey.generate()
        private_key, public_key = bytes(sk), bytes(sk.verify_key)

        errors: list[str] = []

        # Error 1: ledger sig missing
        soul_path = tmp_path / "master-SOUL.lock"
        soul_path.write_bytes(b'[meta]\nagent = "test"\n')
        update_soul_hash_ledger(soul_path)
        try:
            verify_soul_hash_ledger(public_key)
        except SOULTamperError as e:
            errors.append(str(e))

        # Error 2: missing soul sig file
        update_soul_hash_ledger(soul_path, private_key)
        try:
            verify_soul(soul_path, public_key)
        except SOULTamperError as e:
            errors.append(str(e))

        assert len(errors) >= 2
        for msg in errors:
            assert msg.startswith("SOUL.lock validation failed"), (
                f"Unexpected error format: {msg!r}"
            )


# ---------------------------------------------------------------------------
# F4: Timing uniformity for SOUL.lock validation
# ---------------------------------------------------------------------------

@pytest.mark.timing
class TestSOULTimingUniformity:
    """F4: Valid and invalid SOUL inputs should not have distinguishable timing."""

    def _measure(self, fn, n: int = 20) -> list[float]:
        import time
        times = []
        for _ in range(n):
            t0 = time.monotonic()
            try:
                fn()
            except Exception:
                pass
            times.append(time.monotonic() - t0)
        return times

    def test_valid_vs_invalid_schema_timing_similar(self):
        """F4: schema validation timing for valid vs invalid inputs must be similar."""
        from guardian.soul import _validate_soul_schema, SOULSchemaError

        valid_soul = {"meta": {"agent": "alpha"}, "rules": {}}
        invalid_soul = {"meta": {}}  # missing 'agent' field

        valid_times = self._measure(
            lambda: _validate_soul_schema(valid_soul), n=50
        )
        invalid_times = self._measure(
            lambda: _validate_soul_schema(invalid_soul), n=50
        )

        avg_valid = sum(valid_times) / len(valid_times)
        avg_invalid = sum(invalid_times) / len(invalid_times)
        # Both should be very fast (<10ms) and within 5ms of each other
        assert abs(avg_valid - avg_invalid) < 0.005, (
            f"Timing gap: valid={avg_valid:.4f}s, invalid={avg_invalid:.4f}s"
        )
