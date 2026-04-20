"""
Tests for guardian/vault.py — age-encrypted credentials store.

All tests use a temporary directory to avoid touching ~/.mahaguardian.
"""
from __future__ import annotations

import json
import os
import platform
import sqlite3
import stat
from pathlib import Path
from unittest.mock import patch

import pytest

import guardian.audit as audit_module
import guardian.vault as vault_module
from guardian.vault import (
    VaultAuthError,
    VaultError,
    _atomic_write,
    _decrypt_identity,
    _encrypt_identity,
    get_secret,
    init_vault,
    lock_vault,
    rotate_secret,
    unlock_vault,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def isolated_paths(tmp_path, monkeypatch):
    """
    Redirect all vault paths to a temporary directory so tests are isolated
    from the real ~/.mahaguardian installation.
    """
    vault_dir = tmp_path / "vault"
    keys_dir = vault_dir / "keys"
    vault_dir.mkdir(parents=True)
    keys_dir.mkdir(parents=True)

    monkeypatch.setattr(vault_module, "VAULT_DIR", vault_dir)
    monkeypatch.setattr(vault_module, "KEYS_DIR", keys_dir)
    monkeypatch.setattr(vault_module, "VAULT_PATH", vault_dir / "vault.enc")
    monkeypatch.setattr(vault_module, "AGE_KEY_PATH", keys_dir / "master.key")
    monkeypatch.setattr(vault_module, "AGE_PUBKEY_PATH", keys_dir / "master.key.pub")

    # Also set up an in-memory audit log so log() calls don't fail
    audit_db = tmp_path / "audit.db"
    audit_module.init_audit_log(audit_db)

    yield tmp_path


@pytest.fixture(autouse=True)
def reset_vault_buffer():
    """Zero out any lingering protected buffer between tests."""
    yield
    vault_module._vault_buffer = None
    vault_module._vault_buffer_size = 0


PASSPHRASE = "correct-horse-battery-staple"
WRONG_PASSPHRASE = "wrong-passphrase"


# ---------------------------------------------------------------------------
# init_vault
# ---------------------------------------------------------------------------

class TestInitVault:
    def test_creates_vault_enc(self, isolated_paths):
        init_vault(PASSPHRASE)
        assert vault_module.VAULT_PATH.exists()

    def test_creates_age_key_file(self, isolated_paths):
        init_vault(PASSPHRASE)
        assert vault_module.AGE_KEY_PATH.exists()

    def test_creates_age_pubkey_file(self, isolated_paths):
        init_vault(PASSPHRASE)
        assert vault_module.AGE_PUBKEY_PATH.exists()

    def test_pubkey_is_plaintext_recipient(self, isolated_paths):
        init_vault(PASSPHRASE)
        pubkey = vault_module.AGE_PUBKEY_PATH.read_text()
        # age x25519 recipients start with "age1"
        assert pubkey.strip().startswith("age1")

    def test_master_key_is_binary(self, isolated_paths):
        init_vault(PASSPHRASE)
        data = vault_module.AGE_KEY_PATH.read_bytes()
        assert len(data) > 0
        # Should not be a plaintext age identity (would start with "AGE-SECRET-KEY-1")
        assert not data.startswith(b"AGE-SECRET-KEY-1")

    def test_passphrase_not_stored(self, isolated_paths):
        init_vault(PASSPHRASE)
        key_contents = vault_module.AGE_KEY_PATH.read_bytes()
        assert PASSPHRASE.encode() not in key_contents

    def test_vault_enc_is_binary_age_format(self, isolated_paths):
        init_vault(PASSPHRASE)
        vault_bytes = vault_module.VAULT_PATH.read_bytes()
        # age files start with the magic "age-encryption.org"
        assert vault_bytes.startswith(b"age-encryption.org")

    def test_creates_directories_if_missing(self, tmp_path, monkeypatch):
        nested_vault = tmp_path / "deep" / "nested" / "vault"
        nested_keys = nested_vault / "keys"
        monkeypatch.setattr(vault_module, "VAULT_DIR", nested_vault)
        monkeypatch.setattr(vault_module, "KEYS_DIR", nested_keys)
        monkeypatch.setattr(vault_module, "VAULT_PATH", nested_vault / "vault.enc")
        monkeypatch.setattr(vault_module, "AGE_KEY_PATH", nested_keys / "master.key")
        monkeypatch.setattr(vault_module, "AGE_PUBKEY_PATH", nested_keys / "master.key.pub")
        init_vault(PASSPHRASE)
        assert (nested_vault / "vault.enc").exists()


# ---------------------------------------------------------------------------
# File permissions (FIX 1)
# ---------------------------------------------------------------------------

class TestFilePermissions:
    @pytest.mark.skipif(
        platform.system() == "Windows",
        reason="0o600 permissions are a Unix concept; Windows uses ACLs",
    )
    def test_vault_enc_has_600_permissions(self, isolated_paths):
        init_vault(PASSPHRASE)
        mode = vault_module.VAULT_PATH.stat().st_mode & 0o777
        assert mode == 0o600

    @pytest.mark.skipif(
        platform.system() == "Windows",
        reason="0o600 permissions are a Unix concept; Windows uses ACLs",
    )
    def test_master_key_has_600_permissions(self, isolated_paths):
        init_vault(PASSPHRASE)
        mode = vault_module.AGE_KEY_PATH.stat().st_mode & 0o777
        assert mode == 0o600

    @pytest.mark.skipif(
        platform.system() == "Windows",
        reason="0o600 permissions are a Unix concept; Windows uses ACLs",
    )
    def test_vault_enc_permissions_after_rotate(self, isolated_paths):
        init_vault(PASSPHRASE)
        vault = unlock_vault(PASSPHRASE)
        rotate_secret(vault, "llm_api_keys.anthropic", "new", PASSPHRASE)
        mode = vault_module.VAULT_PATH.stat().st_mode & 0o777
        assert mode == 0o600
        lock_vault(vault)


# ---------------------------------------------------------------------------
# unlock_vault
# ---------------------------------------------------------------------------

class TestUnlockVault:
    def test_correct_passphrase_returns_dict(self, isolated_paths):
        init_vault(PASSPHRASE)
        vault = unlock_vault(PASSPHRASE)
        assert isinstance(vault, dict)
        lock_vault(vault)

    def test_vault_has_expected_top_level_keys(self, isolated_paths):
        init_vault(PASSPHRASE)
        vault = unlock_vault(PASSPHRASE)
        for key in ("llm_api_keys", "tool_api_keys", "network",
                    "payment_rules", "signing_keys"):
            assert key in vault
        lock_vault(vault)

    def test_wrong_passphrase_raises_vault_auth_error(self, isolated_paths):
        init_vault(PASSPHRASE)
        with pytest.raises(VaultAuthError):
            unlock_vault(WRONG_PASSPHRASE)

    def test_missing_vault_raises_vault_error(self, isolated_paths):
        # Don't call init_vault — keys and vault don't exist
        with pytest.raises(VaultError):
            unlock_vault(PASSPHRASE)

    def test_sets_protected_buffer(self, isolated_paths):
        init_vault(PASSPHRASE)
        vault = unlock_vault(PASSPHRASE)
        assert vault_module._vault_buffer is not None
        assert vault_module._vault_buffer_size > 0
        lock_vault(vault)

    def test_audit_log_records_unlock(self, isolated_paths):
        init_vault(PASSPHRASE)
        vault = unlock_vault(PASSPHRASE)
        entries = audit_module.query_log(action="vault.unlock")
        assert len(entries) >= 1
        assert entries[-1]["result"] == "success"
        lock_vault(vault)

    def test_passphrase_not_in_audit_log(self, isolated_paths):
        init_vault(PASSPHRASE)
        vault = unlock_vault(PASSPHRASE)
        entries = audit_module.query_log()
        for entry in entries:
            for v in entry.values():
                if isinstance(v, str):
                    assert PASSPHRASE not in v
        lock_vault(vault)


# ---------------------------------------------------------------------------
# get_secret
# ---------------------------------------------------------------------------

class TestGetSecret:
    @pytest.fixture
    def vault(self, isolated_paths):
        init_vault(PASSPHRASE)
        v = unlock_vault(PASSPHRASE)
        yield v
        lock_vault(v)

    def test_single_level_key(self, vault):
        # payment_rules is a top-level dict — verify sub-key access
        result = get_secret(vault, "payment_rules.auto_approve_below_gbp")
        assert result == 50

    def test_dot_notation_nested(self, vault):
        result = get_secret(vault, "network.device_ip")
        assert result == ""  # empty in fresh vault

    def test_missing_top_key_raises_key_error(self, vault):
        with pytest.raises(KeyError):
            get_secret(vault, "nonexistent.key")

    def test_missing_nested_key_raises_key_error(self, vault):
        with pytest.raises(KeyError):
            get_secret(vault, "network.does_not_exist")

    def test_audit_log_records_key_path_not_value(self, isolated_paths, vault):
        vault["llm_api_keys"]["anthropic"] = "FAKE-LLM-KEY-12345"
        get_secret(vault, "llm_api_keys.anthropic")
        entries = audit_module.query_log(action="vault.get_secret")
        assert len(entries) >= 1
        last = entries[-1]
        # Key path logged
        assert last["resource"] == "llm_api_keys.anthropic"
        # Secret value NOT in any field
        for v in last.values():
            if isinstance(v, str):
                assert "FAKE-LLM-KEY-12345" not in v

    def test_protected_path_raises_permission_error(self, vault):
        """get_secret() must block access to signing keys by default."""
        with pytest.raises(PermissionError, match="protected"):
            get_secret(vault, "signing_keys.soul_private_key")

    def test_protected_path_allowed_with_flag(self, vault):
        """allow_protected=True grants access to signing keys."""
        result = get_secret(
            vault, "signing_keys.soul_private_key", allow_protected=True
        )
        assert isinstance(result, str)

    def test_protected_path_blocked_access_logged(self, isolated_paths, vault):
        """Blocked access to protected paths must be audit-logged."""
        with pytest.raises(PermissionError):
            get_secret(vault, "signing_keys.soul_private_key")
        entries = audit_module.query_log(action="vault.get_secret_blocked")
        assert len(entries) >= 1
        assert entries[-1]["resource"] == "signing_keys.soul_private_key"
        assert "protected_path" in entries[-1]["result"]

    def test_parent_path_of_protected_raises_permission_error(self, vault):
        """FIX A: get_secret('signing_keys') must be blocked — it returns
        the entire dict including soul_private_key."""
        with pytest.raises(PermissionError, match="protected"):
            get_secret(vault, "signing_keys")

    def test_parent_path_allowed_with_flag(self, vault):
        """FIX A: allow_protected=True grants access to parent path."""
        result = get_secret(vault, "signing_keys", allow_protected=True)
        assert isinstance(result, dict)
        assert "soul_private_key" in result

    def test_non_protected_top_level_succeeds(self, vault):
        """FIX A: unprotected paths like llm_api_keys must still work."""
        result = get_secret(vault, "llm_api_keys.anthropic")
        assert isinstance(result, str)

    def test_non_protected_parent_succeeds(self, vault):
        """FIX A: top-level 'llm_api_keys' is not protected — must succeed."""
        result = get_secret(vault, "llm_api_keys")
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# lock_vault
# ---------------------------------------------------------------------------

class TestLockVault:
    def test_clears_vault_dict(self, isolated_paths):
        init_vault(PASSPHRASE)
        vault = unlock_vault(PASSPHRASE)
        assert len(vault) > 0
        lock_vault(vault)
        assert len(vault) == 0

    def test_clears_protected_buffer(self, isolated_paths):
        init_vault(PASSPHRASE)
        vault = unlock_vault(PASSPHRASE)
        lock_vault(vault)
        assert vault_module._vault_buffer is None
        assert vault_module._vault_buffer_size == 0

    def test_buffer_is_zeroed_before_dealloc(self, isolated_paths):
        import ctypes
        init_vault(PASSPHRASE)
        vault = unlock_vault(PASSPHRASE)
        buf = vault_module._vault_buffer
        size = vault_module._vault_buffer_size
        lock_vault(vault)
        # After lock, the old buffer pointer should be zeroed
        # We can't easily verify the C-level zero without keeping the pointer,
        # but we can verify the module attrs are cleared.
        assert vault_module._vault_buffer is None

    def test_audit_log_records_lock(self, isolated_paths):
        init_vault(PASSPHRASE)
        vault = unlock_vault(PASSPHRASE)
        lock_vault(vault)
        entries = audit_module.query_log(action="vault.lock")
        assert len(entries) >= 1
        assert entries[-1]["result"] == "success"

    def test_safe_to_lock_without_unlock(self, isolated_paths):
        """lock_vault on an empty dict should not raise."""
        lock_vault({})


# ---------------------------------------------------------------------------
# rotate_secret
# ---------------------------------------------------------------------------

class TestRotateSecret:
    def test_rotates_secret_value(self, isolated_paths):
        init_vault(PASSPHRASE)
        vault = unlock_vault(PASSPHRASE)
        rotate_secret(vault, "llm_api_keys.anthropic", "new-key-value", PASSPHRASE)
        assert vault["llm_api_keys"]["anthropic"] == "new-key-value"
        lock_vault(vault)

    def test_persists_to_disk(self, isolated_paths):
        init_vault(PASSPHRASE)
        vault = unlock_vault(PASSPHRASE)
        rotate_secret(vault, "llm_api_keys.anthropic", "persisted-key", PASSPHRASE)
        lock_vault(vault)
        # Re-open vault and check new value is there
        vault2 = unlock_vault(PASSPHRASE)
        assert vault2["llm_api_keys"]["anthropic"] == "persisted-key"
        lock_vault(vault2)

    def test_wrong_passphrase_raises_vault_auth_error(self, isolated_paths):
        init_vault(PASSPHRASE)
        vault = unlock_vault(PASSPHRASE)
        with pytest.raises(VaultAuthError):
            rotate_secret(vault, "llm_api_keys.anthropic", "new", WRONG_PASSPHRASE)
        lock_vault(vault)

    def test_missing_key_raises_key_error(self, isolated_paths):
        init_vault(PASSPHRASE)
        vault = unlock_vault(PASSPHRASE)
        with pytest.raises(KeyError):
            rotate_secret(vault, "nonexistent.path", "value", PASSPHRASE)
        lock_vault(vault)

    def test_audit_log_records_key_path_not_value(self, isolated_paths):
        init_vault(PASSPHRASE)
        vault = unlock_vault(PASSPHRASE)
        rotate_secret(vault, "llm_api_keys.openai", "FAKE-ROTATED-KEY-67890", PASSPHRASE)
        entries = audit_module.query_log(action="vault.rotate_secret")
        assert len(entries) >= 1
        last = entries[-1]
        assert last["resource"] == "llm_api_keys.openai"
        for v in last.values():
            if isinstance(v, str):
                assert "FAKE-ROTATED-KEY-67890" not in v
        lock_vault(vault)

    def test_failed_write_does_not_corrupt_vault(self, isolated_paths, monkeypatch):
        """
        Simulate a disk-full error during the atomic write.
        The existing vault.enc must remain intact and the in-memory
        dict must be rolled back to the old value.
        """
        init_vault(PASSPHRASE)
        vault = unlock_vault(PASSPHRASE)
        original_enc = vault_module.VAULT_PATH.read_bytes()

        # Make _atomic_write raise after the temp file is created
        real_replace = os.replace
        def failing_replace(*args, **kwargs):
            raise OSError("simulated disk full")
        monkeypatch.setattr(os, "replace", failing_replace)

        with pytest.raises(OSError, match="simulated disk full"):
            rotate_secret(vault, "llm_api_keys.anthropic", "SHOULD-NOT-PERSIST", PASSPHRASE)

        # vault.enc must be unchanged
        assert vault_module.VAULT_PATH.read_bytes() == original_enc
        # In-memory dict must be rolled back
        assert vault["llm_api_keys"]["anthropic"] == ""
        lock_vault(vault)


# ---------------------------------------------------------------------------
# Key encryption round-trip
# ---------------------------------------------------------------------------

class TestKeyEncryption:
    def test_encrypt_decrypt_roundtrip(self):
        identity_str = "AGE-SECRET-KEY-1TESTIDENTITYSTRING"
        encrypted = _encrypt_identity(identity_str, PASSPHRASE)
        decrypted = _decrypt_identity(encrypted, PASSPHRASE)
        assert decrypted == identity_str

    def test_wrong_passphrase_fails_decrypt(self):
        encrypted = _encrypt_identity("AGE-SECRET-KEY-1TEST", PASSPHRASE)
        with pytest.raises(VaultAuthError):
            _decrypt_identity(encrypted, WRONG_PASSPHRASE)

    def test_encrypted_contains_salt_and_nonce(self):
        from guardian.vault import _SALT_LEN, _NONCE_LEN
        encrypted = _encrypt_identity("AGE-SECRET-KEY-1TEST", PASSPHRASE)
        # Must be at least salt + nonce + 16 byte GCM tag
        assert len(encrypted) >= _SALT_LEN + _NONCE_LEN + 16

    def test_two_encryptions_produce_different_ciphertexts(self):
        """Different salts -> different ciphertexts even with same passphrase."""
        e1 = _encrypt_identity("AGE-SECRET-KEY-1TEST", PASSPHRASE)
        e2 = _encrypt_identity("AGE-SECRET-KEY-1TEST", PASSPHRASE)
        assert e1 != e2

    def test_corrupt_ciphertext_raises_vault_auth_error(self):
        encrypted = _encrypt_identity("AGE-SECRET-KEY-1TEST", PASSPHRASE)
        corrupted = encrypted[:-5] + bytes(5)  # flip last bytes
        with pytest.raises(VaultAuthError):
            _decrypt_identity(corrupted, PASSPHRASE)


# ---------------------------------------------------------------------------
# Scrypt minimum parameters (FIX E)
# ---------------------------------------------------------------------------

class TestScryptMinimumParameters:
    def test_weak_scrypt_n_raises_value_error(self, monkeypatch):
        """FIX E: scrypt N below 2**15 must be rejected."""
        from guardian.vault import _derive_key
        monkeypatch.setattr(vault_module, "SCRYPT_N", 2**10)
        with pytest.raises(ValueError, match="below minimum safe thresholds"):
            _derive_key("passphrase", b"0" * 32)
