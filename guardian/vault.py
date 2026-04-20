"""
vault.enc operations — age-encrypted credentials store.

Security guarantees:
  - Vault encrypted with age (pyrage) — NOT PyCryptodome.
  - The age identity key is itself encrypted with a passphrase-derived
    key using scrypt (parameters from config.py).
  - Passphrase is never stored anywhere.
  - Decrypted vault bytes are mlocked (won't be swapped to disk).
  - ctypes.memset zeros the locked buffer on lock_vault().
  - Secret values are never logged — only key paths and metadata.

NOTE: Python's immutable strings and garbage collector mean that
decrypted secret values may persist in process memory after
lock_vault(). The mlock/ctypes zeroing protects the raw JSON buffer
but cannot zero individual Python str objects. This is a known
limitation of memory protection in CPython. For true memory-safe
secret handling, a C extension or rust-backed module would be
required.
"""
from __future__ import annotations

import ctypes
import json
import os
import platform
import struct
import sys
import tempfile
from pathlib import Path
from typing import Optional

import pyrage
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import guardian.audit as audit
from shared.data_item import DataItem, DEMO_ITEMS
from shared.types import Classification
from shared.config import (
    AGE_KEY_PATH,
    AGE_PUBKEY_PATH,
    KEYS_DIR,
    SCRYPT_N,
    SCRYPT_P,
    SCRYPT_R,
    VAULT_DIR,
    VAULT_PATH,
)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class VaultAuthError(Exception):
    """Raised when passphrase-based decryption of the vault fails."""


class VaultError(Exception):
    """General vault operation failure."""



# ---------------------------------------------------------------------------
# Memory protection helpers
# ---------------------------------------------------------------------------

def _mlock(buf: ctypes.Array, size: int) -> None:
    """Lock memory pages so they cannot be swapped to disk."""
    try:
        if platform.system() == "Windows":
            ctypes.windll.kernel32.VirtualLock(buf, size)  # type: ignore[attr-defined]
        else:
            libc_name = "libc.dylib" if platform.system() == "Darwin" else "libc.so.6"
            libc = ctypes.CDLL(libc_name, use_errno=True)
            libc.mlock(buf, size)
    except Exception:
        try:
            audit.log(
                action="vault.mlock_failed",
                result="warning:mlock unavailable",
            )
        except Exception:
            # Audit log may not be initialised yet during early startup
            pass


def _munlock(buf: ctypes.Array, size: int) -> None:
    """Unlock previously mlocked memory pages."""
    try:
        if platform.system() == "Windows":
            ctypes.windll.kernel32.VirtualUnlock(buf, size)  # type: ignore[attr-defined]
        else:
            libc_name = "libc.dylib" if platform.system() == "Darwin" else "libc.so.6"
            libc = ctypes.CDLL(libc_name, use_errno=True)
            libc.munlock(buf, size)
    except Exception:
        try:
            audit.log(
                action="vault.munlock_failed",
                result="warning:munlock unavailable",
            )
        except Exception:
            pass


# Module-level protected buffer for the decrypted vault bytes
_vault_buffer: Optional[ctypes.Array] = None
_vault_buffer_size: int = 0


# ---------------------------------------------------------------------------
# File permission helpers
# ---------------------------------------------------------------------------

def _set_owner_only(path: Path) -> None:
    """Set file permissions to 0o600 (owner read/write only).
    On Windows this is a no-op — NTFS ACLs are the real mechanism."""
    if platform.system() != "Windows":
        os.chmod(path, 0o600)


# ---------------------------------------------------------------------------
# Atomic write helper
# ---------------------------------------------------------------------------

def _atomic_write(target: Path, data: bytes) -> None:
    """
    Write *data* to *target* atomically via a temporary file + os.replace().
    On failure the original file (if any) is left intact.
    """
    fd, tmp_path = tempfile.mkstemp(dir=str(target.parent))
    try:
        os.write(fd, data)
        os.close(fd)
        fd = -1  # sentinel — fd is closed
        os.replace(tmp_path, str(target))
    except BaseException:
        if fd >= 0:
            os.close(fd)
        # Clean up the temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Key file format helpers
# ---------------------------------------------------------------------------
#
# master.key binary layout:
#   [32 bytes]  scrypt salt
#   [12 bytes]  AES-GCM nonce
#   [N  bytes]  AES-256-GCM ciphertext (includes 16-byte GCM tag)
#
_SALT_LEN = 32
_NONCE_LEN = 12


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 32-byte AES key from passphrase + salt using scrypt."""
    if SCRYPT_N < 2**15 or SCRYPT_R < 8 or SCRYPT_P < 1:
        raise ValueError(
            "Scrypt parameters below minimum safe thresholds. "
            f"Got N={SCRYPT_N}, r={SCRYPT_R}, p={SCRYPT_P}. "
            f"Required: N>=2**15, r>=8, p>=1."
        )

    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    kdf = Scrypt(
        salt=salt,
        length=32,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _encrypt_identity(identity_str: str, passphrase: str) -> bytes:
    """
    Encrypt the age identity string with an AES-256-GCM key derived
    from passphrase via scrypt.  Returns salt + nonce + ciphertext.
    """
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, identity_str.encode("utf-8"), None)
    return salt + nonce + ciphertext


def _decrypt_identity(key_data: bytes, passphrase: str) -> str:
    """
    Decrypt the age identity string from key_data (salt + nonce + ciphertext).
    Raises VaultAuthError on decryption failure (wrong passphrase or tampered).
    """
    if len(key_data) < _SALT_LEN + _NONCE_LEN + 16:
        raise VaultAuthError("master.key file is corrupt or truncated.")
    salt = key_data[:_SALT_LEN]
    nonce = key_data[_SALT_LEN: _SALT_LEN + _NONCE_LEN]
    ciphertext = key_data[_SALT_LEN + _NONCE_LEN:]
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise VaultAuthError("Vault passphrase incorrect or vault corrupted.") from exc
    return plaintext.decode("utf-8")


# ---------------------------------------------------------------------------
# Empty vault structure
# ---------------------------------------------------------------------------

_EMPTY_VAULT: dict = {
    "llm_api_keys": {
        "anthropic": "",
        "openai": "",
    },
    "tool_api_keys": {
        "google_calendar": "",
        "ft_news": "",
        "stripe": "",
    },
    "network": {
        "device_ip": "",
        "device_name": "",
        "hetzner_droplet_ip": {},
    },
    "payment_rules": {
        "auto_approve_below_gbp": 50,
        "daily_limit_gbp": 200,
        "approved_categories": ["restaurant", "travel", "shopping"],
        "blocked_merchants": [],
        "external_agent_auto_approve_below_gbp": 0,
        "trusted_external_agents": [],
    },
    "signing_keys": {
        "soul_public_key": "",
        "soul_private_key": "",
    },
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def init_vault(passphrase: str) -> None:
    """
    Create a new vault. Generate age identity key.
    Encrypt an empty vault structure.
    Store the age identity key encrypted with passphrase using scrypt KDF.
    Never store the passphrase.
    Creates directory structure if not present.
    """
    for d in (VAULT_DIR, KEYS_DIR):
        d.mkdir(parents=True, exist_ok=True)

    # Generate age identity (private key)
    identity = pyrage.x25519.Identity.generate()
    recipient = identity.to_public()

    # Persist: master.key  = passphrase-encrypted identity string
    identity_str = str(identity)
    encrypted_key_data = _encrypt_identity(identity_str, passphrase)
    _atomic_write(AGE_KEY_PATH, encrypted_key_data)
    _set_owner_only(AGE_KEY_PATH)

    # Persist: master.key.pub = public recipient (plaintext — not sensitive)
    AGE_PUBKEY_PATH.write_text(str(recipient), encoding="utf-8")

    # Encrypt empty vault with age and write atomically
    vault_json = json.dumps(_EMPTY_VAULT).encode("utf-8")
    vault_enc = pyrage.encrypt(vault_json, [recipient])
    _atomic_write(VAULT_PATH, vault_enc)
    _set_owner_only(VAULT_PATH)

    audit.log(
        action="vault.init",
        result="success",
    )


def unlock_vault(passphrase: str) -> dict:
    """
    Decrypt vault using passphrase.
    Loads the age identity key using passphrase + scrypt.
    Decrypts vault.enc using the age identity.
    Loads decrypted contents into mlock-protected memory.
    Returns vault dict.
    Raises VaultAuthError if passphrase is wrong.
    Logs unlock event (not passphrase) to audit.log.
    """
    global _vault_buffer, _vault_buffer_size

    if not AGE_KEY_PATH.exists():
        raise VaultError("Vault not initialised. Run init_vault() first.")
    if not VAULT_PATH.exists():
        raise VaultError("vault.enc not found. Run init_vault() first.")

    key_data = AGE_KEY_PATH.read_bytes()
    identity_str = _decrypt_identity(key_data, passphrase)

    identity = pyrage.x25519.Identity.from_str(identity_str)

    vault_enc = VAULT_PATH.read_bytes()
    try:
        vault_bytes = pyrage.decrypt(vault_enc, [identity])
    except Exception as exc:
        raise VaultAuthError("Failed to decrypt vault. Possible corruption.") from exc

    # mlock the raw bytes
    _vault_buffer = ctypes.create_string_buffer(vault_bytes)
    _vault_buffer_size = len(vault_bytes)
    _mlock(_vault_buffer, _vault_buffer_size)

    vault_dict: dict = json.loads(vault_bytes)

    audit.log(action="vault.unlock", result="success")
    return vault_dict


# SECURITY NOTE — scope of this protection:
# _PROTECTED_PATHS prevents ACCIDENTAL access to
# high-sensitivity secrets through normal get_secret()
# calls. It defends against developer mistakes and
# prompt injection that reaches get_secret().
# It does NOT protect against an attacker who controls
# the Guardian process itself. Resistance to a compromised
# Guardian requires OS-level controls (Phase 2+).
_PROTECTED_PATHS = frozenset({
    "signing_keys.soul_private_key",
})


def _block_protected_access(key_path: str) -> None:
    """Log and raise PermissionError for protected path access."""
    audit.log(
        action="vault.get_secret_blocked",
        resource=key_path,
        result="failure:protected_path",
    )
    raise PermissionError(
        f"Path '{key_path}' is protected or contains "
        f"protected secrets. Use allow_protected=True."
    )


def get_secret(
    vault: dict,
    key_path: str,
    *,
    allow_protected: bool = False,
) -> str:
    """
    Retrieve a specific secret by dot-notation path.
    e.g. get_secret(vault, "llm_api_keys.anthropic")
    Logs access (key path, NOT value) to audit.log.
    Never logs the secret value.
    Raises KeyError if path does not exist.
    Raises PermissionError if path is protected and allow_protected
    is not explicitly set to True.
    """
    if not allow_protected:
        for protected in _PROTECTED_PATHS:
            # Block exact match
            if key_path == protected:
                _block_protected_access(key_path)
            # Block parent path (e.g. "signing_keys" is parent
            # of "signing_keys.soul_private_key")
            if protected.startswith(key_path + "."):
                _block_protected_access(key_path)
            # Block child path
            if key_path.startswith(protected + "."):
                _block_protected_access(key_path)

    parts = key_path.split(".")
    node: object = vault
    for part in parts:
        if not isinstance(node, dict):
            raise KeyError(f"Path component '{part}' not a dict in '{key_path}'")
        if part not in node:
            raise KeyError(f"Key '{part}' not found in vault at path '{key_path}'")
        node = node[part]

    audit.log(
        action="vault.get_secret",
        resource=key_path,   # path only — never the value
        result="success",
    )
    return node  # type: ignore[return-value]


def lock_vault(vault: dict) -> None:
    """
    Clear vault dict from memory.
    Uses ctypes to zero out the mlocked buffer before deallocation.
    Logs lock event to audit.log.
    """
    global _vault_buffer, _vault_buffer_size

    # Zero and unlock the protected buffer
    if _vault_buffer is not None:
        ctypes.memset(_vault_buffer, 0, _vault_buffer_size)
        _munlock(_vault_buffer, _vault_buffer_size)
        _vault_buffer = None
        _vault_buffer_size = 0

    # Best-effort clear the Python dict (strings are immutable — we clear
    # the container so references are released for GC)
    vault.clear()

    audit.log(action="vault.lock", result="success")


def rotate_secret(
    vault: dict, key_path: str, new_value: str, passphrase: str
) -> None:
    """
    Update a secret at key_path and re-encrypt the vault.
    Logs rotation event (key path only) to audit.log.
    Never logs the new value.
    Raises VaultAuthError if passphrase is wrong (re-verified on write).

    The re-encrypted vault is written atomically via a temp file +
    os.replace() so a crash mid-write cannot corrupt the existing vault.
    """
    # Navigate to parent dict and set the value
    parts = key_path.split(".")
    node: object = vault
    for part in parts[:-1]:
        if not isinstance(node, dict) or part not in node:
            raise KeyError(f"Path '{key_path}' does not exist in vault.")
        node = node[part]

    if not isinstance(node, dict) or parts[-1] not in node:
        raise KeyError(f"Path '{key_path}' does not exist in vault.")

    old_value = node[parts[-1]]
    node[parts[-1]] = new_value

    # Re-encrypt and persist atomically
    try:
        key_data = AGE_KEY_PATH.read_bytes()
        identity_str = _decrypt_identity(key_data, passphrase)
        identity = pyrage.x25519.Identity.from_str(identity_str)
        recipient = identity.to_public()

        vault_json = json.dumps(vault).encode("utf-8")
        vault_enc = pyrage.encrypt(vault_json, [recipient])
        _atomic_write(VAULT_PATH, vault_enc)
        _set_owner_only(VAULT_PATH)
    except Exception:
        # Roll back the in-memory change so vault dict stays consistent
        # with whatever is (still) on disk.
        node[parts[-1]] = old_value
        raise

    audit.log(
        action="vault.rotate_secret",
        resource=key_path,   # path only
        result="success",
    )


# ---------------------------------------------------------------------------
# Phase 3: DataItem-aware vault operations
# ---------------------------------------------------------------------------
#
# DataItems are stored in vault_dict["data_items"] as a list of serialised
# dicts.  The in-memory lookup index uses composite keys
# "{item_id}/{owner_partition}" so duplicate item_ids across partitions are
# supported (ambiguous-key detection in enforcer.py handles that case).
#
# These functions operate on the vault DICT (already unlocked) — they do NOT
# perform TLP enforcement.  All TLP checks stay in guardian/enforcer.py.
# ---------------------------------------------------------------------------

_DATA_ITEMS_KEY = "data_items"


def _item_to_dict(item: DataItem) -> dict:
    return {
        "item_id":         item.item_id,
        "owner_partition": item.owner_partition,
        "classification":  item.classification.value,
        "value":           item.value,
        "description":     item.description,
        "tags":            list(item.tags),
    }


def _item_from_dict(d: dict) -> DataItem:
    return DataItem(
        item_id         = d["item_id"],
        owner_partition = d["owner_partition"],
        classification  = Classification(d["classification"]),
        value           = d["value"],
        description     = d.get("description", ""),
        tags            = list(d.get("tags", [])),
    )


def seed_demo_items(vault_dict: dict) -> None:
    """
    Seed DEMO_ITEMS into vault_dict["data_items"].

    Idempotent: existing items with the same (item_id, owner_partition)
    are replaced; items not in DEMO_ITEMS are preserved.
    Logs the seed event to audit.
    """
    existing: list[dict] = vault_dict.setdefault(_DATA_ITEMS_KEY, [])

    # Index existing by composite key for O(1) duplicate detection
    index: dict[str, int] = {
        f"{d['item_id']}/{d['owner_partition']}": i
        for i, d in enumerate(existing)
    }

    for item in DEMO_ITEMS:
        ck = f"{item.item_id}/{item.owner_partition}"
        serialised = _item_to_dict(item)
        if ck in index:
            existing[index[ck]] = serialised
        else:
            index[ck] = len(existing)
            existing.append(serialised)

    audit.log(
        action="vault.seed_demo_items",
        result=f"success:seeded={len(DEMO_ITEMS)}",
    )


def _get_vault_items_unfiltered(vault_dict: dict) -> dict[str, DataItem]:
    """
    Return all DataItems as a dict keyed by "{item_id}/{owner_partition}".

    PRIVATE — callers outside guardian/ must not access vault data directly.
    This function applies NO partition filtering and NO TLP enforcement.
    All external access must go through enforcer._find_items_no_tlp_check()
    wrapped inside enforce() or resolve_and_enforce().
    """
    raw: list[dict] = vault_dict.get(_DATA_ITEMS_KEY, [])
    return {
        f"{d['item_id']}/{d['owner_partition']}": _item_from_dict(d)
        for d in raw
    }


# ---------------------------------------------------------------------------
# FIX 2: _vault_read, _vault_search, _vault_list and the _TLP_CHECKED ContextVar
# have been removed. Vault data retrieval is now ONLY possible through the
# enforcer pipeline (enforce() or resolve_and_enforce()), which applies both
# partition AND TLP checks before returning any data.
# Public callers that need the vault item index use _get_vault_items_unfiltered()
# inside guardian/ only — never expose raw items to agents.
# ---------------------------------------------------------------------------
