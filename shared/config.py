"""
Configuration constants for MahaGuardian.
All path and parameter constants are defined here.
"""
import os
from pathlib import Path

# Production mode — set via environment for real deployments
PRODUCTION_MODE: bool = os.environ.get(
    "MAHAGUARDIAN_PRODUCTION", "false"
).lower() == "true"

GUARDIAN_HOST: str = "127.0.0.1"     # NEVER 0.0.0.0
GUARDIAN_PORT: int = 7432
AGENT_PORT: int = 8443

MAHAGUARDIAN_DIR: Path = Path.home() / ".mahaguardian"
VAULT_DIR: Path = MAHAGUARDIAN_DIR / "vault"
VAULT_PATH: Path = VAULT_DIR / "vault.enc"
USER_ENC_PATH: Path = VAULT_DIR / "USER.enc"
KEYS_DIR: Path = VAULT_DIR / "keys"
AGE_KEY_PATH: Path = KEYS_DIR / "master.key"
AGE_PUBKEY_PATH: Path = KEYS_DIR / "master.key.pub"

CORE_DIR: Path = MAHAGUARDIAN_DIR / "core"
SOUL_HASH_PATH: Path = CORE_DIR / "SOUL.hash"
AGENTS_SOUL_DIR: Path = CORE_DIR / "agents"

CERTS_DIR: Path = MAHAGUARDIAN_DIR / "certs"
CA_CERT_PATH: Path = CERTS_DIR / "ca.crt"
CA_KEY_PATH: Path = CERTS_DIR / "ca.key"
GUARDIAN_CERT_PATH: Path = CERTS_DIR / "guardian.crt"
GUARDIAN_KEY_PATH: Path = CERTS_DIR / "guardian.key"
AGENT_CERTS_DIR: Path = CERTS_DIR / "agents"

SKILLS_DIR: Path = MAHAGUARDIAN_DIR / "skills"
LOGS_DIR: Path = MAHAGUARDIAN_DIR / "logs"
AUDIT_DB_PATH: Path = LOGS_DIR / "audit.db"
CONFIG_PATH: Path = MAHAGUARDIAN_DIR / "config" / "mahaguardian.toml"

TOKEN_LIFETIME_HOURS: int = 4
KEY_ROTATION_INTERVAL_MINUTES: int = 15
PAYMENT_APPROVAL_TIMEOUT_SECONDS: int = 60

SCRYPT_N: int = 2**17              # scrypt CPU/memory cost
SCRYPT_R: int = 8
SCRYPT_P: int = 1

PARTITIONS_DIR: Path = VAULT_DIR / "partitions"

GENESIS_HASH: str = "GENESIS"     # first audit log entry prev_hash

# WebSocket reconnection settings (Phase 2)
WS_RECONNECT_BASE_SECONDS: int = 2
WS_RECONNECT_MAX_SECONDS: int = 60
WS_MAX_RETRIES: int = 10

# Agent WebSocket server (Phase 2)
# Port from environment allows multi-agent per droplet
AGENT_WS_HOST: str = "0.0.0.0"
AGENT_WS_PORT: int = int(os.environ.get("MAHAGUARDIAN_AGENT_PORT", "8443"))

# LLM key rotation failure threshold
MAX_ROTATION_FAILURES: int = 3
