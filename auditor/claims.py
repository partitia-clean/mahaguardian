"""
Static claim registry for MahaGuardian documentation/code consistency checks.

Each claim has:
  id       - unique identifier (API-NNN, BEH-NNN, SEC-NNN, STR-NNN)
  text     - human-readable description of the claim
  type     - claim category
  source   - documentation file making the claim
  check    - verification descriptor (used by verifiers.py)

Check types:
  file_exists        - referenced path must exist in repo
  file_not_exists    - referenced path must NOT exist (inversion)
  all_contains       - symbol must appear in module __all__
  regex_in_file      - pattern must match in given source file
  enum_members       - enum class must have exactly these members
  constant_value     - constant must equal expected value
  default_arg        - function arg must have expected default
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

CLAIMS: list[dict] = [

    # -----------------------------------------------------------------------
    # STR — Structure claims (directory / file layout)
    # -----------------------------------------------------------------------

    {
        "id": "STR-001",
        "text": "guardian/ directory exists",
        "type": "structure",
        "source": "README.md",
        "check": {"type": "dir_exists", "path": "guardian"},
    },
    {
        "id": "STR-002",
        "text": "agent/ directory exists",
        "type": "structure",
        "source": "README.md",
        "check": {"type": "dir_exists", "path": "agent"},
    },
    {
        "id": "STR-003",
        "text": "shared/ directory exists",
        "type": "structure",
        "source": "README.md",
        "check": {"type": "dir_exists", "path": "shared"},
    },
    {
        "id": "STR-004",
        "text": "deploy/ directory exists",
        "type": "structure",
        "source": "README.md",
        "check": {"type": "dir_exists", "path": "deploy"},
    },
    {
        "id": "STR-005",
        "text": "tests/ directory exists",
        "type": "structure",
        "source": "README.md",
        "check": {"type": "dir_exists", "path": "tests"},
    },
    {
        "id": "STR-006",
        "text": "experiments/ directory exists",
        "type": "structure",
        "source": "README.md",
        "check": {"type": "dir_exists", "path": "experiments"},
    },
    {
        "id": "STR-007",
        "text": "docs/ directory exists",
        "type": "structure",
        "source": "README.md",
        "check": {"type": "dir_exists", "path": "docs"},
    },
    {
        "id": "STR-008",
        "text": "docs/security-model.md exists (referenced in README)",
        "type": "file_reference",
        "source": "README.md",
        "check": {"type": "file_exists", "path": "docs/security-model.md"},
    },
    {
        "id": "STR-010",
        "text": "docs/quickstart.md exists (referenced in README)",
        "type": "file_reference",
        "source": "README.md",
        "check": {"type": "file_exists", "path": "docs/quickstart.md"},
    },
    {
        "id": "STR-011",
        "text": "docs/roadmap.md exists (referenced in README)",
        "type": "file_reference",
        "source": "README.md",
        "check": {"type": "file_exists", "path": "docs/roadmap.md"},
    },

    # -----------------------------------------------------------------------
    # API — Public API surface claims
    # -----------------------------------------------------------------------

    {
        "id": "API-001",
        "text": "enforcer exports resolve_and_enforce in __all__",
        "type": "api",
        "source": "docs/security-model.md",
        "check": {
            "type": "all_contains",
            "file": "guardian/enforcer.py",
            "symbol": "resolve_and_enforce",
        },
    },
    {
        "id": "API-002",
        "text": "enforcer exports enforce in __all__",
        "type": "api",
        "source": "docs/security-model.md",
        "check": {
            "type": "all_contains",
            "file": "guardian/enforcer.py",
            "symbol": "enforce",
        },
    },
    {
        "id": "API-003",
        "text": "enforcer exports scan_params in __all__",
        "type": "api",
        "source": "docs/security-model.md",
        "check": {
            "type": "all_contains",
            "file": "guardian/enforcer.py",
            "symbol": "scan_params",
        },
    },
    {
        "id": "API-004",
        "text": "enforcer exports VaultRequest in __all__",
        "type": "api",
        "source": "docs/security-model.md",
        "check": {
            "type": "all_contains",
            "file": "guardian/enforcer.py",
            "symbol": "VaultRequest",
        },
    },
    {
        "id": "API-005",
        "text": "enforcer exports EnforcementDenied in __all__",
        "type": "api",
        "source": "docs/security-model.md",
        "check": {
            "type": "all_contains",
            "file": "guardian/enforcer.py",
            "symbol": "EnforcementDenied",
        },
    },
    {
        "id": "API-006",
        "text": "enforcer exports AmbiguousKeyError in __all__",
        "type": "api",
        "source": "docs/security-model.md",
        "check": {
            "type": "all_contains",
            "file": "guardian/enforcer.py",
            "symbol": "AmbiguousKeyError",
        },
    },
    {
        "id": "API-007",
        "text": "enforcer exports ConfusedDeputyError in __all__",
        "type": "api",
        "source": "docs/security-model.md",
        "check": {
            "type": "all_contains",
            "file": "guardian/enforcer.py",
            "symbol": "ConfusedDeputyError",
        },
    },
    {
        "id": "API-008",
        "text": "enforcer exports ElevateTimeoutError in __all__",
        "type": "api",
        "source": "docs/security-model.md",
        "check": {
            "type": "all_contains",
            "file": "guardian/enforcer.py",
            "symbol": "ElevateTimeoutError",
        },
    },

    # -----------------------------------------------------------------------
    # BEH — Behavior claims (security-critical runtime behavior)
    # -----------------------------------------------------------------------

    {
        "id": "BEH-001",
        "text": "EnforcementDenied.safe_message defaults to 'access_denied'",
        "type": "behavior",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "guardian/enforcer.py",
            "pattern": r'safe_message\s*(?::\s*str\s*)?\s*=\s*["\']access_denied["\']',
        },
    },
    {
        "id": "BEH-002",
        "text": "audit_chain blocks UPDATE operations (tamper-evident)",
        "type": "behavior",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "guardian/audit_chain.py",
            "pattern": r'SQLITE_UPDATE',
        },
    },
    {
        "id": "BEH-003",
        "text": "audit_chain blocks DELETE operations (tamper-evident)",
        "type": "behavior",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "guardian/audit_chain.py",
            "pattern": r'SQLITE_DELETE',
        },
    },
    {
        "id": "BEH-004",
        "text": "audit_chain blocks DROP TABLE (opcode 11)",
        "type": "behavior",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "guardian/audit_chain.py",
            "pattern": r'\b11\b',
        },
    },
    {
        "id": "BEH-005",
        "text": "audit_chain blocks ALTER TABLE (opcode 26)",
        "type": "behavior",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "guardian/audit_chain.py",
            "pattern": r'\b26\b',
        },
    },
    {
        "id": "BEH-006",
        "text": "format_hash uses 'sha256:' prefix (canonical format)",
        "type": "behavior",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "shared/utils.py",
            "pattern": r'"sha256:"\s*\+',
        },
    },
    {
        "id": "BEH-007",
        "text": "audit_chain GENESIS_HASH uses b'mahaguardian_genesis_v1'",
        "type": "behavior",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "guardian/audit_chain.py",
            "pattern": r'mahaguardian_genesis_v1',
        },
    },
    {
        "id": "BEH-008",
        "text": "check_tlp uses fail-closed default (returns DENY on unknown input)",
        "type": "behavior",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "shared/tlp_matrix.py",
            "pattern": r'except\s*\(ValueError,\s*KeyError\)',
        },
    },
    {
        "id": "BEH-009",
        "text": "check_tlp imported from shared/tlp_matrix.py (not reimplemented)",
        "type": "behavior",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "guardian/enforcer.py",
            "pattern": r'from shared\.tlp_matrix import check_tlp',
        },
    },
    {
        "id": "BEH-010",
        "text": "audit_chain uses HMAC-SHA-256 for tamper-evident chaining",
        "type": "behavior",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "guardian/audit_chain.py",
            "pattern": r'import hmac',
        },
    },
    {
        "id": "BEH-011",
        "text": "audit_chain uses length-prefix encoding (4-byte big-endian)",
        "type": "behavior",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "guardian/audit_chain.py",
            "pattern": r'\.to_bytes\(4,\s*["\']big["\']\)',
        },
    },
    {
        "id": "BEH-012",
        "text": "audit_chain NFC-normalises string fields before hashing",
        "type": "behavior",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "guardian/audit_chain.py",
            "pattern": r'NFC',
        },
    },

    # -----------------------------------------------------------------------
    # SEC — Security property claims (from security-model.md and README)
    # -----------------------------------------------------------------------

    {
        "id": "SEC-001",
        "text": "GREEN+INTERNAL resolves to DENY in TLP matrix",
        "type": "security",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "shared/tlp_matrix.py",
            "pattern": r'TlpLevel\.GREEN,\s*Classification\.INTERNAL\s*\):\s*Decision\.DENY',
        },
    },
    {
        "id": "SEC-002",
        "text": "GREEN+CONFIDENTIAL resolves to DENY in TLP matrix",
        "type": "security",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "shared/tlp_matrix.py",
            "pattern": r'TlpLevel\.GREEN,\s*Classification\.CONFIDENTIAL\s*\):\s*Decision\.DENY',
        },
    },
    {
        "id": "SEC-003",
        "text": "GREEN+RESTRICTED resolves to DENY in TLP matrix",
        "type": "security",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "shared/tlp_matrix.py",
            "pattern": r'TlpLevel\.GREEN,\s*Classification\.RESTRICTED\s*\):\s*Decision\.DENY',
        },
    },
    {
        "id": "SEC-004",
        "text": "RED+RESTRICTED resolves to ALLOW in TLP matrix",
        "type": "security",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "shared/tlp_matrix.py",
            "pattern": r'TlpLevel\.RED,\s*Classification\.RESTRICTED\s*\):\s*Decision\.ALLOW',
        },
    },
    {
        "id": "SEC-005",
        "text": "AMBER_STRICT+RESTRICTED resolves to ELEVATE (human approval required)",
        "type": "security",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "shared/tlp_matrix.py",
            "pattern": r'TlpLevel\.AMBER_STRICT,\s*Classification\.RESTRICTED\s*\):\s*Decision\.ELEVATE',
        },
    },
    {
        "id": "SEC-006",
        "text": "scan_params checks for partition names in URL-encoded form",
        "type": "security",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "guardian/enforcer.py",
            "pattern": r'url.?encod|urllib\.parse|unquote',
        },
    },
    {
        "id": "SEC-007",
        "text": "replay protection implemented (RequestDeduplicator or equivalent)",
        "type": "security",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "shared/token.py",
            "pattern": r'Deduplicat|replay',
        },
    },
    {
        "id": "SEC-008",
        "text": "token revocation implemented (RevocationStore or equivalent)",
        "type": "security",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "shared/token.py",
            "pattern": r'RevocationStore|revoc',
        },
    },

    # -----------------------------------------------------------------------
    # TYP — Type / enum claims
    # -----------------------------------------------------------------------

    {
        "id": "TYP-001",
        "text": "TlpLevel has RED member",
        "type": "type",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "shared/types.py",
            "pattern": r'RED\s*=\s*["\']RED["\']',
        },
    },
    {
        "id": "TYP-002",
        "text": "TlpLevel has AMBER_STRICT member",
        "type": "type",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "shared/types.py",
            "pattern": r'AMBER_STRICT\s*=\s*["\']AMBER_STRICT["\']',
        },
    },
    {
        "id": "TYP-003",
        "text": "TlpLevel has GREEN member",
        "type": "type",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "shared/types.py",
            "pattern": r'GREEN\s*=\s*["\']GREEN["\']',
        },
    },
    {
        "id": "TYP-004",
        "text": "TlpLevel has CLEAR member",
        "type": "type",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "shared/types.py",
            "pattern": r'CLEAR\s*=\s*["\']CLEAR["\']',
        },
    },
    {
        "id": "TYP-005",
        "text": "Decision enum has ALLOW, DENY, ELEVATE members",
        "type": "type",
        "source": "docs/security-model.md",
        "check": {
            "type": "regex_in_file",
            "file": "shared/types.py",
            "pattern": r'ALLOW\s*=.*DENY\s*=.*ELEVATE\s*=',
        },
    },
]
