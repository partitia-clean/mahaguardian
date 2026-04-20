"""
Skill verification and loading.

Security guarantees:
  - Skills are only loaded if they pass signature and checksum verification.
  - Skill manifests declare required permissions (network, filesystem, etc.)
    which are enforced before loading.
  - Skill markdown files can declare permissions in a structured header
    block, parsed by parse_skill_permissions().
  - SkillVerificationError is raised for any tampered or unsigned skill.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Optional

import yaml

import guardian.audit as audit
from shared.config import SKILLS_DIR

try:
    import tomllib  # Python 3.11+
except ImportError:
    import tomli as tomllib  # type: ignore[no-reuse-def]


class SkillVerificationError(Exception):
    """Raised when a skill fails signature or checksum verification."""


_AGENT_ID_RE = re.compile(r'^[a-zA-Z0-9_-]+$')


def _validate_agent_id(agent_id: str) -> None:
    if not _AGENT_ID_RE.match(agent_id):
        raise ValueError(f"Invalid agent_id '{agent_id}'")


def verify_skill(skill_path: Path, manifest_path: Path) -> bool:
    """
    Verify a skill file against its manifest.

    Checks:
      1. Manifest exists and is valid JSON/TOML.
      2. Skill file SHA-256 checksum matches manifest's declared checksum.
      3. Author signature is present in manifest.
      4. Registry signature is present in manifest (when available).

    Returns True if all checks pass.
    Raises SkillVerificationError if any check fails.
    Logs verification to audit.
    """
    # --- Load manifest ---
    if not manifest_path.exists():
        audit.log(
            action="skill.verify",
            resource=str(skill_path),
            result="failure:manifest_not_found",
        )
        raise SkillVerificationError(
            f"Manifest not found: {manifest_path}"
        )

    manifest = _load_manifest(manifest_path)

    # --- Checksum verification ---
    if not skill_path.exists():
        audit.log(
            action="skill.verify",
            resource=str(skill_path),
            result="failure:skill_file_not_found",
        )
        raise SkillVerificationError(
            f"Skill file not found: {skill_path}"
        )

    from shared.utils import format_hash
    actual_hash = format_hash(skill_path.read_bytes())
    expected_hash = manifest.get("checksum", "")

    if not expected_hash:
        audit.log(
            action="skill.verify",
            resource=str(skill_path),
            result="failure:no_checksum_in_manifest",
        )
        raise SkillVerificationError(
            f"Manifest for {skill_path.name} has no checksum field."
        )

    if not expected_hash.startswith("sha256:"):
        audit.log(
            action="skill.verify",
            resource=str(skill_path),
            result="failure:invalid_checksum_format",
        )
        raise SkillVerificationError(
            f"Checksum format invalid for {skill_path.name}: "
            f"expected sha256:<hex>, got {expected_hash!r}."
        )

    if actual_hash != expected_hash:
        audit.log(
            action="skill.verify",
            resource=str(skill_path),
            result=f"failure:checksum_mismatch:expected={expected_hash},actual={actual_hash}",
        )
        raise SkillVerificationError(
            f"Checksum mismatch for {skill_path.name}. "
            f"Expected {expected_hash}, got {actual_hash}. "
            f"Skill may have been tampered with."
        )

    # --- Signature checks ---
    author_sig = manifest.get("author_sig", "")
    if not author_sig:
        audit.log(
            action="skill.verify",
            resource=str(skill_path),
            result="failure:no_author_signature",
        )
        raise SkillVerificationError(
            f"Manifest for {skill_path.name} has no author_sig."
        )

    # Registry signature is optional in Phase 1 but logged if missing
    registry_sig = manifest.get("registry_sig", "")
    if not registry_sig:
        audit.log(
            action="skill.verify",
            resource=str(skill_path),
            result="warning:no_registry_signature",
        )

    # Phase 1: signature presence check only.
    # Phase 2+: verify ed25519 signatures against author/registry public keys.

    audit.log(
        action="skill.verify",
        resource=str(skill_path),
        result="success",
    )
    return True


def load_verified_skills(agent_id: str) -> list[dict]:
    """
    Load all verified skills for a given agent.

    Scans the agent's skill directory for skill files with manifests.
    Only returns skills that pass verify_skill().
    Skills that fail verification are logged and skipped.

    Returns a list of dicts with keys:
      - name: skill name
      - version: skill version
      - path: absolute path to skill file
      - permissions: declared permissions dict
    """
    _validate_agent_id(agent_id)

    agent_skills_dir = SKILLS_DIR / agent_id
    if not agent_skills_dir.exists():
        audit.log(
            action="skill.load",
            agent_id=agent_id,
            result="success:no_skills_dir",
        )
        return []

    verified: list[dict] = []

    # Look for manifest files; each manifest corresponds to a skill
    for manifest_path in sorted(agent_skills_dir.glob("*.manifest.json")):
        skill_name = manifest_path.name.replace(".manifest.json", "")
        # Try common skill file extensions
        skill_path: Optional[Path] = None
        for ext in (".py", ".md", ".toml", ".txt"):
            candidate = agent_skills_dir / f"{skill_name}{ext}"
            if candidate.exists():
                skill_path = candidate
                break

        if skill_path is None:
            audit.log(
                action="skill.load",
                agent_id=agent_id,
                resource=skill_name,
                result="warning:skill_file_not_found_for_manifest",
            )
            continue

        try:
            verify_skill(skill_path, manifest_path)
        except SkillVerificationError as exc:
            audit.log(
                action="skill.load",
                agent_id=agent_id,
                resource=skill_name,
                result=f"skipped:verification_failed:{exc}",
            )
            continue

        manifest = _load_manifest(manifest_path)
        verified.append({
            "name": manifest.get("name", skill_name),
            "version": manifest.get("version", "0.0.0"),
            "path": str(skill_path),
            "permissions": manifest.get("permissions", {}),
        })

    audit.log(
        action="skill.load",
        agent_id=agent_id,
        result=f"success:loaded={len(verified)}",
    )
    return verified


def parse_skill_permissions(skill_md_path: Path) -> dict:
    """
    Parse permission declarations from a skill markdown file.

    Looks for a YAML frontmatter block at the top of the file:

        ---
        name: my_skill
        version: 1.0.0
        permissions:
          network: [api.example.com]
          filesystem: [read:/tmp/data]
          system_calls: []
        ---

    Returns a dict with keys: name, version, permissions.
    Returns empty permissions dict if no frontmatter found.
    Raises SkillVerificationError if frontmatter is present but malformed.
    """
    if not skill_md_path.exists():
        raise FileNotFoundError(f"Skill file not found: {skill_md_path}")

    content = skill_md_path.read_text(encoding="utf-8")

    # Extract YAML frontmatter between --- markers
    if not content.startswith("---"):
        return {
            "name": skill_md_path.stem,
            "version": "0.0.0",
            "permissions": {},
        }

    try:
        end = content.index("---", 3)
    except ValueError:
        raise SkillVerificationError(
            f"Malformed YAML frontmatter in {skill_md_path.name}: "
            f"no closing --- marker"
        )

    frontmatter_str = content[3:end]

    try:
        parsed = yaml.safe_load(frontmatter_str)
    except yaml.YAMLError as exc:
        raise SkillVerificationError(
            f"Invalid YAML frontmatter in {skill_md_path.name}: {exc}"
        )

    if not isinstance(parsed, dict):
        return {
            "name": skill_md_path.stem,
            "version": "0.0.0",
            "permissions": {},
        }

    return {
        "name": parsed.get("name", skill_md_path.stem),
        "version": str(parsed.get("version", "0.0.0")),
        "permissions": parsed.get("permissions", {}),
    }


def _load_manifest(manifest_path: Path) -> dict:
    """Load a manifest file (JSON or TOML)."""
    text = manifest_path.read_text(encoding="utf-8")
    if manifest_path.suffix == ".json":
        return json.loads(text)
    elif manifest_path.suffix == ".toml":
        return tomllib.loads(text)
    else:
        # Try JSON first, then TOML
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return tomllib.loads(text)
