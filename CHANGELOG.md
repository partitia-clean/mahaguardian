# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows a date-based pre-release style until the first stable
public release.

## [Unreleased]

### Added
- Community Edition licensing and contribution documents.
- Production specification for Phase 3 enforcement, audit chain, and SOUL flow.
- Phase 3 shared canonical enums for TLP, classification, decision, and isolation.
- Audit-chain implementation with tamper-evident chained entries.
- Partition-resolving enforcement flow with anti-probing behavior.
- Confused-deputy scanning for partition leakage in request parameters.
- TLP matrix enforcement for classified vault data access.
- Replay protection and token revocation support for Phase 3 access tokens.
- Expanded test coverage across enforcement, audit, token, vault, and WebSocket flows.

### Changed
- Repository has been curated as a focused public-facing MahaGuardian codebase.
- Documentation has been reorganized around product usage, architecture, and security.

### Security
- Guardian-side enforcement is treated as the sole trusted choke point for partition access.
- DENY paths are normalized to avoid existence leakage.
- SOUL-derived prompts are scanned before delivery to agents.

## [2026-04-14]

### Added
- Initial public Community Edition release materials.
- README, AGPLv3 license, commercial licensing notice, security policy, and contribution guide.

### Notes
- This release is intended for evaluation, research, and early integration work.
- The hosted website and broader commercial packaging remain in progress.
