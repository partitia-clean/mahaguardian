# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in MahaGuardian, please report it privately and responsibly.

Primary channel:
- GitHub private vulnerability reporting for this repository

Fallback channel:
- **Email:** alexander@landia.biz
- **Subject line:** [SECURITY] Brief description

Please include:
- description of the vulnerability
- steps to reproduce
- potential impact
- affected commit, branch, or release
- proof-of-concept code or minimal reproduction
- suggested fix, if any

We will acknowledge receipt within 48 hours and aim to provide an initial assessment within 7 days.

## Scope

The following are in scope for security reports:
- partition isolation bypasses
- token forgery or replay attacks
- audit chain integrity violations
- confused deputy / prompt injection escalation
- derived instruction set metadata leakage
- cryptographic weaknesses in the enforcement pipeline
- anti-probing differentiation

The following are out of scope unless explicitly approved in writing:
- vulnerabilities in third-party dependencies without a MahaGuardian-specific exploit path
- social engineering attacks
- phishing
- denial of service against demo or third-party infrastructure
- attacks requiring Guardian host compromise

## Security Architecture

MahaGuardian's security model is based on split-trust architecture:
- Guardian retains high-trust cryptographic enforcement functions
- cloud agents hold no persistent secrets on disk
- agents may receive short-lived LLM credentials in memory only
- all data access is mediated through Guardian-side enforcement
- ALLOW and DENY decisions are logged in a tamper-evident audit chain

For architecture details, see the README and docs directory.

## MahaGuardian Adversarial Challenge

MahaGuardian also runs a focused public adversarial challenge against specific security claims in the public repository.

Summary:
- `$500` per accepted unique category win
- `4` categories
- `$2,000` total cap
- `30-day` challenge window
- `90-day coordinated disclosure`
- human final decision with AI-assisted triage
- legal review before payout

Canonical details:
- [Adversarial Challenge](docs/adversarial-challenge.md)
- [Recommended Payout License Clause](docs/challenge-license-clause.md)

## Safe Harbor and Responsible Disclosure

MahaGuardian intends to support good-faith security research conducted within the published scope and through the official reporting channels.

Researchers should:
- act in good faith
- avoid harming users, third-party systems, or unrelated data
- minimize access, copying, retention, and persistence
- avoid destructive actions and avoid degrading availability
- report privately first
- avoid public disclosure during the coordinated disclosure window

If you act in good faith, comply with this policy, and remain within the stated scope, MahaGuardian states that it will not initiate legal action or refer a matter to law enforcement for accidental, good-faith conduct that stays within this policy.

This does not extend to privacy violations, disruption of service, extortion, third-party access, or activity outside the published scope.

Public disclosure may occur after the earlier of:
- written approval, or
- 90 days from initial private submission

## Adversarial Review

This codebase has undergone multi-round adversarial security review using Gemini, GPT, and Codex, with AI-assisted triage. Human security researchers are encouraged to test the published claims through the official channels above.
