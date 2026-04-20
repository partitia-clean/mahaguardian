# MahaGuardian

[![CI](https://github.com/partitia-clean/mahaguardian/actions/workflows/ci.yml/badge.svg)](https://github.com/partitia-clean/mahaguardian/actions/workflows/ci.yml)

**Trust and enforcement layer for regulated multi-party agentic AI systems.**

MahaGuardian enforces information barriers when AI agents operate across multiple
confidential contexts. It is designed for workflows where agents must operate
across strict boundaries without leaking secrets, crossing client partitions,
or executing sensitive actions outside controlled policy.

Your keys stay on your device. Cloud agents can reason, but trust-critical
decisions remain Guardian-side.

## Documentation

- [Security Policy](SECURITY.md)
- [Support](SUPPORT.md)
- [Security Model](docs/security-model.md)
- [Quickstart](docs/quickstart.md)
- [Roadmap](docs/roadmap.md)

## The Problem

When a strategy advisor uses AI agents for multiple clients, the agent context
window becomes a liability. Client A's deal terms can leak into Client B's
analysis through prompt injection, hallucination, or simple context bleed.
Prompt-only guardrails are not enough for regulated workflows.

## The Solution

MahaGuardian splits trust between a local **Guardian** and cloud **Agents**.

- **Guardian**
  - verifies identity
  - validates tokens
  - resolves partitions locally
  - applies TLP/classification policy
  - mediates sensitive operations
  - records audit outcomes
- **Agent**
  - receives derived instructions
  - requests data by logical key
  - does not receive vault keys, signing keys, or full partition topology
  - may receive a short-lived LLM key in memory only, provisioned and rotated
    by the Guardian

## Key Security Properties

### Identity and Authentication

- mTLS-backed peer identity between trusted components
- short-lived access tokens with expiry, revocation, and replay protection
- token binding to the presenting certificate or session identity

### Authorization

- deny-by-default enforcement
- Guardian-side partition resolution
- logical key requests instead of agent-selected partition access
- TLP/classification gating before protected data is returned
- operation allowlists for sensitive actions

### Agent-Specific Defenses

- anti-probing denial behavior with normalized opaque errors
- confused-deputy scanning for partition references in request parameters
- prompt-derivation controls that avoid exposing sensitive partition metadata
- elevation path for high-sensitivity access

### Observability and Auditability

- structured decision logging for ALLOW, DENY, and ELEVATE outcomes
- tamper-evident audit chain
- consistent hash and timestamp formats

### Secret Handling

- Guardian-held credentials for sensitive operations
- agents do not receive vault keys, signing keys, or partition topology
- agents may receive a short-lived LLM key in memory only, provisioned and
  rotated by the Guardian, and not written to disk

## Quick Start

```bash
git clone https://github.com/partitia-clean/mahaguardian.git
cd mahaguardian
pip install -r requirements.txt
pytest -q
```

More detail: [docs/quickstart.md](docs/quickstart.md)

## Project Structure

```text
mahaguardian/
├── guardian/      # enforcement, audit, vault, SOUL, mTLS
├── agent/         # agent-side runtime components
├── shared/        # shared types, token logic, policy matrix
├── cli/           # init and local management commands
├── auditor/       # documentation/code consistency checker
├── orchestrator/  # multi-reviewer orchestration
├── tools/         # utility modules
├── deploy/        # deployment and scenario generation
├── tests/         # automated verification
└── docs/          # security model, quickstart, challenge, roadmap
```

## Current Status

- extensive automated tests
- CI-based test execution
- public security, quickstart, and governance documentation
- automated enforcement, token, audit, vault, and WebSocket coverage

## Architecture Summary

Agents interact with MahaGuardian through a Guardian that mediates access to
protected data, external tools, and sensitive operations.

1. Agent sends a request for a logical key or action
2. Guardian verifies identity and token validity
3. Guardian checks replay conditions
4. Guardian scans request parameters for confused-deputy indicators
5. Guardian resolves the target partition locally
6. Guardian applies classification/TLP policy
7. Guardian logs the outcome
8. Guardian returns ALLOW, DENY, or ELEVATE behavior

More detail: [docs/security-model.md](docs/security-model.md)

## Limitations

- current public repo is a Community Edition, not a full hosted product
- some enterprise observability and operational controls are not yet public
- some planned features remain roadmap items rather than released capabilities

See [docs/roadmap.md](docs/roadmap.md).

## License

MahaGuardian Community Edition is licensed under the [GNU Affero General Public
License v3.0 (AGPLv3)](LICENSE).

For commercial, closed-source, or proprietary deployments where AGPLv3
compliance is not possible, a Commercial License is required. See
[COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Community

- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Changelog](CHANGELOG.md)
- [Support](SUPPORT.md)

## Security

See [SECURITY.md](SECURITY.md).
