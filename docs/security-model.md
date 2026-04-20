# Security Model

## Scope

MahaGuardian is a trust and enforcement layer for multi-party agent systems that
operate across confidential boundaries.

This document describes the **externally visible** security model:

- identity and authentication
- authorization and policy enforcement
- agent-specific defenses
- observability and auditability
- known limitations

## Threat Model

MahaGuardian is designed to reduce the impact of:

- unauthorized cross-partition access
- prompt injection and confused-deputy attacks
- replayed or stolen access tokens
- disclosure of secrets or sensitive metadata to agents
- tampering with audit history
- unsafe execution of external tools or payment-like operations

## Trust Boundary

The **Guardian** is the trust boundary.

The Guardian:

- verifies identity
- validates tokens
- resolves partitions locally
- applies classification/TLP policy
- mediates sensitive operations
- records the outcome in the audit system

Agents are useful execution nodes, but they are not trusted with unrestricted
access to protected data or long-lived operator-managed credentials.

## Identity and Authentication

MahaGuardian includes these identity controls:

- certificate-backed peer identity for trusted component communication
- short-lived access tokens with expiration
- token revocation support
- replay protection for repeated request identifiers
- token binding to the presenting certificate or session identity

These controls are intended to help distinguish legitimate component requests
from replayed or unauthorized requests.

## Runtime Secret Handling

MahaGuardian is designed so that trust-critical and operator-managed secrets remain
Guardian-side.

In the current design, the agent may receive a **short-lived LLM API key** for
direct model access, but:

- it is delivered by the Guardian over an established trusted channel
- it is stored in memory only
- it is not written to disk
- it is rotated by the Guardian
- old key material is cleared on replacement or session end

## Authorization

Authorization is enforced outside the agent runtime.

Visible controls include:

- deny-by-default enforcement
- Guardian-side authorization for sensitive requests
- partition-resolving access control
- logical key requests instead of agent-selected partition targets
- classification/TLP enforcement before data release
- operation allowlists where applicable

## Agent-Specific Defenses

MahaGuardian includes defenses tailored to agentic systems:

- **Anti-probing**
  - denial responses are normalized to reduce topology leakage
- **Confused-deputy scanning**
  - request parameters are checked for partition references and encoded variants
- **Prompt-derivation controls**
  - derived instructions avoid exposing sensitive partition metadata
- **Elevation path**
  - some high-sensitivity requests require explicit approval rather than silent
    over-granting

## Observability and Auditability

MahaGuardian treats auditability as a first-class security control.

Visible controls include:

- structured logging of both allowed and denied decisions
- tamper-evident audit chain
- normalized hash formats
- normalized timestamp formats
- reviewable enforcement outcomes for incident analysis and policy verification

## Governance and Operational Signals

This repository includes governance and operational signals intended to make the
security model legible:

- automated test suite
- CI-based test execution
- explicit license and commercial licensing notice
- contribution and security reporting guidance
- public documentation for architecture, quickstart, and roadmap

## Known Limitations

- the public website is minimal and does not yet expose all runtime controls
- some enterprise observability and operational controls are not yet public
- some planned features remain roadmap items rather than released capabilities

## Summary

MahaGuardian moves trust-critical decisions out of the agent runtime and into a
Guardian that can authenticate, authorize, scan, and log requests before data
or side effects are released.
