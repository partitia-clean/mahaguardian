# Contributing to MahaGuardian

Thank you for your interest in contributing to MahaGuardian.

## How to Contribute

### Reporting Bugs

Open a GitHub issue with:
- Description of the bug
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version)

### Security Vulnerabilities

Do NOT open a public issue for security vulnerabilities.
See [SECURITY.md](SECURITY.md) for responsible disclosure.

### Code Contributions

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Run the test suite: `python -m pytest tests/ -q`
5. Ensure all tests pass (0 failures)
7. Submit a pull request

### Code Standards

- Python 3.10+
- All enforcement logic must go through the single enforce()
  code path — no bypass paths
- Every new enforcement feature requires both positive (ALLOW)
  and negative (DENY) test cases
- Audit chain entries must be written for all decisions
- Error messages must remain uniform (anti-probing)

### What We're Looking For

- Security hardening (especially prompt injection resistance)
- Performance optimization of the enforcement pipeline
- WebSocket server implementation
- Federation (multi-Guardian) protocol
- Additional encoding variants for the confused deputy scanner
- Documentation improvements

## Contributor License Agreement

By submitting a pull request, you agree that your contributions
are licensed under the same AGPLv3 license as the project, and
that you have the right to submit them.

For contributions that may be included in commercially licensed
versions, we may ask you to sign a Contributor License Agreement
(CLA) granting us the right to dual-license your contribution.

## Code of Conduct

Be professional, constructive, and respectful. We are building
security infrastructure for regulated industries — our community
standards should reflect that.
