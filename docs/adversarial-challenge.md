# MahaGuardian Adversarial Challenge

MahaGuardian is running a focused adversarial challenge against the public repository.

- Reward: `$500` per accepted unique category win
- Categories: `4`
- Total cap: `$2,000`
- Challenge window: `30 days` from launch
- Disclosure window: `90-day coordinated disclosure`
- Reporting: `GitHub private vulnerability reporting` with email fallback

## Scope

An accepted submission must demonstrate one of the following:

1. `Partition isolation bypass`
2. `Metadata leakage from the derived instruction set`
3. `Confused deputy scanner bypass`
4. `Anti-probing differentiation`

## Qualification Requirements

To qualify, a submission must include:

- working proof-of-concept code
- exact reproduction steps
- clear expected vs. actual behavior
- affected commit, branch, or release
- concise impact explanation
- enough detail to reproduce the issue against the public repository and designated test harness

## Reward Rules

- `$500` for the first accepted valid submission in each category
- maximum aggregate payout is `$2,000`
- duplicates are not eligible for payout
- non-reproducible or purely theoretical reports are not eligible
- final acceptance and payout decisions are made by a human maintainer
- AI-assisted triage may be used for intake and comparison only
- legal review may be required before payout

## Reporting

Primary:
- GitHub private vulnerability reporting for this repository

Fallback:
- `alexander@landia.biz`

Please do not open a public GitHub issue for a security submission.

## Disclosure

- submit privately first
- keep details private during the coordinated disclosure window
- public disclosure may occur after the earlier of:
  - written approval, or
  - `90 days` from initial private submission

## Researcher License Upon Payout

If a submission is accepted for payout and the researcher accepts payment, the researcher grants MahaGuardian a perpetual, irrevocable, worldwide, royalty-free license to use, reproduce, modify, adapt, test, analyze, publish, and distribute the submitted exploit code, proof-of-concept materials, and associated writeup solely for vulnerability validation, remediation, regression testing, documentation, coordinated disclosure, and related security research purposes.

Submission alone does not transfer ownership or require blanket assignment of intellectual property.

## Out of Scope

- social engineering
- phishing
- denial-of-service or resource exhaustion
- attacks against third-party infrastructure
- attacks requiring Guardian host compromise
- dependency-only issues without a MahaGuardian-specific exploit path
- advisory comments without a demonstrated exploit

## Safe Harbor

If you act in good faith, comply with the published policy, and limit your activity to the stated scope, MahaGuardian states that it:

- authorizes testing under this challenge for the in-scope public repository and designated challenge environment
- will not initiate legal action or refer a matter to law enforcement for accidental, good-faith conduct that stays within this policy
- will not treat compliant, good-faith security research as a Terms of Service or Acceptable Use Policy violation

This safe harbor does not extend to privacy violations, data destruction, disruption of service, extortion, social engineering, access to third-party accounts or infrastructure, or actions outside the published scope.
