# Quickstart

## Requirements

- Python 3.11+
- `pip`

## Install

```bash
git clone https://github.com/partitia-clean/mahaguardian.git
cd mahaguardian
pip install -r requirements.txt
```

## Run the Test Suite

```bash
pytest -q
```

Expected result:

- automated tests complete successfully
- enforcement, token, audit, vault, and WebSocket flows are exercised

## Key Paths

- `guardian/` — enforcement, audit, vault, SOUL, mTLS
- `agent/` — agent-side runtime components
- `shared/` — shared types, token logic, policy matrix
- `tests/` — automated verification
- `docs/` — architecture, security model, roadmap

## Next Reading

- `README.md`
- `docs/security-model.md`
- `docs/architecture.md`
- `docs/roadmap.md`
