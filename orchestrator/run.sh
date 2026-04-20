#!/usr/bin/env bash
# run.sh — Linux/macOS runner for MahaGuardian review orchestrator
#
# Set API keys before running:
#   export GOOGLE_API_KEY="..."
#   export OPENAI_API_KEY="..."
#   export ANTHROPIC_API_KEY="..."
#
# Optional: override which commits are diffed (default: main~8..HEAD)
#   export REVIEW_BASE_BRANCH="main~4"

set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m orchestrator.main
