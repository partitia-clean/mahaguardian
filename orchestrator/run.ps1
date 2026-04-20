# run.ps1 — Windows PowerShell runner for MahaGuardian review orchestrator
#
# Set API keys before running:
#   $env:GOOGLE_API_KEY    = "..."
#   $env:OPENAI_API_KEY    = "..."
#   $env:ANTHROPIC_API_KEY = "..."
#
# Optional: override which commits are diffed (default: main~8..HEAD)
#   $env:REVIEW_BASE_BRANCH = "main~4"

Set-Location (Split-Path $PSScriptRoot -Parent)
py -3 -m orchestrator.main
