#!/bin/bash
# MahaGuardian Agent Setup Script
# Run on a fresh Ubuntu 24.04 droplet via SSH
set -euo pipefail

echo "=== MahaGuardian Agent Setup ==="

# Create mahaguardian user
if ! id mahaguardian &>/dev/null; then
    useradd -r -m -s /bin/false mahaguardian
    echo "Created mahaguardian user"
fi

# Install Python 3.12+
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv

# Create directory structure
mkdir -p /opt/mahaguardian
chown mahaguardian:mahaguardian /opt/mahaguardian

# Create venv and install dependencies
cd /opt/mahaguardian
sudo -u mahaguardian python3 -m venv .venv
sudo -u mahaguardian .venv/bin/pip install -q fastapi uvicorn pydantic cryptography websockets

# Set cert permissions
if [ -d /opt/mahaguardian/certs ]; then
    chmod 600 /opt/mahaguardian/certs/*.key 2>/dev/null || true
    chown mahaguardian:mahaguardian /opt/mahaguardian/certs/*
fi

echo "=== Setup complete ==="
echo "Create systemd service with deploy_agent.py"
