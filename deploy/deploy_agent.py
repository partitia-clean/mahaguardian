#!/usr/bin/env python3
"""
Deploy a MahaGuardian agent to a Hetzner droplet.

Usage:
    python deploy/deploy_agent.py \
        --agent-id alpha \
        --droplet-ip 1.2.3.4 \
        --port 8443 \
        --partition company-a \
        --type primary
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class SecurityError(Exception):
    pass


# Files that must NEVER be uploaded to a remote droplet.
# These must remain exclusively on the Guardian device.
NEVER_UPLOAD = {
    "ca.key",        # CA private key — compromise yields ability to mint trusted certs
    "guardian.key",  # Guardian private key
    "guardian.crt",  # Guardian cert (not agent-facing)
    "vault.enc",     # Encrypted vault — must not leave Guardian
    "master.key",    # age master key
}

# Files that ARE safe/required to upload per agent:
#   ca.crt               (public CA cert for chain verification)
#   agents/{id}.crt      (agent's public cert)
#   agents/{id}.key      (agent's private key — encrypted with MAHAGUARDIAN_PASSPHRASE)
#   agent/ Python source
#   shared/ Python source


def validate_upload_files(files: list) -> None:
    """Raise SecurityError if any file in the list is on the NEVER_UPLOAD list."""
    for f in files:
        if Path(f).name in NEVER_UPLOAD:
            raise SecurityError(
                f"FATAL: Refusing to upload '{Path(f).name}' to remote droplet. "
                f"This file must NEVER leave the Guardian device. "
                f"Check NEVER_UPLOAD in deploy_agent.py."
            )


def main():
    parser = argparse.ArgumentParser(description="Deploy MahaGuardian agent")
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--droplet-ip", required=True)
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--partition", required=True)
    parser.add_argument("--type", choices=["primary", "external"], default="primary")
    args = parser.parse_args()

    print(f"Deploying agent '{args.agent_id}' to {args.droplet_ip}:{args.port}")
    print(f"  Partition: {args.partition}")
    print(f"  Type: {args.type}")

    # Step 1: Generate agent cert
    print("\n[1/6] Generating agent certificate...")
    cert_passphrase = os.environ.get("MAHAGUARDIAN_PASSPHRASE", "")
    if not cert_passphrase:
        print("  WARNING: No MAHAGUARDIAN_PASSPHRASE set, using empty passphrase")

    from shared.config import CA_CERT_PATH, CA_KEY_PATH
    if not CA_CERT_PATH.exists():
        print(f"  ERROR: CA cert not found at {CA_CERT_PATH}")
        print("  Run 'mahaguardian init' first")
        sys.exit(1)

    from guardian.mtls import generate_agent_cert
    ca_cert = CA_CERT_PATH.read_bytes()
    ca_key = CA_KEY_PATH.read_bytes()
    agent_cert, agent_key = generate_agent_cert(
        args.agent_id, ca_cert, ca_key, cert_passphrase,
    )
    print(f"  Generated cert for CN={args.agent_id}")

    # Step 2: SCP files to droplet
    print("\n[2/6] Uploading files to droplet...")
    # Files intended for upload (validate BEFORE any SCP command):
    #   ca.crt, agents/{id}.crt, agents/{id}.key (encrypted), agent/, shared/
    files_to_upload = [
        "certs/ca.crt",
        f"certs/agents/{args.agent_id}.crt",
        f"certs/agents/{args.agent_id}.key",
    ]
    try:
        validate_upload_files(files_to_upload)
        print(f"  Upload validation passed: {len(files_to_upload)} cert file(s) cleared")
    except SecurityError as e:
        print(f"  {e}")
        sys.exit(1)
    print("  TODO: SCP agent/, shared/, cleared certs to droplet")
    print(f"  Target: {args.droplet_ip}:/opt/mahaguardian/")

    # Step 3: Run setup script
    print("\n[3/6] Running setup script...")
    print("  TODO: SSH and run setup_agent.sh")

    # Step 4: Create systemd service (non-root, mahaguardian user)
    print("\n[4/6] Creating systemd service...")
    service_name = f"mahaguardian-agent-{args.agent_id}"
    print(f"  Service: {service_name}")
    print(f"  User=mahaguardian")
    print(f"  Group=mahaguardian")
    print(f"  Environment: AGENT_ID={args.agent_id}")
    print(f"  Environment: MAHAGUARDIAN_AGENT_PORT={args.port}")
    print(f"  Environment: MAHAGUARDIAN_PRODUCTION=true")
    print(f"  File permissions:")
    print(f"    certs/agents/{args.agent_id}.key → 0600, owned by mahaguardian")
    print(f"    certs/agents/{args.agent_id}.crt → 0644")
    print(f"    certs/ca.crt                     → 0644")

    # Step 5: Register in vault
    print("\n[5/6] Registering agent in vault...")
    print(f"  deployments.{args.agent_id} = "
          f'{{"host": "{args.droplet_ip}", "port": {args.port}}}')
    if args.type == "external":
        print(f"  Adding {args.agent_id} to external_agents list")

    # Step 6: Verify health
    print("\n[6/6] Verifying agent health...")
    print(f"  TODO: GET https://{args.droplet_ip}:{args.port}/health")

    print(f"\nAgent '{args.agent_id}' deployment complete (stub).")
    print("Full deployment requires SSH access to the droplet.")


if __name__ == "__main__":
    main()
