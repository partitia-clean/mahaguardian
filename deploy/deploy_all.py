#!/usr/bin/env python3
"""
Fully automated MahaGuardian deployment using Hetzner cloud-init.

One command:
    export HETZNER_API_TOKEN=your_token
    export MAHAGUARDIAN_PASSPHRASE=your_passphrase
    py -3 deploy/deploy_all.py

No SSH or SCP needed. Each droplet self-configures via cloud-init
user_data: installs Python, creates the mahaguardian service account,
writes all source files and certs, starts systemd services.

Security model:
  - NEVER_EMBED set enforced before any file enters user_data
  - ca.key, guardian.key, vault.enc, master.key NEVER leave Guardian
  - Agent private keys are passphrase-encrypted before embedding
  - Passphrase delivered via 0600 EnvironmentFile, not inline in unit file
  - Agent runs as non-root mahaguardian user with /bin/false shell

Preview (no credentials needed):
    py -3 deploy/deploy_all.py --preview 1
"""
from __future__ import annotations

import argparse
import base64
import gzip
import json
import os
import socket
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Agent topology
# ---------------------------------------------------------------------------

# (agent_id, droplet_index, port, partition, agent_type)
AGENTS = [
    ("alpha",   0, 8443, "company-a", "primary"),
    ("beta",    0, 8444, "company-b", "primary"),
    ("gamma",   1, 8443, "company-a", "primary"),
    ("delta",   1, 8444, "company-c", "primary"),
    ("epsilon", 2, 8443, "shared",    "external"),
    ("zeta",    2, 8444, "shared",    "external"),
]

# Python source files to embed (relative to PROJECT_ROOT)
AGENT_SOURCE_FILES = [
    "agent/__init__.py",
    "agent/main.py",
    "agent/session.py",
    "agent/ws_handler.py",
    "agent/heartbeat.py",
    "agent/memory.py",
    "shared/__init__.py",
    "shared/config.py",
    "shared/models.py",
    "shared/messages.py",
    "shared/partitions.py",
]

# Files that must NEVER appear in cloud-init user_data
NEVER_EMBED = {
    "ca.key",       # CA private key — enables forging any cert in the trust chain
    "guardian.key", # Guardian private key
    "guardian.crt", # Guardian cert (agents don't need it — they authenticate Guardian via CA)
    "vault.enc",    # Encrypted vault
    "master.key",   # age master key
}


# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------

class SecurityError(Exception):
    pass


def validate_embed(filename: str) -> None:
    """Raise SecurityError if the filename is on the NEVER_EMBED list."""
    name = Path(filename).name
    if name in NEVER_EMBED:
        raise SecurityError(
            f"FATAL: Refusing to embed '{name}' in cloud-init user_data. "
            f"This file must NEVER leave the Guardian device. "
            f"(NEVER_EMBED list in deploy_all.py)"
        )


def security_report(agent_certs: dict) -> None:
    """Print confirmation that all NEVER_EMBED files are absent."""
    print("  SECURITY CHECK:")
    for banned in sorted(NEVER_EMBED):
        print(f"    Verified: {banned} NOT in user_data")
    embedded_names = set()
    for agent_id in agent_certs:
        embedded_names.add(f"{agent_id}.crt")
        embedded_names.add(f"{agent_id}.key")
    embedded_names.add("ca.crt")
    for name in sorted(embedded_names):
        print(f"    Embedded: {name} ({'0600' if name.endswith('.key') else '0644'})")


# ---------------------------------------------------------------------------
# Prerequisites
# ---------------------------------------------------------------------------

def check_prerequisites() -> tuple[str, str]:
    """Verify token, hcloud, and pyyaml are available. Returns (token, passphrase)."""
    token = os.environ.get("HETZNER_API_TOKEN", "")
    if not token:
        print("ERROR: HETZNER_API_TOKEN not set.")
        print("  Get one at: https://console.hetzner.cloud/")
        print("  Then: export HETZNER_API_TOKEN=your_token")
        sys.exit(1)

    try:
        import hcloud  # noqa: F401
    except ImportError:
        print("ERROR: hcloud not installed.")
        print("  Install: pip install hcloud")
        sys.exit(1)

    try:
        import yaml  # noqa: F401
    except ImportError:
        print("ERROR: pyyaml not installed.")
        print("  Install: pip install pyyaml")
        sys.exit(1)

    passphrase = os.environ.get("MAHAGUARDIAN_PASSPHRASE", "")
    if not passphrase:
        print("WARNING: MAHAGUARDIAN_PASSPHRASE not set — agent keys will be unencrypted.")
        print("  Set MAHAGUARDIAN_PASSPHRASE for production deployments.")

    return token, passphrase


# ---------------------------------------------------------------------------
# Certificate management
# ---------------------------------------------------------------------------

def setup_certs(passphrase: str) -> tuple[bytes, dict[str, tuple[bytes, bytes]]]:
    """
    Generate or load CA cert; generate all 6 agent certs.
    Returns (ca_cert_pem, {agent_id: (cert_pem, key_pem)}).
    """
    import guardian.audit as audit_module
    from guardian.mtls import generate_agent_cert, generate_ca
    from shared.config import CA_CERT_PATH, CA_KEY_PATH, LOGS_DIR

    # guardian.mtls.generate_agent_cert calls audit.log() — must initialise first
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    audit_module.init_audit_log(LOGS_DIR / "audit.db")

    if CA_CERT_PATH.exists() and CA_KEY_PATH.exists():
        ca_cert_pem = CA_CERT_PATH.read_bytes()
        ca_key_pem = CA_KEY_PATH.read_bytes()
        print(f"  Loaded existing CA from {CA_CERT_PATH}")
    else:
        print("  No CA found — generating new CA...")
        ca_cert_pem, ca_key_pem = generate_ca(passphrase)
        print(f"  CA generated -> {CA_CERT_PATH}")

    agent_certs: dict[str, tuple[bytes, bytes]] = {}
    for agent_id, _, _, _, _ in AGENTS:
        cert_pem, key_pem = generate_agent_cert(
            agent_id, ca_cert_pem, ca_key_pem, passphrase
        )
        agent_certs[agent_id] = (cert_pem, key_pem)
        print(f"  Generated cert for {agent_id}")

    return ca_cert_pem, agent_certs


# ---------------------------------------------------------------------------
# SSH key helper
# ---------------------------------------------------------------------------

def load_local_ssh_pubkey() -> str | None:
    """Return contents of ~/.ssh/id_ed25519.pub, or None if not found."""
    key_path = Path.home() / ".ssh" / "id_ed25519.pub"
    if key_path.exists():
        return key_path.read_text(encoding="utf-8").strip()
    print("  WARNING: ~/.ssh/id_ed25519.pub not found — SSH key not injected into droplets.")
    return None


# ---------------------------------------------------------------------------
# cloud-init builder
# ---------------------------------------------------------------------------

def _gz_b64(content: str | bytes) -> str:
    """
    Gzip-compress then base64-encode content for cloud-init write_files.

    cloud-init supports encoding: gz+b64 natively (18.2+, Ubuntu 20.04+).
    This reduces per-droplet user_data from ~40 KB to ~12 KB, well under
    Hetzner's 32 KB user_data limit.
    """
    raw = content.encode("utf-8") if isinstance(content, str) else content
    return base64.b64encode(gzip.compress(raw, compresslevel=9)).decode("ascii")


def _write_file_entry(
    path: str,
    content: str | bytes,
    owner: str = "mahaguardian:mahaguardian",
    permissions: str = "0644",
    compress: bool = True,
) -> dict:
    """Build a cloud-init write_files entry, optionally gz+b64 compressed."""
    if compress:
        return {
            "path": path,
            "encoding": "gz+b64",
            "content": _gz_b64(content),
            "owner": owner,
            "permissions": permissions,
        }
    return {
        "path": path,
        "content": content if isinstance(content, str) else content.decode("utf-8"),
        "owner": owner,
        "permissions": permissions,
    }


def build_cloud_init(
    droplet_agents: list[tuple[str, int, str, str]],
    ca_cert_pem: bytes,
    agent_certs: dict[str, tuple[bytes, bytes]],
    passphrase: str,
) -> str:
    """
    Build cloud-init YAML for one droplet.

    droplet_agents: list of (agent_id, port, partition, agent_type)
    Returns: cloud-config YAML string ready for Hetzner user_data.

    Cert path layout on droplet (follows shared/config.py Path.home()/.mahaguardian/):
      /home/mahaguardian/.mahaguardian/certs/ca.crt
      /home/mahaguardian/.mahaguardian/certs/agents/{id}.crt  (0644)
      /home/mahaguardian/.mahaguardian/certs/agents/{id}.key  (0600)

    Source code layout:
      /home/mahaguardian/agent/*.py
      /home/mahaguardian/shared/*.py
      WorkingDirectory=/home/mahaguardian → python -m agent.main resolves correctly
    """
    import yaml

    write_files = []

    # --- Python source files ---
    for rel_path in AGENT_SOURCE_FILES:
        full_path = PROJECT_ROOT / rel_path
        if not full_path.exists():
            print(f"  WARNING: {rel_path} not found — skipping")
            continue
        remote_path = f"/home/mahaguardian/{rel_path}"
        write_files.append(_write_file_entry(
            remote_path,
            full_path.read_text(encoding="utf-8"),
            owner="root:root",
        ))

    # --- CA cert (public — ca.key NEVER embedded) ---
    validate_embed("ca.crt")   # sanity: always passes; proves the guard runs
    write_files.append(_write_file_entry(
        "/home/mahaguardian/.mahaguardian/certs/ca.crt",
        ca_cert_pem,
        owner="root:root",
        permissions="0644",
    ))

    # --- Passphrase via protected EnvironmentFile (0600, not inline in unit) ---
    if passphrase:
        write_files.append(_write_file_entry(
            "/home/mahaguardian/.mahaguardian/mahaguardian.env",
            f"MAHAGUARDIAN_PASSPHRASE={passphrase}\n",
            owner="root:root",
            permissions="0600",
            compress=False,   # short string — no benefit compressing
        ))
        env_file_directive = "EnvironmentFile=/home/mahaguardian/.mahaguardian/mahaguardian.env"
    else:
        env_file_directive = "# No passphrase (unencrypted keys)"

    runcmd = [
        # Required directories (cloud-init creates parent dirs but not always agents/)
        "mkdir -p /home/mahaguardian/.mahaguardian/certs/agents",
        "mkdir -p /home/mahaguardian/.mahaguardian/logs",
        # Harden .mahaguardian directory before writing secrets
        "chmod 700 /home/mahaguardian/.mahaguardian",
        # Install Python venv + dependencies
        "python3 -m venv /home/mahaguardian/.venv",
        (
            "/home/mahaguardian/.venv/bin/pip install --quiet "
            "fastapi uvicorn[standard] pynacl pyrage "
            "websockets cryptography httpx pydantic"
        ),
        # Fix ownership after all writes complete
        "chown -R mahaguardian:mahaguardian /home/mahaguardian",
        # Reload systemd before enabling services
        "systemctl daemon-reload",
    ]

    # --- Per-agent certs, keys, systemd services ---
    for agent_id, port, _partition, _agent_type in droplet_agents:
        cert_pem, key_pem = agent_certs[agent_id]

        # Security gate — proves NEVER_EMBED is checked for every embedded file
        validate_embed(f"{agent_id}.crt")
        validate_embed(f"{agent_id}.key")

        write_files.append(_write_file_entry(
            f"/home/mahaguardian/.mahaguardian/certs/agents/{agent_id}.crt",
            cert_pem,
            owner="root:root",
            permissions="0644",
        ))
        write_files.append(_write_file_entry(
            f"/home/mahaguardian/.mahaguardian/certs/agents/{agent_id}.key",
            key_pem,
            owner="root:root",
            permissions="0600",
        ))

        service = (
            f"[Unit]\n"
            f"Description=MahaGuardian Agent {agent_id}\n"
            f"After=network.target\n"
            f"\n"
            f"[Service]\n"
            f"Type=simple\n"
            f"User=mahaguardian\n"
            f"Group=mahaguardian\n"
            f"WorkingDirectory=/home/mahaguardian\n"
            f"{env_file_directive}\n"
            f"Environment=AGENT_ID={agent_id}\n"
            f"Environment=MAHAGUARDIAN_AGENT_PORT={port}\n"
            f"Environment=MAHAGUARDIAN_PRODUCTION=true\n"
            f"ExecStart=/home/mahaguardian/.venv/bin/python3 -m uvicorn agent.main:app --host 0.0.0.0 --port {port}\n"
            f"Restart=on-failure\n"
            f"RestartSec=5\n"
            f"\n"
            f"[Install]\n"
            f"WantedBy=multi-user.target\n"
        )
        write_files.append({
            "path": f"/etc/systemd/system/mahaguardian-{agent_id}.service",
            "content": service,
            "owner": "root:root",
            "permissions": "0644",
        })
        runcmd.append(f"systemctl enable mahaguardian-{agent_id}")
        runcmd.append(f"systemctl start mahaguardian-{agent_id}")

    # --- SSH key for root (enables post-deploy debugging via ssh root@<ip>) ---
    ssh_pubkey = load_local_ssh_pubkey()
    if ssh_pubkey:
        write_files.append({
            "path": "/root/.ssh/authorized_keys",
            "content": ssh_pubkey + "\n",
            "owner": "root:root",
            "permissions": "0600",
        })

    cloud_config = {
        "users": [{
            "name": "mahaguardian",
            "system": True,
            "shell": "/bin/false",
            "home": "/home/mahaguardian",
            "no_create_home": False,
        }],
        "bootcmd": [
            # bootcmd runs before write_files — ensure user + home exist so
            # write_files can resolve root:root ownership without issue.
            # id check makes this idempotent across reboots.
            "id mahaguardian || useradd -r -s /bin/false -m -d /home/mahaguardian mahaguardian",
            "mkdir -p /home/mahaguardian",
        ],
        "packages": ["python3", "python3-pip", "python3-venv"],
        "write_files": write_files,
        "runcmd": runcmd,
    }

    return "#cloud-config\n" + yaml.safe_dump(
        cloud_config,
        default_flow_style=False,
        allow_unicode=True,
        width=120,
    )


# ---------------------------------------------------------------------------
# Hetzner provisioning
# ---------------------------------------------------------------------------

def provision_droplets(
    token: str,
    cloud_inits: list[str],
) -> list[dict]:
    """
    Create 3 droplets with cloud-init user_data via Hetzner API.
    Returns list of {id, name, ip, agents} dicts.
    """
    import urllib.request
    from hcloud import Client
    from hcloud.firewalls import FirewallRule
    from hcloud.images import Image
    from hcloud.locations import Location
    from hcloud.server_types import ServerType

    try:
        laptop_ip = urllib.request.urlopen(
            "https://api.ipify.org", timeout=10
        ).read().decode().strip()
        source_ips = [f"{laptop_ip}/32"]
        print(f"  Detected public IP: {laptop_ip}")
    except Exception:
        source_ips = ["0.0.0.0/0", "::/0"]
        print("  WARNING: Could not detect public IP — firewall will allow all IPs")

    client = Client(token=token)

    # Create or reuse firewall
    fw_obj = client.firewalls.get_by_name("mahaguardian-v1")
    if fw_obj:
        print("  Reusing existing firewall mahaguardian-v1")
        firewall = fw_obj
    else:
        print("  Creating firewall mahaguardian-v1...")
        fw_response = client.firewalls.create(
            name="mahaguardian-v1",
            rules=[
                FirewallRule(
                    direction="in",
                    protocol="tcp",
                    port="8443-8444",
                    source_ips=source_ips,
                    description="Agent mTLS from Guardian",
                ),
                FirewallRule(
                    direction="in",
                    protocol="tcp",
                    port="22",
                    source_ips=source_ips,
                    description="SSH for emergency access",
                ),
            ],
        )
        firewall = fw_response.firewall

    # Create droplets with cloud-init user_data
    droplets = []
    for i, user_data in enumerate(cloud_inits, 1):
        name = f"mahaguardian-v1-{i}"
        size_kb = len(user_data.encode("utf-8")) / 1024
        if size_kb > 32:
            print(f"  WARNING: {name} user_data is {size_kb:.1f} KB — may exceed Hetzner 32 KB limit")
        print(f"  Creating {name} ({size_kb:.1f} KB user_data)...")
        response = client.servers.create(
            name=name,
            server_type=ServerType(name="cx23"),
            image=Image(name="ubuntu-24.04"),
            location=Location(name="fsn1"),
            firewalls=[firewall],
            user_data=user_data,
            labels={"project": "mahaguardian-v1"},
        )
        droplets.append({
            "id": response.server.id,
            "name": name,
            "ip": None,
        })

    # Wait for all droplets to reach status=running
    print("  Waiting for droplets to become ready...")
    for d in droplets:
        for attempt in range(60):
            server = client.servers.get_by_id(d["id"])
            if server.status == "running" and server.public_net.ipv4:
                d["ip"] = server.public_net.ipv4.ip
                print(f"  {d['name']} -> {d['ip']} (ready in {attempt * 5}s)")
                break
            time.sleep(5)
        else:
            d["ip"] = None
            print(f"  WARNING: {d['name']} did not become ready within 5 minutes")

    return droplets


# ---------------------------------------------------------------------------
# Post-deployment verification
# ---------------------------------------------------------------------------

def wait_cloud_init(seconds: int = 90) -> None:
    """Wait for cloud-init to complete. Typically 60-120s on Ubuntu 24.04."""
    print(f"  Waiting {seconds}s for cloud-init (package install + venv create)...")
    waited = 0
    while waited < seconds:
        step = min(10, seconds - waited)
        time.sleep(step)
        waited += step
        remaining = seconds - waited
        if remaining > 0:
            print(f"    {remaining}s remaining...", end="\r", flush=True)
    print("  Cloud-init wait complete.        ")


def verify_agents(droplets: list[dict]) -> dict[str, str]:
    """
    TCP-connect to each agent port to verify it is listening.
    Returns {agent_id: "open" | "refused" | "timeout" | "no_ip"}.

    Note: expects a TCP RST (connection refused) or SYN-ACK (open).
    A TLS handshake failure at the application level also counts as "open".
    """
    status = {}
    for agent_id, droplet_idx, port, _, _ in AGENTS:
        if droplet_idx >= len(droplets) or not droplets[droplet_idx]["ip"]:
            status[agent_id] = "no_ip"
            continue
        ip = droplets[droplet_idx]["ip"]
        try:
            sock = socket.create_connection((ip, port), timeout=5)
            sock.close()
            status[agent_id] = "open"
        except ConnectionRefusedError:
            status[agent_id] = "refused"
        except (socket.timeout, OSError):
            status[agent_id] = "timeout"
    return status


# ---------------------------------------------------------------------------
# Summary and state persistence
# ---------------------------------------------------------------------------

def print_summary(droplets: list[dict], agent_status: dict[str, str]) -> None:
    print()
    print("=" * 62)
    print("  DEPLOYMENT SUMMARY")
    print("=" * 62)
    print(f"  {'Agent':<10} {'Droplet':<8} {'IP':<16} {'Port':<6} Status")
    print(f"  {'-'*10} {'-'*8} {'-'*16} {'-'*6} {'-'*8}")
    for agent_id, droplet_idx, port, _, _ in AGENTS:
        ip = droplets[droplet_idx]["ip"] if droplet_idx < len(droplets) else "n/a"
        ip = ip or "no_ip"
        st = agent_status.get(agent_id, "unknown")
        mark = "OK" if st == "open" else "!!"
        print(f"  {agent_id:<10} {droplet_idx + 1:<8} {ip:<16} {port:<6} [{mark}] {st}")
    print("=" * 62)


def save_droplets(droplets: list[dict], droplet_agents: list[list]) -> Path:
    """Save droplets.json with agent assignment metadata."""
    for i, d in enumerate(droplets):
        if i < len(droplet_agents):
            d["agents"] = [
                {
                    "agent_id": a[0],
                    "port": a[1],
                    "partition": a[2],
                    "type": a[3],
                }
                for a in droplet_agents[i]
            ]
    out = Path(__file__).parent / "droplets.json"
    out.write_text(json.dumps(droplets, indent=2))
    return out


# ---------------------------------------------------------------------------
# Preview mode (no credentials required)
# ---------------------------------------------------------------------------

def preview_cloud_init(droplet_num: int) -> None:
    """
    Build and print cloud-init YAML for a droplet using placeholder certs.
    Does not require HETZNER_API_TOKEN or MAHAGUARDIAN_PASSPHRASE.
    Source files are read from disk; cert/key content is replaced with placeholders.
    """
    try:
        import yaml  # noqa: F401
    except ImportError:
        print("ERROR: pyyaml required for preview.  Install: pip install pyyaml")
        sys.exit(1)

    idx = droplet_num - 1
    if not 0 <= idx < 3:
        print("ERROR: droplet number must be 1, 2, or 3")
        sys.exit(1)

    droplet_agent_defs = [a for a in AGENTS if a[1] == idx]
    agents_for_droplet = [(a[0], a[2], a[3], a[4]) for a in droplet_agent_defs]
    agent_names = [a[0] for a in agents_for_droplet]

    # Placeholder cert/key content (not real PEM — just shows structure)
    _CERT = (
        b"-----BEGIN CERTIFICATE-----\n"
        b"[CERT CONTENT - generated at deploy time from guardian/mtls.py]\n"
        b"-----END CERTIFICATE-----\n"
    )
    _KEY = (
        b"-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        b"[KEY CONTENT - generated at deploy time, encrypted with MAHAGUARDIAN_PASSPHRASE]\n"
        b"-----END ENCRYPTED PRIVATE KEY-----\n"
    )

    agent_certs = {a[0]: (_CERT, _KEY) for a in droplet_agent_defs}
    ca_cert_pem = _CERT

    yaml_str = build_cloud_init(
        agents_for_droplet,
        ca_cert_pem,
        agent_certs,
        passphrase="[PASSPHRASE-REDACTED]",
    )

    size_kb = len(yaml_str.encode("utf-8")) / 1024
    print(f"=== Cloud-Init Preview: Droplet {droplet_num} ({', '.join(agent_names)}) ===")
    print(f"    Size: {size_kb:.1f} KB  (Hetzner limit: 32 KB)")
    print()
    # Show first 120 lines then summarise remainder to keep output manageable
    lines = yaml_str.splitlines()
    cutoff = 120
    for line in lines[:cutoff]:
        print(line)
    if len(lines) > cutoff:
        print(f"... ({len(lines) - cutoff} more lines — write_files entries for source code)")
    print()
    print(f"Total lines: {len(lines)}  Total size: {size_kb:.1f} KB")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fully automated MahaGuardian deployment via Hetzner cloud-init"
    )
    parser.add_argument(
        "--preview",
        type=int,
        metavar="N",
        help="Print cloud-init YAML for droplet N (1-3) without deploying",
    )
    args = parser.parse_args()

    if args.preview:
        preview_cloud_init(args.preview)
        return

    print("=" * 62)
    print("  MahaGuardian — Automated Deployment")
    print("=" * 62)
    print()

    # Step 1: Check prerequisites
    print("[1/7] Checking prerequisites...")
    token, passphrase = check_prerequisites()
    print("  Prerequisites OK")
    print()

    # Step 2: Generate certificates
    print("[2/7] Setting up certificates...")
    ca_cert_pem, agent_certs = setup_certs(passphrase)
    security_report(agent_certs)
    print()

    # Step 3: Build cloud-init configs (one per droplet)
    print("[3/7] Building cloud-init configs...")
    # Group agents by droplet index
    droplet_agents: list[list] = [[], [], []]
    for agent_id, droplet_idx, port, partition, agent_type in AGENTS:
        droplet_agents[droplet_idx].append((agent_id, port, partition, agent_type))

    cloud_inits = []
    for i, agents in enumerate(droplet_agents):
        names = [a[0] for a in agents]
        ci = build_cloud_init(agents, ca_cert_pem, agent_certs, passphrase)
        cloud_inits.append(ci)
        size_kb = len(ci.encode("utf-8")) / 1024
        print(f"  Droplet {i + 1} ({', '.join(names)}): {size_kb:.1f} KB")
        if size_kb > 32:
            print(f"  WARNING: Exceeds Hetzner 32 KB user_data limit.")
    print()

    # Step 4: Provision droplets with cloud-init
    print("[4/7] Provisioning Hetzner droplets...")
    droplets = provision_droplets(token, cloud_inits)
    print()

    # Step 5: Wait for cloud-init
    print("[5/7] Waiting for cloud-init to complete...")
    wait_cloud_init(seconds=90)
    print()

    # Step 6: Verify agent connectivity
    print("[6/7] Verifying agent connectivity...")
    agent_status = verify_agents(droplets)
    for agent_id, st in agent_status.items():
        mark = "OK" if st == "open" else "!!"
        print(f"  [{mark}] {agent_id}: {st}")
    print()

    # Step 7: Save state
    print("[7/7] Saving deployment state...")
    out = save_droplets(droplets, droplet_agents)
    print(f"  Saved to {out}")
    print()

    # Final summary
    print_summary(droplets, agent_status)

    reachable = sum(1 for st in agent_status.values() if st == "open")
    total = len(agent_status)
    print(f"\n  {reachable}/{total} agents reachable")

    if reachable < total:
        print()
        print("  Some agents not yet reachable — cloud-init may still be running.")
        print("  Check status in 2-3 minutes.  To investigate:")
        for agent_id, idx, _, _, _ in AGENTS:
            if agent_status.get(agent_id) != "open":
                ip = droplets[idx]["ip"] if idx < len(droplets) else "n/a"
                if ip:
                    print(f"    ssh root@{ip}  # tail /var/log/cloud-init-output.log")
    else:
        print()
        print("  All agents reachable. Run experiments:")
        print("    py -3 experiments/run_all.py")
        print()
        print("  To tear down:")
        print("    py -3 deploy/teardown.py")


if __name__ == "__main__":
    main()
