#!/usr/bin/env python3
"""
Provision MahaGuardian agents — local (in-process) or Hetzner cloud (Docker).

Usage:
    # Local mode — no cloud account required:
    py -3 deploy/provision.py --local

    # Cloud mode — requires HCLOUD_TOKEN env var:
    $env:HCLOUD_TOKEN = "your-token"        # PowerShell
    export HCLOUD_TOKEN="your-token"        # bash
    py -3 deploy/provision.py --cloud

    # Dry run — print what would be created, no API calls:
    py -3 deploy/provision.py --cloud --dry-run

    # Check status of running droplets + containers:
    py -3 deploy/provision.py --status

    # Tear down all cloud resources:
    py -3 deploy/provision.py --teardown

Options:
    --cloud             Deploy to Hetzner cloud
    --local             Local in-process mode (default)
    --status            Show droplet and container status
    --teardown          Destroy all droplets and firewall
    --dry-run           Print plan without creating anything
    --droplets N        Number of droplets (default: 6)
    --ssh-key PATH      Path to SSH public key (default: ~/.ssh/id_rsa.pub)
"""
from __future__ import annotations

import argparse
import io
import json
import os
import socket
import sys
import tarfile
import threading
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Agent topology — mirrors provision_local()
# ---------------------------------------------------------------------------

# Company-named droplets
DROPLET_NAMES = [
    "mahaguardian-lea",
    "mahaguardian-mh",
    "mahaguardian-greengrid",
    "mahaguardian-kessler",
    "mahaguardian-nordbatt",
    "mahaguardian-chargenet",
]

# (droplet_index, [agent_ids]) — 5 agents per droplet, 6 droplets
AGENT_TOPOLOGY: list[list[str]] = [
    ["e1_director",   "e1_advisor_a",       "e2_advisor_a",        "e1_internal_a",    "e2_internal_a"],
    ["e1_internal_b", "e1_managing_b_for_a","e3_internal_b_legal", "e3_managing_b_for_d","e1_external_b"],
    ["e2_director",   "e2_internal_c",      "e2_managing_c",       "e2_external_c",    "e3_external_b"],
    ["e3_director",   "e3_lawyer_d",        "e3_internal_d",       "e4_lawyer_d",      "e5_lawyer_d"],
    ["e4_director",   "e4_internal_d",      "e4_internal_e",       "e4_managing_e",    "e4_external_e"],
    ["e5_director",   "e5_internal_d",      "e5_internal_f",       "e5_managing_f",    "e5_external_f"],
]

# External host ports for the 5 containers on each droplet
AGENT_PORTS = [9001, 9002, 9003, 9004, 9005]

# Hetzner resource labels — used for scoped teardown
PROJECT_LABEL = "project=mahaguardian-v1"
FIREWALL_NAME  = "mahaguardian-v1"
SSH_KEY_NAME   = "mahaguardian-v1"

# Droplet creation timeout (seconds per droplet)
DROPLET_READY_TIMEOUT = 60

# SSH connection retry window after droplet reaches "running"
SSH_READY_TIMEOUT = 120
SSH_RETRY_INTERVAL = 5

# Docker image name built on each droplet
DOCKER_IMAGE = "mahaguardian-agent:latest"

# Source files to upload — relative to PROJECT_ROOT
UPLOAD_FILES = [
    Path("deploy/Dockerfile.agent"),
    Path("requirements.txt"),
]
UPLOAD_DIRS = [
    Path("agent"),
    Path("shared"),
]


# ---------------------------------------------------------------------------
# Local provisioning — no cloud, no network
# ---------------------------------------------------------------------------

def provision_local() -> None:
    """
    Write a local-mode droplets.json and generate the scenario.

    Local topology mirrors the engagement structure: one process
    per engagement rather than one droplet per pair of agents.
    """
    scenarios_dir = PROJECT_ROOT / "deploy" / "scenarios"

    sys.path.insert(0, str(PROJECT_ROOT))
    from deploy.generate_scenario import generate
    generate(scenarios_dir)

    local_topology = [
        {
            "id":     f"local-{i + 1}",
            "name":   DROPLET_NAMES[i],
            "ip":     "127.0.0.1",
            "mode":   "local",
            "agents": agents,
        }
        for i, agents in enumerate(AGENT_TOPOLOGY)
    ]

    output = PROJECT_ROOT / "deploy" / "droplets.json"
    output.write_text(json.dumps(local_topology, indent=2))
    print(f"Local topology written to {output}")
    print("Run: py -3 -m pytest tests/ -q")


# ---------------------------------------------------------------------------
# Shared utilities
# ---------------------------------------------------------------------------

def get_public_ip() -> str:
    """Auto-detect laptop's public IP for firewall rules."""
    return urllib.request.urlopen(
        "https://api.ipify.org", timeout=10
    ).read().decode().strip()


def _require_hcloud() -> tuple:
    """Import hcloud library or exit with install instructions."""
    try:
        from hcloud import Client
        from hcloud.images.domain import Image
        from hcloud.server_types.domain import ServerType
        from hcloud.locations.domain import Location
        from hcloud.firewalls.domain import FirewallRule
        from hcloud.ssh_keys.domain import SSHKey
        return Client, Image, ServerType, Location, FirewallRule, SSHKey
    except ImportError:
        print("ERROR: hcloud library not found.")
        print("Install with: pip install hcloud")
        sys.exit(1)


def _require_paramiko():
    """Import paramiko or exit with install instructions."""
    try:
        import paramiko
        return paramiko
    except ImportError:
        print("ERROR: paramiko library not found.")
        print("Install with: pip install paramiko")
        sys.exit(1)


def _hcloud_client():
    """Return an hcloud Client using HCLOUD_TOKEN from environment."""
    token = os.environ.get("HCLOUD_TOKEN")
    if not token:
        print("ERROR: HCLOUD_TOKEN environment variable is not set.")
        print("Set it with:")
        print("  PowerShell: $env:HCLOUD_TOKEN = 'your-token'")
        print("  bash:       export HCLOUD_TOKEN='your-token'")
        print("Get a token at: https://console.hetzner.cloud/")
        sys.exit(1)
    Client, *_ = _require_hcloud()
    return Client(token=token)


# ---------------------------------------------------------------------------
# SSH helpers (paramiko)
# ---------------------------------------------------------------------------

def _wait_for_ssh(ip: str, timeout: int = SSH_READY_TIMEOUT) -> None:
    """
    Poll TCP port 22 until it accepts connections.

    Cloud-init may still be running even after the Hetzner API reports
    "running" — we wait for the SSH daemon to actually be ready.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            sock = socket.create_connection((ip, 22), timeout=3)
            sock.close()
            return
        except OSError:
            time.sleep(SSH_RETRY_INTERVAL)
    raise TimeoutError(f"SSH on {ip}:22 not available after {timeout}s")


def _ssh_connect(ip: str, ssh_key_path: Optional[Path], paramiko) -> "paramiko.SSHClient":
    """Open an SSH connection to root@ip using the given key."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    key_path = ssh_key_path or Path.home() / ".ssh" / "id_rsa"
    if not key_path.exists():
        raise FileNotFoundError(
            f"SSH private key not found: {key_path}\n"
            "Pass --ssh-key /path/to/id_rsa or generate one with ssh-keygen."
        )

    client.connect(
        hostname=ip,
        username="root",
        key_filename=str(key_path),
        timeout=30,
        banner_timeout=30,
        allow_agent=False,
        look_for_keys=False,
    )
    return client


def _run(ssh: "paramiko.SSHClient", cmd: str, *, timeout: int = 300) -> str:
    """
    Execute cmd on the remote host.

    Returns combined stdout. Raises RuntimeError on non-zero exit.
    """
    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
    stdin.close()
    out = stdout.read().decode(errors="replace")
    err = stderr.read().decode(errors="replace")
    rc  = stdout.channel.recv_exit_status()
    if rc != 0:
        raise RuntimeError(
            f"Remote command failed (exit {rc}):\n"
            f"  cmd:    {cmd!r}\n"
            f"  stderr: {err.strip()}\n"
            f"  stdout: {out.strip()}"
        )
    return out


def _upload_sources(ssh: "paramiko.SSHClient", remote_dir: str = "/opt/mahaguardian") -> None:
    """
    Bundle PROJECT_ROOT source files into an in-memory tar and upload via SFTP.

    Uploads:
      deploy/Dockerfile.agent  →  {remote_dir}/Dockerfile
      requirements.txt         →  {remote_dir}/requirements.txt
      agent/                   →  {remote_dir}/agent/
      shared/                  →  {remote_dir}/shared/
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        # Individual files
        for rel in UPLOAD_FILES:
            local = PROJECT_ROOT / rel
            if not local.exists():
                print(f"  WARNING: {rel} not found — skipping")
                continue
            # Rename Dockerfile.agent → Dockerfile in the archive
            arcname = "Dockerfile" if local.name == "Dockerfile.agent" else local.name
            tar.add(str(local), arcname=arcname)

        # Directory trees
        for rel_dir in UPLOAD_DIRS:
            local_dir = PROJECT_ROOT / rel_dir
            if not local_dir.exists():
                print(f"  WARNING: {rel_dir}/ not found — skipping")
                continue
            tar.add(str(local_dir), arcname=str(rel_dir))

    buf.seek(0)
    data = buf.read()

    sftp = ssh.open_sftp()
    try:
        sftp.putfo(io.BytesIO(data), "/tmp/mahaguardian-src.tar.gz")
    finally:
        sftp.close()

    _run(ssh, f"mkdir -p {remote_dir} && tar -xzf /tmp/mahaguardian-src.tar.gz -C {remote_dir}")


# ---------------------------------------------------------------------------
# Per-droplet Docker setup
# ---------------------------------------------------------------------------

_SETUP_LOG: dict[str, list[str]] = {}
_SETUP_LOCK = threading.Lock()


def _log(name: str, msg: str) -> None:
    with _SETUP_LOCK:
        _SETUP_LOG.setdefault(name, []).append(msg)
        print(f"  [{name}] {msg}")


def _setup_droplet(
    droplet: dict,
    guardian_ip: str,
    ssh_key_path: Optional[Path],
    paramiko,
) -> None:
    """
    Full Docker setup on one droplet.

    Steps:
      1. Wait for SSH daemon
      2. apt install docker.io openssl
      3. Upload source files
      4. docker build
      5. Generate self-signed TLS certs per agent
      6. Start 5 containers (ports 9001-9005)
      7. iptables: containers can only reach Guardian IP
    """
    name = droplet["name"]
    ip   = droplet["ip"]
    agents: list[str] = droplet["agents"]

    try:
        _log(name, f"Waiting for SSH on {ip}...")
        _wait_for_ssh(ip, timeout=SSH_READY_TIMEOUT)

        _log(name, "Connecting via SSH...")
        ssh = _ssh_connect(ip, ssh_key_path, paramiko)

        try:
            # 1. Install Docker + openssl
            _log(name, "Installing docker.io and openssl...")
            _run(ssh,
                "DEBIAN_FRONTEND=noninteractive apt-get update -qq && "
                "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io openssl",
                timeout=300,
            )
            _run(ssh, "systemctl enable docker && systemctl start docker")

            # 2. Upload sources
            _log(name, "Uploading source files...")
            _upload_sources(ssh, "/opt/mahaguardian")

            # 3. Build image
            _log(name, "Building Docker image (this takes ~2 min)...")
            _run(ssh,
                f"docker build -t {DOCKER_IMAGE} /opt/mahaguardian",
                timeout=600,
            )

            # 4. Generate self-signed TLS certs per agent
            _log(name, "Generating TLS certificates...")
            for agent_id in agents:
                cert_dir = f"/opt/mahaguardian/certs/{agent_id}"
                _run(ssh, f"mkdir -p {cert_dir}")
                _run(ssh,
                    f"openssl req -x509 -newkey rsa:2048 "
                    f"-keyout {cert_dir}/agent.key "
                    f"-out {cert_dir}/agent.crt "
                    f"-days 365 -nodes "
                    f"-subj '/CN={agent_id}.mahaguardian.local'",
                )

            # 5. Start containers
            _log(name, "Starting agent containers...")
            for i, (agent_id, host_port) in enumerate(zip(agents, AGENT_PORTS)):
                cert_dir = f"/opt/mahaguardian/certs/{agent_id}"
                _run(ssh,
                    f"docker run -d "
                    f"--name {agent_id} "
                    f"--restart unless-stopped "
                    f"-e AGENT_ID={agent_id} "
                    f"-e GUARDIAN_HOST={guardian_ip} "
                    f"-e GUARDIAN_PORT=7432 "
                    f"-e AGENT_PORT={host_port} "
                    f"-v {cert_dir}:/certs:ro "
                    f"-p {host_port}:8443 "
                    f"{DOCKER_IMAGE}",
                )

            # 6. iptables — containers can only reach Guardian IP
            _log(name, f"Configuring iptables (Guardian: {guardian_ip})...")
            # DOCKER-USER is traversed before Docker's own rules and
            # persists across `docker restart` without needing iptables-save.
            iptables_cmds = [
                # Flush DOCKER-USER first (idempotent)
                "iptables -F DOCKER-USER 2>/dev/null || true",
                # Allow established/related traffic back from Guardian
                "iptables -I DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                # Allow containers to reach Guardian
                f"iptables -I DOCKER-USER -d {guardian_ip}/32 -j ACCEPT",
                # Allow DNS on localhost (necessary for internal resolution)
                "iptables -I DOCKER-USER -d 127.0.0.53/32 -j ACCEPT",
                # Drop all other outbound forwarded traffic
                "iptables -A DOCKER-USER -j DROP",
            ]
            for cmd in iptables_cmds:
                _run(ssh, cmd)

            # 7. Verify all containers running
            out = _run(ssh, "docker ps --format '{{.Names}}\t{{.Status}}'")
            running = [line.split("\t")[0] for line in out.strip().splitlines()]
            for agent_id in agents:
                if agent_id not in running:
                    raise RuntimeError(
                        f"Container {agent_id} did not start.\n"
                        f"docker ps output:\n{out}"
                    )

            _log(name, f"All {len(agents)} containers running. Ports: {AGENT_PORTS[:len(agents)]}")
            droplet["status"] = "ready"

        finally:
            ssh.close()

    except Exception as exc:
        droplet["status"] = "failed"
        droplet["error"] = str(exc)
        _log(name, f"FAILED: {exc}")


# ---------------------------------------------------------------------------
# Cloud provisioning
# ---------------------------------------------------------------------------

def _hourly_price_eur(server_type_obj) -> float:
    """Return the cheapest advertised hourly gross price for a server type."""
    prices = []
    for price_entry in getattr(server_type_obj, "prices", []):
        hourly = getattr(price_entry, "price_hourly", None)
        if hourly and hourly.get("gross") is not None:
            prices.append(float(hourly["gross"]))
    return min(prices) if prices else float("inf")


def _select_server_type(client, requested: Optional[str] = None):
    """
    Return the requested server type, or auto-select the cheapest
    non-deprecated type with >= 2 cores.
    """
    if requested:
        st = client.server_types.get_by_name(requested)
        if st is None:
            raise RuntimeError(f"Unknown server type '{requested}'.")
        if getattr(st, "deprecated", False):
            raise RuntimeError(f"Server type '{requested}' is deprecated.")
        if getattr(st, "cores", 0) < 2:
            raise RuntimeError(
                f"Server type '{requested}' has only {getattr(st, 'cores', 0)} cores; need >= 2."
            )
        return st

    candidates = [
        st for st in client.server_types.get_all()
        if not getattr(st, "deprecated", False) and getattr(st, "cores", 0) >= 2
    ]
    if not candidates:
        raise RuntimeError("No non-deprecated Hetzner server type with >= 2 cores was found.")

    candidates.sort(
        key=lambda st: (
            _hourly_price_eur(st),
            getattr(st, "cores", 0),
            getattr(st, "memory", 0),
            st.name,
        )
    )
    return candidates[0]


def _iter_supported_locations(client, server_type_obj) -> list:
    """
    Return all locations advertised for this server type.

    Falls back to all known locations if the SDK does not expose prices/location
    data, then lets the create API decide.
    """
    seen: set[str] = set()
    result = []

    for price_entry in getattr(server_type_obj, "prices", []):
        loc = getattr(price_entry, "location", None)
        name = getattr(loc, "name", None)
        if not name or name in seen:
            continue
        bound_loc = client.locations.get_by_name(name)
        if bound_loc is not None:
            result.append(bound_loc)
            seen.add(name)

    if result:
        return result

    for bound_loc in client.locations.get_all():
        name = getattr(bound_loc, "name", None)
        if not name or name in seen:
            continue
        result.append(bound_loc)
        seen.add(name)

    if not result:
        raise RuntimeError(f"No Hetzner locations found for server type '{server_type_obj.name}'.")
    return result


def _create_server_with_any_location(
    client,
    *,
    name: str,
    server_type_obj,
    image_obj,
    ssh_key,
    labels: dict[str, str],
):
    """
    Try every available location for this server type until one succeeds.

    Returns (CreateServerResponse, chosen_location_name).
    """
    attempts: list[str] = []

    for loc_obj in _iter_supported_locations(client, server_type_obj):
        try:
            resp = client.servers.create(
                name=name,
                server_type=server_type_obj,
                image=image_obj,
                location=loc_obj,
                ssh_keys=[ssh_key],
                labels=labels,
            )
            return resp, loc_obj.name
        except Exception as exc:
            attempts.append(f"{loc_obj.name}: {exc}")
            continue

    raise RuntimeError(
        f"Server creation failed in every available location for '{server_type_obj.name}':\n"
        + "\n".join(f"  - {line}" for line in attempts)
    )


def provision_cloud(
    n_droplets: int = 6,
    ssh_key_path: Optional[Path] = None,
    dry_run: bool = False,
    server_type: Optional[str] = None,
) -> None:
    """
    Create n_droplets Hetzner servers and deploy 6 Docker agent
    containers on each.  Writes deploy/droplets.json on success.

    If server_type is omitted, auto-select the cheapest non-deprecated
    server type with >= 2 vCPU. Use --server-type to override.

    If any droplet fails setup, all droplets are torn down and the
    error is reported.
    """
    laptop_ip = get_public_ip()
    print(f"Laptop public IP (Guardian): {laptop_ip}")

    if dry_run:
        _print_dry_run(n_droplets, laptop_ip, ssh_key_path, server_type)
        return

    (Client, Image, ServerType, Location,
     FirewallRule, SSHKey) = _require_hcloud()
    paramiko = _require_paramiko()

    client = _hcloud_client()

    # --- SSH key ---
    try:
        pub_key_path = _resolve_ssh_pubkey_path(ssh_key_path)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)
    ssh_private_path = pub_key_path.with_suffix("")  # ~/.ssh/id_rsa
    pub_key_text = pub_key_path.read_text().strip()

    hcloud_key = _ensure_ssh_key(client, pub_key_text)
    print(f"SSH key: {hcloud_key.name} (id={hcloud_key.id})")

    # --- Firewall ---
    firewall = _ensure_firewall(client, laptop_ip, FirewallRule)
    print(f"Firewall: {firewall.name} (id={firewall.id})")

    # --- Resolve server type and architecture-matched image ---
    st_obj = _select_server_type(client, server_type)
    architecture = getattr(st_obj, "architecture", None) or "x86"
    img_obj = client.images.get_by_name_and_architecture("ubuntu-24.04", architecture)
    if img_obj is None:
        raise RuntimeError(
            f"Hetzner image 'ubuntu-24.04' not found for architecture '{architecture}'."
        )

    print(
        f"Server type: {st_obj.name} "
        f"({getattr(st_obj, 'cores', '?')} vCPU, "
        f"{getattr(st_obj, 'memory', '?')} GB RAM, arch={architecture})"
    )
    print("Locations: will try every available location for this server type until one succeeds")

    # --- Create servers (each tries all supported locations) ---
    server_responses = []
    print(f"\nCreating {n_droplets} x {st_obj.name} droplets...")
    for i in range(1, n_droplets + 1):
        name = DROPLET_NAMES[i - 1] if i - 1 < len(DROPLET_NAMES) else f"mahaguardian-agent-{i}"
        print(f"  Creating {name}...")
        resp, chosen_location = _create_server_with_any_location(
            client,
            name=name,
            server_type_obj=st_obj,
            image_obj=img_obj,
            ssh_key=hcloud_key,
            labels={"project": "mahaguardian-v1"},
        )
        print(f"    created in {chosen_location}")
        server_responses.append((resp, name))

    # --- Wait for running + collect IPs ---
    droplets = []
    print("\nWaiting for droplets to reach 'running' status...")
    for i, (resp, name) in enumerate(server_responses, 1):
        server_id = resp.server.id
        agents = AGENT_TOPOLOGY[i - 1] if i - 1 < len(AGENT_TOPOLOGY) else []

        ip = _wait_for_running(client, server_id, name)
        droplets.append({
            "id": str(server_id),
            "name": name,
            "ip": ip,
            "agents": agents,
            "status": "provisioning",
        })
        print(f"  {name}: {ip}")

    # --- Parallel SSH setup ---
    print("\nSetting up Docker on all droplets (parallel)...")
    threads = []
    for droplet in droplets:
        t = threading.Thread(
            target=_setup_droplet,
            args=(droplet, laptop_ip, ssh_private_path, paramiko),
            daemon=True,
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # --- Check for failures ---
    failed = [d for d in droplets if d.get("status") != "ready"]
    if failed:
        names = ", ".join(d["name"] for d in failed)
        print(f"\nERROR: {len(failed)} droplet(s) failed setup: {names}")
        for d in failed:
            print(f"  {d['name']}: {d.get('error', 'unknown error')}")
        print("\nTearing down all droplets...")
        _teardown_by_label(client)
        sys.exit(1)

    # --- Write droplets.json ---
    output_data = {
        "droplets": [
            {
                "id":      d["id"],
                "name":    d["name"],
                "ip":      d["ip"],
                "agents":  d["agents"],
                "status":  d["status"],
            }
            for d in droplets
        ],
        "guardian_ip": laptop_ip,
        "created_at":  datetime.now(timezone.utc).isoformat(),
    }
    output = PROJECT_ROOT / "deploy" / "droplets.json"
    output.write_text(json.dumps(output_data, indent=2))

    print(f"\n{'=' * 60}")
    print(f"Deployment complete: {n_droplets} droplets, {n_droplets * len(AGENT_PORTS)} containers")
    print(f"droplets.json: {output}")
    print(f"\nRun experiments:")
    print("  py -3 -m pytest tests/ -q")
    print(f"\nTo teardown:")
    print(f"  py -3 deploy/provision.py --teardown")


def _wait_for_running(client, server_id: int, name: str) -> str:
    """
    Poll until the server reaches 'running' and has a public IPv4.

    Raises TimeoutError after DROPLET_READY_TIMEOUT seconds.
    Returns the IPv4 address.
    """
    deadline = time.monotonic() + DROPLET_READY_TIMEOUT
    while time.monotonic() < deadline:
        server = client.servers.get_by_id(server_id)
        if server.status == "running" and server.public_net.ipv4:
            return server.public_net.ipv4.ip
        time.sleep(3)
    raise TimeoutError(
        f"{name} did not reach 'running' within {DROPLET_READY_TIMEOUT}s"
    )


def _resolve_ssh_pubkey_path(ssh_key_param: Optional[Path]) -> Path:
    """
    Return the SSH public key path, defaulting to ~/.ssh/id_rsa.pub.

    Raises FileNotFoundError (rather than sys.exit) so callers can handle
    the missing-key case gracefully (e.g. dry-run still prints a plan).
    """
    if ssh_key_param:
        p = Path(ssh_key_param)
        if not p.exists():
            raise FileNotFoundError(f"SSH key not found: {p}")
        return p

    # Try common default names
    for name in ("id_rsa.pub", "id_ed25519.pub", "id_ecdsa.pub"):
        p = Path.home() / ".ssh" / name
        if p.exists():
            return p

    raise FileNotFoundError(
        "No SSH public key found in ~/.ssh/ — "
        "run ssh-keygen or pass --ssh-key /path/to/key.pub"
    )


def _ensure_ssh_key(client, pub_key_text: str):
    """
    Upload SSH public key to Hetzner if not already present.

    Matches by name (mahaguardian-v1) or by public key fingerprint.
    Returns the SSHKey object.
    """
    existing = client.ssh_keys.get_by_name(SSH_KEY_NAME)
    if existing:
        return existing
    return client.ssh_keys.create(name=SSH_KEY_NAME, public_key=pub_key_text)


def _ensure_firewall(client, laptop_ip: str, FirewallRule):
    """
    Create (or reuse) the mahaguardian-v1 firewall.

    Rules:
      - SSH (22) inbound from laptop only
      - Agent ports (9001-9006) inbound from laptop only
      - All other inbound: denied by default (Hetzner deny-by-default)
    """
    existing = client.firewalls.get_by_name(FIREWALL_NAME)
    if existing:
        return existing

    resp = client.firewalls.create(
        name=FIREWALL_NAME,
        rules=[
            FirewallRule(
                direction="in",
                protocol="tcp",
                port="22",
                source_ips=[f"{laptop_ip}/32"],
                description="SSH for deployment",
            ),
            FirewallRule(
                direction="in",
                protocol="tcp",
                port="9001-9005",
                source_ips=[f"{laptop_ip}/32"],
                description="Agent HTTPS from Guardian laptop",
            ),
        ],
        labels={"project": "mahaguardian-v1"},
    )
    return resp.firewall


# ---------------------------------------------------------------------------
# --status
# ---------------------------------------------------------------------------

def show_status() -> None:
    """Show current status of droplets and their Docker containers."""
    droplets_json = PROJECT_ROOT / "deploy" / "droplets.json"
    if not droplets_json.exists():
        print("No droplets.json found. Run --cloud first.")
        return

    data = json.loads(droplets_json.read_text())

    # Handle both the new {"droplets": [...]} format and the old flat list
    if isinstance(data, list):
        droplets_list = data
        guardian_ip = "unknown"
    else:
        droplets_list = data.get("droplets", [])
        guardian_ip = data.get("guardian_ip", "unknown")

    # Local-mode droplets have no Hetzner ID to query
    if any(d.get("mode") == "local" for d in droplets_list):
        print("Local mode — no cloud resources to check.")
        return

    paramiko = _require_paramiko()
    client = _hcloud_client()

    print(f"Guardian IP : {guardian_ip}")
    print(f"Droplets    : {len(droplets_list)}")
    print()

    for d in droplets_list:
        server_id = d.get("id")
        name = d.get("name", "?")
        ip   = d.get("ip", "?")

        # Hetzner API status
        hcloud_status = "unknown"
        try:
            server = client.servers.get_by_id(int(server_id))
            hcloud_status = server.status
        except Exception:
            hcloud_status = "not found"

        print(f"{name}  {ip}  [{hcloud_status}]")

        # Docker container status via SSH
        try:
            _wait_for_ssh(ip, timeout=10)
            ssh_priv = _resolve_ssh_private_key()
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=ip, username="root",
                        key_filename=str(ssh_priv), timeout=10,
                        allow_agent=False, look_for_keys=False)
            try:
                out = ssh.exec_command(
                    "docker ps --format '{{.Names}}\t{{.Status}}'",
                    timeout=15,
                )[1].read().decode(errors="replace")
                for line in out.strip().splitlines():
                    parts = line.split("\t", 1)
                    cname  = parts[0] if parts else line
                    status = parts[1] if len(parts) > 1 else "?"
                    mark = "✓" if "Up" in status else "✗"
                    print(f"  {mark} {cname:30s}  {status}")
            finally:
                ssh.close()
        except Exception as exc:
            print(f"  (SSH unavailable: {exc})")
        print()


def _resolve_ssh_private_key() -> Path:
    """Return the SSH private key path."""
    for name in ("id_rsa", "id_ed25519", "id_ecdsa"):
        p = Path.home() / ".ssh" / name
        if p.exists():
            return p
    raise FileNotFoundError("No SSH private key found in ~/.ssh/")


# ---------------------------------------------------------------------------
# --list-server-types
# ---------------------------------------------------------------------------

def list_server_types() -> None:
    """
    Query Hetzner for all available server types and print a table
    sorted by hourly price, highlighting those meeting 2 vCPU / 2 GB.

    Requires HCLOUD_TOKEN.
    """
    client = _hcloud_client()
    server_types = client.server_types.get_all()

    # Use the module-level helper for consistent price extraction
    def _hourly_price(st) -> float:
        return _hourly_price_eur(st)

    rows = []
    for st in server_types:
        if st.deprecated:
            continue
        rows.append((st.name, st.cores, st.memory, _hourly_price(st)))

    rows.sort(key=lambda r: (r[3], r[1], r[2]))

    print(f"{'Name':<14} {'vCPU':>4} {'RAM (GB)':>8} {'EUR/hr':>8}  Note")
    print("-" * 52)
    for name, cores, memory, price in rows:
        meets = cores >= 2 and memory >= 2
        note = "<-- meets 2vCPU/2GB" if meets else ""
        marker = "*" if meets else " "
        print(f"{marker}{name:<13} {cores:>4} {memory:>8.1f} {price:>8.4f}  {note}")

    print()
    print("Default: cpx11 (cheapest AMD 2vCPU/2GB).  Pass --server-type NAME to override.")


# ---------------------------------------------------------------------------
# --teardown
# ---------------------------------------------------------------------------

def teardown() -> None:
    """Destroy all Hetzner resources (servers + firewall + SSH key)."""
    client = _hcloud_client()
    _teardown_by_label(client)


def _teardown_by_label(client) -> None:
    """Delete all Hetzner resources labelled project=mahaguardian-v1."""
    servers = client.servers.get_all(label_selector=PROJECT_LABEL)
    if servers:
        print(f"Deleting {len(servers)} server(s)...")
        for s in servers:
            ip = s.public_net.ipv4.ip if s.public_net.ipv4 else "no-ip"
            print(f"  Deleting {s.name} ({ip})...")
            s.delete()
    else:
        print("No servers found.")

    fw = client.firewalls.get_by_name(FIREWALL_NAME)
    if fw:
        print(f"Deleting firewall {FIREWALL_NAME}...")
        fw.delete()

    key = client.ssh_keys.get_by_name(SSH_KEY_NAME)
    if key:
        print(f"Deleting SSH key {SSH_KEY_NAME}...")
        key.delete()

    droplets_json = PROJECT_ROOT / "deploy" / "droplets.json"
    if droplets_json.exists():
        droplets_json.unlink()
        print("Removed droplets.json")

    print("Teardown complete.")


# ---------------------------------------------------------------------------
# --dry-run
# ---------------------------------------------------------------------------

def _print_dry_run(
    n_droplets: int,
    laptop_ip: str,
    ssh_key_path: Optional[Path],
    server_type: Optional[str] = None,
) -> None:
    try:
        pub_key_path = _resolve_ssh_pubkey_path(ssh_key_path)
    except FileNotFoundError:
        pub_key_path = Path("~/.ssh/id_rsa.pub  (not found -- pass --ssh-key)")
    agents_per_droplet = len(AGENT_PORTS)
    total_containers = n_droplets * agents_per_droplet
    chosen = server_type or "auto (cheapest non-deprecated type with >= 2 vCPU)"

    print("=" * 60)
    print("DRY RUN -- nothing will be created")
    print("=" * 60)
    print(f"\nHetzner resources to create:")
    print(f"  SSH key   : {SSH_KEY_NAME}  (from {pub_key_path})")
    print(f"  Firewall  : {FIREWALL_NAME}")
    print(f"              TCP 22     from {laptop_ip}/32  (SSH)")
    print(f"              TCP 9001-9005 from {laptop_ip}/32  (agents)")
    print(f"  Servers   : {n_droplets} x {chosen} (location auto-selected)")
    print(f"              (run --list-server-types to see specs and pricing)")
    print(f"\nPer-droplet Docker setup:")
    print(f"  Image     : {DOCKER_IMAGE}")
    print(f"  Containers: {agents_per_droplet} per droplet x {n_droplets} droplets = {total_containers} total")
    print(f"  Ports     : {AGENT_PORTS}")
    print(f"  iptables  : containers -> {laptop_ip} only (Guardian)")
    print(f"\nAgent topology:")
    for i, agents in enumerate(AGENT_TOPOLOGY[:n_droplets], 1):
        droplet_name = DROPLET_NAMES[i - 1] if i - 1 < len(DROPLET_NAMES) else f"mahaguardian-agent-{i}"
        ports = AGENT_PORTS[:len(agents)]
        print(f"  {droplet_name}:")
        for agent, port in zip(agents, ports):
            print(f"    :{port}  {agent}")
    print(f"\nOutput: deploy/droplets.json")
    print(f"\nTo deploy for real, remove --dry-run.")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Provision MahaGuardian agents (local or Hetzner cloud).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--local",
        action="store_true",
        help="Local in-process mode -- no cloud account required.",
    )
    mode.add_argument(
        "--cloud",
        action="store_true",
        help="Deploy to Hetzner cloud (requires HCLOUD_TOKEN).",
    )
    mode.add_argument(
        "--status",
        action="store_true",
        help="Show status of existing droplets and containers.",
    )
    mode.add_argument(
        "--teardown",
        action="store_true",
        help="Destroy all Hetzner resources.",
    )
    mode.add_argument(
        "--list-server-types",
        action="store_true",
        help="List available Hetzner server types with pricing (requires HCLOUD_TOKEN).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be created without making API calls.",
    )
    parser.add_argument(
        "--droplets",
        type=int,
        default=6,
        metavar="N",
        help="Number of droplets to create (default: 6).",
    )
    parser.add_argument(
        "--ssh-key",
        type=Path,
        default=None,
        metavar="PATH",
        help="Path to SSH public key (default: ~/.ssh/id_rsa.pub).",
    )
    parser.add_argument(
        "--server-type",
        default=None,
        metavar="NAME",
        help="Hetzner server type. Default: auto-select cheapest non-deprecated type "
             "with >= 2 vCPU. Use --list-server-types to see options.",
    )
    args = parser.parse_args()

    if args.local:
        provision_local()
    elif args.cloud or args.dry_run:
        provision_cloud(
            n_droplets=args.droplets,
            ssh_key_path=args.ssh_key,
            dry_run=args.dry_run,
            server_type=args.server_type,
        )
    elif args.status:
        show_status()
    elif args.teardown:
        teardown()
    elif args.list_server_types:
        list_server_types()
    else:
        # Default to local for backwards compatibility
        provision_local()


if __name__ == "__main__":
    main()

