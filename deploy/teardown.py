#!/usr/bin/env python3
"""
Destroy all MahaGuardian cloud resources.

Deletes all droplets with label project=mahaguardian-v1 and
the firewall mahaguardian-v1.
"""
from __future__ import annotations

import os
import sys


def main():
    token = os.environ.get("HETZNER_API_TOKEN")
    if not token:
        print("Set HETZNER_API_TOKEN environment variable")
        sys.exit(1)

    try:
        from hcloud import Client
    except ImportError:
        print("Install hcloud: pip install hcloud")
        sys.exit(1)

    client = Client(token=token)

    # Delete servers
    servers = client.servers.get_all(
        label_selector="project=mahaguardian-v1"
    )
    for server in servers:
        print(f"Deleting server {server.name} ({server.public_net.ipv4.ip})...")
        client.servers.delete(server)

    # Delete firewall
    firewalls = client.firewalls.get_all()
    for fw in firewalls:
        if fw.name == "mahaguardian-v1":
            print(f"Deleting firewall {fw.name}...")
            client.firewalls.delete(fw)

    print("All resources deleted.")


if __name__ == "__main__":
    main()
