#!/usr/bin/env python3
"""
Update Hetzner firewall with current laptop IP.
Run if your IP changed since provisioning.
"""
from __future__ import annotations

import os
import sys
import urllib.request


def main():
    token = os.environ.get("HETZNER_API_TOKEN")
    if not token:
        print("Set HETZNER_API_TOKEN environment variable")
        sys.exit(1)

    current_ip = urllib.request.urlopen(
        "https://api.ipify.org"
    ).read().decode().strip()
    print(f"Current public IP: {current_ip}")

    try:
        from hcloud import Client
    except ImportError:
        print("Install: pip install hcloud")
        sys.exit(1)

    client = Client(token=token)
    fw = client.firewalls.get_by_name("mahaguardian-v1")
    if not fw:
        print("Firewall 'mahaguardian-v1' not found")
        sys.exit(1)

    # Update all inbound rules to current IP
    from hcloud.firewalls import FirewallRule
    new_rules = []
    for rule in fw.rules:
        updated = FirewallRule(
            direction=rule.direction,
            protocol=rule.protocol,
            port=rule.port,
            source_ips=[f"{current_ip}/32"],
            description=rule.description,
        )
        new_rules.append(updated)

    client.firewalls.set_rules(fw, new_rules)
    print(f"Firewall updated: all rules now allow {current_ip}/32")


if __name__ == "__main__":
    main()
