#!/usr/bin/env python3
import argparse
import json
import subprocess
import os
import sys

CONFIG_DIR = "/etc/pyfw"
RULES_FILE = f"{CONFIG_DIR}/rules.json"

def require_root():
    if os.geteuid() != 0:
        print("[-] Must be run as root")
        sys.exit(1)

def run(cmd):
    subprocess.run(cmd, check=True)

def setup_dirs():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    if not os.path.exists(RULES_FILE):
        with open(RULES_FILE, "w") as f:
            json.dump([], f)

def load_rules():
    with open(RULES_FILE) as f:
        return json.load(f)

def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)

def reset_iptables():
    run(["iptables", "-F"])
    run(["iptables", "-X"])
    run(["iptables", "-P", "INPUT", "DROP"])
    run(["iptables", "-P", "FORWARD", "DROP"])
    run(["iptables", "-P", "OUTPUT", "ACCEPT"])

    # Allow loopback
    run(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])

    # Allow established connections
    run([
        "iptables", "-A", "INPUT",
        "-m", "conntrack",
        "--ctstate", "ESTABLISHED,RELATED",
        "-j", "ACCEPT"
    ])

def apply_rule(rule):
    cmd = ["iptables", "-A", "INPUT"]

    if rule["proto"]:
        cmd += ["-p", rule["proto"]]

    if rule["from_ip"]:
        cmd += ["-s", rule["from_ip"]]

    if rule["port"]:
        cmd += ["--dport", str(rule["port"])]

    cmd += ["-j", "ACCEPT" if rule["action"] == "allow" else "DROP"]
    run(cmd)

def enable_firewall():
    reset_iptables()
    for rule in load_rules():
        apply_rule(rule)
    print("[+] Firewall enabled")

def add_rule(action, port, proto, from_ip):
    rules = load_rules()
    rule = {
        "action": action,
        "port": port,
        "proto": proto,
        "from_ip": from_ip
    }
    rules.append(rule)
    save_rules(rules)
    print(f"[+] Rule added: {rule}")

def status():
    rules = load_rules()
    if not rules:
        print("No rules defined.")
        return
    for i, r in enumerate(rules, 1):
        print(f"{i}. {r['action'].upper()} "
              f"{r['proto'] or 'any'} "
              f"port {r['port'] or 'any'} "
              f"from {r['from_ip'] or 'any'}")

def main():
    require_root()
    setup_dirs()

    parser = argparse.ArgumentParser(description="pyfw - Debian Firewall Tool")
    sub = parser.add_subparsers(dest="cmd")

    allow = sub.add_parser("allow")
    allow.add_argument("port", type=int)
    allow.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    allow.add_argument("--from-ip")

    deny = sub.add_parser("deny")
    deny.add_argument("port", type=int)
    deny.add_argument("--proto", choices=["tcp", "udp"], default="tcp")
    deny.add_argument("--from-ip")

    sub.add_parser("enable")
    sub.add_parser("status")

    args = parser.parse_args()

    if args.cmd == "allow":
        add_rule("allow", args.port, args.proto, args.from_ip)
    elif args.cmd == "deny":
        add_rule("deny", args.port, args.proto, args.from_ip)
    elif args.cmd == "enable":
        enable_firewall()
    elif args.cmd == "status":
        status()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()

