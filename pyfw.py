#!/usr/bin/env python3
import subprocess
import sys

def run(cmd):
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def enable():
    run(["iptables", "-F"])

    # Allow established/related traffic
    run([
        "iptables", "-A", "INPUT",
        "-m", "conntrack",
        "--ctstate", "ESTABLISHED,RELATED",
        "-j", "ACCEPT"
      ])

    # Default policies
    run(["iptables", "-P", "INPUT", "DROP"])
    run(["iptables", "-P", "FORWARD", "DROP"])
    run(["iptables", "-P", "OUTPUT", "ACCEPT"])

    print("Firewall enabled (stateful)")

def disable():
    run(["iptables", "-P", "INPUT", "ACCEPT"])
    run(["iptables", "-P", "FORWARD", "ACCEPT"])
    run(["iptables", "-P", "OUTPUT", "ACCEPT"])
    print("Firewall disabled")

def status():
    subprocess.run(["iptables", "-L", "-n", "--line-numbers"])

def allow(port, proto):
    for chain in ["INPUT", "OUTPUT"]:
        run(["iptables", "-D", chain, "-p", proto, "--dport", port, "-j", "DROP"])
        cmd = ["iptables", "-I", chain]
        if proto != "all":
            cmd += ["-p", proto]
        if port != "all":
            cmd += ["--dport", port]
        cmd += ["-j", "ACCEPT"]
        run(cmd)
    print("Rule added: ALLOW (highest priority)")

def deny(port, proto):
    for chain in ["INPUT", "OUTPUT"]:
        run(["iptables", "-D", chain, "-p", proto, "--dport", port, "-j", "ACCEPT"])
        cmd = ["iptables", "-I", chain]
        if proto != "all":
            cmd += ["-p", proto]
        if port != "all":
            cmd += ["--dport", port]
        cmd += ["-j", "DROP"]
        run(cmd)
    print("Rule added: DENY (highest priority)")

def delete(rule):
    run(["iptables", "-D", "INPUT", rule])
    run(["iptables", "-D", "OUTPUT", rule])
    print("Rule deleted from INPUT & OUTPUT")

def reset():
    run(["iptables", "-F"])
    print("All rules flushed")

def help_menu():
    print("""
Usage:
  pyfw enable
  pyfw disable
  pyfw status
  pyfw allow <port|all> <tcp|udp|icmp|all>
  pyfw deny <port|all> <tcp|udp|icmp|all>
  pyfw delete <rule_number>
  pyfw reset
""")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        help_menu()
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "enable":
        enable()
    elif cmd == "disable":
        disable()
    elif cmd == "status":
        status()
    elif cmd == "allow":
        allow(sys.argv[2], sys.argv[3])
    elif cmd == "deny":
        deny(sys.argv[2], sys.argv[3])
    elif cmd == "delete":
        delete(sys.argv[2])
    elif cmd == "reset":
        reset()
    else:
        help_menu()

