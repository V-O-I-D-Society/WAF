#!/usr/bin/env python3
import subprocess
import sys

def run(cmd):
    subprocess.run(cmd, stdout=subprocess.DEVNULL , stderr=subprocess.DEVNULL)

def enable():
    run(["iptables" , "-F"])

    run(["iptables" , "-A" , "INPUT" , "-m", "conntrack" , "--cstate", "ESTABLISHED,RELATED" , "-j" , "ACCEPT"])

    run(["iptables" , "-P" , "INPUT" , "DROP"])
    run(["iptables" , "-P", "FORWARD" , "DROP"])
    run(["iptables" , "-P" , "OUTPUT" , "ACCEPT"])

    print("Firewall enabled (stateful)")

def enable_safe():
    enable()

    allow("443","tcp")
    allow("22","tcp")
    allow("53","udp")

    print("Firewall enabled with safe mode")

def disable():

    run(["iptables" , "-P" , "INPUT" , "ACCEPT"])
    run(["iptables" , "-P" , "FORWARD" , "ACEEPT"])
    run(["iptables" , "-P" , "OUTPUT" , "ACCEPT"])

    print("Firewall disabled")

def status():
    result = subprocess.run(["iptables", "-S"] , capture_output = True , text = True)

    rules=result.stdout.strip().split("\n")

    print("firewall rules:")

    count =1

    for rule in rules:
        if not rule.startswith("-A"):
            continue
        parts=rule.split()
        chain=parts[1]
        action=parts[-1]
        proto="all"
        port="all"
        
        if "-p" in parts:
            proto=parts[parts.index("-p")+1]
        if "--dport" in parts:
            port = parts[parts.index("--dport")+1]

        print(f"[{count}] {chain:6} {action:6} {proto:4} port {port}")

        count+=1

def allow(port , proto):
    for chain in ["INPUT" , "OUTPUT"]:
        run(["iptables" ,"-D" , chain , "-p" , "proto" ,"--dport" , "port" , "-j" ,"DROP"])
        cmd=(["iptables" ,"-I" , chain])
        if proto != all:
            cmd += ["-p" , proto]
        if port != all:
            cmd += ["--dport" , port]
        cmd += ["-j" , "ACCEPT"]
        run(cmd)
    print("Rule Added : Allow (Highest priority)")

def deny(port , proto):
    for chain in ["INPUT" , "OUTPUT"]:
        run(["iptables" , "-D" , chain , "-p" , "proto" , "--dport" , "port" , "-j" , "ACCEPT"])
        cmd(["iptables" , "-I" , chain])
        if proto != all:
            cmd += ["-p" , proto]
        if port != all:
            cmd += ["--dport" , port]
        cmd += ["-j" , "DROP"]
        run(cmd)
    print("Rule Added : DENY (Highest Priority)")

def get_rules():
    result=subprocess.run(["iptables","-S"] , capture_output=True , text = True)
    return [line for line in result.stdout.splitlines() if line.startswith("-A")]


def delete(index):
    rules = get_rules()
    
    try:
        rule = rules[int(index)-1]
    except (IndexError , ValueError):
        print("Invalid rule number")
        return
    
    delete_cmd = rule.replace("-A" ,"-D" , 1).split()
    run(["iptables"] + delete_cmd)

    chain = rule.split()[1]
    print(f"Rule [{index}] deleted from {chain}")

def reset():
    run(["iptables","-F"])
    print("All Rules Flushed")

def help_menu():
    print("""
Usage:
    sudo python3 pyfw.py enable
    sudo python3 pyfw.py disable
    sudo python3 pyfw.py status
    sudo python3 pyfw.py allow <port|all> <tcp|udp|icmp|ssh|all>
    sudo python3 pyfw.py deny <port|all> <tcp|udp|icmp|ssh|all>
    sudo python3 pyfw.py delete <rule number>
    sudo python3 pyfw.py reset
""")

def state():
    result=subprocess.run(["iptables","-L","INPUT"],capture_output=True , text=True)

    output=result.stdout

    if "policy DROP" in output:
        print("Firewall state: Active")
    else:
        print("Firewall state: Inactive")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        help_menu()
        sys.exit(1)

    cmd=sys.argv[1]

    if cmd == "enable":
        if len(sys.argv) == 3 and sys.argv[2] == "--safe":
            enable_safe()
        elif len(sys.argv) == 2:
            enable()
        else:
            print("Usage: sudo python3 pyfw.py [--safe]")
            sys.exit(1)
    elif cmd == "disable":
        disable()
    elif cmd == "allow":
        allow(sys.argv[2] , sys.argv[3])
    elif cmd == "deny":
        deny(sys.argv[2] , sys.argv[3])
    elif cmd == "reset":
        reset()
    elif cmd == "help":
        help_menu()
    elif cmd == "state":
        state()
    elif cmd == "delete":
        if len(sys.argv) != 3:
            print("Usage: sudo python3 pyfw.py delete <rule_number>")
            sys.exit(1)
        delete(sys.argv[2])
    elif cmd == "status":
        status()
    else:
        help_menu()
