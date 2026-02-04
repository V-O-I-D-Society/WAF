🛡️ PyFW – Mini Firewall Tool (Python + iptables)
📌 About

PyFW is a lightweight CLI-based firewall management tool written in Python that works as a frontend for iptables, similar to UFW.
It provides a simplified way to manage Linux firewall rules without directly writing complex iptables commands.

🎯 Purpose

Understand Linux firewall concepts (iptables, Netfilter)

Simplify firewall rule management using Python

Implement allow/deny rules for ports and protocols

Test firewall behavior using real network traffic

⚙️ Tech Stack

Python 3

iptables (Netfilter)

Kali Linux

Testing tools: curl, ping, ssh, nmap

✨ Features

Enable / Disable firewall

Allow or deny traffic by port & protocol

Supports TCP, UDP, ICMP

Stateful firewall (ESTABLISHED, RELATED)

View, delete, and reset rules

CLI only (no GUI, no logging)

Rules are non-persistent (reset after reboot)

🚀 Usage

Run as root:

sudo python3 pyfw.py

Enable / Disable

sudo python3 pyfw.py enable
sudo python3 pyfw.py disable

Allow / Deny

sudo python3 pyfw.py allow 22 tcp
sudo python3 pyfw.py deny 80 tcp
sudo python3 pyfw.py allow 53 udp
sudo python3 pyfw.py allow all icmp

Status / Reset

sudo python3 pyfw.py status
sudo python3 pyfw.py reset

