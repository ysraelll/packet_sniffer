# 🕵️‍♂️ PacketSniff — Cross-Platform Packet Sniffer (Python + Scapy)

A lightweight command-line packet sniffer built with Python and [Scapy](https://scapy.net/), compatible with **Linux**, **WSL**, and **Windows**. It supports protocol filtering, IP/port targeting, and optional interface selection.

---

## ⚙️ Features

- 🔍 Sniff TCP or UDP packets
- 🎯 Filter by source/destination IP and ports
- 🌐 Capture from a specific interface
- 🔁 Cross-platform support (Linux/WSL/Windows)
- 🧰 Uses BPF filters (Berkeley Packet Filter) for efficient sniffing

---

## 🐍 Requirements

- Python 3.6+
- [Scapy](https://scapy.net/)
- Admin/root privileges

### 🔧 Install Dependencies

```bash
pip install scapy

####
🚀 Usage

python packetsniff.py -h 

🔍 Common Examples

sudo python sniff.py

sudo python sniff.py --protocol tcp

sudo python sniff.py --protocol udp --src-ip 192.168.1.10

sudo python sniff.py --protocol tcp --dst-port 443

sudo python sniff.py --iface eth0 --protocol udp
