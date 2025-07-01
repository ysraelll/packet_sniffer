import argparse
from scapy.all import sniff, IP, TCP, UDP

def build_bpf_filter(args):
    filters = []

    if args.protocol:
        filters.append(args.protocol.lower())

    if args.src_ip:
        filters.append(f"src host {args.src_ip}")

    if args.dst_ip:
        filters.append(f"dst host {args.dst_ip}")

    if args.src_port:
        filters.append(f"src port {args.src_port}")

    if args.dst_port:
        filters.append(f"dst port {args.dst_port}")

    return " and ".join(filters)

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"
        print(f"[{proto}] {ip_layer.src}:{packet.sport if hasattr(packet, 'sport') else ''} -> {ip_layer.dst}:{packet.dport if hasattr(packet, 'dport') else ''}")

def main():
    parser = argparse.ArgumentParser(
        description="Cross-Platform Packet Sniffer (Linux/Windows)",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  # All packets
  sudo python sniffer.py

  # Only TCP packets
  sudo python sniffer.py --protocol tcp

  # UDP packets from a specific source IP
  sudo python sniffer.py --protocol udp --src-ip 192.168.1.10

  # TCP packets to a specific destination port
  sudo python sniffer.py --protocol tcp --dst-port 443

  # From a specific interface (optional)
  sudo python sniffer.py --iface eth0 --protocol udp
"""
    )

    parser.add_argument("--protocol", choices=["tcp", "udp"], help="Filter by protocol")
    parser.add_argument("--src-ip", help="Filter by source IP address")
    parser.add_argument("--dst-ip", help="Filter by destination IP address")
    parser.add_argument("--src-port", type=int, help="Filter by source port")
    parser.add_argument("--dst-port", type=int, help="Filter by destination port")
    parser.add_argument("--iface", help="Network interface to sniff on (optional)")
    parser.add_argument("--count", type=int, help="Number of packets to capture (0 = infinite)", default=0)

    args = parser.parse_args()

    bpf_filter = build_bpf_filter(args)
    print(f"[*] Starting packet sniffing with filter: {bpf_filter or 'None'}")
    print("[*] Press Ctrl+C to stop.\n")

    sniff(filter=bpf_filter, prn=process_packet, store=False, iface=args.iface, count=args.count or 0)

    
if __name__ == "__main__":
    main()