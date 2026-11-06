#!/usr/bin/env python3

import argparse

from scapy.all import sniff


def packet_handler(packet):
    try:
        from scapy.all import IP, TCP, UDP, ICMP
    except ImportError:
        from scapy.layers.inet import IP, TCP, UDP, ICMP

    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            print(f"[TCP] {src}:{tcp.sport} -> {dst}:{tcp.dport} "
                  f"| Flags: {tcp.flags}")
        elif packet.haslayer(UDP):
            print(f"[UDP] {src} -> {dst}")
        elif packet.haslayer(ICMP):
            print(f"[ICMP] {src} -> {dst}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="PySniffer - a simple Scapy-based packet sniffer."
    )
    parser.add_argument(
        "-i", "--interface",
        default=None,
        help="Interface to sniff on (e.g., eth0).",
    )
    parser.add_argument(
        "-f", "--filter",
        default=None,
        help="BPF filter string (e.g., 'tcp port 80').",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    print("[INFO] PySniffer initialized.")
    try:
        sniff(iface=args.interface, filter=args.filter, prn=packet_handler)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[INFO] Stopping capture...", flush=True)


if __name__ == "__main__":
    main()
