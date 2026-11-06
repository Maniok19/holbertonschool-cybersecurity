#!/usr/bin/env python3

import argparse


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
    parser.add_argument("-i", "--interface", default=None,
                        help="Interface to sniff on (e.g., eth0).")
    parser.add_argument("-f", "--filter", default=None,
                        help="BPF filter string (e.g., 'tcp port 80').")
    parser.add_argument("-w", "--write", default=None, metavar="FILE",
                        help="Write captured packets to a pcap file.")
    return parser.parse_args()


def main():
    from scapy.all import sniff

    args = parse_args()
    print("[INFO] PySniffer initialized.")

    writer = None
    if args.write:
        from scapy.utils import PcapWriter
        writer = PcapWriter(args.write, append=True, sync=True)

    def handler(packet):
        packet_handler(packet)
        if writer is not None:
            writer.write(packet)

    try:
        sniff(iface=args.interface, filter=args.filter, prn=handler)
    except KeyboardInterrupt:
        pass
    finally:
        if writer is not None:
            writer.close()
        print("\n[INFO] Stopping capture...", flush=True)


if __name__ == "__main__":
    main()
