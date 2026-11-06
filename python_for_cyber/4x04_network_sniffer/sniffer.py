#!/usr/bin/env python3

import argparse


def _get_scapy():
    """Return the scapy module or None if it can't be loaded safely."""
    try:
        import scapy
    except ImportError:
        return None
    try:
        from scapy.sendrecv import sniff  # noqa: F401
        return scapy
    except ImportError:
        return None


def packet_handler(packet, verbose=False):
    if packet is None:
        return
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
    except ImportError:
        IP, TCP, UDP, ICMP = "IP", "TCP", "UDP", "ICMP"

    try:
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

        if verbose:
            from scapy.all import hexdump
            hexdump(packet)
    except Exception:
        pass


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="PySniffer - a simple Scapy-based packet sniffer."
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Interface to sniff on (e.g., eth0).")
    parser.add_argument("-f", "--filter", default=None,
                        help="BPF filter string (e.g., 'tcp port 80').")
    parser.add_argument("-w", "--write", default=None, metavar="FILE",
                        help="Write captured packets to a pcap file.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print a hexdump after each packet summary.")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    print("[INFO] PySniffer initialized.")

    scapy = _get_scapy()
    if scapy is None:
        print("[ERROR] Scapy is not available in this environment.")
        return

    sniff = scapy.sendrecv.sniff

    writer = None
    if args.write:
        try:
            from scapy.utils import PcapWriter
            writer = PcapWriter(args.write, append=True, sync=True)
        except ImportError:
            print("[WARN] PcapWriter unavailable; not writing to file.")

    def handler(packet):
        packet_handler(packet, verbose=args.verbose)
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
