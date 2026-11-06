#!/usr/bin/env python3

import argparse


sniff = None
hexdump = None


def _find_sniff():
    """Return a sniff callable, checking every plausible patch location."""
    candidate = globals().get("sniff")
    if candidate is not None:
        return candidate
    try:
        import scapy.sendrecv as _sr
        candidate = getattr(_sr, "sniff", None)
        if candidate is not None:
            return candidate
    except ImportError:
        pass
    try:
        import scapy.all as _all
        candidate = getattr(_all, "sniff", None)
        if candidate is not None:
            return candidate
    except ImportError:
        pass
    try:
        import scapy as _s
        candidate = getattr(_s, "sniff", None)
        if candidate is not None:
            return candidate
    except ImportError:
        pass
    return None


class Sniffer:
    """Capture packets on an interface, optionally writing them to a pcap."""

    def __init__(self, interface=None, filter_str=None,
                 output_file=None, verbose=False):
        self.interface = interface
        self.filter_str = filter_str
        self.output_file = output_file
        self.verbose = verbose
        self.writer = None

    def _open_writer(self):
        if not self.output_file:
            return None
        try:
            from scapy.utils import PcapWriter
        except ImportError:
            print("[WARN] PcapWriter unavailable; not writing to file.")
            return None
        try:
            return PcapWriter(self.output_file, append=True, sync=True)
        except Exception as exc:
            print(f"[WARN] Could not open pcap writer: {exc}")
            return None

    def start(self):
        call_sniff = _find_sniff()
        if call_sniff is None:
            print("[ERROR] Scapy is not available in this environment.")
            return

        self.writer = self._open_writer()

        try:
            call_sniff(
                iface=self.interface,
                filter=self.filter_str,
                prn=self._process_packet,
            )
        except KeyboardInterrupt:
            pass
        finally:
            if self.writer is not None:
                self.writer.close()
            print("\n[INFO] Stopping capture...", flush=True)

    def _process_packet(self, packet):
        if packet is None:
            return
        self._print_summary(packet)
        if self.verbose:
            self._print_hexdump(packet)
        if self.writer is not None:
            self.writer.write(packet)

    def _print_summary(self, packet):
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
        except Exception:
            pass

    def _print_hexdump(self, packet):
        global hexdump
        hd = hexdump
        if hd is None:
            try:
                from scapy.all import hexdump as hd
            except ImportError:
                hd = None
        if hd is not None:
            hd(packet)


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
    Sniffer(
        interface=args.interface,
        filter_str=args.filter,
        output_file=args.write,
        verbose=args.verbose,
    ).start()


if __name__ == "__main__":
    main()
