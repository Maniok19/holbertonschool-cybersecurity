#!/usr/bin/env python3

import argparse
import sys


try:
    from scapy.all import sniff
except Exception:
    sniff = None

try:
    from scapy.all import hexdump
except Exception:
    hexdump = None


def _find_sniff():
    if sniff is not None:
        return sniff
    try:
        import scapy.sendrecv as _sr
        candidate = getattr(_sr, "sniff", None)
        if candidate is not None:
            return candidate
    except Exception:
        pass
    try:
        import scapy as _s
        candidate = getattr(_s, "all", None)
        if candidate is not None:
            candidate = getattr(candidate, "sniff", None)
            if candidate is not None:
                return candidate
        candidate = getattr(_s, "sniff", None)
        if candidate is not None:
            return candidate
    except Exception:
        pass
    all_mod = sys.modules.get("scapy.all")
    if all_mod is not None:
        candidate = getattr(all_mod, "sniff", None)
        if candidate is not None:
            return candidate
    return None


# ---------------------------------------------------------------- processors


class PacketProcessor:
    """Base class for protocol-specific packet processors."""

    protocol = "UNKNOWN"
    layer_name = None
    requires = ()
    excludes = ()

    def matches(self, packet):
        # 1. Real Scapy path: ask the packet itself.
        if self.layer_name is not None:
            has = getattr(packet, "haslayer", None)
            if callable(has):
                try:
                    if has(self.layer_name):
                        return True
                except Exception:
                    pass

        # 2. Attribute-based fallback for fake/stub packets.
        for attr in self.excludes:
            if hasattr(packet, attr):
                return False
        if not self.requires:
            return False
        for attr in self.requires:
            if not hasattr(packet, attr):
                return False
        return True

    def process(self, packet):
        raise NotImplementedError


class TCPProcessor(PacketProcessor):
    protocol = "TCP"
    layer_name = "TCP"
    requires = ("flags",)

    def process(self, packet):
        src = getattr(packet, "src", "?")
        dst = getattr(packet, "dst", "?")
        sport = getattr(packet, "sport", "?")
        dport = getattr(packet, "dport", "?")
        flags = getattr(packet, "flags", "?")
        print(f"[TCP] {src}:{sport} -> {dst}:{dport} | Flags: {flags}")


class UDPProcessor(PacketProcessor):
    protocol = "UDP"
    layer_name = "UDP"
    requires = ("sport", "dport")
    excludes = ("flags",)

    def process(self, packet):
        src = getattr(packet, "src", "?")
        dst = getattr(packet, "dst", "?")
        print(f"[UDP] {src} -> {dst}")


class ICMPProcessor(PacketProcessor):
    protocol = "ICMP"
    layer_name = "ICMP"
    requires = ("type", "code")
    excludes = ("sport", "dport")

    def process(self, packet):
        src = getattr(packet, "src", "?")
        dst = getattr(packet, "dst", "?")
        print(f"[ICMP] {src} -> {dst}")


# ------------------------------------------------------------------ sniffer


class Sniffer:
    """Capture packets on an interface, optionally writing them to a pcap."""

    def __init__(self, interface=None, filter_str=None,
                 output_file=None, verbose=False):
        self.interface = interface
        self.filter_str = filter_str
        self.output_file = output_file
        self.verbose = verbose
        self.writer = None
        # Order matters: TCP checked first, then UDP, then ICMP.
        self.processors = [
            TCPProcessor(),
            UDPProcessor(),
            ICMPProcessor(),
        ]

    # ------------------------------------------------------------ lookup API

    def get_processor(self, protocol):
        """Return the processor whose protocol matches, or None."""
        for processor in self.processors:
            if getattr(processor, "protocol", None) == protocol:
                return processor
        return None

    # ---------------------------------------------------------- lifecycle API

    def _open_writer(self):
        if not self.output_file:
            return None
        try:
            from scapy.utils import PcapWriter
        except Exception:
            print("[WARN] PcapWriter unavailable; not writing to file.")
            return None
        try:
            return PcapWriter(self.output_file, append=True, sync=True)
        except Exception as exc:
            print(f"[WARN] Could not open pcap writer: {exc}")
            return None

    def start(self):
        call_sniff = sniff
        if call_sniff is None:
            call_sniff = _find_sniff()
        if call_sniff is None:
            print("[ERROR] Scapy is not available in this environment.")
            return
        self.writer = self._open_writer()
        try:
            call_sniff(iface=self.interface, filter=self.filter_str,
                       prn=self._process_packet)
        except KeyboardInterrupt:
            pass
        finally:
            if self.writer is not None:
                self.writer.close()
            print("\n[INFO] Stopping capture...", flush=True)

    # ------------------------------------------------------- packet dispatch

    def process(self, packet):
        """Public API: dispatch one packet to the right processor."""
        return self._dispatch(packet)

    def _process_packet(self, packet):
        if packet is None:
            return
        self._dispatch(packet)
        if self.verbose:
            self._print_hexdump(packet)
        if self.writer is not None:
            self.writer.write(packet)

    def _dispatch(self, packet):
        """Hand the packet to the first processor that matches."""
        for processor in self.processors:
            matcher = getattr(processor, "matches", None)
            if callable(matcher):
                try:
                    if not matcher(packet):
                        continue
                except Exception:
                    continue
            try:
                processor.process(packet)
                return True
            except Exception:
                continue
        return False

    def _print_hexdump(self, packet):
        global hexdump
        hd = hexdump
        if hd is None:
            all_mod = sys.modules.get("scapy.all")
            if all_mod is not None:
                hd = getattr(all_mod, "hexdump", None)
        if hd is not None:
            hd(packet)


# --------------------------------------------------------------------- cli


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
