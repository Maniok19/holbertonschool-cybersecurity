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


_global_search = None


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


def _raw_layer_class():
    try:
        from scapy.all import Raw
        return Raw
    except Exception:
        pass
    try:
        from scapy.layers.inet import Raw
        return Raw
    except Exception:
        pass
    return "Raw"


class PacketProcessor:
    protocol = "UNKNOWN"
    layer_name = None
    requires = ()
    excludes = ()

    def __init__(self, search=None):
        self.search = search

    def matches(self, packet):
        if self.layer_name is not None:
            has = getattr(packet, "haslayer", None)
            if callable(has):
                try:
                    if has(self.layer_name):
                        return True
                except Exception:
                    pass
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

    # ------------------------------------------------------------------
    # Shared payload-search helpers
    # ------------------------------------------------------------------
    def _payload_bytes(self, packet):
        """Best-effort extraction of raw payload bytes from *packet*.

        Tries the scapy ``Raw`` layer first, then falls back to any
        ``load`` attribute regardless of whether a ``Raw`` layer is
        present.  This ensures matching works even when ``haslayer``
        is unavailable or reports ``False`` (e.g. mock packets).
        """
        Raw = _raw_layer_class()
        raw_bytes = None
        try:
            if packet.haslayer(Raw):
                raw_layer = packet[Raw]
                load = getattr(raw_layer, "load", None)
                if load is None and isinstance(raw_layer,
                                               (bytes, bytearray)):
                    load = bytes(raw_layer)
                if load is not None:
                    if isinstance(load, str):
                        raw_bytes = load.encode("utf-8",
                                                errors="ignore")
                    else:
                        raw_bytes = bytes(load)
        except Exception:
            raw_bytes = None

        # Fallback: look for a ``load`` attribute directly.  This was
        # previously nested inside the ``has_raw`` branch, which meant
        # it was never reached when ``haslayer(Raw)`` was False.
        if raw_bytes is None:
            load = getattr(packet, "load", None)
            if load is not None:
                if isinstance(load, str):
                    raw_bytes = load.encode("utf-8", errors="ignore")
                else:
                    try:
                        raw_bytes = bytes(load)
                    except Exception:
                        raw_bytes = None
        return raw_bytes

    def _check_search(self, packet):
        search = self.search or _global_search
        if not search:
            return
        raw_bytes = self._payload_bytes(packet)
        if raw_bytes is None:
            return
        try:
            text = raw_bytes.decode("utf-8", errors="ignore")
        except Exception:
            text = ""
        if search in text:
            print("[ALERT] Payload Match found!")


class TCPProcessor(PacketProcessor):
    protocol = "TCP"
    layer_name = "TCP"
    # Rely solely on the TCP layer for matching.  The previous
    # ``requires = ("flags",)`` caused UDP/ICMP packets (which have IP
    # flags) to be misclassified as TCP.
    requires = ()

    def process(self, packet):
        src = getattr(packet, "src", "?")
        dst = getattr(packet, "dst", "?")
        sport = getattr(packet, "sport", "?")
        dport = getattr(packet, "dport", "?")
        flags = getattr(packet, "flags", "?")
        print(f"[TCP] {src}:{sport} -> {dst}:{dport} | Flags: {flags}")
        self._check_search(packet)


class UDPProcessor(PacketProcessor):
    protocol = "UDP"
    layer_name = "UDP"
    requires = ("sport", "dport")
    excludes = ("flags",)

    def process(self, packet):
        src = getattr(packet, "src", "?")
        dst = getattr(packet, "dst", "?")
        print(f"[UDP] {src} -> {dst}")
        self._check_search(packet)


class ICMPProcessor(PacketProcessor):
    protocol = "ICMP"
    layer_name = "ICMP"
    requires = ("type", "code")
    excludes = ("sport", "dport")

    def process(self, packet):
        src = getattr(packet, "src", "?")
        dst = getattr(packet, "dst", "?")
        print(f"[ICMP] {src} -> {dst}")
        self._check_search(packet)


def packet_handler(packet, verbose=False, search=None):
    if search is not None:
        global _global_search
        _global_search = search
    s = Sniffer(search=search if search is not None else _global_search)
    s.verbose = verbose
    s._process_packet(packet)


class Sniffer:
    def __init__(self, interface=None, filter_str=None,
                 output_file=None, verbose=False, search=None):
        self.interface = interface
        self.filter_str = filter_str
        self.output_file = output_file
        self.verbose = verbose
        self.search = search
        self.writer = None
        self.processors = [
            TCPProcessor(search=search),
            UDPProcessor(search=search),
            ICMPProcessor(search=search),
        ]

    def get_processor(self, protocol):
        for processor in self.processors:
            if getattr(processor, "protocol", None) == protocol:
                return processor
        return None

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

    def process(self, packet):
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
        for processor in self.processors:
            try:
                processor.search = self.search
            except Exception:
                pass
            matcher = getattr(processor, "matches", None)
            if callable(matcher):
                try:
                    if not matcher(packet):
                        continue
                except Exception:
                    continue
            try:
                processor.process(packet)
            except Exception:
                pass
            return True
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


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="PySniffer - a simple Scapy-based packet sniffer."
    )
    parser.add_argument("-i", "--interface", default=None)
    parser.add_argument("-f", "--filter", default=None)
    parser.add_argument("-w", "--write", default=None, metavar="FILE")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-s", "--search", default=None, metavar="STRING")
    return parser.parse_args(argv)


def main(argv=None):
    global _global_search
    args = parse_args(argv)
    _global_search = args.search
    print("[INFO] PySniffer initialized.")
    Sniffer(
        interface=args.interface,
        filter_str=args.filter,
        output_file=args.write,
        verbose=args.verbose,
        search=args.search,
    ).start()


if __name__ == "__main__":
    main()
