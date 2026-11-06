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
    # Look up a live sniff first so test monkeypatches are honored.
    try:
        import scapy.sendrecv as _sr
        candidate = getattr(_sr, "sniff", None)
        if candidate is not None:
            return candidate
    except Exception:
        pass

    try:
        import scapy.all as _all
        candidate = getattr(_all, "sniff", None)
        if candidate is not None:
            return candidate
    except Exception:
        pass

    all_mod = sys.modules.get("scapy.all")
    if all_mod is not None:
        candidate = getattr(all_mod, "sniff", None)
        if candidate is not None:
            return candidate

    if sniff is not None:
        return sniff

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
        """Best-effort extraction of raw payload bytes from packet."""

        Raw = _raw_layer_class()
        raw_bytes = None

        try:
            if packet.haslayer(Raw):
                raw_layer = packet[Raw]
                load = getattr(raw_layer, "load", None)

                if load is None and isinstance(
                    raw_layer, (bytes, bytearray)
                ):
                    load = bytes(raw_layer)

                if load is not None:
                    if isinstance(load, str):
                        raw_bytes = load.encode(
                            "utf-8", errors="ignore"
                        )
                    else:
                        raw_bytes = bytes(load)

        except Exception:
            raw_bytes = None

        # Fallback: look for a load attribute directly.
        if raw_bytes is None:
            load = getattr(packet, "load", None)

            if load is not None:
                if isinstance(load, str):
                    raw_bytes = load.encode(
                        "utf-8", errors="ignore"
                    )
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
    requires = ()

    def process(self, packet):
        src = getattr(packet, "src", "?")
        dst = getattr(packet, "dst", "?")
        sport = getattr(packet, "sport", "?")
        dport = getattr(packet, "dport", "?")
        flags = getattr(packet, "flags", "?")

        print(
            f"[TCP] {src}:{sport} -> {dst}:{dport} | Flags: {flags}"
        )


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


def packet_handler(packet, verbose=False, search=None):
    global _global_search

    if search is not None:
        _global_search = search

    s = Sniffer(
        search=search if search is not None else _global_search
    )

    s.verbose = verbose
    s._process_packet(packet)


class Sniffer:

    def __init__(
        self,
        interface=None,
        filter_str=None,
        output_file=None,
        verbose=False,
        search=None
    ):
        self.interface = interface
        self.filter_str = filter_str
        self.output_file = output_file
        self.verbose = verbose
        self.search = search
        self.writer = None

        # Packet statistics.
        self.stats = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
        }

        # Protocol identified for the current packet.
        self._last_protocol = None

        # Dedicated payload searcher.
        self.searcher = PacketProcessor(search=search)

        self.processors = [
            TCPProcessor(search=None),
            UDPProcessor(search=None),
            ICMPProcessor(search=None),
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
            print(
                "[WARN] PcapWriter unavailable; not writing to file."
            )
            return None

        try:
            return PcapWriter(
                self.output_file,
                append=True,
                sync=True
            )
        except Exception as exc:
            print(f"[WARN] Could not open pcap writer: {exc}")
            return None

    def start(self):
        # Always re-resolve sniff at call time so monkeypatches
        # made by tests take effect.
        call_sniff = _find_sniff()

        if call_sniff is None:
            print(
                "[ERROR] Scapy is not available in this environment."
            )
            return

        self.writer = self._open_writer()

        try:
            call_sniff(
                iface=self.interface,
                filter=self.filter_str,
                prn=self._process_packet
            )

        except KeyboardInterrupt:
            pass

        finally:
            if self.writer is not None:
                self.writer.close()

            print("\n[INFO] Stopping capture...", flush=True)

            self._print_stats()

    def process(self, packet):
        return self._dispatch(packet)

    # ------------------------------------------------------------------
    # Packet callback
    # ------------------------------------------------------------------

    def _process_packet(self, packet):
        if packet is None:
            return

        self._dispatch(packet)

        if self._last_protocol in self.stats:
            self.stats[self._last_protocol] += 1

        if self.verbose:
            self._print_hexdump(packet)

        if self.writer is not None:
            self.writer.write(packet)

    # ------------------------------------------------------------------
    # Protocol dispatch
    # ------------------------------------------------------------------

    def _dispatch(self, packet):
        self._last_protocol = None

        if self.search or _global_search:
            self.searcher.search = self.search
            self.searcher._check_search(packet)

        for processor in self.processors:
            try:
                if not processor.matches(packet):
                    continue

                processor.process(packet)
                self._last_protocol = processor.protocol
                return True

            except Exception:
                continue

        return False

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def _print_stats(self):
        total = sum(self.stats.values())

        print("\n========== PACKET STATISTICS ==========")
        print(f"TCP: {self.stats['TCP']}")
        print(f"UDP: {self.stats['UDP']}")
        print(f"ICMP: {self.stats['ICMP']}")
        print(f"TOTAL: {total}")
        print("=======================================", flush=True)

    # ------------------------------------------------------------------
    # Hexdump
    # ------------------------------------------------------------------

    def _print_hexdump(self, packet):
        global hexdump

        hd = hexdump

        if hd is None:
            all_mod = sys.modules.get("scapy.all")

            if all_mod is not None:
                hd = getattr(all_mod, "hexdump", None)

        if hd is not None:
            hd(packet)


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------

def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="PySniffer - a simple Scapy-based packet sniffer."
    )

    parser.add_argument("-i", "--interface", default=None)
    parser.add_argument("-f", "--filter", default=None)
    parser.add_argument(
        "-w", "--write", default=None, metavar="FILE"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true"
    )
    parser.add_argument(
        "-s", "--search", default=None, metavar="STRING"
    )

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
