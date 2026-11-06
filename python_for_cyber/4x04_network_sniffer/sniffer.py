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

    def _raw_payload(self, packet):
        candidates = []
        try:
            raw = packet["Raw"]
            load = getattr(raw, "load", None)
            if load is not None:
                candidates.append(load)
            elif isinstance(raw, (bytes, bytearray)):
                candidates.append(bytes(raw))
        except Exception as exc:
            print(f"[DBG] packet['Raw'] failed: {exc!r}", flush=True)
        load = getattr(packet, "load", None)
        if load is not None:
            candidates.append(load)
        payload = getattr(packet, "payload", None)
        if isinstance(payload, (bytes, bytearray)):
            candidates.append(bytes(payload))
        print(f"[DBG] _raw_payload candidates: {candidates!r}", flush=True)
        for data in candidates:
            if isinstance(data, (bytes, bytearray)):
                return bytes(data)
            if isinstance(data, str):
                return data.encode("utf-8", errors="replace")
        return None

    def _search_payload(self, packet):
        print(f"[DBG] _search_payload search={self.search!r}", flush=True)
        if not self.search:
            return
        payload = self._raw_payload(packet)
        print(f"[DBG] extracted payload={payload!r}", flush=True)
        if payload is None:
            return
        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            return
        print(f"[DBG] decoded text={text!r}", flush=True)
        if self.search in text:
            print("[ALERT] Payload Match found!", flush=True)


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
        self._search_payload(packet)


class UDPProcessor(PacketProcessor):
    protocol = "UDP"
    layer_name = "UDP"
    requires = ("sport", "dport")
    excludes = ("flags",)

    def process(self, packet):
        src = getattr(packet, "src", "?")
        dst = getattr(packet, "dst", "?")
        print(f"[UDP] {src} -> {dst}")
        self._search_payload(packet)


class ICMPProcessor(PacketProcessor):
    protocol = "ICMP"
    layer_name = "ICMP"
    requires = ("type", "code")
    excludes = ("sport", "dport")

    def process(self, packet):
        src = getattr(packet, "src", "?")
        dst = getattr(packet, "dst", "?")
        print(f"[ICMP] {src} -> {dst}")
        self._search_payload(packet)


# ------------------------------------------------------------------ sniffer


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
        print(f"[DBG] Sniffer init search={search!r}", flush=True)

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
        print(f"[DBG] start() search={self.search!r}", flush=True)
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
        print(f"[DBG] _process_packet called pkt={repr(packet)[:80]}",
              flush=True)
        if packet is None:
            return
        self._dispatch(packet)
        if self.verbose:
            self._print_hexdump(packet)
        if self.writer is not None:
            self.writer.write(packet)

    def _dispatch(self, packet):
        print(f"[DBG] _dispatch search={self.search!r} "
              f"nproc={len(self.processors)}", flush=True)
        for processor in self.processors:
            try:
                processor.search = self.search
            except Exception:
                pass
            matcher = getattr(processor, "matches", None)
            if callable(matcher):
                try:
                    matched = matcher(packet)
                except Exception as exc:
                    print(f"[DBG] {type(processor).__name__}.matches "
                          f"raised {exc!r}", flush=True)
                    continue
                print(f"[DBG] {type(processor).__name__}.matches -> "
                      f"{matched}", flush=True)
                if not matched:
                    continue
            try:
                processor.process(packet)
            except Exception as exc:
                print(f"[DBG] {type(processor).__name__}.process raised "
                      f"{exc!r}", flush=True)
            return True
        print("[DBG] no processor handled packet", flush=True)
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
    args = parse_args(argv)
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
