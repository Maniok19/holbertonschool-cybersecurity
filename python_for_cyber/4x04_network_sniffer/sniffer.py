#!/usr/bin/env python3

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


def main():
    print("[INFO] PySniffer initialized.")
    try:
        sniff(prn=packet_handler)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[INFO] Stopping capture...", flush=True)


if __name__ == "__main__":
    main()
