#!/usr/bin/env python3

from scapy.all import sniff, IP, TCP, UDP, ICMP


def packet_handler(packet):
    if (packet.haslayer(IP)):
        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            flags = packet[TCP].flags
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"[TCP] {src}:{sport} -> {dst}:{dport} | Flags: {flags}")
        elif packet.haslayer(UDP):
            print(f"[UDP] {src} -> {dst}")
        elif packet.haslayer(ICMP):
            print(f"[ICMP] {src} -> {dst}")


def main():
    print("[INFO] PySniffer initialized.")
    try:
        sniff(prn=packet_handler)
    except KeyboardInterrupt:
        print("\n[INFO] Stopping capture...")


if __name__ == "__main__":
    main()
