#!/usr/bin/env python3

from scapy.all import sniff, IP, TCP, UDP, ICMP


def packet_handler(packet):
    if (packet.haslayer(IP)):
        src = packet[IP].src
        dst = packet[IP].dst

        if packet.haslayer(TCP):
            print(f"[TCP] {src} -> {dst}")
        elif packet.haslayer(UDP):
            print(f"[UDP] {src} -> {dst}")
        elif packet.haslayer(ICMP):
            print(f"[ICMP] {src} -> {dst}")


def main():
    print("[INFO] PySniffer initialized.")
    sniff(count=5, prn=packet_handler)


if __name__ == "__main__":
    main()
