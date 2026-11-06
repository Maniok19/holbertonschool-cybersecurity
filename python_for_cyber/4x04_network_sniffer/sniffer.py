#!/usr/bin/env python3

from scapy.all import sniff


def packet_handler(packet):
    print(packet.summary())


def main():
    print("[INFO] PySniffer initialized.")
    sniff(count=5, prn=packet_handler)


if __name__ == "__main__":
    main()
