#!/usr/bin/env python3
"""Shared constants and helpers for NetProbe."""
import random
import socket
import sys
import time


# Common ports -> service name, used when a service is silent.
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
}

# Ports we treat as web services for deep HTTP inspection.
HTTP_PORTS = {80, 8080, 8000, 8888}

# Known-vulnerable signatures. Matching is case-insensitive substring.
VULNERABLE_SIGNATURES = [
    "vsftpd 2.3.4",
    "apache 2.2.8",
    "proftpd 1.3.3",
    "openssh 7.4",
    "microsoft ftpd",
    "pure-ftpd 1.0.2",
    "nginx/1.4",
]


def parse_port_range(spec):
    """Parse a "start-end" string into a (start, end) tuple of ints."""
    try:
        start_s, end_s = spec.split("-", 1)
        start, end = int(start_s), int(end_s)
    except (ValueError, AttributeError):
        sys.exit("error: invalid port range %r; expected START-END" % spec)

    if not (0 <= start <= 65535 and 0 <= end <= 65535):
        sys.exit("error: port range %r out of bounds (0-65535)" % spec)
    if start > end:
        sys.exit("error: port range %r is reversed (start > end)" % spec)
    return start, end


def guess_service(port):
    """Guess a service name from a well-known port number."""
    return COMMON_PORTS.get(port, "Unknown")


def is_vulnerable_service(service):
    """Return True if a service string matches a vulnerable signature."""
    if not service:
        return False
    lowered = service.lower()
    return any(sig in lowered for sig in VULNERABLE_SIGNATURES)


def check_vulnerability(banner):
    """Flag a banner that matches a known-vulnerable signature."""
    if not banner:
        return ""
    lowered = banner.lower()
    for sig in VULNERABLE_SIGNATURES:
        if sig in lowered:
            return "[VULNERABLE]"
    return ""


def sleep_delay(delay):
    """Sleep before a scan packet (IDS evasion)."""
    if delay > 0:
        print("[DEBUG] Sleeping %ss before next packet..." % delay)
        time.sleep(delay)


def shuffle_ports(ports):
    """Shuffle a list of ports in place (firewall evasion)."""
    random.shuffle(ports)
    return ports


def is_local_ip(ip):
    """Return True if `ip` is an address assigned to a local interface."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((ip, 0))
        return True
    except OSError:
        return False
    finally:
        sock.close()
