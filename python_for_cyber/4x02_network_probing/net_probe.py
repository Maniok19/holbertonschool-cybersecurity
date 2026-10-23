#!/usr/bin/env python3
import argparse
import json
import random
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


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

# Known-vulnerable signatures. Matching is case-insensitive substring.
VULNERABLE_SIGNATURES = [
    "vsftpd 2.3.4",        # CVE-2011-2523 (backdoor)
    "apache 2.2.8",        # Old Apache, multiple CVEs
    "proftpd 1.3.3",       # CVE-2010-4221
    "openssh 7.4",         # Informational — flag old SSH builds
    "microsoft ftpd",      # Anonymous access / weak auth
    "pure-ftpd 1.0.2",     # CVE-2011-0411
    "nginx/1.4",           # Old nginx, multiple CVEs
]


def main(argv=None):
    args = parse_args(argv)

    start_port, end_port = parse_port_range(args.ports)

    print("NetProbe v1.0 initialized...")
    results = scan_ports(
        args.target,
        start_port,
        end_port,
        delay=args.delay,
        randomize=args.random,
    )

    report = [
        {
            "port": r["port"],
            "state": "open",
            "service": r["service"],
            "vulnerability": (
                "YES" if is_vulnerable_service(r.get("service", "")) else "NO"
            ),
        }
        for r in results
    ]

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"[*] Report written to {args.output}")

    return report


def parse_args(argv=None):
    """Build and parse the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="net_probe",
        description="Scan a TCP port range on a target host and report.",
    )
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IPv4 address (e.g. 192.168.1.1)",
    )
    parser.add_argument(
        "-p", "--ports",
        default="1-1024",
        help='Port range as "start-end" (default: "1-1024")',
    )
    parser.add_argument(
        "-o", "--output",
        help="Write results to this JSON file (optional)",
    )
    parser.add_argument(
        "-d", "--delay",
        type=float,
        default=0.0,
        help="Seconds to sleep between scan attempts (evade IDS; default 0)",
    )
    parser.add_argument(
        "-r", "--random",
        action="store_true",
        help="Shuffle the port order before scanning (evade firewalls)",
    )
    return parser.parse_args(argv)


def parse_port_range(spec: str):
    """Parse a "start-end" string into a (start, end) tuple of ints."""
    try:
        start_s, end_s = spec.split("-", 1)
        start, end = int(start_s), int(end_s)
    except (ValueError, AttributeError):
        sys.exit(f"error: invalid port range {spec!r}; expected START-END")

    if not (0 <= start <= 65535 and 0 <= end <= 65535):
        sys.exit(f"error: port range {spec!r} out of bounds (0-65535)")
    if start > end:
        sys.exit(f"error: port range {spec!r} is reversed (start > end)")
    return start, end


def check_port(ip: str, port: int) -> bool:
    """Check if a TCP port on the given IP is open."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1.0)
    try:
        sock.connect((ip, port))
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    finally:
        sock.close()


def ping_sweep(subnet: str) -> list:
    """Scan port 80 on every host in a /24 subnet."""
    base = subnet.split("/")[0]
    prefix = ".".join(base.split(".")[:3])

    live = []
    for host in range(1, 255):
        ip = f"{prefix}.{host}"
        if check_port(ip, 80):
            live.append(ip)
    return live


def get_banner(ip: str, port: int) -> str:
    """Grab a service banner from an open TCP port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2.0)
    try:
        sock.connect((ip, port))
        try:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        except OSError:
            pass

        data = sock.recv(1024)
        if not data:
            return "Unknown"
        return data.decode("utf-8", errors="replace").strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return "Unknown"
    finally:
        sock.close()


def guess_service(port: int) -> str:
    """Guess a service name from a well-known port number."""
    return COMMON_PORTS.get(port, "Unknown")


def check_vulnerability(banner: str) -> str:
    """Flag a banner that matches a known-vulnerable signature."""
    if not banner:
        return ""

    lowered = banner.lower()
    for sig in VULNERABLE_SIGNATURES:
        if sig in lowered:
            return "[VULNERABLE]"
    return ""


def is_vulnerable_service(service: str) -> bool:
    """Return True if a service string matches a vulnerable signature."""
    if not service:
        return False
    lowered = service.lower()
    return any(sig in lowered for sig in VULNERABLE_SIGNATURES)


def get_service_info(ip: str, port: int) -> str:
    """Return a best-effort service name for an open port."""
    banner = get_banner(ip, port)

    if banner and banner != "Unknown":
        service = banner.splitlines()[0]
    else:
        guess = guess_service(port)
        service = f"{guess} (Guessed)" if guess != "Unknown" else "Unknown"

    if is_vulnerable_service(banner if banner != "Unknown" else ""):
        return f"{service} [VULNERABLE]"
    return service


def _probe_port(ip: str, port: int, delay: float = 0.0):
    """Worker: check a single port and return a result dict, or None."""
    if delay > 0:
        print(f"[DEBUG] Sleeping {delay}s before next packet...")
        time.sleep(delay)

    if not check_port(ip, port):
        return None

    banner = get_banner(ip, port)

    if banner and banner != "Unknown":
        service = banner.splitlines()[0]
    else:
        guess = guess_service(port)
        service = f"{guess} (Guessed)" if guess != "Unknown" else "Unknown"

    vuln_banner = banner if banner != "Unknown" else ""
    vulnerable = is_vulnerable_service(vuln_banner)

    return {
        "port": port,
        "service": service,
        "vulnerable": vulnerable,
    }


def scan_ports(ip: str,
               start_port: int,
               end_port: int,
               max_workers: int = 50,
               delay: float = 0.0,
               randomize: bool = False) -> list:
    """Scan a range of TCP ports on a single host, concurrently."""
    ports = list(range(start_port, end_port + 1))

    if randomize:
        random.shuffle(ports)
        print("Scanning ports randomly...")
    else:
        print(f"Scanning {ip} from {start_port} to {end_port}...")

    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(_probe_port, ip, port, delay): port
            for port in ports
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
            except Exception as exc:
                print(f"[!] Port {port} probe failed: {exc}")
                continue
            if result is None:
                continue

            service = result.get("service", "Unknown")
            vulnerable = result.get(
                "vulnerable", is_vulnerable_service(service)
            )

            if vulnerable:
                tag = " [VULNERABLE]"
            else:
                tag = ""

            print(
                f"[+] Port {result['port']} Open: {service}{tag}"
            )
            results.append(
                {"port": result["port"],
                 "service": service,
                 "vulnerable": vulnerable}
            )

    results.sort(key=lambda r: r["port"])
    return results


def scan_udp(ip: str, port: int):
    """ergjsdfgvljgv"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        sock.sendto(b"", (ip, port))
        try:
            data, _ = sock.recvfrom
            return True
        except socket.timeout:
            return True
        except ConnectionRefusedError:
            return False
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    finally:
        sock.close()


if __name__ == "__main__":
    main()
