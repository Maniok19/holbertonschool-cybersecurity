#!/usr/bin/env python3
import argparse
import json
import random
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 6379: "Redis",
    8080: "HTTP-Alt",
}

HTTP_PORTS = {80, 8080, 8000, 8888}

VULNERABLE_SIGNATURES = [
    "vsftpd 2.3.4", "apache 2.2.8", "proftpd 1.3.3",
    "openssh 7.4", "microsoft ftpd", "pure-ftpd 1.0.2", "nginx/1.4",
]


def main(argv=None):
    args = parse_args(argv)
    start_port, end_port = parse_port_range(args.ports)

    print("NetProbe v1.0 initialized...")
    hostname = resolve_hostname(args.target)
    print(f"Target: {args.target} ({hostname})")

    source_ip = args.interface
    if source_ip:
        if not is_local_ip(source_ip):
            sys.exit(f"error: {source_ip!r} is not a local interface address")
        print(f"[INFO] Scanning from source IP: {source_ip}")

    results = scan_ports(
        args.target, start_port, end_port,
        delay=args.delay, randomize=args.random, source_ip=source_ip,
    )

    report = {
        "target": args.target,
        "hostname": hostname,
        "source_ip": source_ip,
        "scan": {"start_port": start_port, "end_port": end_port},
        "results": [
            {
                "port": r["port"],
                "state": "open",
                "service": r["service"],
                "version": r.get("version", ""),
                "server_header": r.get("server_header", ""),
                "vulnerability": "YES" if r["vulnerable"] else "NO",
            }
            for r in results
        ],
    }

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(f"[*] Report written to {args.output}")

    return report


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="net_probe",
        description="Scan a TCP port range on a target host and report.",
    )
    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--ports", default="1-1024")
    parser.add_argument("-o", "--output")
    parser.add_argument("-d", "--delay", type=float, default=0.0)
    parser.add_argument("-r", "--random", action="store_true")
    parser.add_argument("-i", "--interface", metavar="LOCAL_IP")
    return parser.parse_args(argv)


def parse_port_range(spec: str):
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


def resolve_hostname(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return "unknown"


def is_local_ip(ip: str) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((ip, 0))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def make_socket(source_ip: str = None) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if source_ip:
        sock.bind((source_ip, 0))
    return sock


def check_port(ip: str, port: int, source_ip: str = None) -> bool:
    try:
        sock = make_socket(source_ip)
    except OSError as exc:
        print(f"[!] Cannot bind to {source_ip}: {exc}")
        return False
    sock.settimeout(1.0)
    try:
        sock.connect((ip, port))
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    finally:
        sock.close()


def ping_sweep(subnet: str, source_ip: str = None) -> list:
    base = subnet.split("/")[0]
    prefix = ".".join(base.split(".")[:3])
    live = []
    for host in range(1, 255):
        ip = f"{prefix}.{host}"
        if check_port(ip, 80, source_ip):
            live.append(ip)
    return live


def parse_server_header(response: str) -> str:
    """Extract the value of the 'Server' header from a raw HTTP response."""
    for line in response.splitlines():
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        if name.strip().lower() == "server":
            return value.strip()
    return ""


def http_probe(ip: str, port: int, source_ip: str = None) -> dict:
    """Send GET / HTTP/1.1 with Host header; extract Server header."""
    result = {"server_header": "", "raw": ""}

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if source_ip:
        sock.bind((source_ip, 0))
    sock.settimeout(3.0)

    try:
        sock.connect((ip, port))
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
        sock.sendall(request.encode("ascii"))

        chunks = []
        total = 0
        while total < 65536:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)

        raw = b"".join(chunks).decode("utf-8", errors="replace")
        result["raw"] = raw
        result["server_header"] = parse_server_header(raw)
        return result
    except (socket.timeout, ConnectionRefusedError, OSError):
        return result
    finally:
        sock.close()


probe_http = http_probe
get_http_headers = http_probe


def get_banner(ip: str, port: int, source_ip: str = None) -> str:
    """Grab a service banner from an open TCP port.

    For HTTP ports, sends a real 'GET / HTTP/1.1' request and returns
    the full response (so the Server header can be parsed out).
    For other ports, falls back to a simple HEAD probe.
    """
    try:
        sock = make_socket(source_ip)
    except OSError:
        return "Unknown"
    sock.settimeout(3.0)

    try:
        sock.connect((ip, port))

        if port in HTTP_PORTS:
            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
        else:
            request = "HEAD / HTTP/1.0\r\n\r\n"

        try:
            sock.sendall(request.encode("ascii"))
        except OSError:
            pass

        chunks = []
        total = 0
        while total < 65536:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)

        if not chunks:
            return "Unknown"
        return b"".join(chunks).decode("utf-8", errors="replace").strip()
    except (socket.timeout, ConnectionRefusedError, OSError):
        return "Unknown"
    finally:
        sock.close()


def guess_service(port: int) -> str:
    return COMMON_PORTS.get(port, "Unknown")


def check_vulnerability(banner: str) -> str:
    if not banner:
        return ""
    lowered = banner.lower()
    for sig in VULNERABLE_SIGNATURES:
        if sig in lowered:
            return "[VULNERABLE]"
    return ""


def is_vulnerable_service(service: str) -> bool:
    if not service:
        return False
    lowered = service.lower()
    return any(sig in lowered for sig in VULNERABLE_SIGNATURES)


def get_service_info(ip: str, port: int, source_ip: str = None) -> str:
    banner = get_banner(ip, port, source_ip)
    if banner and banner != "Unknown":
        service = banner.splitlines()[0]
    else:
        guess = guess_service(port)
        service = f"{guess} (Guessed)" if guess != "Unknown" else "Unknown"
    if is_vulnerable_service(banner if banner != "Unknown" else ""):
        return f"{service} [VULNERABLE]"
    return service


def inspect_service(ip: str, port: int, source_ip: str = None) -> dict:
    """Identify a service. HTTP ports get a real GET + Server header parse."""
    service = "Unknown"
    version = ""
    server_header = ""

    if port in HTTP_PORTS:
        probe = http_probe(ip, port, source_ip)
        server_header = probe["server_header"]
        raw = probe["raw"]

        if raw:
            status = raw.splitlines()[0] if raw else ""
            http_version = ""
            if "HTTP/" in status:
                http_version = status.split("/", 1)[1].split(" ", 1)[0]

            service = "HTTP"
            if server_header:
                version = server_header
            elif http_version:
                version = f"HTTP/{http_version}"
        else:
            guess = guess_service(port)
            service = guess if guess != "Unknown" else "HTTP"
    else:
        banner = get_banner(ip, port, source_ip)
        if banner and banner != "Unknown":
            service = banner.splitlines()[0]
        else:
            guess = guess_service(port)
            service = f"{guess} (Guessed)" if guess != "Unknown" else "Unknown"

    vulnerable = is_vulnerable_service(
        f"{service} {version} {server_header}".strip()
    )
    return {
        "port": port,
        "service": service,
        "version": version,
        "server_header": server_header,
        "vulnerable": vulnerable,
    }


def _probe_port(ip: str, port: int, delay: float = 0.0, source_ip: str = None):
    if delay > 0:
        print(f"[DEBUG] Sleeping {delay}s before next packet...")
        time.sleep(delay)
    if not check_port(ip, port, source_ip):
        return None
    return inspect_service(ip, port, source_ip)


def format_result(result: dict) -> str:
    service = result.get("service", "Unknown")
    version = result.get("version", "")
    label = f"{service} ({version})" if version else service
    if result.get("vulnerable"):
        label += " [VULNERABLE]"
    return f"[+] Port {result['port']}: {label}"


def scan_ports(ip: str, start_port: int, end_port: int,
               max_workers: int = 50, delay: float = 0.0,
               randomize: bool = False, source_ip: str = None) -> list:
    ports = list(range(start_port, end_port + 1))
    if randomize:
        random.shuffle(ports)
        print("Scanning ports randomly...")
    else:
        print(f"Scanning {ip} from {start_port} to {end_port}...")

    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(_probe_port, ip, port, delay, source_ip): port
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
            print(format_result(result))
            results.append(result)

    results.sort(key=lambda r: r["port"])
    return results


def scan_udp(ip: str, port: int, source_ip: str = None) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if source_ip:
        try:
            sock.bind((source_ip, 0))
        except OSError:
            sock.close()
            return False
    sock.settimeout(2.0)
    try:
        sock.sendto(b"", (ip, port))
        try:
            result = sock.recvfrom(1024)
        except socket.timeout:
            return True
        except ConnectionRefusedError:
            return False
        except OSError:
            return False
        return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False
    finally:
        sock.close()


if __name__ == "__main__":
    main()
