import socket
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


def main():
    print("NetProbe v1.0 initialized...")


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
    """Flag a banner that matches a known-vulnerable signature.

    Args:
        banner: The service banner string (e.g. "vsftpd 2.3.4").

    Returns:
        "[VULNERABLE]" if the banner contains any known-bad signature,
        otherwise an empty string.
    """
    if not banner:
        return ""

    lowered = banner.lower()
    for sig in VULNERABLE_SIGNATURES:
        if sig in lowered:
            return "[VULNERABLE]"
    return ""


def get_service_info(ip: str, port: int) -> str:
    """Return a best-effort service name for an open port.

    Tries the real banner first; if the service is silent, falls back
    to guessing from the port number. Appends "[VULNERABLE]" when the
    banner matches a known-bad signature.
    """
    banner = get_banner(ip, port)

    if banner and banner != "Unknown":
        service = banner.splitlines()[0]
    else:
        guess = guess_service(port)
        service = f"{guess} (Guessed)" if guess != "Unknown" else "Unknown"

    status = check_vulnerability(banner if banner != "Unknown" else "")
    if status:
        return f"{service} {status}"
    return service


def _probe_port(ip: str, port: int):
    """Worker: check a single port and return its result dict, or None."""
    if not check_port(ip, port):
        return None

    service = get_service_info(ip, port)
    return {"port": port, "service": service}


def scan_ports(ip: str,
               start_port: int,
               end_port: int,
               max_workers: int = 50) -> list:
    """Scan a range of TCP ports on a single host, concurrently."""
    print(f"Scanning {ip} from {start_port} to {end_port}...")

    results = []
    ports = range(start_port, end_port + 1)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(_probe_port, ip, port): port for port in ports
        }

        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                result = future.result()
            except Exception as exc:
                print(f"[!] Port {port} probe failed: {exc}")
                continue
            if result is not None:
                print(f"[+] Port {result['port']} Open: {result['service']}")
                results.append(result)

    results.sort(key=lambda r: r["port"])
    return results


if __name__ == "__main__":
    main()
