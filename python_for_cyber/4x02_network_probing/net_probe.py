#!/usr/bin/env python3
import socket


def main():
    print("NetProbe v1.0 initialized...")


def check_port(ip: str, port: int) -> bool:
    """Check if a TCP port on the given IP is open.

    Args:
        ip: Target IPv4 address as a string.
        port: Target TCP port number.

    Returns:
        True if the connection succeeds, False on connection refused,
        timeout, or any socket error.
    """
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
    """Check if a TCP port on the given IP is open."""
    base = subnet.split("/")[0]
    prefix = ".".join(base.split(".")[:3])

    live = []
    for host in range(1, 255):  # .1 through .254 inclusive
        ip = f"{prefix}.{host}"
        if check_port(ip, 80):
            live.append(ip)
    return live


def get_banner(ip: str, port: int) -> str:
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
            except Exception as exc:  # defensive: worker should not raise
                print(f"[!] Port {port} probe failed: {exc}")
                continue
            if result is not None:
                print(f"[+] Port {result['port']} Open: {result['service']}")
                results.append(result)

    results.sort(key=lambda r: r["port"])
    return results


if (__name__ == "__main__"):
    main()
