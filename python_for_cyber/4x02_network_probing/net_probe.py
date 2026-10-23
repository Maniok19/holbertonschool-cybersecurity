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
