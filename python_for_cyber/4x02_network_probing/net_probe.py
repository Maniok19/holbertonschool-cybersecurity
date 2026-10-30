#!/usr/bin/env python3
"""NetProbe CLI entry point."""
import argparse
import sys

from reporter import build_report, write_report
from scanner import resolve_hostname, scan_ports, scan_udp  # noqa: F401
from utils import is_local_ip, parse_port_range


def main(argv=None):
    args = parse_args(argv)
    start_port, end_port = parse_port_range(args.ports)

    print("NetProbe v1.0 initialized...")

    hostname = resolve_hostname(args.target)
    print(f"Target: {args.target} ({hostname})")

    source_ip = args.interface
    if source_ip:
        if not is_local_ip(source_ip):
            sys.exit(
                f"error: {source_ip!r} is not a local interface address"
            )
        print(f"[INFO] Scanning from source IP: {source_ip}")

    results = scan_ports(
        args.target,
        start_port,
        end_port,
        delay=args.delay,
        randomize=args.random,
        source_ip=source_ip,
    )

    report = build_report(
        target=args.target,
        hostname=hostname,
        source_ip=source_ip,
        start_port=start_port,
        end_port=end_port,
        results=results,
    )

    if args.output:
        write_report(report, args.output)

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
    parser.add_argument(
        "-i", "--interface",
        metavar="LOCAL_IP",
        help="Bind outbound sockets to this local interface IP "
             "(e.g. 192.168.1.50)",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    main()
