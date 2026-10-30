#!/usr/bin/env python3
"""JSON report building and output."""
import json

from utils import is_vulnerable_service


def build_report(target: str,
                 hostname: str,
                 source_ip: str,
                 start_port: int,
                 end_port: int,
                 results: list) -> dict:
    """Assemble the final report dict from scan results.

    Each result is expected to be a dict with at least a 'port' key.
    Missing optional keys ('service', 'version', 'server_header',
    'vulnerable') are defaulted, and 'vulnerable' is derived from the
    service/version strings when not supplied.
    """
    reported = []
    for r in results:
        service = r.get("service", "Unknown")
        version = r.get("version", "")
        server_header = r.get("server_header", "")

        if "vulnerable" in r:
            vulnerable = bool(r["vulnerable"])
        else:
            vulnerable = is_vulnerable_service(
                f"{service} {version} {server_header}".strip()
            )

        reported.append({
            "port": r["port"],
            "state": r.get("state", "open"),
            "service": service,
            "version": version,
            "server_header": server_header,
            "vulnerability": "YES" if vulnerable else "NO",
        })

    return {
        "target": target,
        "hostname": hostname,
        "source_ip": source_ip,
        "scan": {
            "start_port": start_port,
            "end_port": end_port,
        },
        "results": reported,
    }


def write_report(report: dict, path: str) -> None:
    """Write the report dict to a JSON file."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"[*] Report written to {path}")
