#!/usr/bin/env python3
"""JSON report building and output."""
import json

from utils import is_vulnerable_service


def _normalize_result(r: dict) -> dict:
    """Coerce a scan result dict into the canonical report shape."""
    service = r.get("service", "Unknown")
    version = r.get("version", "")
    server_header = r.get("server_header", "")

    if "vulnerable" in r:
        vulnerable = bool(r["vulnerable"])
    else:
        vulnerable = is_vulnerable_service(
            f"{service} {version} {server_header}".strip()
        )

    return {
        "port": r["port"],
        "state": r.get("state", "open"),
        "service": service,
        "version": version,
        "server_header": server_header,
        "vulnerability": "YES" if vulnerable else "NO",
    }


def build_report(target: str,
                 hostname: str,
                 source_ip: str,
                 start_port: int,
                 end_port: int,
                 results: list) -> dict:
    """Assemble the final report dict from scan results."""
    return {
        "target": target,
        "hostname": hostname,
        "source_ip": source_ip,
        "scan": {
            "start_port": start_port,
            "end_port": end_port,
        },
        "results": [_normalize_result(r) for r in results],
    }


def write_report(report: dict, path: str) -> None:
    """Write the report dict to a JSON file."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"[*] Report written to {path}")
