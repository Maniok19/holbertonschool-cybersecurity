#!/usr/bin/env python3
"""JSON report building and output."""
import json


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


def write_report(report: dict, path: str) -> None:
    """Write the report dict to a JSON file."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print(f"[*] Report written to {path}")
