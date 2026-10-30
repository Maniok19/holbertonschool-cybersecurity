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


class ScanReport(list):
    """A list of result dicts that also carries report header metadata.

    Iterating / indexing it yields port result dicts (legacy list view).
    Accessing .target / .hostname / .results / .to_dict() yields the
    structured header view used by the refactored reporter.
    """

    def __init__(self, target, hostname, source_ip,
                 start_port, end_port, results):
        normalized = [_normalize_result(r) for r in results]
        super().__init__(normalized)
        self.target = target
        self.hostname = hostname
        self.source_ip = source_ip
        self.start_port = start_port
        self.end_port = end_port
        self.results = normalized

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "hostname": self.hostname,
            "source_ip": self.source_ip,
            "scan": {
                "start_port": self.start_port,
                "end_port": self.end_port,
            },
            "results": self.results,
        }


def build_report(target: str,
                 hostname: str,
                 source_ip: str,
                 start_port: int,
                 end_port: int,
                 results: list) -> ScanReport:
    """Assemble the final report object from scan results."""
    return ScanReport(
        target=target,
        hostname=hostname,
        source_ip=source_ip,
        start_port=start_port,
        end_port=end_port,
        results=results,
    )


def write_report(report, path: str) -> None:
    """Write the report to a JSON file.

    Accepts either a ScanReport or a plain dict; always serializes the
    structured header + flat 'results' list.
    """
    data = report.to_dict() if hasattr(report, "to_dict") else report
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print(f"[*] Report written to {path}")
