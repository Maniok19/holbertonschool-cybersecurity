#!/usr/bin/env python3
"""JSON report building and output for NetProbe."""
import json

from utils import is_vulnerable_service


def _normalize_result(r):
    """Coerce a scan result dict into the canonical report shape."""
    service = r.get("service", "Unknown")
    version = r.get("version", "")
    server_header = r.get("server_header", "")

    if "vulnerable" in r:
        vulnerable = bool(r["vulnerable"])
    else:
        vulnerable = is_vulnerable_service(
            ("%s %s %s" % (service, version, server_header)).strip()
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
    String keys and attribute access yield the structured header view.
    """

    def __init__(self, target, hostname, source_ip, start_port, end_port,
                 results):
        normalized = [_normalize_result(r) for r in results]
        super().__init__(normalized)
        self.target = target
        self.hostname = hostname
        self.source_ip = source_ip
        self.start_port = start_port
        self.end_port = end_port
        self.results = normalized

    def _dict(self):
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

    def __getitem__(self, key):
        if isinstance(key, str):
            return self._dict()[key]
        return list.__getitem__(self, key)

    def get(self, key, default=None):
        return self._dict().get(key, default)

    def keys(self):
        return self._dict().keys()

    def to_dict(self):
        return self._dict()


def build_report(target, hostname, source_ip, start_port, end_port,
                 results):
    """Assemble the final report object from scan results."""
    return ScanReport(
        target=target,
        hostname=hostname,
        source_ip=source_ip,
        start_port=start_port,
        end_port=end_port,
        results=results,
    )


def write_report(report, path):
    """Write the report to a JSON file."""
    data = report.to_dict() if hasattr(report, "to_dict") else report
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print("[*] Report written to %s" % path)
