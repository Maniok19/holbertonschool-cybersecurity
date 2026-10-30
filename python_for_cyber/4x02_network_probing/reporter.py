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


def build_report(results):
    """Convert raw scan results into the on-disk report list."""
    return [_normalize_result(r) for r in results]


def write_report(report, path):
    """Write the report list to a JSON file."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
    print("[*] Report written to %s" % path)
