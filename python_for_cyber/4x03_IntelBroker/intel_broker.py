#!/usr/bin/env python3
"""IntelBroker CLI entry point."""
import argparse
import asyncio
import json

import api_client
import scanner
import utils
from models import TargetDossier


async def build_dossier_async(ip):
    """Populate and return a TargetDossier for the given IP (async)."""
    intel_task = api_client.gather_intel(ip)
    nmap_task = scanner.run_nmap_async(ip)

    (vt_data, shodan_data, abuse_data), nmap_xml = await asyncio.gather(
        intel_task, nmap_task
    )

    dossier = TargetDossier(ip)
    dossier.vt_data = vt_data
    dossier.shodan_data = shodan_data
    dossier.abuse_data = abuse_data
    dossier.nmap_ports = scanner.parse_nmap_xml(nmap_xml)
    return dossier


def build_dossier(ip):
    """Populate and return a TargetDossier for the given IP (sync)."""
    dossier = TargetDossier(ip)
    dossier.vt_data = api_client.query_virustotal(ip)
    dossier.abuse_data = api_client.query_abuseipdb(ip)
    try:
        xml = scanner.run_nmap(ip)
    except (RuntimeError, FileNotFoundError) as exc:
        print("[!] %s" % exc)
        xml = ""
    dossier.nmap_ports = scanner.parse_nmap_xml(xml)
    return dossier


def write_report(dossier, path):
    """Serialize a TargetDossier to a JSON file."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(dossier.to_dict(), fh, indent=2)
    print("[*] Report written to %s" % path)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="intel_broker",
        description="Aggregate intel about an IP from mock APIs and nmap.",
    )
    parser.add_argument("ip", help="Target IPv4 address")
    parser.add_argument(
        "-o", "--output",
        help="Write the dossier to this JSON file (optional)",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Print progress and status messages",
    )
    args = parser.parse_args(argv)

    utils.set_verbose(args.verbose)

    dossier = asyncio.run(build_dossier_async(args.ip))
    print(dossier)

    if args.output:
        write_report(dossier, args.output)
        print("[SUCCESS] Report generated.")

    return dossier


if __name__ == "__main__":
    main()
