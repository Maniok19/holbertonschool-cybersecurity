#!/usr/bin/env python3
"""IntelBroker: build a target dossier from mock APIs and nmap."""
import argparse
import asyncio
import datetime
import json
import subprocess
import xml.etree.ElementTree as ET


BASE_URL = "http://localhost:5000"


class TargetDossier:
    """Holds aggregated intelligence about a single target IP."""

    def __init__(self, ip=None):
        self.ip = ip
        self.vt_data = {}
        self.abuse_data = {}
        self.shodan_data = {}
        self.nmap_ports = []

    def __str__(self):
        vt_score = self.vt_data.get("reputation_score", "n/a")
        vt_mal = self.vt_data.get("malicious", "n/a")
        abuse_score = self.abuse_data.get("abuse_confidence_score", "n/a")
        abuse_reports = self.abuse_data.get("reports", "n/a")
        shodan_ports = self.shodan_data.get("ports", "n/a")
        ports = self.nmap_ports if self.nmap_ports else "none"
        return (
            "=== Dossier for %s ===\n"
            "VirusTotal: reputation=%s malicious=%s\n"
            "AbuseIPDB:  confidence=%s reports=%s\n"
            "Shodan:     ports=%s\n"
            "Nmap:       open ports=%s"
            % (self.ip, vt_score, vt_mal, abuse_score, abuse_reports,
               shodan_ports, ports)
        )

    def to_dict(self):
        """Return the dossier as a JSON-serializable dict."""
        return {
            "target": self.ip,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "intelligence": {
                "virustotal": self.vt_data,
                "shodan": self.shodan_data,
                "abuseipdb": self.abuse_data,
                "nmap": {
                    "open_ports": self.nmap_ports,
                },
            },
        }


async def fetch_api(session, url):
    """Async GET a mock-API URL and return parsed JSON."""
    import aiohttp

    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=5)
        ) as response:
            if response.status != 200:
                print("[!] Unexpected status: %s" % response.status)
                return {}
            try:
                return await response.json()
            except (aiohttp.ContentTypeError, ValueError) as exc:
                print("[!] Invalid JSON in response: %s" % exc)
                return {}
    except aiohttp.ClientConnectionError as exc:
        print("[!] Connection error: %s" % exc)
        return {}
    except asyncio.TimeoutError as exc:
        print("[!] Timeout: %s" % exc)
        return {}


async def gather_intel(ip):
    """Query VirusTotal, Shodan, and AbuseIPDB in parallel.

    Falls back to sync requests (sequentially) if aiohttp is not
    installed, and to empty dicts if requests is also unavailable.
    """
    try:
        import aiohttp
    except ImportError:
        print("[!] aiohttp not installed; falling back to sync requests")
        return (
            _get_json("virustotal/%s" % ip),
            _get_json("shodan/%s" % ip),
            _get_json("abuseipdb/%s" % ip),
        )

    urls = (
        "%s/virustotal/%s" % (BASE_URL, ip),
        "%s/shodan/%s" % (BASE_URL, ip),
        "%s/abuseipdb/%s" % (BASE_URL, ip),
    )

    async with aiohttp.ClientSession() as session:
        vt_data, shodan_data, abuse_data = await asyncio.gather(
            fetch_api(session, urls[0]),
            fetch_api(session, urls[1]),
            fetch_api(session, urls[2]),
        )

    return vt_data, shodan_data, abuse_data


async def run_nmap_async(ip):
    """Run 'nmap -p 22,80 <IP> -oX -' asynchronously.

    Returns the raw XML stdout as a str. Returns '' if nmap fails
    or is not installed.
    """
    try:
        process = await asyncio.create_subprocess_exec(
            "nmap", "-p", "22,80", ip, "-oX", "-",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        print("[!] nmap not found; skipping live scan")
        return ""

    stdout, stderr = await process.communicate()

    if process.returncode != 0:
        err = stderr.decode("utf-8", "replace").strip()
        print("[!] nmap failed (exit %s): %s"
              % (process.returncode, err))
        return ""

    return stdout.decode("utf-8", "replace")


def _get_json(endpoint):
    """Sync GET an endpoint from the mock API and return parsed JSON."""
    try:
        import requests
    except ImportError:
        print("[!] requests not installed; returning empty data")
        return {}

    url = "%s/%s" % (BASE_URL, endpoint)
    try:
        response = requests.get(url, timeout=5)
    except requests.exceptions.ConnectionError as exc:
        print("[!] Connection error: %s" % exc)
        return {}

    if response.status_code != 200:
        print("[!] Unexpected status: %s" % response.status_code)
        return {}

    try:
        return response.json()
    except ValueError as exc:
        print("[!] Invalid JSON in response: %s" % exc)
        return {}


def query_virustotal(ip):
    """Query the (mock) VirusTotal API for an IP's reputation."""
    return _get_json("virustotal/%s" % ip)


def query_abuseipdb(ip):
    """Query the (mock) AbuseIPDB API for an IP's abuse reports."""
    return _get_json("abuseipdb/%s" % ip)


def run_nmap(ip):
    """Run 'nmap -p 22,80 <IP> -oX -' and return the raw XML stdout."""
    command = ["nmap", "-p", "22,80", ip, "-oX", "-"]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "nmap failed (exit %s): %s"
            % (result.returncode, result.stderr.strip())
        )

    return result.stdout


def parse_nmap_xml(xml_data):
    """Parse nmap XML output and return a list of open port numbers."""
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as exc:
        print("[!] Could not parse nmap XML: %s" % exc)
        return []

    open_ports = []
    for port in root.iter("port"):
        state_el = port.find("state")
        if state_el is None:
            continue
        if state_el.get("state") != "open":
            continue
        portid = port.get("portid")
        if portid is None:
            continue
        open_ports.append(int(portid))

    return open_ports


def build_dossier(ip):
    """Populate and return a TargetDossier for the given IP (sync)."""
    dossier = TargetDossier(ip)
    dossier.vt_data = query_virustotal(ip)
    dossier.abuse_data = query_abuseipdb(ip)
    try:
        xml = run_nmap(ip)
    except (RuntimeError, FileNotFoundError) as exc:
        print("[!] %s" % exc)
        xml = ""
    dossier.nmap_ports = parse_nmap_xml(xml)
    return dossier


async def build_dossier_async(ip):
    """Populate and return a TargetDossier for the given IP (async)."""
    intel_task = gather_intel(ip)
    nmap_task = run_nmap_async(ip)

    (vt_data, shodan_data, abuse_data), nmap_xml = await asyncio.gather(
        intel_task, nmap_task
    )

    dossier = TargetDossier(ip)
    dossier.vt_data = vt_data
    dossier.shodan_data = shodan_data
    dossier.abuse_data = abuse_data
    dossier.nmap_ports = parse_nmap_xml(nmap_xml)
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
    args = parser.parse_args(argv)

    dossier = asyncio.run(build_dossier_async(args.ip))
    print(dossier)

    if args.output:
        write_report(dossier, args.output)

    return dossier


if __name__ == "__main__":
    main()
