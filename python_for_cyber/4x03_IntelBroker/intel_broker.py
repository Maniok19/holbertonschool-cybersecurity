#!/usr/bin/env python3
"""IntelBroker: build a target dossier from mock APIs and nmap."""
import argparse
import asyncio
import datetime
import json
import os
import subprocess
import time
import xml.etree.ElementTree as ET


BASE_URL = "http://localhost:5000"
CACHE_FILE = "cache.json"
CACHE_TTL = 3600  # 1 hour, in seconds
MAX_CONCURRENCY = 5
UNAVAILABLE = {"error": "Unavailable"}

VERBOSE = False


def status(message):
    """Print a status line when verbose mode is enabled."""
    if VERBOSE:
        print(message)


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


def _load_cache():
    """Load the cache file. Returns {} if missing or corrupt."""
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (ValueError, OSError) as exc:
        print("[!] Could not read cache: %s" % exc)
        return {}


def _save_cache(cache):
    """Write the cache dict to disk as JSON."""
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, indent=2)
    except OSError as exc:
        print("[!] Could not write cache: %s" % exc)


def _cache_get(ip):
    """Return cached intel for `ip` if fresh (< 1 hour), else None."""
    cache = _load_cache()
    entry = cache.get(ip)
    if not entry:
        return None
    if time.time() - entry.get("timestamp", 0) > CACHE_TTL:
        return None
    return entry.get("data")


def _cache_put(ip, data):
    """Store intel for `ip` in the cache with the current timestamp."""
    cache = _load_cache()
    cache[ip] = {"timestamp": time.time(), "data": data}
    _save_cache(cache)


def _is_unavailable(data):
    """Return True if `data` marks the source as unavailable."""
    return isinstance(data, dict) and data.get("error") == "Unavailable"


async def fetch_api(session, url, semaphore=None):
    """Async GET a mock-API URL and return parsed JSON.

    On any HTTP error (non-200), connection failure, timeout, or
    invalid JSON, returns {"error": "Unavailable"} so callers can
    proceed without crashing.
    """
    import aiohttp

    if semaphore is not None:
        async with semaphore:
            return await _fetch_api_inner(session, url, aiohttp)
    return await _fetch_api_inner(session, url, aiohttp)


async def _fetch_api_inner(session, url, aiohttp):
    """Do the actual HTTP GET; return UNAVAILABLE on any failure."""
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=5)
        ) as response:
            if response.status != 200:
                print("[!] HTTP %s from %s" % (response.status, url))
                return dict(UNAVAILABLE)
            try:
                return await response.json()
            except (aiohttp.ContentTypeError, ValueError) as exc:
                print("[!] Invalid JSON from %s: %s" % (url, exc))
                return dict(UNAVAILABLE)
    except aiohttp.ClientConnectionError as exc:
        print("[!] Connection error: %s" % exc)
        return dict(UNAVAILABLE)
    except asyncio.TimeoutError as exc:
        print("[!] Timeout: %s" % exc)
        return dict(UNAVAILABLE)


async def _fetch_or_cache(session, ip, source, semaphore):
    """Fetch one API source for `ip`, using the cache when fresh."""
    cached = _cache_get(ip)
    if cached is not None:
        return cached.get(source, {})

    labels = {
        "virustotal": "VirusTotal",
        "shodan": "Shodan",
        "abuseipdb": "AbuseIPDB",
    }
    status("[+] Querying %s..." % labels.get(source, source))

    url = "%s/%s/%s" % (BASE_URL, source, ip)
    data = await fetch_api(session, url, semaphore)
    if data and not _is_unavailable(data):
        _cache_put(ip, _merge_cache(ip, source, data))
    return data


def _merge_cache(ip, source, new_data):
    """Merge a single source's fresh data into the cached bundle."""
    bundle = _cache_get(ip) or {}
    bundle[source] = new_data
    return bundle


async def gather_intel(ip):
    """Query VirusTotal, Shodan, and AbuseIPDB in parallel.

    Caps concurrent in-flight requests at MAX_CONCURRENCY via a
    shared asyncio.Semaphore. A failure from one source does not
    abort the others; the failed source yields UNAVAILABLE.
    """
    cached = _cache_get(ip)
    if cached is not None:
        status("[*] Cache hit for %s (age < 1h)" % ip)
        return (
            cached.get("virustotal", {}),
            cached.get("shodan", {}),
            cached.get("abuseipdb", {}),
        )

    try:
        import aiohttp
    except ImportError:
        print("[!] aiohttp not installed; falling back to sync requests")
        status("[+] Querying VirusTotal...")
        vt = _get_json("virustotal/%s" % ip)
        status("[+] Querying Shodan...")
        sh = _get_json("shodan/%s" % ip)
        status("[+] Querying AbuseIPDB...")
        ab = _get_json("abuseipdb/%s" % ip)
        bundle = {"virustotal": vt, "shodan": sh, "abuseipdb": ab}
        if any(v and not _is_unavailable(v) for v in bundle.values()):
            _cache_put(ip, bundle)
        return vt, sh, ab

    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)

    async with aiohttp.ClientSession() as session:
        vt_data, shodan_data, abuse_data = await asyncio.gather(
            _fetch_or_cache(session, ip, "virustotal", semaphore),
            _fetch_or_cache(session, ip, "shodan", semaphore),
            _fetch_or_cache(session, ip, "abuseipdb", semaphore),
        )

    return vt_data, shodan_data, abuse_data


async def run_nmap_async(ip):
    """Run 'nmap -p 22,80 <IP> -oX -' asynchronously.

    Returns the raw XML stdout as a str. Returns '' if nmap fails
    or is not installed.
    """
    status("[+] Launching nmap...")
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

    status("[+] Nmap finished.")
    return stdout.decode("utf-8", "replace")


def _get_json(endpoint):
    """Sync GET an endpoint from the mock API and return parsed JSON."""
    try:
        import requests
    except ImportError:
        print("[!] requests not installed; returning empty data")
        return dict(UNAVAILABLE)

    url = "%s/%s" % (BASE_URL, endpoint)
    try:
        response = requests.get(url, timeout=5)
    except requests.exceptions.ConnectionError as exc:
        print("[!] Connection error: %s" % exc)
        return dict(UNAVAILABLE)

    if response.status_code != 200:
        print("[!] HTTP %s from %s"
              % (response.status_code, url))
        return dict(UNAVAILABLE)

    try:
        return response.json()
    except ValueError as exc:
        print("[!] Invalid JSON in response: %s" % exc)
        return dict(UNAVAILABLE)


def query_virustotal(ip):
    """Query the (mock) VirusTotal API, with caching."""
    cached = _cache_get(ip)
    if cached is not None and "virustotal" in cached:
        return cached["virustotal"]
    status("[+] Querying VirusTotal...")
    data = _get_json("virustotal/%s" % ip)
    if data and not _is_unavailable(data):
        _cache_put(ip, _merge_cache(ip, "virustotal", data))
    return data


def query_abuseipdb(ip):
    """Query the (mock) AbuseIPDB API, with caching."""
    cached = _cache_get(ip)
    if cached is not None and "abuseipdb" in cached:
        return cached["abuseipdb"]
    status("[+] Querying AbuseIPDB...")
    data = _get_json("abuseipdb/%s" % ip)
    if data and not _is_unavailable(data):
        _cache_put(ip, _merge_cache(ip, "abuseipdb", data))
    return data


def run_nmap(ip):
    """Run 'nmap -p 22,80 <IP> -oX -' and return the raw XML stdout."""
    status("[+] Launching nmap...")
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

    status("[+] Nmap finished.")
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
    global VERBOSE

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

    VERBOSE = args.verbose

    dossier = asyncio.run(build_dossier_async(args.ip))
    print(dossier)

    if args.output:
        write_report(dossier, args.output)
        print("[SUCCESS] Report generated.")

    return dossier


if __name__ == "__main__":
    main()
