#!/usr/bin/env python3
"""IntelBroker: query mock APIs and run live nmap scans."""
import subprocess

import requests


BASE_URL = "http://localhost:5000"


def _get_json(endpoint):
    """GET an endpoint from the mock API and return parsed JSON.

    Returns the parsed dict on success, or an empty dict on
    connection failure, non-200 status, or invalid JSON.
    """
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
    """Run 'nmap -p 22,80 <IP> -oX -' and return the raw XML stdout.

    Raises RuntimeError if nmap exits non-zero.
    """
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


if __name__ == "__main__":
    print(query_virustotal("1.2.3.4"))
    print(query_abuseipdb("1.2.3.4"))
    print(run_nmap("127.0.0.1")[:200])
