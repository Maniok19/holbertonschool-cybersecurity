#!/usr/bin/env python3
"""IntelBroker: query a local mock VirusTotal/Shodan/AbuseIPDB API."""
import requests


BASE_URL = "http://localhost:5000"


def query_virustotal(ip):
    """Query the (mock) VirusTotal API for an IP's reputation.

    Returns the parsed JSON payload as a dict on success.
    Returns an empty dict on connection failure or non-200 status.
    """
    url = "%s/virustotal/%s" % (BASE_URL, ip)
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


if __name__ == "__main__":
    print(query_virustotal("1.2.3.4"))
