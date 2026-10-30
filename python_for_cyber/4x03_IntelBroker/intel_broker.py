#!/usr/bin/env python3
"""IntelBroker: query mock APIs and run live nmap scans."""
import subprocess
import xml.etree.ElementTree as ET

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


if __name__ == "__main__":
    print(query_virustotal("1.2.3.4"))
    print(query_abuseipdb("1.2.3.4"))
    xml = run_nmap("127.0.0.1")
    print(parse_nmap_xml(xml))
