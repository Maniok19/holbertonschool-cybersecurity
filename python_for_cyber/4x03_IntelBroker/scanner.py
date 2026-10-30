#!/usr/bin/env python3
"""Nmap wrapper for IntelBroker."""
import asyncio
import subprocess
import xml.etree.ElementTree as ET

import utils


async def run_nmap_async(ip):
    """Run 'nmap -p 22,80 <IP> -oX -' asynchronously.

    Returns the raw XML stdout as a str. Returns '' if nmap fails
    or is not installed.
    """
    utils.status("[+] Launching nmap...")
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

    utils.status("[+] Nmap finished.")
    return stdout.decode("utf-8", "replace")


def run_nmap(ip):
    """Run 'nmap -p 22,80 <IP> -oX -' and return the raw XML stdout."""
    utils.status("[+] Launching nmap...")
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

    utils.status("[+] Nmap finished.")
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
