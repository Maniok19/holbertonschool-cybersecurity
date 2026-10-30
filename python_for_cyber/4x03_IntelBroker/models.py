#!/usr/bin/env python3
"""Data models for IntelBroker."""
import datetime


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
