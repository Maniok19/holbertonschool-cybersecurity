#!/usr/bin/env python3
"""Mock VirusTotal / Shodan / AbuseIPDB API for local testing."""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import random


class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        ip = self.path.split('/')[-1]

        if "virustotal" in self.path:
            score = random.randint(0, 10)
            data = {
                "ip": ip,
                "reputation_score": score,
                "malicious": score > 5,
            }
        elif "shodan" in self.path:
            ports = [80, 443, 22, 8080]
            data = {
                "ip": ip,
                "ports": random.sample(ports, k=random.randint(1, 3)),
                "os": "Linux",
                "isp": "CloudNet",
            }
        elif "abuseipdb" in self.path:
            data = {
                "ip": ip,
                "abuse_confidence_score": random.randint(0, 100),
                "reports": random.randint(0, 50),
            }
        else:
            data = {"error": "Unknown API"}

        self.wfile.write(json.dumps(data).encode())


if __name__ == "__main__":
    server = HTTPServer(('localhost', 5000), MockHandler)
    print("Mock API Server running on port 5000...")
    server.serve_forever()
