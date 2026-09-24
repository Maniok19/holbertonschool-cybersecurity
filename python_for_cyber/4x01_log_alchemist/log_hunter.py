#!/usr/bin/env python3
import sys
import re
import argparse
from collections import Counter, defaultdict
from datetime import datetime


APACHE_RE = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)'
    r' \S+ \S+ '
    r'\[(?P<date>[^\]]+)\]'
    r' "(?P<method>\S+) (?P<path>\S+)(?: [^"]*)?"'
    r' (?P<status>\d{3})'
    r' (?P<size>\d+|-)'
)

SYSLOG_RE = re.compile(
    r'(?P<date>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})'
    r' (?P<host>\S+)'
    r' (?P<process>\w+\[\d+\])'
    r': (?P<message>.*)'
)

IP_RE = re.compile(r'(\d+\.\d+\.\d+\.\d+)')

GEOIP_DB = {'1.2.3.4': 'US', '5.6.7.8': 'RU'}

BOT_SIGNATURES = ['sqlmap', 'nikto', 'curl', 'python']

BLACKLIST = {'10.0.0.1', '192.168.1.66'}

SQLI_PATTERNS = [
    re.compile(r"union\s+select", re.IGNORECASE),
    re.compile(r"'\s*or\s*'?\d+'?\s*=\s*'?\d+", re.IGNORECASE),
    re.compile(r"--"),
    re.compile(r";\s*drop\s+table", re.IGNORECASE),
    re.compile(r"'\s*or\s*1\s*=\s*1", re.IGNORECASE),
]

XSS_PATTERNS = [
    re.compile(r"<script", re.IGNORECASE),
    re.compile(r"javascript:", re.IGNORECASE),
    re.compile(r"onload\s*=", re.IGNORECASE),
    re.compile(r"onerror\s*=", re.IGNORECASE),
    re.compile(r"<img[^>]+src", re.IGNORECASE),
]


class LogEntry:
    def __init__(self, ip='', timestamp='', service='', message='',
                 raw_line='', method='', path='', status=None,
                 user_agent='', size=None, source='', **kwargs):
        self.ip = ip
        self.timestamp = timestamp
        self.service = service
        self.message = message
        self.raw_line = raw_line
        self.method = method
        self.path = path
        self.status = status
        self.user_agent = user_agent
        self.size = size
        self.source = source
        for key, value in kwargs.items():
            setattr(self, key, value)


def parse_timestamp(ts: str):
    if not ts:
        return None
    ts = ts.strip()
    # Apache: 11/Feb/2026:14:01:24 +0000
    for fmt in ("%d/%b/%Y:%H:%M:%S %z", "%d/%b/%Y:%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt)
        except ValueError:
            pass
    # Syslog: Feb 11 14:31:24 (no year -> assume 2026)
    try:
        dt = datetime.strptime(ts, "%b %d %H:%M:%S")
        return dt.replace(year=2026)
    except ValueError:
        return None


def detect_burst(entries, window_seconds=60, threshold=10):
    windows = defaultdict(list)
    for entry in entries:
        ip = getattr(entry, 'ip', None)
        if not ip:
            continue
        ts = parse_timestamp(getattr(entry, 'timestamp', '') or '')
        if ts is None:
            continue

        times = windows[ip]
        times.append(ts)
        # drop timestamps older than the window
        cutoff = ts.timestamp() - window_seconds
        while times and times[0].timestamp() < cutoff:
            times.pop(0)

        if len(times) >= threshold:
            yield {
                'ip': ip,
                'count': len(times),
                'window': window_seconds,
                'alert_type': 'BURST',
            }
            times.clear()  # reset so we don't re-alert every subsequent entry


def detect_bruteforce(entries):
    failures = Counter()
    for entry in entries:
        ip = getattr(entry, 'ip', None)
        if not ip:
            continue
        status = getattr(entry, 'status', None)
        try:
            status = int(status) if status is not None else None
        except (ValueError, TypeError):
            status = None
        message = getattr(entry, 'message', '') or ''
        if status == 401 or 'Failed password' in message:
            failures[ip] += 1

    for ip, count in failures.items():
        if count > 5:
            yield {'ip': ip, 'count': count, 'alert_type': 'BRUTE_FORCE'}


def detect_xss(log_entry):
    if getattr(log_entry, 'attack_type', None) == 'SQLi':
        return False
    fields = (
        getattr(log_entry, 'path', '') or '',
        getattr(log_entry, 'message', '') or '',
        getattr(log_entry, 'raw_line', '') or '',
    )
    haystack = ' '.join(fields)
    for pattern in XSS_PATTERNS:
        if pattern.search(haystack):
            log_entry.attack_type = 'XSS'
            return True
    return False


def detect_sqli(log_entry):
    fields = (
        getattr(log_entry, 'path', '') or '',
        getattr(log_entry, 'message', '') or '',
        getattr(log_entry, 'raw_line', '') or '',
    )
    haystack = ' '.join(fields)
    for pattern in SQLI_PATTERNS:
        if pattern.search(haystack):
            log_entry.attack_type = 'SQLi'
            return True
    return False


def check_threat_intel(log_entry):
    ip = getattr(log_entry, 'ip', None)
    if ip in BLACKLIST:
        log_entry.alert_level = 'HIGH'
    else:
        log_entry.alert_level = 'LOW'
    return log_entry.alert_level


def analyze_user_agent(log_entry):
    fields = (
        getattr(log_entry, 'user_agent', '') or '',
        getattr(log_entry, 'message', '') or '',
        getattr(log_entry, 'raw_line', '') or '',
    )
    haystack = ' '.join(fields).lower()
    log_entry.is_bot = any(sig in haystack for sig in BOT_SIGNATURES)
    return log_entry.is_bot


def enrich_ip(log_entry):
    ip = getattr(log_entry, "ip", None)
    country = GEOIP_DB.get(ip, "UNKNOWN")
    setattr(log_entry, "country", country)
    return country != "UNKNOWN"


def filter_logs(stream, status_codes=[404, 500]):
    for entry in stream:
        status = getattr(entry, 'status', None)
        if status in status_codes:
            yield entry


def normalize_entry(parsed_dict, log_type, raw_line='') -> LogEntry:
    if parsed_dict is None:
        return None

    if log_type == 'apache':
        entry = LogEntry(
            ip=parsed_dict.get('ip', ''),
            timestamp=parsed_dict.get('date', ''),
            service='http',
            message=parsed_dict.get('path', ''),
            raw_line=raw_line,
        )
        entry.method = parsed_dict.get('method', '')
        entry.path = parsed_dict.get('path', '')
        try:
            entry.status = int(parsed_dict.get('status', 0))
        except (ValueError, TypeError):
            entry.status = 0
        entry.user_agent = parsed_dict.get('user_agent', '')
        entry.size = parsed_dict.get('size', None)
        return entry

    if log_type == 'syslog':
        message = parsed_dict.get('message', '')
        m = IP_RE.search(message)
        ip = m.group(1) if m else ''
        entry = LogEntry(
            ip=ip,
            timestamp=parsed_dict.get('date', ''),
            service='ssh',
            message=message,
            raw_line=raw_line,
        )
        return entry

    return None


def read_stream(file_path: str):
    try:
        with open(file_path, "r") as f:
            for line in f:
                yield line
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        print("[!] No data to process. Exiting.")
        sys.exit(1)


def parse_apache_line(line: str):
    m = APACHE_RE.search(line)
    if not m:
        return None
    return m.groupdict()


def parse_syslog_line(line: str):
    m = SYSLOG_RE.search(line)
    if not m:
        return None
    return m.groupdict()


def main():
    parser = argparse.ArgumentParser(prog='log_hunter.py',
                                     description='The program is good',
                                     epilog='End')
    parser.add_argument("file", help='Input file path')
    args = parser.parse_args()

    print("[*] LogHunter - Log Analysis Engine")
    print(f"[*] Reading: {args.file}")

    apache_count = 0
    syslog_count = 0

    entries = []
    print("--- Parsing ---")
    sample = None
    for line in read_stream(args.file):
        parsed = parse_apache_line(line)
        if parsed:
            apache_count += 1
            entry = normalize_entry(parsed, 'apache', line)
        else:
            parsed = parse_syslog_line(line)
            if parsed:
                syslog_count += 1
                entry = normalize_entry(parsed, 'syslog', line)
            else:
                continue
        entries.append(entry)
        if sample is None:
            sample = entry

    print(f"[*] Apache lines:  {apache_count}")
    print(f"[*] Syslog lines:  {syslog_count}")
    print(f"[*] Total parsed: {apache_count + syslog_count}")

    if sample:
        print("[*] Sample entry:")
        extra = ""
        if sample.service == 'http':
            extra = f" | status={sample.status} | path={sample.path}"
        print(f"    ip={sample.ip} | service={sample.service}{extra}")

    print("--- Filtering ---")
    suspicious = sum(1 for _ in filter_logs(entries, [404, 500]))
    print(f"[*] Suspicious (404, 500): {suspicious}")

    print("--- Enrichment ---")
    known = 0
    bots = 0
    for entry in entries:
        if enrich_ip(entry):
            known += 1
        if analyze_user_agent(entry):
            bots += 1
    print(f"[*] GeoIP: {len(entries)} entries enriched ({known} known IPs)")
    print(f"[*] Bots detected: {bots}")

    print("--- Threat Intelligence ---")
    high = 0
    for entry in entries:
        if check_threat_intel(entry) == 'HIGH':
            high += 1
    print(f"[*] HIGH alerts: {high} entries from blacklisted IPs")

    print("--- Attack Detection ---")
    sqli = 0
    xss = 0
    for entry in entries:
        if detect_sqli(entry):
            sqli += 1
        elif detect_xss(entry):
            xss += 1
    print(f"[*] SQLi attempts: {sqli}")
    print(f"[*] XSS attempts:  {xss}")

    print("--- Brute Force ---")
    alerts = list(detect_bruteforce(entries))
    print(f"[*] BRUTE_FORCE alerts: {len(alerts)}")
    for alert in sorted(alerts, key=lambda a: a['count'], reverse=True):
        print(f"    {alert['ip']}: {alert['count']} failures")

    print("--- Burst Detection ---")
    bursts = list(detect_burst(entries))
    print(f"[*] BURST alerts: {len(bursts)}")
    for alert in bursts:
        print(
            f"    {alert['ip']}: {alert['count']} requests "
            f"in {alert['window']}s window"
        )


if __name__ == '__main__':
    main()
