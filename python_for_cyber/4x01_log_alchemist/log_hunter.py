#!/usr/bin/env python3
import sys
import re
import argparse


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


class LogEntry:
    def __init__(self, ip, timestamp, service, message, raw_line):
        self.ip = ip 
        self.timestamp = timestamp
        self.service = service
        self.message = message
        self.raw_line = raw_line


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


if __name__ == '__main__':
    main()
