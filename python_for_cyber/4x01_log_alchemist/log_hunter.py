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
    for line in read_stream(args.file):
        if parse_apache_line(line):
            apache_count += 1
        elif parse_syslog_line(line):
            syslog_count += 1

    print(f"[*] Apache lines:  {apache_count}")
    print(f"[*] Syslog lines:  {syslog_count}")
    print(f"[*] Total parsed: {apache_count + syslog_count}")


if __name__ == '__main__':
    main()
