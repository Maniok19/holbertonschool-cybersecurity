#!/usr/bin/env python3
import sys
import argparse


def read_stream(file_path: str):
    with open(file_path, "r") as f:
        for line in f:
            yield line

def main():
    parser = argparse.ArgumentParser(prog='log_hunter.py',
                                     description='The program is good',
                                     epilog='End')
    parser.add_argument("file", help='Input file path')
    args = parser.parse_args()
    count = 0

    print("[*] LogHunter - Log Analysis Engine")
    print(f"[*] Reading: {args.file}")
    try:
        for line in read_stream(args.file):
            count += 1
    except FileNotFoundError:
        print(f"[ERROR] File not found: {args.file}")
        print("[!] No data to process. Exiting.")
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied: {args.file}")
        sys.exit(1)
    print(f"[*] Lines read: {count}")

if __name__ == '__main__':
    main()
