#!/usr/bin/env python3
import sys
import argparse

def read_stream(file_path: str):
    try:
        with open(file_path, "r") as f:
            for line in f:
                yield line
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        sys.exit(1)
    except PermissionError:
        print(f"Permission denied: {file_path}")
        sys.exit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='log_hunter.py',
                                     description='The program is good',
                                     epilog='End')
    parser.add_argument("file", help='Input file path')
    args = parser.parse_args()