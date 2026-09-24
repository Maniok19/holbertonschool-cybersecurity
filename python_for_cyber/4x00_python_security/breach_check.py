#!/usr/bin/env python3
import argparse
import sys

def main():
    parser = argparse.ArgumentParser(prog='Main',
                                     description='The program is good',
                                     epilog='End')
    parser.add_argument("--file","-f", help='Input file path', required=True)
    parser.add_argument("--verbose","-v", help='Print debug')
    parser.add_argument("--output","-o", help='Output report file path')
    args = parser.parse_args()


    print("BreachCheck v1.0 startup...")
    data = read_file(args.file)
    data_clean = clean_data(data)
    print(data_clean)

def read_file(filename: str) -> list:
    try:
        with open(filename, "r") as f:
            return f.readlines()
    except FileNotFoundError:
        print(f"[ERROR] File not found: {filename}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"[ERROR] Permission denied: {filename}", file=sys.stderr)
        sys.exit(1)

def clean_data(lines: list) -> list:
    cleaned = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        cleaned.append(stripped)
    return cleaned

if __name__ == "__main__":
    main()
