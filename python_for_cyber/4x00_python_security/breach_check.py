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
    read_file(args.file)

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

if __name__ == "__main__":
    main()
