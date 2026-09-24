#!/usr/bin/env python3
import argparse
import sys
import re
import logging

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
LINE_RE = re.compile(r"^([^:]+):(.+)$")


def setup_logging():
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    console.setFormatter(fmt)

    file_handler = logging.FileHandler("breach_check.log")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(fmt)

    logger.addHandler(console)
    logger.addHandler(file_handler)


def main():
    parser = argparse.ArgumentParser(prog='Main',
                                     description='The program is good',
                                     epilog='End')
    parser.add_argument("--file", "-f", help='Input file path', required=True)
    parser.add_argument("--verbose", "-v", action="store_true", help='Print debug')
    parser.add_argument("--output", "-o", help='Output report file path')
    args = parser.parse_args()

    setup_logging()

    logging.info("BreachCheck v1.0 startup...")
    data = read_file(args.file)
    data_clean = clean_data(data)
    logging.info(f"Processing file... {len(data_clean)} valid entries")


def read_file(filename: str) -> list:
    try:
        with open(filename, "r") as f:
            return f.readlines()
    except FileNotFoundError:
        logging.error(f"File not found: {filename}")
        sys.exit(1)
    except PermissionError:
        logging.error(f"Permission denied: {filename}")
        sys.exit(1)


def clean_data(lines: list) -> list:
    cleaned = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        logging.debug(f"Starting regex check on line {i}...")
        if not validate_line(stripped):
            continue
        cleaned.append(stripped)
    return cleaned


def validate_line(line: str) -> bool:
    match = LINE_RE.match(line)
    if not match:
        return False
    email = match.group(1)
    return bool(EMAIL_RE.match(email))


if __name__ == "__main__":
    main()