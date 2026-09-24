#!/usr/bin/env python3
import argparse
import sys
import logging
import configparser

from utils import hash_password, clean_data, validate_line, configure


def load_config(path: str = "config.ini") -> configparser.ConfigParser:
    config = configparser.ConfigParser()
    if not config.read(path):
        logging.error("Config file missing")
        sys.exit(1)
    return config


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


def main():
    parser = argparse.ArgumentParser(prog='Main',
                                     description='The program is good',
                                     epilog='End')
    parser.add_argument("--file", "-f", help='Input file path', required=True)
    parser.add_argument("--verbose", "-v", action="store_true", help='Print debug')
    parser.add_argument("--output", "-o", help='Output report file path')
    args = parser.parse_args()

    setup_logging()
    config = load_config()

    salt = config["SECURITY"]["Salt"]
    min_length = config.getint("SECURITY", "MinLength")
    common_list = {p.strip().lower()
                   for p in config["SECURITY"]["CommonList"].split(",")}
    configure(salt, min_length, common_list)

    logging.info("BreachCheck v1.0 startup...")
    data = read_file(args.file)
    data_clean = clean_data(data)
    logging.info(f"Processing file... {len(data_clean)} valid entries")


if __name__ == "__main__":
    main()