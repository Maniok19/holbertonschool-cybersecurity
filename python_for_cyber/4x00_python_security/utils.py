#!/usr/bin/env python3
import re
import logging
import hashlib
import sys

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
LINE_RE = re.compile(r"^([^:]+):(.+)$")

# Populated at startup from config.ini by the main script
SALT = ""
MIN_LENGTH = 0
COMMON_LIST = set()


def read_file(filename: str):
    try:
        with open(filename, "r") as f:
            for line in f:
                yield line
    except FileNotFoundError:
        logging.error(f"File not found: {filename}")
        sys.exit(1)
    except PermissionError:
        logging.error(f"Permission denied: {filename}")
        sys.exit(1)


def configure(salt: str, min_length: int, common_list: set) -> None:
    """Inject config values loaded by the main script."""
    global SALT, MIN_LENGTH, COMMON_LIST
    SALT = salt
    MIN_LENGTH = min_length
    COMMON_LIST = common_list


def hash_password(password: str, salt: str) -> str:
    data = (password + salt).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def check_policy(password: str) -> str:
    if len(password) < MIN_LENGTH:
        return "WEAK"
    if not any(c.isdigit() for c in password):
        return "WEAK"
    if password.lower() in COMMON_LIST:
        return "WEAK"
    return "COMPLIANT"


def validate_line(line: str) -> bool:
    match = LINE_RE.match(line)
    if not match:
        return False
    email = match.group(1)
    return bool(EMAIL_RE.match(email))


def clean_data(lines) -> "generator":
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        logging.debug(f"Starting regex check on line {i}...")
        if not validate_line(stripped):
            continue
        email, password = stripped.split(":", 1)
        status = check_policy(password)
        logging.debug(f"Line {i}: policy check -> {status}")
        if status == "WEAK":
            logging.warning(f"Line {i}: weak password detected for {email}")
            hashed = hash_password(password, SALT)
            yield f"{email}:{hashed}"
        else:
            yield f"{email}:{status}"
