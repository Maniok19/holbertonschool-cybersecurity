#!/usr/bin/env python3
"""Shared helpers and constants for IntelBroker."""
import json
import os
import time


BASE_URL = "http://localhost:5000"
CACHE_FILE = "cache.json"
CACHE_TTL = 3600  # 1 hour, in seconds
MAX_CONCURRENCY = 5
UNAVAILABLE = {"error": "Unavailable"}

VERBOSE = False


def status(message):
    """Print a status line when verbose mode is enabled."""
    if VERBOSE:
        print(message)


def set_verbose(flag):
    """Enable or disable verbose status output."""
    global VERBOSE
    VERBOSE = flag


def is_unavailable(data):
    """Return True if `data` marks the source as unavailable."""
    return isinstance(data, dict) and data.get("error") == "Unavailable"


def load_cache():
    """Load the cache file. Returns {} if missing or corrupt."""
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (ValueError, OSError) as exc:
        print("[!] Could not read cache: %s" % exc)
        return {}


def save_cache(cache):
    """Write the cache dict to disk as JSON."""
    try:
        with open(CACHE_FILE, "w", encoding="utf-8") as fh:
            json.dump(cache, fh, indent=2)
    except OSError as exc:
        print("[!] Could not write cache: %s" % exc)


def cache_get(ip):
    """Return cached intel for `ip` if fresh (< 1 hour), else None."""
    cache = load_cache()
    entry = cache.get(ip)
    if not entry:
        return None
    if time.time() - entry.get("timestamp", 0) > CACHE_TTL:
        return None
    return entry.get("data")


def cache_put(ip, data):
    """Store intel for `ip` in the cache with the current timestamp."""
    cache = load_cache()
    cache[ip] = {"timestamp": time.time(), "data": data}
    save_cache(cache)


def merge_cache(ip, source, new_data):
    """Merge a single source's fresh data into the cached bundle."""
    bundle = cache_get(ip) or {}
    bundle[source] = new_data
    return bundle
