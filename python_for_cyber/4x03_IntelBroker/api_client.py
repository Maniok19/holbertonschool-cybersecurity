#!/usr/bin/env python3
"""Async and sync HTTP clients for IntelBroker."""
import asyncio

import utils


async def fetch_api(session, url, semaphore=None):
    """Async GET a mock-API URL and return parsed JSON.

    On any HTTP error (non-200), connection failure, timeout, or
    invalid JSON, returns {"error": "Unavailable"} so callers can
    proceed without crashing.
    """
    import aiohttp

    if semaphore is not None:
        async with semaphore:
            return await _fetch_api_inner(session, url, aiohttp)
    return await _fetch_api_inner(session, url, aiohttp)


async def _fetch_api_inner(session, url, aiohttp):
    """Do the actual HTTP GET; return UNAVAILABLE on any failure."""
    try:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=5)
        ) as response:
            if response.status != 200:
                print("[!] HTTP %s from %s" % (response.status, url))
                return dict(utils.UNAVAILABLE)
            try:
                return await response.json()
            except (aiohttp.ContentTypeError, ValueError) as exc:
                print("[!] Invalid JSON from %s: %s" % (url, exc))
                return dict(utils.UNAVAILABLE)
    except aiohttp.ClientConnectionError as exc:
        print("[!] Connection error: %s" % exc)
        return dict(utils.UNAVAILABLE)
    except asyncio.TimeoutError as exc:
        print("[!] Timeout: %s" % exc)
        return dict(utils.UNAVAILABLE)


async def _fetch_or_cache(session, ip, source, semaphore):
    """Fetch one API source for `ip`, using the cache when fresh."""
    cached = utils.cache_get(ip)
    if cached is not None:
        return cached.get(source, {})

    labels = {
        "virustotal": "VirusTotal",
        "shodan": "Shodan",
        "abuseipdb": "AbuseIPDB",
    }
    utils.status("[+] Querying %s..." % labels.get(source, source))

    url = "%s/%s/%s" % (utils.BASE_URL, source, ip)
    data = await fetch_api(session, url, semaphore)
    if data and not utils.is_unavailable(data):
        utils.cache_put(ip, utils.merge_cache(ip, source, data))
    return data


async def gather_intel(ip):
    """Query VirusTotal, Shodan, and AbuseIPDB in parallel.

    Caps concurrent in-flight requests at MAX_CONCURRENCY via a
    shared asyncio.Semaphore. A failure from one source does not
    abort the others; the failed source yields UNAVAILABLE.
    """
    cached = utils.cache_get(ip)
    if cached is not None:
        utils.status("[*] Cache hit for %s (age < 1h)" % ip)
        return (
            cached.get("virustotal", {}),
            cached.get("shodan", {}),
            cached.get("abuseipdb", {}),
        )

    try:
        import aiohttp
    except ImportError:
        print("[!] aiohttp not installed; falling back to sync requests")
        vt = _get_json("virustotal/%s" % ip)
        sh = _get_json("shodan/%s" % ip)
        ab = _get_json("abuseipdb/%s" % ip)
        bundle = {"virustotal": vt, "shodan": sh, "abuseipdb": ab}
        if any(v and not utils.is_unavailable(v)
               for v in bundle.values()):
            utils.cache_put(ip, bundle)
        return vt, sh, ab

    semaphore = asyncio.Semaphore(utils.MAX_CONCURRENCY)

    async with aiohttp.ClientSession() as session:
        vt_data, shodan_data, abuse_data = await asyncio.gather(
            _fetch_or_cache(session, ip, "virustotal", semaphore),
            _fetch_or_cache(session, ip, "shodan", semaphore),
            _fetch_or_cache(session, ip, "abuseipdb", semaphore),
        )

    return vt_data, shodan_data, abuse_data


def _get_json(endpoint):
    """Sync GET an endpoint from the mock API and return parsed JSON."""
    try:
        import requests
    except ImportError:
        print("[!] requests not installed; returning empty data")
        return dict(utils.UNAVAILABLE)

    url = "%s/%s" % (utils.BASE_URL, endpoint)
    try:
        response = requests.get(url, timeout=5)
    except requests.exceptions.ConnectionError as exc:
        print("[!] Connection error: %s" % exc)
        return dict(utils.UNAVAILABLE)

    if response.status_code != 200:
        print("[!] HTTP %s from %s"
              % (response.status_code, url))
        return dict(utils.UNAVAILABLE)

    try:
        return response.json()
    except ValueError as exc:
        print("[!] Invalid JSON in response: %s" % exc)
        return dict(utils.UNAVAILABLE)


def query_virustotal(ip):
    """Query the (mock) VirusTotal API, with caching."""
    cached = utils.cache_get(ip)
    if cached is not None and "virustotal" in cached:
        return cached["virustotal"]
    utils.status("[+] Querying VirusTotal...")
    data = _get_json("virustotal/%s" % ip)
    if data and not utils.is_unavailable(data):
        utils.cache_put(ip, utils.merge_cache(ip, "virustotal", data))
    return data


def query_abuseipdb(ip):
    """Query the (mock) AbuseIPDB API, with caching."""
    cached = utils.cache_get(ip)
    if cached is not None and "abuseipdb" in cached:
        return cached["abuseipdb"]
    utils.status("[+] Querying AbuseIPDB...")
    data = _get_json("abuseipdb/%s" % ip)
    if data and not utils.is_unavailable(data):
        utils.cache_put(ip, utils.merge_cache(ip, "abuseipdb", data))
    return data
