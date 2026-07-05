#!/usr/bin/env python3
"""
url_checker.py - Stage 1: Basic URL structure analysis for phishing detection.

Checks a single URL for common structural red flags associated with
phishing links. This is Stage 1 of the project plan (URL structure
analysis) - no scoring, no typosquatting, no external APIs yet.
"""

import argparse
import re
from urllib.parse import urlparse

from typosquatting import check_typosquatting

# Common URL shortener domains
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "adf.ly", "shorte.st", "rebrand.ly",
}

# Keywords often abused in phishing domains/paths
SUSPICIOUS_KEYWORDS = {
    "secure", "verify", "account", "update", "login",
    "signin", "confirm", "banking", "password", "webscr",
}

# Matches a bare IPv4 address, e.g. 192.168.1.1
IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

LONG_URL_THRESHOLD = 75  # characters
MANY_SUBDOMAINS_THRESHOLD = 3
MANY_HYPHENS_THRESHOLD = 2


def normalize_url(url: str) -> str:
    """Ensure the URL has a scheme so urlparse works correctly."""
    if not re.match(r"^[a-zA-Z]+://", url):
        return "http://" + url
    return url


def check_length(url: str) -> dict:
    length = len(url)
    flagged = length > LONG_URL_THRESHOLD
    return {
        "name": "URL length",
        "flagged": flagged,
        "detail": f"{length} characters (threshold: {LONG_URL_THRESHOLD})",
    }


def check_ip_address(hostname: str) -> dict:
    flagged = bool(IPV4_PATTERN.match(hostname or ""))
    return {
        "name": "IP address instead of domain",
        "flagged": flagged,
        "detail": hostname if flagged else "No IP address used as host",
    }


def check_subdomain_count(hostname: str) -> dict:
    if not hostname:
        return {"name": "Subdomain count", "flagged": False, "detail": "N/A"}
    parts = hostname.split(".")
    subdomain_count = max(len(parts) - 2, 0)
    flagged = subdomain_count >= MANY_SUBDOMAINS_THRESHOLD
    return {
        "name": "Subdomain count",
        "flagged": flagged,
        "detail": f"{subdomain_count} subdomain(s) (threshold: {MANY_SUBDOMAINS_THRESHOLD})",
    }


def check_at_symbol(url: str) -> dict:
    flagged = "@" in url
    return {
        "name": "'@' symbol in URL",
        "flagged": flagged,
        "detail": "Found '@', which can hide the real destination" if flagged else "Not found",
    }


def check_hyphens(hostname: str) -> dict:
    hyphen_count = (hostname or "").count("-")
    flagged = hyphen_count >= MANY_HYPHENS_THRESHOLD
    return {
        "name": "Excessive hyphens in domain",
        "flagged": flagged,
        "detail": f"{hyphen_count} hyphen(s) (threshold: {MANY_HYPHENS_THRESHOLD})",
    }


def check_suspicious_keywords(url: str) -> dict:
    lowered = url.lower()
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lowered]
    flagged = len(found) > 0
    return {
        "name": "Suspicious keywords",
        "flagged": flagged,
        "detail": f"Found: {', '.join(found)}" if flagged else "None found",
    }


def check_shortener(hostname: str) -> dict:
    flagged = (hostname or "").lower() in SHORTENER_DOMAINS
    return {
        "name": "URL shortener service",
        "flagged": flagged,
        "detail": hostname if flagged else "Not a known shortener",
    }


def analyze_url(raw_url: str) -> list:
    """Run all Stage 1 checks on a single URL and return a list of results."""
    url = normalize_url(raw_url.strip())
    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    return [
        check_length(url),
        check_ip_address(hostname),
        check_subdomain_count(hostname),
        check_at_symbol(url),
        check_hyphens(hostname),
        check_suspicious_keywords(url),
        check_shortener(hostname),
        check_typosquatting(hostname),
    ]


def print_report(url: str, results: list) -> None:
    flagged_count = sum(1 for r in results if r["flagged"])
    print(f"\nURL: {url}")
    print("-" * 60)
    for r in results:
        mark = "[FLAGGED]" if r["flagged"] else "[ok]     "
        print(f"{mark} {r['name']}: {r['detail']}")
    print("-" * 60)
    print(f"Total flags raised: {flagged_count} / {len(results)}\n")

