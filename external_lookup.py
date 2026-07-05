import os
from dotenv import load_dotenv

load_dotenv(override=True)

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

API_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
REQUEST_TIMEOUT_SECONDS = 5

THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]


def _build_request_body(url: str) -> dict:
    return {
        "client": {
            "clientId": "phishing-url-checker",
            "clientVersion": "1.0.0",
        },
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }


def _skipped_result(reason: str) -> dict:
    """A neutral, non-flagged result used whenever the check can't run."""
    return {
        "name": "External threat intelligence (Google Safe Browsing)",
        "flagged": False,
        "detail": f"Skipped - {reason}",
    }


def check_safe_browsing(url: str) -> dict:
    """
    Query Google Safe Browsing for the given URL.

    Returns a result dict in the same shape as the local checks
    (name/flagged/detail), so it can be merged into the same report and
    scoring pipeline. Never raises - any failure results in a skipped,
    non-flagged result instead of crashing the tool.
    """
    if not REQUESTS_AVAILABLE:
        return _skipped_result("'requests' library is not installed")

    api_key = os.getenv("SAFE_BROWSING_API_KEY")
    if not api_key:
        return _skipped_result("SAFE_BROWSING_API_KEY environment variable not set")

    try:
        response = requests.post(
            API_ENDPOINT,
            params={"key": api_key},
            json=_build_request_body(url),
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
    except requests.exceptions.Timeout:
        return _skipped_result("request timed out")
    except requests.exceptions.ConnectionError:
        return _skipped_result("no internet connection / could not reach API")
    except requests.exceptions.RequestException as exc:
        return _skipped_result(f"request failed ({exc.__class__.__name__})")

    if response.status_code == 403:
        return _skipped_result("invalid or unauthorized API key")
    if response.status_code == 429:
        return _skipped_result("rate limit exceeded")
    if response.status_code != 200:
        return _skipped_result(f"unexpected API response (HTTP {response.status_code})")

    try:
        data = response.json()
    except ValueError:
        return _skipped_result("could not parse API response")

    matches = data.get("matches", [])
    if matches:
        threat_types_found = sorted({m.get("threatType", "UNKNOWN") for m in matches})
        return {
            "name": "External threat intelligence (Google Safe Browsing)",
            "flagged": True,
            "detail": f"Listed as: {', '.join(threat_types_found)}",
        }

    return {
        "name": "External threat intelligence (Google Safe Browsing)",
        "flagged": False,
        "detail": "Not found on Google Safe Browsing threat lists",
    }
