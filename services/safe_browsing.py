"""Optional Google Safe Browsing lookup. Disabled by default.

Privacy note: enabling this sends the submitted URL to Google's servers.
The API key is read from the server environment only and is never logged or shown.
"""
import logging
from typing import Any

import requests

log = logging.getLogger(__name__)
API_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
NOT_CONFIGURED = ("External threat-database check is not configured. "
                  "The current assessment uses local heuristic checks only.")
NO_MATCH = ("No matching known threat was returned by the enabled database. "
            "This does not mean the URL is safe.")


def check_url(url: str, enabled: bool, api_key: str) -> dict[str, Any]:
    """Return {"status": "disabled"|"not_configured"|"match"|"no_match"|"error", "message": str}."""
    if not enabled or not api_key:
        return {"status": "not_configured", "message": NOT_CONFIGURED}
    body = {
        "client": {"clientId": "phishguard-educational", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    try:
        resp = requests.post(API_ENDPOINT, params={"key": api_key}, json=body, timeout=5)
        resp.raise_for_status()
        matches = resp.json().get("matches", [])
    except (requests.RequestException, ValueError) as exc:
        # Log only the exception type: messages can contain the request URL (and the key).
        log.warning("Safe Browsing lookup failed: %s", type(exc).__name__)
        return {"status": "error",
                "message": "The external threat-database check could not be completed. Local checks still apply."}
    if matches:
        kinds = sorted({m.get("threatType", "UNKNOWN") for m in matches})
        return {"status": "match", "message": "A known threat match was returned: " + ", ".join(kinds) + "."}
    return {"status": "no_match", "message": NO_MATCH}
