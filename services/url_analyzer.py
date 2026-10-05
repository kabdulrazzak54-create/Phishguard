"""URL analyzer: validates a URL string and extracts features from its TEXT only.

IMPORTANT: nothing in this file ever connects to the submitted URL.
We only split the text into parts (scheme, host, path ...) and measure them.
"""
import ipaddress
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import tldextract
import validators

# Offline extractor: uses the public-suffix list bundled with tldextract (no network call).
_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "verification", "secure", "account", "update",
    "password", "otp", "bank", "wallet", "payment", "reward", "gift", "free",
    "urgent", "alert", "support", "confirm", "unlock", "bonus", "invoice",
    "kyc", "refund",
]

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "rebrand.ly", "shorturl.at", "ow.ly",
}

MAX_URL_LENGTH = 2048
_PERCENT_RE = re.compile(r"%[0-9a-fA-F]{2}")


def validate_url(raw: str) -> tuple[bool, str, str]:
    """Check that `raw` is a well-formed http/https URL.

    Returns (is_valid, cleaned_url, error_message).
    Valid syntax does NOT mean the website is safe.
    """
    cleaned = (raw or "").strip()
    if not cleaned:
        return False, "", "Please enter a URL."
    if len(cleaned) > MAX_URL_LENGTH:
        return False, "", f"URL is too long (maximum {MAX_URL_LENGTH} characters)."
    if re.search(r"[\s\x00-\x1f\x7f]", cleaned):
        return False, "", "URL must not contain spaces or control characters."
    try:
        parts = urlsplit(cleaned)
        _ = parts.port  # raises ValueError for an invalid port
    except ValueError:
        return False, "", "This URL is malformed."
    if parts.scheme.lower() not in ("http", "https"):
        return False, "", "Only http:// and https:// URLs are accepted."
    if not parts.hostname:
        return False, "", "The URL has no hostname."
    if validators.url(cleaned) is not True:
        return False, "", "This does not look like a valid URL."
    return True, cleaned, ""


def _is_ip(host: str) -> bool:
    """Return True if `host` is an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def analyze_url(url: str) -> dict[str, Any]:
    """Extract features from an already-validated URL. Pure text analysis.

    Raises ValueError if the URL is invalid.
    """
    ok, cleaned, error = validate_url(url)
    if not ok:
        raise ValueError(error)

    parts = urlsplit(cleaned)
    host = (parts.hostname or "").lower()
    is_ip = _is_ip(host)

    if is_ip:
        registered_domain, subdomain_count = host, 0
    else:
        ext = _EXTRACTOR(host)
        # tldextract >= 5.2 renamed registered_domain; support both names.
        registered_domain = (getattr(ext, "top_domain_under_public_suffix", None) or ext.registered_domain) or host
        subdomain_count = len([p for p in ext.subdomain.split(".") if p]) if ext.subdomain else 0

    searchable = f"{host}{parts.path}?{parts.query}".lower()
    keywords = [k for k in SUSPICIOUS_KEYWORDS if k in searchable]

    port = parts.port
    percent_count = len(_PERCENT_RE.findall(cleaned))
    after_scheme = cleaned.split("://", 1)[1]
    unusual = []
    if "//" in after_scheme.split("?", 1)[0].split("/", 1)[-1] and "/" in after_scheme:
        unusual.append("repeated slashes in the path")
    if "\\" in cleaned:
        unusual.append("backslash characters")
    if ";" in parts.path:
        unusual.append("semicolons in the path")
    if ".." in parts.path:
        unusual.append("'..' sequences in the path")

    return {
        "original_url": cleaned,
        "scheme": parts.scheme.lower(),
        "hostname": host,
        "registered_domain": registered_domain,
        "subdomain_count": subdomain_count,
        "dot_count": host.count("."),
        "hyphen_count": host.count("-"),
        "path_length": len(parts.path),
        "query_param_count": len(parse_qsl(parts.query, keep_blank_values=True)),
        "url_length": len(cleaned),
        "uses_https": parts.scheme.lower() == "https",
        "is_ip_address": is_ip,
        "port": port,
        "non_standard_port": port is not None and port not in (80, 443),
        "is_shortener": host in URL_SHORTENERS or registered_domain in URL_SHORTENERS,
        "suspicious_keywords": keywords,
        "has_punycode": "xn--" in host,
        "has_at_symbol": "@" in cleaned,
        "percent_encoding_count": percent_count,
        "excessive_percent_encoding": percent_count > 5,
        "unusual_patterns": unusual,
    }
