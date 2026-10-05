"""Rule-based risk engine. Deterministic: the same features always give the same score.

Tiered rules (length, subdomains) give the HIGHEST matching tier only,
e.g. a 250-character URL gets 20 points, not 10 + 20.
"""
from typing import Any

CATEGORIES = [(20, "LOW RISK", "success"), (45, "CAUTION", "warning"),
              (70, "SUSPICIOUS", "orange"), (100, "HIGH RISK", "danger")]

RECOMMENDATIONS = {
    "LOW RISK": [
        "No strong warning signs were found, but this is not a safety guarantee.",
        "Still confirm the sender and the exact domain before entering any information.",
        "Prefer typing the official address yourself or using the official app.",
    ],
    "CAUTION": [
        "Do not enter passwords, OTPs or payment details through this link.",
        "Check the exact domain carefully and confirm with the sender via another channel.",
        "Use the official website or app instead of this link.",
    ],
    "SUSPICIOUS": [
        "Do not open this link or enter any personal information.",
        "Verify the message with the organisation using contact details you already trust.",
        "Report and block the sender if the message was unexpected.",
    ],
    "HIGH RISK": [
        "Do not open this link. Do not share OTPs, UPI PINs, passwords, CVV or bank details.",
        "Delete the message and report/block the sender.",
        "If you already clicked it, change affected passwords, enable multi-factor authentication and contact your bank if money or cards are involved.",
    ],
}


def _rule(rule: str, points: int, severity: str, message: str) -> dict[str, Any]:
    return {"rule": rule, "points": points, "severity": severity, "message": message}


def categorize(score: int) -> tuple[str, str]:
    """Map a 0-100 score to (label, bootstrap-style color name)."""
    for limit, label, color in CATEGORIES:
        if score <= limit:
            return label, color
    return "HIGH RISK", "danger"


def score_url(f: dict[str, Any]) -> dict[str, Any]:
    """Apply every rule to the features `f` and return score, label and reasons."""
    rules: list[dict[str, Any]] = []

    if not f["uses_https"]:
        rules.append(_rule("missing_https", 20, "medium",
                           "This link does not use HTTPS, so information sent to it may not be encrypted."))
    if f["is_ip_address"]:
        rules.append(_rule("ip_address_host", 30, "high",
                           "The link uses a raw IP address instead of a recognizable domain name."))
    if f["has_at_symbol"]:
        rules.append(_rule("at_symbol", 20, "high",
                           "The '@' symbol can hide the real destination: text before it is ignored by browsers."))
    if f["has_punycode"]:
        rules.append(_rule("punycode", 25, "high",
                           "The hostname contains 'xn--' (punycode), which can disguise look-alike characters."))
    if f["url_length"] > 200:
        rules.append(_rule("very_long_url", 20, "medium", "The URL is very long (over 200 characters)."))
    elif f["url_length"] > 100:
        rules.append(_rule("long_url", 10, "low", "The URL is long (over 100 characters)."))
    if f["subdomain_count"] > 5:
        rules.append(_rule("many_subdomains_extreme", 20, "medium",
                           "The hostname has more than 5 subdomains, which can hide the real domain."))
    elif f["subdomain_count"] > 3:
        rules.append(_rule("many_subdomains", 10, "low", "The hostname has more than 3 subdomains."))
    if f["hyphen_count"] > 3:
        rules.append(_rule("many_hyphens", 10, "low", "The hostname contains more than 3 hyphens."))
    if f["suspicious_keywords"]:
        pts = min(8 * len(f["suspicious_keywords"]), 24)
        rules.append(_rule("suspicious_keywords", pts, "medium",
                           "Words often used in phishing were found: " + ", ".join(f["suspicious_keywords"]) + "."))
    if f["is_shortener"]:
        rules.append(_rule("url_shortener", 15, "medium",
                           "A URL shortener hides the final destination, so you cannot see where it leads."))
    if f["non_standard_port"]:
        rules.append(_rule("non_standard_port", 10, "low",
                           "The link uses an unusual port number (not 80 or 443)."))
    if f["excessive_percent_encoding"]:
        rules.append(_rule("excessive_percent_encoding", 10, "low",
                           "The URL has many percent-encoded characters (%XX), which can hide its real content."))
    if f["query_param_count"] > 5:
        rules.append(_rule("many_query_params", 8, "low", "The URL has more than 5 query parameters."))
    if f["unusual_patterns"]:
        pts = 10 if len(f["unusual_patterns"]) > 1 else 5
        rules.append(_rule("unusual_patterns", pts, "low",
                           "Unusual patterns found: " + ", ".join(f["unusual_patterns"]) + "."))

    score = max(0, min(100, sum(r["points"] for r in rules)))
    label, color = categorize(score)
    return {"score": score, "label": label, "color": color, "rules": rules,
            "recommendations": RECOMMENDATIONS[label]}
