import pytest
from services.url_analyzer import analyze_url, validate_url


def test_normal_https():
    f = analyze_url("https://example.com")
    assert f["uses_https"] and not f["is_ip_address"] and f["registered_domain"] == "example.com"


def test_http_url():
    assert analyze_url("http://example.com")["uses_https"] is False


def test_ip_address_url():
    f = analyze_url("http://192.0.2.1/login")
    assert f["is_ip_address"] and "login" in f["suspicious_keywords"]


def test_punycode():
    assert analyze_url("https://xn--example-test.example")["has_punycode"]


def test_at_symbol():
    f = analyze_url("https://example.com@evil.example")
    assert f["has_at_symbol"] and f["hostname"] == "evil.example"


def test_shortener():
    assert analyze_url("https://bit.ly/example")["is_shortener"]


def test_multiple_keywords():
    f = analyze_url("https://example.com/login/verify/account")
    assert {"login", "verify", "account"} <= set(f["suspicious_keywords"])


def test_non_standard_port_and_subdomains():
    f = analyze_url("https://a.b.c.example.com:8443/x")
    assert f["non_standard_port"] and f["subdomain_count"] == 3


@pytest.mark.parametrize("bad", ["javascript:alert(1)", "data:text/html,hi", "file:///etc/passwd",
                                 "ftp://example.com", "mailto:a@b.com", "https://", "", "   ",
                                 "http://exa mple.com", "https://example.com:99999"])
def test_invalid_urls_rejected(bad):
    ok, _, err = validate_url(bad)
    assert not ok and err
    with pytest.raises(ValueError):
        analyze_url(bad)


def test_whitespace_trimmed():
    ok, cleaned, _ = validate_url("  https://example.com  ")
    assert ok and cleaned == "https://example.com"
