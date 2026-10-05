from services.risk_scoring import categorize, score_url
from services.url_analyzer import analyze_url


def risk(url):
    return score_url(analyze_url(url))


def test_clean_url_is_low():
    r = risk("https://example.com")
    assert r["score"] == 0 and r["label"] == "LOW RISK" and r["rules"] == []


def test_http_adds_20():
    assert risk("http://example.com")["score"] == 20


def test_ip_login_is_suspicious():
    r = risk("http://192.0.2.1/login")
    assert r["score"] == 58 and r["label"] == "SUSPICIOUS"


def test_punycode_and_at_and_shortener():
    assert risk("https://xn--example-test.example")["score"] == 25
    assert risk("https://example.com@evil.example")["score"] == 20
    assert risk("https://bit.ly/example")["score"] == 15


def test_long_url_tiers_not_stacked():
    assert risk("https://example.com/" + "a" * 120)["score"] == 10
    assert risk("https://example.com/" + "a" * 250)["score"] == 20


def test_keyword_points_capped_at_24():
    r = risk("https://example.com/login/verify/account/update/password")
    kw = [x for x in r["rules"] if x["rule"] == "suspicious_keywords"][0]
    assert kw["points"] == 24


def test_score_always_between_0_and_100():
    url = ("http://" + "a-b-c-d-e." * 3 + "x.y.z.w.v.u.t.example.com:8080//login//verify/account/update/"
           "password/otp/bank/wallet?" + "&".join(f"p{i}=%41%42" for i in range(10)) + "@" + "q" * 250)
    r = score_url({**analyze_url("http://192.0.2.1/login"), "has_punycode": True, "has_at_symbol": True,
                   "url_length": 500, "subdomain_count": 9, "hyphen_count": 9,
                   "is_shortener": True, "non_standard_port": True, "excessive_percent_encoding": True,
                   "query_param_count": 20, "unusual_patterns": ["a", "b"],
                   "suspicious_keywords": ["login", "verify", "otp", "bank"], "uses_https": False})
    assert 0 <= r["score"] <= 100 and r["score"] == 100


def test_deterministic_and_reasons_present():
    a, b = risk("http://192.0.2.1/login"), risk("http://192.0.2.1/login")
    assert a == b
    assert all({"rule", "points", "severity", "message"} <= set(x) for x in a["rules"])


def test_categories():
    assert categorize(0)[0] == "LOW RISK" and categorize(20)[0] == "LOW RISK"
    assert categorize(21)[0] == "CAUTION" and categorize(45)[0] == "CAUTION"
    assert categorize(46)[0] == "SUSPICIOUS" and categorize(70)[0] == "SUSPICIOUS"
    assert categorize(71)[0] == "HIGH RISK" and categorize(100)[0] == "HIGH RISK"
