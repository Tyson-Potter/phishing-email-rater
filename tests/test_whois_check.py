"""Tests for WHOIS-related URL parsing logic.

The actual WHOIS lookup makes a network call and isn't tested here — we only
test the URL-to-registered-domain extraction, which is pure local logic.
"""
from phishing_rater.rules.whois_check import registered_domain


def test_basic_url():
    assert registered_domain("https://example.com/path") == "example.com"


def test_strips_subdomain():
    assert registered_domain("https://login.mail.example.com/x") == "example.com"


def test_co_uk_public_suffix():
    # tldextract should recognize "co.uk" as the suffix, not "uk"
    assert registered_domain("https://shop.example.co.uk/page") == "example.co.uk"


def test_invalid_url_returns_none():
    assert registered_domain("not-a-url-at-all") is None


def test_url_without_path():
    assert registered_domain("https://example.com") == "example.com"


def test_url_with_port():
    assert registered_domain("https://example.com:8080/x") == "example.com"
