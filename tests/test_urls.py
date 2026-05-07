"""Tests for URL extraction and defanging."""
from phishing_rater.rules.urls import defang, extract_urls


def test_extract_urls_finds_http_and_https():
    text = "Visit https://example.com/a and http://foo.bar/x"
    assert extract_urls(text) == ["https://example.com/a", "http://foo.bar/x"]


def test_extract_urls_dedupes():
    text = "https://x.com/a then https://x.com/a then https://x.com/a"
    assert extract_urls(text) == ["https://x.com/a"]


def test_extract_urls_strips_trailing_punctuation():
    text = "See https://example.com/page."
    assert extract_urls(text) == ["https://example.com/page"]


def test_extract_urls_handles_html_attributes():
    text = '<a href="https://evil.tld/x">click</a>'
    assert extract_urls(text) == ["https://evil.tld/x"]


def test_extract_urls_returns_empty_for_no_urls():
    assert extract_urls("just text, no link here") == []


def test_defang_replaces_protocol_and_dots():
    assert defang("https://evil.com/path") == "hxxps://evil[.]com/path"


def test_defang_handles_http():
    assert defang("http://foo.bar/x") == "hxxp://foo[.]bar/x"


def test_defang_neutralizes_every_dot():
    # Even dots in the path get defanged — slightly noisy but maximally safe.
    assert defang("https://a.b.c/d.e") == "hxxps://a[.]b[.]c/d[.]e"
