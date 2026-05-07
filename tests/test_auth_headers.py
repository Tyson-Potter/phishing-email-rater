"""Tests for SPF/DKIM/DMARC parsing from Authentication-Results."""
from phishing_rater.rules.auth_headers import auth_findings, parse_auth_results


def test_all_pass(make_msg):
    msg = make_msg(auth_results="mx.example.com; spf=pass; dkim=pass; dmarc=pass")
    assert parse_auth_results(msg) == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}


def test_all_fail(make_msg):
    msg = make_msg(auth_results="mx.example.com; spf=fail; dkim=fail; dmarc=fail")
    result = parse_auth_results(msg)
    assert result["spf"] == "fail"
    assert result["dkim"] == "fail"
    assert result["dmarc"] == "fail"


def test_missing_header_returns_all_none(make_msg):
    msg = make_msg(auth_results=None)
    assert parse_auth_results(msg) == {"spf": None, "dkim": None, "dmarc": None}


def test_partial_header(make_msg):
    msg = make_msg(auth_results="mx.example.com; spf=pass")
    result = parse_auth_results(msg)
    assert result["spf"] == "pass"
    assert result["dkim"] is None
    assert result["dmarc"] is None


def test_findings_format_pass(make_msg):
    msg = make_msg(auth_results="mx.example.com; spf=pass; dkim=pass; dmarc=pass")
    findings = auth_findings(parse_auth_results(msg))
    assert "SPF: pass" in findings
    assert "DKIM: pass" in findings
    assert "DMARC: pass" in findings


def test_findings_marks_failures_with_stars(make_msg):
    msg = make_msg(auth_results="mx.example.com; spf=fail; dkim=pass; dmarc=fail")
    findings = auth_findings(parse_auth_results(msg))
    assert any("SPF: FAIL" in f and "***" in f for f in findings)
    assert any("DMARC: FAIL" in f and "***" in f for f in findings)


def test_findings_marks_missing_as_not_present(make_msg):
    msg = make_msg(auth_results="mx.example.com; spf=pass")
    findings = auth_findings(parse_auth_results(msg))
    assert any("DKIM: not present" in f for f in findings)
