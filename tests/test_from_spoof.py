"""Tests for display-name vs From-address spoofing detection."""
from phishing_rater.rules.from_spoof import from_findings, parse_from_header


def test_brand_impersonation_paypal_on_gmail(make_msg):
    msg = make_msg(from_value='"PayPal Support" <foo@gmail.com>')
    findings = from_findings(msg)
    assert any("paypal" in f.lower() for f in findings)


def test_brand_match_no_finding(make_msg):
    msg = make_msg(from_value='"PayPal" <noreply@paypal.com>')
    # PayPal display + paypal.com domain → no brand mismatch
    brand_findings = [f for f in from_findings(msg) if "claims" in f.lower()]
    assert brand_findings == []


def test_corporate_role_on_gmail(make_msg):
    msg = make_msg(from_value='"Sarah Chen, CEO" <sarah@gmail.com>')
    findings = from_findings(msg)
    assert any("ceo" in f.lower() and "gmail.com" in f for f in findings)


def test_corporate_role_on_corporate_domain_no_finding(make_msg):
    msg = make_msg(from_value='"BigCo CEO" <ceo@bigco.com>')
    # Corporate role on a corporate (non-free) domain → no finding
    role_findings = [f for f in from_findings(msg) if "free provider" in f]
    assert role_findings == []


def test_no_findings_for_clean_email(make_msg):
    msg = make_msg(from_value='"BigCo Newsletter" <newsletter@bigco.com>')
    assert from_findings(msg) == []


def test_parse_from_extracts_registered_domain(make_msg):
    msg = make_msg(from_value='"Test" <user@mail.subdomain.example.com>')
    _, _, registered = parse_from_header(msg)
    assert registered == "example.com"


def test_parse_from_handles_co_uk(make_msg):
    msg = make_msg(from_value='"Test" <user@shop.example.co.uk>')
    _, _, registered = parse_from_header(msg)
    assert registered == "example.co.uk"
