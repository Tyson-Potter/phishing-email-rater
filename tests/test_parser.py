"""Tests for .eml parsing and body extraction."""
from phishing_rater.parser import extract_body_text


def test_parse_email_file_returns_message_with_headers(sample_msg):
    msg = sample_msg("benign_newsletter.eml")
    assert msg["From"] is not None
    assert msg["Subject"] == "Your weekly digest"


def test_extract_body_from_single_part(sample_msg):
    msg = sample_msg("benign_newsletter.eml")
    body = extract_body_text(msg)
    assert "tysonpotter.com" in body
    assert "weekly digest" in body.lower() or "this week" in body.lower()


def test_extract_body_from_multipart_includes_both_parts(sample_msg):
    msg = sample_msg("phish_multipart_html.eml")
    body = extract_body_text(msg)
    # The plain-text part links to docusign-share.net
    assert "docusign-share.net" in body
    # The HTML part has a different URL — both should be extracted
    assert "malicious-redirect.tk" in body


def test_extract_body_skips_attachment_payload(sample_msg):
    msg = sample_msg("phish_with_attachment.eml")
    body = extract_body_text(msg)
    assert "FAKE_PDF" not in body
    assert "Wire transfer" in body


def test_extract_body_handles_html_only(sample_msg):
    msg = sample_msg("phish_html_only.eml")
    body = extract_body_text(msg)
    assert "Apple ID" in body
    assert "apple-id-verify.com" in body
