"""Tests for attachment metadata extraction and SHA-256 hashing."""
from phishing_rater.rules.attachments import extract_attachments


def test_no_attachments_in_plain_text_email(sample_msg):
    msg = sample_msg("benign_newsletter.eml")
    assert extract_attachments(msg) == []


def test_extracts_pdf_attachment_metadata(sample_msg):
    msg = sample_msg("phish_with_attachment.eml")
    atts = extract_attachments(msg)
    assert len(atts) == 1
    assert atts[0]["filename"] == "invoice.pdf"
    assert atts[0]["content_type"] == "application/pdf"
    assert atts[0]["size_bytes"] > 0
    assert len(atts[0]["sha256"]) == 64


def test_attachment_hash_is_deterministic(sample_msg):
    msg1 = sample_msg("phish_with_attachment.eml")
    msg2 = sample_msg("phish_with_attachment.eml")
    h1 = extract_attachments(msg1)[0]["sha256"]
    h2 = extract_attachments(msg2)[0]["sha256"]
    assert h1 == h2


def test_ups_delivery_attachment(sample_msg):
    msg = sample_msg("phish_ups_delivery.eml")
    atts = extract_attachments(msg)
    assert len(atts) == 1
    assert atts[0]["filename"] == "shipping_label.pdf"
    assert atts[0]["content_type"] == "application/pdf"
