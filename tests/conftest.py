"""Shared pytest fixtures for the phishing-email-rater test suite."""
from email import message_from_string
from email.policy import default
from pathlib import Path

import pytest

from phishing_rater.parser import parse_email_file

SAMPLES_DIR = Path(__file__).parent.parent / "samples"


@pytest.fixture
def sample_msg():
    """Return a callable that parses a sample by filename."""
    def _load(name):
        return parse_email_file(SAMPLES_DIR / name)
    return _load


@pytest.fixture
def make_msg():
    """Build a tiny EmailMessage from headers + body strings, for unit testing rules."""
    def _build(from_value="alice@example.com", auth_results=None, body="hello"):
        lines = [f"From: {from_value}", "To: bob@example.com"]
        if auth_results is not None:
            lines.append(f"Authentication-Results: {auth_results}")
        lines.append("")
        lines.append(body)
        raw = "\n".join(lines)
        return message_from_string(raw, policy=default)
    return _build
