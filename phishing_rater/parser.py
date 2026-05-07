"""Parse a .eml file into a Python EmailMessage object."""
from email import message_from_bytes
from email.policy import default


def parse_email_file(path):
    """Read a .eml file from disk and return the parsed message."""
    with open(path, "rb") as f:
        raw_bytes = f.read()
    return message_from_bytes(raw_bytes, policy=default)


def extract_body_text(msg):
    """Walk the email and return concatenated text from text/plain and text/html parts."""
    wanted_types = ("text/plain", "text/html")
    parts = []
    for part in msg.walk():
        if part.get_content_type() not in wanted_types:
            continue
        parts.append(part.get_content())
    return "\n".join(parts)
