"""Extract attachment metadata and SHA-256 hashes without opening file content."""
import hashlib


def extract_attachments(msg):
    """Return a list of dicts: {filename, content_type, size_bytes, sha256}."""
    attachments = []
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue
        filename = part.get_filename()
        if not filename:
            continue

        payload = part.get_payload(decode=True) or b""
        attachments.append({
            "filename": filename,
            "content_type": part.get_content_type(),
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        })
    return attachments
