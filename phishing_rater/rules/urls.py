"""Find URLs in email text and defang them for safe display."""
import re

URL_PATTERN = re.compile(r"https?://[^\s<>\"')]+")


def extract_urls(text):
    """Return URLs found in text, deduplicated, in order of first appearance."""
    seen = set()
    ordered = []
    for url in URL_PATTERN.findall(text):
        cleaned = url.rstrip(".,;:!?)")
        if cleaned not in seen:
            seen.add(cleaned)
            ordered.append(cleaned)
    return ordered


def defang(url):
    """Render a URL non-clickable for safe display in reports and tickets."""
    return url.replace("http", "hxxp").replace(".", "[.]")
