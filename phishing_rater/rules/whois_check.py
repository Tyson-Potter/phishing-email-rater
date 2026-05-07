"""Look up domain age via WHOIS and flag newly-registered domains."""
import logging
from datetime import datetime, timezone

import tldextract
import whois

logging.getLogger("whois.whois").setLevel(logging.CRITICAL)

SUSPICIOUS_AGE_DAYS = 30


def registered_domain(url):
    """Return the registered domain from a URL (e.g. 'paypa1-secure-verify.com')."""
    extracted = tldextract.extract(url)
    if not extracted.domain or not extracted.suffix:
        return None
    return f"{extracted.domain}.{extracted.suffix}"


def check_domain_age(domain):
    """Query WHOIS for `domain` and return age info as a dict.

    Returns dict with keys: domain, created, age_days, suspicious, error.
    `suspicious` is True if age < SUSPICIOUS_AGE_DAYS, False if older, None on error.
    """
    result = {"domain": domain, "created": None, "age_days": None,
              "suspicious": None, "error": None}

    try:
        record = whois.whois(domain)
    except Exception as e:
        first_line = str(e).split("\n", 1)[0].strip()
        if "no match" in first_line.lower():
            result["error"] = "domain not registered"
        else:
            result["error"] = f"whois lookup failed: {first_line}"
        return result

    created = record.creation_date
    if isinstance(created, list):
        created = created[0] if created else None
    if created is None:
        result["error"] = "no creation date in WHOIS record"
        return result

    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    age_days = (datetime.now(timezone.utc) - created).days

    result["created"] = created.isoformat()
    result["age_days"] = age_days
    result["suspicious"] = age_days < SUSPICIOUS_AGE_DAYS
    return result
