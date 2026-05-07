"""Detect display-name vs From-address mismatches (impersonation / BEC patterns)."""
import re
from email.utils import parseaddr

import tldextract

BRAND_DOMAINS = {
    "paypal":        ("paypal.com",),
    "microsoft":     ("microsoft.com", "outlook.com"),
    "google":        ("google.com", "googlemail.com"),
    "apple":         ("apple.com", "icloud.com"),
    "amazon":        ("amazon.com",),
    "docusign":      ("docusign.net", "docusign.com"),
    "dropbox":       ("dropbox.com",),
    "fedex":         ("fedex.com",),
    "ups":           ("ups.com",),
    "irs":           ("irs.gov",),
    "linkedin":      ("linkedin.com",),
    "netflix":       ("netflix.com",),
    "chase":         ("chase.com",),
    "bankofamerica": ("bankofamerica.com",),
}

FREE_MAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "icloud.com", "protonmail.com", "aol.com", "msn.com",
}

CORPORATE_ROLE_TERMS = {
    "ceo", "cfo", "cto", "coo", "president", "director",
    "support", "team", "department", "billing", "accounting",
    "hr", "admin", "noreply", "security", "compliance",
}


def parse_from_header(msg):
    """Return (display_name, address, registered_domain) for the From: header."""
    raw = msg["From"] or ""
    display, addr = parseaddr(raw)
    if "@" not in addr:
        return display, addr, ""
    full_domain = addr.rsplit("@", 1)[-1].lower()
    extracted = tldextract.extract(full_domain)
    if extracted.domain and extracted.suffix:
        registered = f"{extracted.domain}.{extracted.suffix}"
    else:
        registered = full_domain
    return display, addr, registered


def from_findings(msg):
    """Return a list of human-readable findings about display-name spoofing."""
    findings = []
    display, addr, registered = parse_from_header(msg)
    if not addr:
        return findings

    display_lower = display.lower()
    display_words = set(re.findall(r"[a-z]+", display_lower))

    for brand, allowed in BRAND_DOMAINS.items():
        if brand in display_lower and registered not in allowed:
            findings.append(
                f"Display name claims '{brand}' but address domain is "
                f"'{registered}' (expected: {', '.join(allowed)})"
            )

    if registered in FREE_MAIL_PROVIDERS:
        matched = display_words & CORPORATE_ROLE_TERMS
        if matched:
            findings.append(
                f"Display name has corporate role term(s) "
                f"[{', '.join(sorted(matched))}] but address is on "
                f"free provider '{registered}'"
            )

    return findings
