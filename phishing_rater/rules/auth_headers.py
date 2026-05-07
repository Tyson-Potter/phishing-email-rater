"""Parse SPF, DKIM, and DMARC results from the Authentication-Results header."""
import re

RESULT_PATTERN = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|none|neutral|softfail|temperror|permerror)\b",
                            re.IGNORECASE)


def parse_auth_results(msg):
    """Return a dict like {'spf': 'pass', 'dkim': 'fail', 'dmarc': None}."""
    result = {"spf": None, "dkim": None, "dmarc": None}

    header = msg.get_all("Authentication-Results")
    if not header:
        return result

    combined = " ; ".join(header)
    for mech, verdict in RESULT_PATTERN.findall(combined):
        mech = mech.lower()
        if result[mech] is None:
            result[mech] = verdict.lower()

    return result


def auth_findings(auth):
    """Convert the dict from parse_auth_results into a list of human-readable flags."""
    findings = []
    for mech in ("spf", "dkim", "dmarc"):
        verdict = auth[mech]
        if verdict is None:
            findings.append(f"{mech.upper()}: not present")
        elif verdict == "pass":
            findings.append(f"{mech.upper()}: pass")
        else:
            findings.append(f"{mech.upper()}: {verdict.upper()} ***")
    return findings
