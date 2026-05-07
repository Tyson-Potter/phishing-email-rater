"""Command-line interface and orchestration for the phishing email rater."""
import argparse

from phishing_rater.parser import parse_email_file, extract_body_text
from phishing_rater.rules.attachments import extract_attachments
from phishing_rater.rules.auth_headers import auth_findings, parse_auth_results
from phishing_rater.rules.from_spoof import from_findings
from phishing_rater.rules.urls import defang, extract_urls
from phishing_rater.rules.whois_check import check_domain_age, registered_domain


def analyze(path):
    """Run all rule-based checks on a .eml file and return a structured report."""
    msg = parse_email_file(path)
    body = extract_body_text(msg)
    urls = extract_urls(body)

    seen_domains = set()
    url_findings = []
    for url in urls:
        domain = registered_domain(url)
        age = None
        if domain and domain not in seen_domains:
            seen_domains.add(domain)
            age = check_domain_age(domain)
        url_findings.append({"url": url, "domain": domain, "age": age})

    return {
        "from": msg["From"],
        "subject": msg["Subject"],
        "auth": parse_auth_results(msg),
        "from_findings": from_findings(msg),
        "attachments": extract_attachments(msg),
        "urls": url_findings,
    }


def print_report(report):
    """Pretty-print an analysis report for human consumption."""
    print(f"From:    {report['from']}")
    print(f"Subject: {report['subject']}")
    print()
    print("Authentication results:")
    for line in auth_findings(report["auth"]):
        print(f"  {line}")
    print()
    print("From-header findings:")
    if not report["from_findings"]:
        print("  (none)")
    for line in report["from_findings"]:
        print(f"  *** {line}")
    print()
    print("Attachments:")
    if not report["attachments"]:
        print("  (none)")
    for a in report["attachments"]:
        print(f"  {a['filename']}  ({a['content_type']}, {a['size_bytes']} bytes)")
        print(f"    sha256: {a['sha256']}")
    print()
    print("URLs found (defanged) + domain age:")
    if not report["urls"]:
        print("  (none)")
    for f in report["urls"]:
        print(f"  {defang(f['url'])}")
        age = f["age"]
        if age is None:
            continue
        if age["error"]:
            print(f"    domain: {age['domain']}  (whois: {age['error']})")
        else:
            flag = "  *** SUSPICIOUS (<30d) ***" if age["suspicious"] else ""
            print(f"    domain: {age['domain']}  age: {age['age_days']}d{flag}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a .eml file for phishing indicators (rule-based)."
    )
    parser.add_argument("file", help="Path to a .eml file to analyze")
    args = parser.parse_args()
    report = analyze(args.file)
    print_report(report)


if __name__ == "__main__":
    main()
