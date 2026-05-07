"""Command-line interface and orchestration for the phishing email rater."""
import argparse

from phishing_rater.llm.analyzer import analyze_email as llm_analyze
from phishing_rater.ml.hf_classifier import classify as ml_classify
from phishing_rater.parser import parse_email_file, extract_body_text
from phishing_rater.rules.attachments import extract_attachments
from phishing_rater.rules.auth_headers import auth_findings, parse_auth_results
from phishing_rater.rules.from_spoof import from_findings
from phishing_rater.rules.urls import defang, extract_urls
from phishing_rater.rules.whois_check import check_domain_age, registered_domain
from phishing_rater.score import aggregate


def analyze(path, *, skip_llm=False):
    """Run all checks on a .eml file and return a structured report.

    skip_llm: if True, skip the LLM call (useful for fast local iteration
    when Ollama isn't running).
    """
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

    report = {
        "from": msg["From"],
        "subject": msg["Subject"],
        "auth": parse_auth_results(msg),
        "from_findings": from_findings(msg),
        "attachments": extract_attachments(msg),
        "urls": url_findings,
        "ml": ml_classify(body),
        "llm": None if skip_llm else llm_analyze(body),
    }
    report["score"] = aggregate(report)
    return report


def print_report(report):
    """Pretty-print an analysis report for human consumption."""
    score = report["score"]
    risk = score["risk"].upper()
    flag = "  ***" if risk in ("HIGH", "MEDIUM") else ""
    print(f"=== RISK: {risk} ({score['points']} points){flag} ===")
    for line in score["rationale"]:
        print(f"  {line}")
    if not score["rationale"]:
        print("  (no signals contributed)")
    print()
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
    print()
    print("ML classifier (HuggingFace DistilBERT):")
    ml = report["ml"]
    if ml["error"]:
        print(f"  (skipped: {ml['error']})")
    else:
        flag = "  *** SUSPICIOUS ***" if ml["phishing_score"] >= 0.5 else ""
        print(f"  phishing_score:   {ml['phishing_score']:.3f}{flag}")
        print(f"  legitimate_score: {ml['legitimate_score']:.3f}")
        print(f"  top label:        {ml['top_label']}")
    print()
    print("LLM verdict (local Ollama):")
    llm = report["llm"]
    if llm is None:
        print("  (skipped via --skip-llm)")
    elif llm["error"]:
        print(f"  (skipped: {llm['error']})")
    else:
        cls = (llm["classification"] or "?").upper()
        conf = (llm["confidence"] or "?").upper()
        flag = "  ***" if cls in ("PHISHING", "SUSPICIOUS") else ""
        print(f"  classification:    {cls} ({conf} confidence){flag}")
        print(f"  recommended action: {llm['recommended_action']}")
        if llm["indicators"]:
            print("  indicators:")
            for ind in llm["indicators"]:
                print(f"    - {ind}")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a .eml file for phishing indicators."
    )
    parser.add_argument("file", help="Path to a .eml file to analyze")
    parser.add_argument(
        "--skip-llm",
        action="store_true",
        help="Skip the LLM call (useful when Ollama isn't running)",
    )
    args = parser.parse_args()
    report = analyze(args.file, skip_llm=args.skip_llm)
    print_report(report)


if __name__ == "__main__":
    main()
