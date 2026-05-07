# phishing-email-rater

A Python tool that analyzes a `.eml` file and produces a hybrid risk assessment combining rule-based checks, an ML classifier, and an LLM verdict.

The goal is **defensible** phishing triage: each layer's strengths and failure modes are documented so a SOC analyst (or a hiring manager) can see exactly what the tool does and does not know.

## Status

| Layer | Status | What it does |
| --- | --- | --- |
| Rule-based | Implemented | Auth headers (SPF/DKIM/DMARC), display-name vs From-domain spoofing, attachment hashing, URL extraction + defang, WHOIS domain age |
| ML classifier | Planned | Pre-trained HuggingFace phishing classifier scoring body content |
| LLM verdict | Planned | Structured JSON verdict (classification, confidence, top indicators, recommended action) |
| Combined risk score | Planned | Low / Medium / High weighted across the three signals |

## Usage

```
python -m phishing_rater path/to/email.eml
```

Sample emails for testing live in `samples/` (synthetic — crafted by hand, not captured from real traffic).

## Safety constraints

These are non-negotiable design rules:

- **Never open links.** URLs are only extracted, defanged (`hxxps://evil[.]com`), and shown for human review.
- **Never execute attachments.** Attachments are hashed (SHA-256) and metadata-listed only — payload bytes are never written back to disk or opened.
- **No outbound requests to suspicious domains.** WHOIS lookups go to the registry, not to the suspect domain itself.

## Limitations (rule-based layer)

Rules are fast, explainable, and brittle. They will miss anything they weren't written to see:

- **Novel display-name spoofs.** The brand list in `from_spoof.py` is hand-curated. A spoofed brand not in the list won't be flagged.
- **WHOIS gaps.** Some TLDs return sparse or no creation date; the lookup falls back to a soft error rather than a verdict.
- **Header trust.** `Authentication-Results` is taken at face value. A forwarder that rewrites that header without re-checking can mislead the parser.
- **Body-only URL extraction.** URLs hidden in HTML attributes, images, or QR codes are not currently extracted.

ML and LLM layers will have their own limitations sections (adversarial examples, hallucination, privacy implications of sending email content to external APIs) once those layers land.
