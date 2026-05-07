"""Combined risk scoring across rule-based, ML, and LLM signals.

The aggregator returns both a Low/Medium/High verdict AND a rationale list
showing which signals contributed how many points. The rationale is the
point - an analyst can disagree with the verdict and see exactly why.
"""

# Point thresholds for the final verdict
HIGH_THRESHOLD = 6
MEDIUM_THRESHOLD = 3


def aggregate(report):
    """Combine signals from all layers into a verdict + rationale.

    Returns: {"risk": "low"|"medium"|"high", "points": int, "rationale": [str, ...]}
    """
    points = 0
    rationale = []

    # ---------------------------------------------------------------------
    # Rule-based signals: highest weight, lowest false-positive rate.
    # ---------------------------------------------------------------------
    auth = report.get("auth") or {}
    if auth.get("dmarc") == "fail":
        points += 3
        rationale.append("+3  DMARC fail")
    if auth.get("spf") == "fail":
        points += 2
        rationale.append("+2  SPF fail")
    if auth.get("dkim") == "fail":
        points += 1
        rationale.append("+1  DKIM fail")

    for finding in report.get("from_findings") or []:
        points += 3
        rationale.append(f"+3  {finding}")

    for url_info in report.get("urls") or []:
        age = url_info.get("age")
        if not age:
            continue
        if age.get("error") == "domain not registered":
            points += 4
            rationale.append(f"+4  {age['domain']} is not registered")
        elif age.get("suspicious"):
            points += 4
            rationale.append(f"+4  {age['domain']} only {age['age_days']}d old")

    # ---------------------------------------------------------------------
    # ML classifier: only contribute when confidently phishing.
    # Below 0.7 the model is too unreliable on legit transactional emails
    # to be trusted as an independent signal.
    # ---------------------------------------------------------------------
    ml = report.get("ml") or {}
    ml_score = ml.get("phishing_score")
    if ml_score is not None:
        if ml_score >= 0.9:
            points += 2
            rationale.append(f"+2  ML high-confidence phishing ({ml_score:.2f})")
        elif ml_score >= 0.7:
            points += 1
            rationale.append(f"+1  ML phishing ({ml_score:.2f})")

    # ---------------------------------------------------------------------
    # LLM verdict: weighted by the model's own stated confidence.
    # ---------------------------------------------------------------------
    llm = report.get("llm") or {}
    cls = (llm.get("classification") or "").lower()
    conf = (llm.get("confidence") or "").lower()
    if cls == "phishing":
        bump = 3 if conf == "high" else 2
        points += bump
        rationale.append(f"+{bump}  LLM PHISHING ({conf or 'unspecified'})")
    elif cls == "suspicious":
        bump = 2 if conf == "high" else 1
        points += bump
        rationale.append(f"+{bump}  LLM SUSPICIOUS ({conf or 'unspecified'})")

    # ---------------------------------------------------------------------
    # Suppression: strong legit signals override weak AI noise.
    #   - All three auth checks pass
    #   - At least one URL on a domain >365 days old
    #   - No display-name spoof findings
    #   - Total accumulated points are still in "weak signal" territory
    # ---------------------------------------------------------------------
    auth_all_pass = (
        auth.get("spf") == "pass"
        and auth.get("dkim") == "pass"
        and auth.get("dmarc") == "pass"
    )
    has_aged_domain = any(
        (u.get("age") or {}).get("age_days") and u["age"]["age_days"] > 365
        for u in (report.get("urls") or [])
    )
    no_spoof = not (report.get("from_findings") or [])
    if auth_all_pass and has_aged_domain and no_spoof and 0 < points <= 5:
        rationale.append(
            f"--  suppress: all-pass auth + aged domain + no spoof "
            f"(was {points} points; AI noise overruled)"
        )
        points = 0

    # ---------------------------------------------------------------------
    # Map total points to a verdict.
    # ---------------------------------------------------------------------
    if points >= HIGH_THRESHOLD:
        risk = "high"
    elif points >= MEDIUM_THRESHOLD:
        risk = "medium"
    else:
        risk = "low"

    return {"risk": risk, "points": points, "rationale": rationale}
