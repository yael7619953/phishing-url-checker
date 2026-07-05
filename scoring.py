
# Weight (importance) of each check, keyed by the check's "name" field
# as produced in url_checker.py. Higher weight = stronger phishing signal.
CHECK_WEIGHTS = {
    "URL length": 10,
    "IP address instead of domain": 25,
    "Subdomain count": 15,
    "'@' symbol in URL": 20,
    "Excessive hyphens in domain": 10,
    "Suspicious keywords": 15,
    "URL shortener service": 15,
}

# Score thresholds for classification (inclusive lower bound)
LOW_RISK_MAX = 24
MEDIUM_RISK_MAX = 59
# 60+ is considered High risk


def calculate_score(results: list) -> int:
    """
    Sum the weights of all flagged checks and cap the total at 100.
    Unknown check names (not in CHECK_WEIGHTS) are ignored safely, so the
    scoring module doesn't break if new checks are added later without
    updating the weights table.
    """
    raw_score = sum(
        CHECK_WEIGHTS.get(r["name"], 0)
        for r in results
        if r["flagged"]
    )
    return min(raw_score, 100)


def classify_risk(score: int) -> str:
    """Translate a numeric score into a human-readable risk level."""
    if score <= LOW_RISK_MAX:
        return "Low"
    if score <= MEDIUM_RISK_MAX:
        return "Medium"
    return "High"


def explain_score(results: list) -> list:
    """
    Return a list of strings, one per flagged check, explaining how much
    each one contributed to the final score. Used for a transparent,
    human-readable report - not just a bare number.
    """
    explanations = []
    for r in results:
        if r["flagged"]:
            weight = CHECK_WEIGHTS.get(r["name"], 0)
            explanations.append(f"+{weight} pts - {r['name']}: {r['detail']}")
    return explanations


def score_report(results: list) -> dict:
    """Convenience wrapper returning score, risk level, and explanation together."""
    score = calculate_score(results)
    return {
        "score": score,
        "risk_level": classify_risk(score),
        "explanations": explain_score(results),
    }
