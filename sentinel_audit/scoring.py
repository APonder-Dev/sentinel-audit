_SEVERITY_PENALTY: dict[str, int] = {
    "critical": 40,
    "high": 20,
    "medium": 10,
    "low": 5,
    "informational": 0,
}


def calculate_risk_score(findings: list[dict]) -> dict:
    penalty = sum(_SEVERITY_PENALTY.get(f.get("severity", ""), 0) for f in findings)
    score = max(0, 100 - penalty)

    if score >= 90:
        label = "Low Risk"
    elif score >= 70:
        label = "Moderate Risk"
    elif score >= 50:
        label = "Elevated Risk"
    else:
        label = "High Risk"

    return {"score": score, "label": label}
