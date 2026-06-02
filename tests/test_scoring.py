from sentinel_audit.scoring import calculate_risk_score


def test_no_findings_gives_perfect_score():
    result = calculate_risk_score([])
    assert result["score"] == 100
    assert result["label"] == "Low Risk"


def test_single_high_finding_penalizes_score():
    findings = [{"severity": "high"}]
    result = calculate_risk_score(findings)
    assert result["score"] == 80


def test_multiple_findings_accumulate_penalty():
    findings = [{"severity": "high"}, {"severity": "medium"}, {"severity": "low"}]
    result = calculate_risk_score(findings)
    assert result["score"] == 65


def test_score_does_not_go_below_zero():
    findings = [{"severity": "high"}] * 10
    result = calculate_risk_score(findings)
    assert result["score"] == 0


def test_informational_findings_do_not_penalize():
    findings = [{"severity": "informational"}, {"severity": "informational"}]
    result = calculate_risk_score(findings)
    assert result["score"] == 100


def test_risk_labels():
    assert calculate_risk_score([])["label"] == "Low Risk"
    assert calculate_risk_score([{"severity": "medium"}] * 3)["label"] == "Moderate Risk"
    assert calculate_risk_score([{"severity": "high"}] * 2)["label"] == "Elevated Risk"
    assert calculate_risk_score([{"severity": "high"}] * 3)["label"] == "High Risk"
