from ai.incident_analyst import analyze_alert, analyze_alerts


def test_brute_force_incident_analysis():
    alert = {
        "rule": "BRUTE_FORCE",
        "severity": "HIGH",
        "source_ip": "192.0.2.50",
        "event_count": 5,
        "description": "5 failed login attempts from 192.0.2.50",
    }

    result = analyze_alert(alert)

    assert result["rule"] == "BRUTE_FORCE"
    assert result["mitre_attack"]["technique_id"] == "T1110"
    assert result["mitre_attack"]["tactic"] == "Credential Access"
    assert len(result["recommended_actions"]) > 0


def test_privilege_escalation_does_not_assume_technique():
    alert = {
        "rule": "PRIVILEGE_ESCALATION",
        "severity": "CRITICAL",
        "source_ip": "192.0.2.75",
        "username": "testuser",
        "description": "Privilege escalation detected for testuser",
    }

    result = analyze_alert(alert)

    assert result["mitre_attack"]["tactic_id"] == "TA0004"
    assert result["mitre_attack"]["technique_id"] is None


def test_unauthorized_api_access_does_not_assume_technique():
    alert = {
        "rule": "UNAUTHORIZED_API_ACCESS",
        "severity": "HIGH",
        "source_ip": "192.0.2.100",
        "event_count": 5,
        "description": "5 unauthorized API requests",
    }

    result = analyze_alert(alert)

    assert result["mitre_attack"]["technique_id"] is None
    assert result["analysis_type"] == "deterministic_rule_based"


def test_analyze_multiple_alerts():
    alerts = [
        {
            "rule": "BRUTE_FORCE",
            "severity": "HIGH",
            "description": "Brute force detected",
        },
        {
            "rule": "PRIVILEGE_ESCALATION",
            "severity": "CRITICAL",
            "description": "Privilege escalation detected",
        },
    ]

    results = analyze_alerts(alerts)

    assert len(results) == 2
    assert results[0]["rule"] == "BRUTE_FORCE"
    assert results[1]["rule"] == "PRIVILEGE_ESCALATION"
