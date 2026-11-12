from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.main import app
from detection.engine import analyze_events


client = TestClient(app)


def make_event(event_type, status, source_ip="192.0.2.50",
               username="testuser", timestamp=None):
    return {
        "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
        "event_type": event_type,
        "status": status,
        "source_ip": source_ip,
        "username": username,
    }


def test_brute_force_detection():
    events = [
        make_event("login", "failed")
        for _ in range(5)
    ]

    alerts = analyze_events(events)

    assert any(alert["rule"] == "BRUTE_FORCE" for alert in alerts)


def test_four_failed_logins_do_not_trigger_alert():
    events = [
        make_event("login", "failed")
        for _ in range(4)
    ]

    alerts = analyze_events(events)

    assert not any(alert["rule"] == "BRUTE_FORCE" for alert in alerts)


def test_privilege_escalation_detection():
    events = [
        make_event("privilege_escalation", "success")
    ]

    alerts = analyze_events(events)

    assert any(
        alert["rule"] == "PRIVILEGE_ESCALATION"
        and alert["severity"] == "CRITICAL"
        for alert in alerts
    )


def test_old_events_are_ignored():
    old_timestamp = datetime.now(timezone.utc) - timedelta(minutes=10)

    events = [
        make_event("login", "failed", timestamp=old_timestamp)
        for _ in range(5)
    ]

    alerts = analyze_events(events)

    assert alerts == []


def test_analyze_api_returns_alerts():
    events = [
        make_event("login", "failed")
        for _ in range(5)
    ]

    events.append(
        make_event(
            "privilege_escalation",
            "success",
            source_ip="192.0.2.75"
        )
    )

    response = client.post("/analyze", json={"events": events})

    assert response.status_code == 200

    result = response.json()

    assert result["total_events"] == 6
    assert result["total_alerts"] == 2


def test_analyze_api_rejects_empty_events():
    response = client.post("/analyze", json={"events": []})

    assert response.status_code == 422

def test_unauthorized_api_access_detection():
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()

    events = [
        {
            "timestamp": now,
            "event_type": "api_access",
            "status": "unauthorized",
            "source_ip": "192.0.2.100",
            "username": "testuser",
        }
        for _ in range(5)
    ]

    response = client.post("/analyze", json={"events": events})

    assert response.status_code == 200

    result = response.json()

    assert result["total_alerts"] == 1
    assert result["alerts"][0]["rule"] == "UNAUTHORIZED_API_ACCESS"
    assert result["alerts"][0]["severity"] == "HIGH"


def test_four_unauthorized_api_requests_do_not_trigger_alert():
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc).isoformat()

    events = [
        {
            "timestamp": now,
            "event_type": "api_access",
            "status": "unauthorized",
            "source_ip": "192.0.2.100",
            "username": "testuser",
        }
        for _ in range(4)
    ]

    response = client.post("/analyze", json={"events": events})

    assert response.status_code == 200
    assert response.json()["total_alerts"] == 0

def test_api_ai_disabled_returns_deterministic_analysis(monkeypatch):
    from ai import incident_analyst

    def unexpected_ai_call(alert):
        raise AssertionError("AI should not be called")

    monkeypatch.setattr(
        incident_analyst,
        "analyze_alert_with_ollama",
        unexpected_ai_call,
    )

    events = [
        make_event("login", "failed")
        for _ in range(5)
    ]

    response = client.post(
        "/analyze?use_ai=false",
        json={"events": events},
    )

    assert response.status_code == 200

    result = response.json()

    assert result["ai_enabled"] is False
    assert result["total_alerts"] == 1
    assert result["incident_analyses"][0]["rule"] == "BRUTE_FORCE"
    assert "ai_analysis" not in result["incident_analyses"][0]


def test_api_ai_enabled_returns_ai_analysis(monkeypatch):
    from ai import incident_analyst

    def mock_ai_analysis(alert):
        return {
            "status": "success",
            "model": "qwen2.5:3b",
            "assessment": "Possible brute-force activity.",
            "recommended_actions": ["Review authentication logs."],
            "confidence": "medium",
            "limitations": ["Targeted service is unknown."],
        }

    monkeypatch.setattr(
        incident_analyst,
        "analyze_alert_with_ollama",
        mock_ai_analysis,
    )

    events = [
        make_event("login", "failed")
        for _ in range(5)
    ]

    response = client.post(
        "/analyze?use_ai=true",
        json={"events": events},
    )

    assert response.status_code == 200

    result = response.json()
    analysis = result["incident_analyses"][0]

    assert result["ai_enabled"] is True
    assert result["total_alerts"] == 1
    assert analysis["rule"] == "BRUTE_FORCE"
    assert analysis["severity"] == "HIGH"
    assert analysis["ai_analysis"]["status"] == "success"
    assert analysis["ai_analysis"]["model"] == "qwen2.5:3b"


def test_api_ollama_failure_preserves_deterministic_alert(monkeypatch):
    from ai import incident_analyst

    def failed_ai_analysis(alert):
        raise ConnectionError("Ollama unavailable")

    monkeypatch.setattr(
        incident_analyst,
        "analyze_alert_with_ollama",
        failed_ai_analysis,
    )

    events = [
        make_event("login", "failed")
        for _ in range(5)
    ]

    response = client.post(
        "/analyze?use_ai=true",
        json={"events": events},
    )

    assert response.status_code == 200

    result = response.json()
    analysis = result["incident_analyses"][0]

    assert result["total_alerts"] == 1
    assert analysis["rule"] == "BRUTE_FORCE"
    assert analysis["severity"] == "HIGH"
    assert analysis["mitre_attack"]["technique_id"] == "T1110"
    assert analysis["ai_analysis"]["status"] == "unavailable"


def test_api_rejects_invalid_event_data():
    events = [
        make_event("login", "failed")
        for _ in range(5)
    ]

    events[0]["event_type"] = "unknown_event"

    response = client.post(
        "/analyze",
        json={"events": events},
    )

    assert response.status_code == 422
