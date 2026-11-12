import json
import logging

import httpx
import pytest

from ai import incident_analyst, ollama_client


SAMPLE_ALERT = {
    "rule": "BRUTE_FORCE",
    "severity": "HIGH",
    "source_ip": "192.0.2.50",
    "event_count": 5,
    "description": "5 failed login attempts from 192.0.2.50",
}

VALID_AI_RESPONSE = {
    "assessment": "Possible brute-force activity requires investigation.",
    "recommended_actions": [
        "Review authentication logs.",
        "Check for successful logins."
    ],
    "confidence": "medium",
    "limitations": [
        "The targeted service is unknown."
    ],
}


class MockResponse:
    def __init__(self, data):
        self.data = data

    def json(self):
        return self.data

    def raise_for_status(self):
        pass


def mock_ollama_response(monkeypatch, response):
    monkeypatch.setattr(
        ollama_client.httpx,
        "post",
        lambda *args, **kwargs: MockResponse(response),
    )


def test_successful_ollama_response(monkeypatch):
    mock_ollama_response(
        monkeypatch,
        {"response": json.dumps(VALID_AI_RESPONSE)},
    )

    result = ollama_client.analyze_alert_with_ollama(SAMPLE_ALERT)

    assert result["status"] == "success"
    assert result["model"] == "qwen2.5:3b"
    assert result["assessment"] == VALID_AI_RESPONSE["assessment"]
    assert result["confidence"] == "medium"


def test_ollama_unavailable(monkeypatch):
    def unavailable(*args, **kwargs):
        raise httpx.ConnectError("Ollama unavailable")

    monkeypatch.setattr(
        ollama_client.httpx,
        "post",
        unavailable,
    )

    with pytest.raises(httpx.ConnectError):
        ollama_client.analyze_alert_with_ollama(SAMPLE_ALERT)


def test_ollama_timeout(monkeypatch):
    def timeout(*args, **kwargs):
        raise httpx.TimeoutException("Ollama request timed out")

    monkeypatch.setattr(
        ollama_client.httpx,
        "post",
        timeout,
    )

    with pytest.raises(httpx.TimeoutException):
        ollama_client.analyze_alert_with_ollama(SAMPLE_ALERT)


def test_invalid_json_from_model(monkeypatch):
    mock_ollama_response(
        monkeypatch,
        {"response": "This is not valid JSON"},
    )

    with pytest.raises(json.JSONDecodeError):
        ollama_client.analyze_alert_with_ollama(SAMPLE_ALERT)


def test_missing_required_response_fields(monkeypatch):
    incomplete_response = {
        "assessment": "Possible brute-force activity.",
        "confidence": "medium",
    }

    mock_ollama_response(
        monkeypatch,
        {"response": json.dumps(incomplete_response)},
    )

    with pytest.raises(ValueError, match="missing required fields"):
        ollama_client.analyze_alert_with_ollama(SAMPLE_ALERT)


def test_invalid_ollama_url_rejected(monkeypatch):
    monkeypatch.setattr(
        ollama_client,
        "OLLAMA_URL",
        "file:///etc/passwd",
    )

    with pytest.raises(ValueError, match="HTTP or HTTPS"):
        ollama_client.analyze_alert_with_ollama(SAMPLE_ALERT)


def test_ollama_url_without_hostname_rejected(monkeypatch):
    monkeypatch.setattr(
        ollama_client,
        "OLLAMA_URL",
        "http:///api",
    )

    with pytest.raises(ValueError, match="hostname"):
        ollama_client.analyze_alert_with_ollama(SAMPLE_ALERT)


def test_deterministic_analysis_survives_ai_failure(monkeypatch, caplog):
    caplog.set_level(
        logging.ERROR,
        logger="ai.incident_analyst",
    )

    def ai_failure(alert):
        raise ConnectionError("Ollama unavailable")

    monkeypatch.setattr(
        incident_analyst,
        "analyze_alert_with_ollama",
        ai_failure,
    )

    results = incident_analyst.analyze_alerts(
        [SAMPLE_ALERT],
        use_ai=True,
    )

    analysis = results[0]

    assert analysis["rule"] == "BRUTE_FORCE"
    assert analysis["severity"] == "HIGH"
    assert analysis["mitre_attack"]["technique_id"] == "T1110"
    assert analysis["analysis_type"] == "deterministic_rule_based"
    assert analysis["ai_analysis"]["status"] == "unavailable"

    assert "Local AI analysis failed for rule BRUTE_FORCE" in caplog.text
    assert "Ollama unavailable" in caplog.text


def test_ai_disabled_does_not_call_ollama(monkeypatch):
    def unexpected_call(alert):
        pytest.fail("Ollama should not be called when use_ai=False")

    monkeypatch.setattr(
        incident_analyst,
        "analyze_alert_with_ollama",
        unexpected_call,
    )

    results = incident_analyst.analyze_alerts(
        [SAMPLE_ALERT],
        use_ai=False,
    )

    assert len(results) == 1
    assert results[0]["rule"] == "BRUTE_FORCE"
    assert "ai_analysis" not in results[0]
