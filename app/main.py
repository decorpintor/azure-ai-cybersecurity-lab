from datetime import datetime
from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel, Field, field_validator

from detection.engine import analyze_events
from ai.incident_analyst import analyze_alerts


app = FastAPI(
    title="Azure AI Cybersecurity Lab",
    description="AI-assisted security monitoring and threat detection",
    version="1.2.0",
)


class SecurityEvent(BaseModel):
    timestamp: datetime

    event_type: Literal[
        "login",
        "privilege_escalation",
        "api_access",
    ]

    status: Literal[
        "failed",
        "success",
        "unauthorized",
    ]

    source_ip: str
    username: str

    @field_validator("timestamp")
    @classmethod
    def require_timezone(cls, value):
        if value.tzinfo is None:
            raise ValueError("Timestamp must include a timezone")
        return value


class EventsRequest(BaseModel):
    events: list[SecurityEvent] = Field(
        min_length=1,
        max_length=1000,
    )


@app.get("/")
def root():
    return {
        "project": "Azure AI Cybersecurity Lab",
        "status": "operational",
        "message": "Security monitoring API is running",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/rules")
def rules():
    return {
        "detection_rules": [
            "BRUTE_FORCE",
            "PRIVILEGE_ESCALATION",
            "UNAUTHORIZED_API_ACCESS",
        ]
    }


@app.post("/analyze")
def analyze(
    request: EventsRequest,
    use_ai: bool = False,
):
    events = [
        event.model_dump(mode="json")
        for event in request.events
    ]

    alerts = analyze_events(events)

    incident_analyses = analyze_alerts(
        alerts,
        use_ai=use_ai,
    )

    return {
        "total_events": len(events),
        "total_alerts": len(alerts),
        "ai_enabled": use_ai,
        "alerts": alerts,
        "incident_analyses": incident_analyses,
    }
