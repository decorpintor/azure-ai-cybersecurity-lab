from collections import Counter
from datetime import datetime, timedelta, timezone


def analyze_events(events):
    alerts = []

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=5)

    recent_events = []

    for event in events:
        timestamp = datetime.fromisoformat(
            event["timestamp"].replace("Z", "+00:00")
        )

        if window_start <= timestamp <= now:
            recent_events.append(event)

    # Brute-force detection
    failed_logins = Counter(
        event["source_ip"]
        for event in recent_events
        if event["event_type"] == "login"
        and event["status"] == "failed"
    )

    for ip, count in failed_logins.items():
        if count >= 5:
            alerts.append({
                "rule": "BRUTE_FORCE",
                "severity": "HIGH",
                "source_ip": ip,
                "event_count": count,
                "description": (
                    f"{count} failed login attempts from {ip}"
                )
            })

    # Privilege escalation detection
    for event in recent_events:
        if event["event_type"] == "privilege_escalation":
            alerts.append({
                "rule": "PRIVILEGE_ESCALATION",
                "severity": "CRITICAL",
                "source_ip": event["source_ip"],
                "username": event["username"],
                "description": (
                    f"Privilege escalation detected for "
                    f"{event['username']}"
                )
            })

    # Unauthorized API access
    unauthorized = Counter(
        event["source_ip"]
        for event in recent_events
        if event["event_type"] == "api_access"
        and event["status"] == "unauthorized"
    )

    for ip, count in unauthorized.items():
        if count >= 5:
            alerts.append({
                "rule": "UNAUTHORIZED_API_ACCESS",
                "severity": "HIGH",
                "source_ip": ip,
                "event_count": count,
                "description": (
                    f"{count} unauthorized API requests from {ip}"
                )
            })

    return alerts
