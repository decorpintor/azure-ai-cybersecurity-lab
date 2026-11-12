import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

from detection.engine import analyze_events


now = datetime.now(timezone.utc)

events = []

# Five failed login attempts
for i in range(5):
    events.append({
        "timestamp": (now - timedelta(seconds=30-i)).isoformat(),
        "event_type": "login",
        "status": "failed",
        "source_ip": "192.0.2.50",
        "username": "admin"
    })

# Privilege escalation event
events.append({
    "timestamp": now.isoformat(),
    "event_type": "privilege_escalation",
    "status": "success",
    "source_ip": "192.0.2.75",
    "username": "testuser"
})

# Save test events
log_file = Path("detection/sample-logs/events.json")
log_file.write_text(json.dumps(events, indent=2))

# Analyze events
alerts = analyze_events(events)

print("\n===== CYBERSECURITY THREAT DETECTION =====")

for alert in alerts:
    print(f"\nSeverity: {alert['severity']}")
    print(f"Rule: {alert['rule']}")
    print(f"Description: {alert['description']}")

print("\n==========================================")
print(f"Total alerts detected: {len(alerts)}")
