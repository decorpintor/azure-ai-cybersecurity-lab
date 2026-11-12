from ai.mitre_mapping import MITRE_MAPPINGS
from ai.ollama_client import analyze_alert_with_ollama

import logging
logger = logging.getLogger(__name__)
RESPONSE_GUIDANCE = {
    "BRUTE_FORCE": {
        "assessment": (
            "Multiple failed authentication attempts indicate "
            "possible password guessing or credential abuse."
        ),
        "recommended_actions": [
            "Review authentication logs for the affected account.",
            "Check whether any login attempts succeeded.",
            "Investigate the source IP and related activity.",
            "Apply rate limiting or temporary IP restrictions "
            "where appropriate.",
            "Require a password reset if account compromise "
            "is suspected.",
        ],
    },
    "PRIVILEGE_ESCALATION": {
        "assessment": (
            "A privilege escalation event may indicate an attempt "
            "to obtain permissions beyond the user's normal access."
        ),
        "recommended_actions": [
            "Verify whether the privilege change was authorized.",
            "Review IAM roles, group membership, and permission changes.",
            "Inspect audit logs around the event timestamp.",
            "Revoke unauthorized privileges.",
            "Investigate activity performed using the elevated access.",
        ],
    },
    "UNAUTHORIZED_API_ACCESS": {
        "assessment": (
            "Repeated unauthorized API requests may indicate "
            "access-control probing or attempted misuse of an API."
        ),
        "recommended_actions": [
            "Review API gateway and application access logs.",
            "Identify the endpoints and resources targeted.",
            "Check authentication and authorization failures.",
            "Inspect associated tokens, keys, and service accounts.",
            "Apply rate limiting and block malicious sources "
            "when justified by the investigation.",
        ],
    },
}


def analyze_alert(alert):
    rule = alert["rule"]

    mitre = MITRE_MAPPINGS.get(
        rule,
        {
            "tactic_id": None,
            "tactic": None,
            "technique_id": None,
            "technique": None,
            "mapping_basis": "No MITRE mapping is available.",
        },
    )

    guidance = RESPONSE_GUIDANCE.get(
        rule,
        {
            "assessment": "The alert requires manual investigation.",
            "recommended_actions": [
                "Review the original security events.",
                "Correlate the activity with other security logs.",
            ],
        },
    )

    evidence = {
        key: alert[key]
        for key in (
            "source_ip",
            "username",
            "event_count",
            "description",
        )
        if key in alert
    }

    return {
        "rule": rule,
        "severity": alert["severity"],
        "summary": alert["description"],
        "assessment": guidance["assessment"],
        "mitre_attack": mitre,
        "evidence": evidence,
        "recommended_actions": guidance["recommended_actions"],
        "analysis_type": "deterministic_rule_based",
    }


def analyze_alerts(alerts, use_ai=False):
    results = []

    for alert in alerts:
        analysis = analyze_alert(alert)

        if use_ai:
            try:
                analysis["ai_analysis"] = analyze_alert_with_ollama(
                    alert
                )
            except Exception:
                logger.exception(
                    "Local AI analysis failed for rule %s",
                    alert["rule"],
                )

                analysis["ai_analysis"] = {
                    "status": "unavailable",
                    "message": (
                        "Local AI analysis failed. "
                        "Deterministic analysis remains available."
                    ),
                }

        results.append(analysis)

    return results
