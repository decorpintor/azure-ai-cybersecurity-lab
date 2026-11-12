MITRE_MAPPINGS = {
    "BRUTE_FORCE": {
        "tactic_id": "TA0006",
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique": "Brute Force",
        "mapping_basis": (
            "Repeated failed login attempts are consistent "
            "with brute-force activity."
        ),
    },
    "PRIVILEGE_ESCALATION": {
        "tactic_id": "TA0004",
        "tactic": "Privilege Escalation",
        "technique_id": None,
        "technique": None,
        "mapping_basis": (
            "Privilege escalation was reported, but the "
            "specific mechanism is not available in the event."
        ),
    },
    "UNAUTHORIZED_API_ACCESS": {
        "tactic_id": None,
        "tactic": None,
        "technique_id": None,
        "technique": None,
        "mapping_basis": (
            "Unauthorized API activity alone is insufficient "
            "to assign a specific MITRE ATT&CK technique."
        ),
    },
}
