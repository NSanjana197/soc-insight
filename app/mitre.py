"""
MITRE ATT&CK Mapping.

Maps each detection rule's alert_type to the MITRE ATT&CK technique it
corresponds to, per the "Advanced Features" section of the project
proposal. This is a lookup table, not a live API call - MITRE technique
IDs are stable identifiers, so a static mapping is the correct approach
here rather than an external dependency.

Reference: https://attack.mitre.org/
"""

MITRE_MAP = {
    "BRUTE_FORCE": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "REPEATED_AUTH_FAILURES": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "SUCCESS_AFTER_FAILURES": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "UNUSUAL_LOGIN_TIME": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "NEW_SOURCE_IP": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
    "PRIVILEGE_ESCALATION": {
        "id": "T1548.003",
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation, Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1548/003/",
    },
    "SENSITIVE_RESOURCE_ACCESS": {
        "id": "T1552.001",
        "name": "Unsecured Credentials: Credentials In Files",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1552/001/",
    },
}


def get_technique(alert_type: str):
    """Returns the MITRE technique dict for an alert type, or None if this
    alert type has no mapping yet."""
    return MITRE_MAP.get(alert_type)
