"""
Incident severity classification.

Maps a set of co-occurring alert types (from the correlation engine) to an
incident type and severity, following the rules in the proposal:

    CRITICAL - account compromise combined with privileged access and
               sensitive resource access
    HIGH     - brute-force activity, or successful auth after failures
    MEDIUM   - unusual login location/time
    LOW      - minor authentication anomalies

Severity is derived from documented rules, not from a single "everything
unusual is an attack" heuristic.
"""

from typing import List, Tuple

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _highest(a: str, b: str) -> str:
    return a if SEVERITY_ORDER.index(a) >= SEVERITY_ORDER.index(b) else b


def classify_incident_type_and_severity(alert_types: List[str]) -> Tuple[str, str]:
    types = set(alert_types)

    has_sensitive_access = "SENSITIVE_RESOURCE_ACCESS" in types
    has_privilege_escalation = "PRIVILEGE_ESCALATION" in types
    has_success_after_failures = "SUCCESS_AFTER_FAILURES" in types
    has_brute_force = "BRUTE_FORCE" in types
    has_unusual_time = "UNUSUAL_LOGIN_TIME" in types
    has_repeated_failures = "REPEATED_AUTH_FAILURES" in types

    if has_sensitive_access and (has_privilege_escalation or has_success_after_failures):
        return "ACCOUNT_COMPROMISE", "CRITICAL"

    if has_success_after_failures and has_privilege_escalation:
        return "ACCOUNT_COMPROMISE", "CRITICAL"

    if has_brute_force or has_success_after_failures:
        return "POSSIBLE_ACCOUNT_COMPROMISE", "HIGH"

    if has_privilege_escalation:
        return "PRIVILEGE_ESCALATION", "HIGH"

    if has_unusual_time:
        return "UNUSUAL_LOGIN_ACTIVITY", "MEDIUM"

    if has_repeated_failures:
        return "REPEATED_AUTH_FAILURES", "MEDIUM"

    return "AUTHENTICATION_ANOMALY", "LOW"


def recommend_actions(incident_type: str) -> List[str]:
    common = [
        "Review the affected account's recent activity.",
        "Preserve relevant logs and evidence.",
    ]
    specific = {
        "ACCOUNT_COMPROMISE": [
            "Reset credentials for the affected account immediately.",
            "Investigate the source IP address.",
            "Review all privileged commands executed during the session.",
            "Check for lateral movement to other accounts or systems.",
        ],
        "POSSIBLE_ACCOUNT_COMPROMISE": [
            "Investigate the source IP address.",
            "Confirm whether the successful login was legitimate with the account owner.",
            "Consider resetting credentials as a precaution.",
        ],
        "PRIVILEGE_ESCALATION": [
            "Review the specific privileged commands executed.",
            "Confirm the escalation was authorized.",
        ],
        "UNUSUAL_LOGIN_ACTIVITY": [
            "Confirm the login time/location with the account owner.",
        ],
        "REPEATED_AUTH_FAILURES": [
            "Monitor the account and source IP for continued attempts.",
        ],
        "AUTHENTICATION_ANOMALY": [
            "Continue monitoring; no immediate action required.",
        ],
    }
    return common + specific.get(incident_type, [])
