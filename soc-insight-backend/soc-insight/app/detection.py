"""
Detection Engine.

Runs a set of rule-based detectors against LogEvent rows stored in the DB.
Each detector looks at a relevant slice of events and returns zero or more
"findings" - plain dicts describing what was detected, before they're
turned into Alert rows (that happens in main.py / the ingest pipeline).

Rules implemented (mirroring the proposal):
    1. Brute force: N+ failed logins, same user+ip, within a time window
    2. Successful login after multiple failures (possible compromise)
    3. Unusual login time (outside configured business hours)
    4. Privilege escalation shortly after a login
    5. Sensitive resource access shortly after privilege escalation

Thresholds are module-level constants so they're easy to tune without
touching the detection logic itself.
"""

from datetime import timedelta
from collections import defaultdict
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from app.models import LogEvent

# ---- Tunable thresholds -----------------------------------------------
BRUTE_FORCE_FAILED_THRESHOLD = 10      # failed attempts
BRUTE_FORCE_WINDOW_MINUTES = 5
REPEATED_FAILURE_THRESHOLD = 5
BUSINESS_HOURS_START = 6                # 06:00
BUSINESS_HOURS_END = 22                 # 22:00
POST_LOGIN_ESCALATION_WINDOW_MINUTES = 15
POST_ESCALATION_SENSITIVE_WINDOW_MINUTES = 15
# -------------------------------------------------------------------------


def _group_by_user_ip(events: List[LogEvent]):
    groups = defaultdict(list)
    for e in events:
        groups[(e.username, e.source_ip)].append(e)
    for key in groups:
        groups[key].sort(key=lambda e: e.timestamp)
    return groups


def detect_brute_force(events: List[LogEvent]) -> List[Dict[str, Any]]:
    """10+ failed logins, same username+IP, within a short window."""
    findings = []
    failed = [e for e in events if e.event_type == "LOGIN_FAILED"]
    for (user, ip), group in _group_by_user_ip(failed).items():
        window = []
        for e in group:
            window.append(e)
            window = [w for w in window if e.timestamp - w.timestamp <=
                      timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)]
            if len(window) >= BRUTE_FORCE_FAILED_THRESHOLD:
                findings.append({
                    "alert_type": "BRUTE_FORCE",
                    "severity": "HIGH",
                    "username": user,
                    "source_ip": ip,
                    "description": (
                        f"{len(window)} failed login attempts for user '{user}' "
                        f"from {ip} within {BRUTE_FORCE_WINDOW_MINUTES} minutes."
                    ),
                    "evidence_log_ids": [w.id for w in window],
                })
                window = []  # reset so we don't re-fire on every extra failure
    return findings


def detect_repeated_failures(events: List[LogEvent]) -> List[Dict[str, Any]]:
    """5+ failed logins for a user/IP that don't necessarily hit brute-force
    volume/speed, but are still worth a lower-severity alert."""
    findings = []
    failed = [e for e in events if e.event_type == "LOGIN_FAILED"]
    for (user, ip), group in _group_by_user_ip(failed).items():
        if REPEATED_FAILURE_THRESHOLD <= len(group) < BRUTE_FORCE_FAILED_THRESHOLD:
            findings.append({
                "alert_type": "REPEATED_AUTH_FAILURES",
                "severity": "MEDIUM",
                "username": user,
                "source_ip": ip,
                "description": (
                    f"{len(group)} failed login attempts for user '{user}' from {ip}."
                ),
                "evidence_log_ids": [e.id for e in group],
            })
    return findings


def detect_success_after_failures(events: List[LogEvent]) -> List[Dict[str, Any]]:
    """A successful login immediately preceded by several failures - a
    classic indicator of a guessed or brute-forced credential."""
    findings = []
    by_user_ip = _group_by_user_ip(events)
    for (user, ip), group in by_user_ip.items():
        for i, e in enumerate(group):
            if e.event_type != "LOGIN_SUCCESS":
                continue
            preceding_failures = [
                p for p in group[:i]
                if p.event_type == "LOGIN_FAILED"
                and e.timestamp - p.timestamp <= timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
            ]
            if len(preceding_failures) >= 3:
                findings.append({
                    "alert_type": "SUCCESS_AFTER_FAILURES",
                    "severity": "HIGH",
                    "username": user,
                    "source_ip": ip,
                    "description": (
                        f"Successful login for '{user}' from {ip} followed "
                        f"{len(preceding_failures)} failed attempts - possible "
                        f"account compromise."
                    ),
                    "evidence_log_ids": [p.id for p in preceding_failures] + [e.id],
                })
    return findings


def detect_unusual_login_time(events: List[LogEvent]) -> List[Dict[str, Any]]:
    """Successful logins outside configured business hours."""
    findings = []
    for e in events:
        if e.event_type != "LOGIN_SUCCESS":
            continue
        hour = e.timestamp.hour
        if hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END:
            findings.append({
                "alert_type": "UNUSUAL_LOGIN_TIME",
                "severity": "MEDIUM",
                "username": e.username,
                "source_ip": e.source_ip,
                "description": (
                    f"Login for '{e.username}' from {e.source_ip} at "
                    f"{e.timestamp.strftime('%H:%M')}, outside normal "
                    f"business hours."
                ),
                "evidence_log_ids": [e.id],
            })
    return findings


def detect_privilege_escalation(events: List[LogEvent]) -> List[Dict[str, Any]]:
    """A privilege escalation (sudo) event shortly after a login for the
    same user."""
    findings = []
    by_user = defaultdict(list)
    for e in events:
        if e.username:
            by_user[e.username].append(e)
    for user, group in by_user.items():
        group.sort(key=lambda e: e.timestamp)
        logins = [e for e in group if e.event_type == "LOGIN_SUCCESS"]
        escalations = [e for e in group if e.event_type == "PRIVILEGE_ESCALATION"]
        for esc in escalations:
            recent_logins = [
                l for l in logins
                if timedelta(0) <= esc.timestamp - l.timestamp
                <= timedelta(minutes=POST_LOGIN_ESCALATION_WINDOW_MINUTES)
            ]
            if recent_logins:
                login = recent_logins[-1]
                findings.append({
                    "alert_type": "PRIVILEGE_ESCALATION",
                    "severity": "HIGH",
                    "username": user,
                    "source_ip": login.source_ip,
                    "description": (
                        f"Privileged command executed by '{user}' shortly "
                        f"after login."
                    ),
                    "evidence_log_ids": [login.id, esc.id],
                })
    return findings


def detect_sensitive_access(events: List[LogEvent]) -> List[Dict[str, Any]]:
    """Sensitive resource access shortly after a privilege escalation -
    the strongest single-event indicator in this ruleset."""
    findings = []
    by_user = defaultdict(list)
    for e in events:
        if e.username:
            by_user[e.username].append(e)
    for user, group in by_user.items():
        group.sort(key=lambda e: e.timestamp)
        escalations = [e for e in group if e.event_type == "PRIVILEGE_ESCALATION"]
        accesses = [e for e in group if e.event_type == "SENSITIVE_ACCESS"]
        for acc in accesses:
            recent_esc = [
                esc for esc in escalations
                if timedelta(0) <= acc.timestamp - esc.timestamp
                <= timedelta(minutes=POST_ESCALATION_SENSITIVE_WINDOW_MINUTES)
            ]
            if recent_esc:
                findings.append({
                    "alert_type": "SENSITIVE_RESOURCE_ACCESS",
                    "severity": "CRITICAL",
                    "username": user,
                    "source_ip": acc.source_ip,
                    "description": (
                        f"Sensitive resource accessed by '{user}' shortly "
                        f"after a privilege escalation."
                    ),
                    "evidence_log_ids": [recent_esc[-1].id, acc.id],
                })
    return findings


ALL_DETECTORS = [
    detect_brute_force,
    detect_repeated_failures,
    detect_success_after_failures,
    detect_unusual_login_time,
    detect_privilege_escalation,
    detect_sensitive_access,
]


def run_all_detectors(db: Session, events: List[LogEvent]) -> List[Dict[str, Any]]:
    """Run every detector against the given batch of events and return the
    combined list of findings. Detectors only need the in-memory events
    passed in (typically "all events for the affected users/IPs in this
    batch, plus recent history"), so this stays fast even as log volume
    grows, since we don't scan the entire table on every ingest."""
    findings = []
    for detector in ALL_DETECTORS:
        findings.extend(detector(events))
    return findings
