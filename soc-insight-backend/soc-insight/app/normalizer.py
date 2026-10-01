"""
Log Normalizer.

Converts raw, source-specific log lines into the platform's common
structured event format:

    {
        "timestamp": datetime,
        "username": str | None,
        "source_ip": str | None,
        "event_type": "LOGIN_FAILED" | "LOGIN_SUCCESS" | "PRIVILEGE_ESCALATION"
                       | "SENSITIVE_ACCESS" | "OTHER",
        "service": str,
        "raw_log": str,
    }

Currently understands common Linux/SSH auth.log style lines. This module
is intentionally the single place that knows about log *formats* - adding
a new source (Windows Event Log, firewall, app log) means adding one more
regex + mapping function here, nothing else in the pipeline changes.
"""

import re
from datetime import datetime
from typing import Optional, Dict, Any

CURRENT_YEAR = datetime.now().year

# Sep 27 10:31:02 server sshd: Failed password for admin from 192.168.1.25
_SSH_FAILED_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*"
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)",
    re.IGNORECASE,
)

_SSH_ACCEPTED_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd.*"
    r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+)",
    re.IGNORECASE,
)

# Sep 27 10:33:04 server sudo: admin : COMMAND=/bin/su ; USER=root
_SUDO_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?sudo:\s*"
    r"(?P<user>\S+)\s*:.*?COMMAND=(?P<command>\S+)",
    re.IGNORECASE,
)

# Sep 27 10:33:20 server app: admin accessed /etc/shadow from 192.168.1.25
_SENSITIVE_RE = re.compile(
    r"(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*?:\s*"
    r"(?P<user>\S+) accessed (?P<resource>\S+)(?: from (?P<ip>[\d.]+))?",
    re.IGNORECASE,
)

SENSITIVE_PATHS = ("/etc/shadow", "/etc/passwd", "/etc/pam.d", "credentials", "secrets")


def _parse_syslog_ts(ts_str: str) -> datetime:
    """'Sep 27 10:31:02' -> datetime, assuming current year."""
    dt = datetime.strptime(f"{CURRENT_YEAR} {ts_str}", "%Y %b %d %H:%M:%S")
    return dt


def normalize_line(line: str, service: str = "SSH") -> Optional[Dict[str, Any]]:
    """Try each known pattern against a raw log line. Returns a normalized
    event dict, or None if the line doesn't match anything recognized."""
    line = line.strip()
    if not line:
        return None

    m = _SSH_FAILED_RE.search(line)
    if m:
        return {
            "timestamp": _parse_syslog_ts(m.group("ts")),
            "username": m.group("user"),
            "source_ip": m.group("ip"),
            "event_type": "LOGIN_FAILED",
            "service": service,
            "raw_log": line,
        }

    m = _SSH_ACCEPTED_RE.search(line)
    if m:
        return {
            "timestamp": _parse_syslog_ts(m.group("ts")),
            "username": m.group("user"),
            "source_ip": m.group("ip"),
            "event_type": "LOGIN_SUCCESS",
            "service": service,
            "raw_log": line,
        }

    m = _SUDO_RE.search(line)
    if m:
        return {
            "timestamp": _parse_syslog_ts(m.group("ts")),
            "username": m.group("user"),
            "source_ip": None,
            "event_type": "PRIVILEGE_ESCALATION",
            "service": service,
            "raw_log": line,
        }

    m = _SENSITIVE_RE.search(line)
    if m and any(p in m.group("resource") for p in SENSITIVE_PATHS):
        return {
            "timestamp": _parse_syslog_ts(m.group("ts")),
            "username": m.group("user"),
            "source_ip": m.group("ip"),
            "event_type": "SENSITIVE_ACCESS",
            "service": service,
            "raw_log": line,
        }

    return None


def normalize_lines(lines, service: str = "SSH"):
    """Normalize a list of raw log lines. Silently skips unrecognized lines
    (a production version would route these to an 'unparsed' bucket for
    review rather than dropping them)."""
    events = []
    for line in lines:
        event = normalize_line(line, service=service)
        if event:
            events.append(event)
    return events
