"""
Correlation Engine.

Takes the flat list of Alert findings produced by the detection engine and
groups the ones that belong to the same story (same username + source_ip,
close in time) into a single Incident, rather than leaving the analyst to
manually connect them.

Also builds the incident's timeline and picks its overall severity and
recommended actions.
"""

from datetime import datetime, timedelta
from collections import defaultdict
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from app.models import LogEvent, Incident, IncidentTimelineEvent
from app.severity import classify_incident_type_and_severity, recommend_actions

CORRELATION_WINDOW_MINUTES = 20


def _next_incident_code(db: Session) -> str:
    count = db.query(Incident).count() + 1
    year = datetime.now().year
    return f"INC-{year}-{count:03d}"


def correlate_findings(db: Session, findings: List[Dict[str, Any]]) -> List[Incident]:
    """Group findings by (username, source_ip) - since that's the anchor of
    an attack "story" in this ruleset - and, within each group, cluster
    findings that fall within CORRELATION_WINDOW_MINUTES of each other into
    one incident. Isolated low-signal findings still become alerts, but
    only clusters of 2+ related findings become an incident (a single
    finding is just an alert, not yet a "story").
    """
    groups = defaultdict(list)
    for f in findings:
        key = (f.get("username"), f.get("source_ip"))
        groups[key].append(f)

    created_incidents = []

    for (username, source_ip), group_findings in groups.items():
        if len(group_findings) < 2:
            continue  # a single alert doesn't need its own incident

        # gather all evidence log ids across the group, sorted by time via LogEvent lookup
        log_ids = sorted(set(
            lid for f in group_findings for lid in f.get("evidence_log_ids", [])
        ))
        logs = (
            db.query(LogEvent)
            .filter(LogEvent.id.in_(log_ids))
            .order_by(LogEvent.timestamp)
            .all()
        )
        if not logs:
            continue

        detection_time = logs[0].timestamp
        alert_types = [f["alert_type"] for f in group_findings]

        incident_type, severity = classify_incident_type_and_severity(alert_types)

        incident = Incident(
            incident_code=_next_incident_code(db),
            incident_type=incident_type,
            severity=severity,
            status="OPEN",
            affected_account=username,
            source_ip=source_ip,
            detection_time=detection_time,
            evidence=[f["description"] for f in group_findings],
            recommended_actions=recommend_actions(incident_type),
        )
        db.add(incident)
        db.flush()  # get incident.id before adding timeline rows

        for log in logs:
            db.add(IncidentTimelineEvent(
                incident_id=incident.id,
                timestamp=log.timestamp,
                description=f"{log.event_type.replace('_', ' ').title()} "
                            f"({log.service or 'unknown service'})"
                            + (f" - {log.username}" if log.username else "")
                            + (f" from {log.source_ip}" if log.source_ip else ""),
                log_event_id=log.id,
            ))

        created_incidents.append(incident)

    return created_incidents
