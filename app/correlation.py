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


def correlate_findings(
    db: Session,
    findings: List[Dict[str, Any]]
) -> List[Incident]:
    """Group findings by username + source IP and create one incident
    for a cluster of related findings.

    Duplicate protection prevents the same attack story from creating
    another incident when the same simulation/log pattern is processed
    again within the correlation window.
    """

    groups = defaultdict(list)

    for f in findings:
        key = (f.get("username"), f.get("source_ip"))
        groups[key].append(f)

    created_incidents = []

    for (username, source_ip), group_findings in groups.items():

        if len(group_findings) < 2:
            continue

        # Gather evidence log IDs.
        log_ids = sorted(set(
            lid
            for f in group_findings
            for lid in f.get("evidence_log_ids", [])
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

        alert_types = [
            f["alert_type"]
            for f in group_findings
        ]

        incident_type, severity = classify_incident_type_and_severity(
            alert_types
        )

        # ---------------------------------------------------------
        # DUPLICATE INCIDENT PROTECTION
        # ---------------------------------------------------------
        #
        # The same simulation creates NEW LogEvent IDs each time.
        # Therefore, checking log_event_id alone is not enough.
        #
        # Instead, check whether an incident already exists for:
        #   - same account
        #   - same source IP
        #   - same incident type
        #   - within the correlation window
        #
        window_start = detection_time - timedelta(
            minutes=CORRELATION_WINDOW_MINUTES
        )

        window_end = detection_time + timedelta(
            minutes=CORRELATION_WINDOW_MINUTES
        )

        existing_incident = (
            db.query(Incident)
            .filter(
                Incident.affected_account == username,
                Incident.source_ip == source_ip,
                Incident.incident_type == incident_type,
                Incident.detection_time >= window_start,
                Incident.detection_time <= window_end,
            )
            .first()
        )

        if existing_incident:
            # This attack story already has an incident.
            # Do not create another duplicate incident.
            continue

        # ---------------------------------------------------------
        # CREATE NEW INCIDENT
        # ---------------------------------------------------------

        incident = Incident(
            incident_code=_next_incident_code(db),
            incident_type=incident_type,
            severity=severity,
            status="OPEN",
            affected_account=username,
            source_ip=source_ip,
            detection_time=detection_time,
            evidence=[
                f["description"]
                for f in group_findings
            ],
            recommended_actions=recommend_actions(incident_type),
        )

        db.add(incident)
        db.flush()

        # Build incident timeline.
        for log in logs:

            description = (
                f"{log.event_type.replace('_', ' ').title()} "
                f"({log.service or 'unknown service'})"
            )

            if log.username:
                description += f" - {log.username}"

            if log.source_ip:
                description += f" from {log.source_ip}"

            db.add(
                IncidentTimelineEvent(
                    incident_id=incident.id,
                    timestamp=log.timestamp,
                    description=description,
                    log_event_id=log.id,
                )
            )

        created_incidents.append(incident)

    return created_incidents