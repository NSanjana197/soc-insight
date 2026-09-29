"""
Ties the modules together into the pipeline described in the proposal:

    Parse -> Normalize -> Store -> Detect -> Correlate -> Incident -> Timeline

This is the one function both the /logs/ingest and /simulate endpoints
call, so there's a single source of truth for "what happens to a log once
it arrives".
"""

from typing import List, Dict, Any
from datetime import timedelta

from sqlalchemy.orm import Session

from app.models import LogEvent, Alert
from app.detection import run_all_detectors
from app.correlation import correlate_findings


CORRELATION_WINDOW_MINUTES = 20


def _finding_is_duplicate_alert(
    db: Session,
    finding: Dict[str, Any],
) -> bool:
    """
    Check whether this detection finding already exists as an alert.

    A new simulation creates new LogEvent IDs, so comparing only
    evidence_log_ids is not enough.

    Instead, compare:
        - alert type
        - username
        - source IP
        - evidence timestamps

    If the same type of detection for the same account/IP occurs
    within the correlation window of an existing alert, treat it
    as the same alert and do not create another one.
    """

    alert_type = finding.get("alert_type")
    username = finding.get("username")
    source_ip = finding.get("source_ip")

    evidence_log_ids = finding.get("evidence_log_ids", [])

    if not evidence_log_ids:
        return False

    # Get timestamps of the new finding's evidence logs.
    new_logs = (
        db.query(LogEvent)
        .filter(LogEvent.id.in_(evidence_log_ids))
        .all()
    )

    if not new_logs:
        return False

    new_timestamps = [
        log.timestamp
        for log in new_logs
        if log.timestamp is not None
    ]

    if not new_timestamps:
        return False

    new_start = min(new_timestamps)
    new_end = max(new_timestamps)

    # Look only at alerts with the same detection characteristics.
    existing_alerts = (
        db.query(Alert)
        .filter(
            Alert.alert_type == alert_type,
            Alert.username == username,
            Alert.source_ip == source_ip,
        )
        .all()
    )

    for existing_alert in existing_alerts:

        existing_log_ids = existing_alert.evidence_log_ids or []

        if not existing_log_ids:
            continue

        existing_logs = (
            db.query(LogEvent)
            .filter(LogEvent.id.in_(existing_log_ids))
            .all()
        )

        existing_timestamps = [
            log.timestamp
            for log in existing_logs
            if log.timestamp is not None
        ]

        if not existing_timestamps:
            continue

        existing_start = min(existing_timestamps)
        existing_end = max(existing_timestamps)

        # Expand both time ranges by the correlation window.
        window = timedelta(minutes=CORRELATION_WINDOW_MINUTES)

        existing_start -= window
        existing_end += window

        # Check whether the two evidence ranges overlap.
        if (
            new_start <= existing_end
            and new_end >= existing_start
        ):
            return True

    return False


def ingest_normalized_events(
    db: Session,
    normalized_events: List[Dict[str, Any]]
):
    """
    Store normalized events, run detection + correlation, persist
    alerts and any resulting incidents.

    Returns:
        (stored_logs, alerts, incidents)
    """

    stored_logs = []

    # ---------------------------------------------------------
    # STORE LOGS
    # ---------------------------------------------------------

    for ev in normalized_events:
        log = LogEvent(**ev)
        db.add(log)
        stored_logs.append(log)

    # Assign IDs before detectors reference them.
    db.flush()

    # ---------------------------------------------------------
    # DETECTION
    # ---------------------------------------------------------

    recent_events = (
        db.query(LogEvent)
        .order_by(LogEvent.timestamp.desc())
        .limit(500)
        .all()
    )

    recent_events.sort(key=lambda e: e.timestamp)

    findings = run_all_detectors(db, recent_events)

    # ---------------------------------------------------------
    # CORRELATION
    # ---------------------------------------------------------

    incidents = correlate_findings(db, findings)

    # ---------------------------------------------------------
    # ALERT CREATION WITH DUPLICATE PROTECTION
    # ---------------------------------------------------------

    alerts = []

    for f in findings:

        # Do not create another alert if this finding already
        # represents an existing alert.
        if _finding_is_duplicate_alert(db, f):
            continue

        alert = Alert(
            alert_type=f["alert_type"],
            severity=f["severity"],
            username=f.get("username"),
            source_ip=f.get("source_ip"),
            description=f["description"],
            evidence_log_ids=f.get("evidence_log_ids", []),
        )

        # Link the alert to an incident if its evidence belongs
        # to one of the newly created incidents.
        for incident in incidents:

            incident_log_ids = {
                te.log_event_id
                for te in incident.timeline_events
            }

            if incident_log_ids.intersection(
                alert.evidence_log_ids
            ):
                alert.incident_id = incident.id
                break

        db.add(alert)
        alerts.append(alert)

    # ---------------------------------------------------------
    # SAVE
    # ---------------------------------------------------------

    db.commit()

    for log in stored_logs:
        db.refresh(log)

    for alert in alerts:
        db.refresh(alert)

    for incident in incidents:
        db.refresh(incident)

    return stored_logs, alerts, incidents
