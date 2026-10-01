"""
Ties the modules together into the pipeline described in the proposal:

    Parse -> Normalize -> Store -> Detect -> Correlate -> Incident -> Timeline

This is the one function both the /logs/ingest and /simulate endpoints
call, so there's a single source of truth for "what happens to a log once
it arrives".
"""

from typing import List, Dict, Any
from sqlalchemy.orm import Session

from app.models import LogEvent, Alert
from app.detection import run_all_detectors
from app.correlation import correlate_findings


def ingest_normalized_events(db: Session, normalized_events: List[Dict[str, Any]]):
    """Store normalized events, run detection + correlation, persist alerts
    and any resulting incidents. Returns (stored_logs, alerts, incidents)."""

    stored_logs = []
    for ev in normalized_events:
        log = LogEvent(**ev)
        db.add(log)
        stored_logs.append(log)
    db.flush()  # assign ids before detectors reference them

    # Detection works over the full recent history for the affected
    # users/IPs, not just this batch, so brute-force windows spanning two
    # ingests are still caught. For a prototype, "recent history" = last
    # 500 events; a production version would scope this by time window.
    recent_events = (
        db.query(LogEvent)
        .order_by(LogEvent.timestamp.desc())
        .limit(500)
        .all()
    )
    recent_events.sort(key=lambda e: e.timestamp)

    findings = run_all_detectors(db, recent_events)

    incidents = correlate_findings(db, findings)

    # Findings that ended up part of an incident: link the incident id.
    # Match by evidence overlap with the incident's timeline log ids.
    alerts = []
    for f in findings:
        alert = Alert(
            alert_type=f["alert_type"],
            severity=f["severity"],
            username=f.get("username"),
            source_ip=f.get("source_ip"),
            description=f["description"],
            evidence_log_ids=f.get("evidence_log_ids", []),
        )
        for incident in incidents:
            incident_log_ids = {te.log_event_id for te in incident.timeline_events}
            if incident_log_ids.intersection(alert.evidence_log_ids):
                alert.incident_id = incident.id
                break
        db.add(alert)
        alerts.append(alert)

    db.commit()
    for log in stored_logs:
        db.refresh(log)
    for alert in alerts:
        db.refresh(alert)
    for incident in incidents:
        db.refresh(incident)

    return stored_logs, alerts, incidents
