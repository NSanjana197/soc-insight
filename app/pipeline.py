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
from app.correlation import correlate_alerts


def _already_stored(db: Session, ev: Dict[str, Any]) -> bool:
    """Exact duplicate of a stored event (same time, user, IP, type, raw
    line). Makes re-ingesting the same file or lines harmless."""
    return (
        db.query(LogEvent.id)
        .filter(
            LogEvent.timestamp == ev["timestamp"],
            LogEvent.username == ev.get("username"),
            LogEvent.source_ip == ev.get("source_ip"),
            LogEvent.event_type == ev["event_type"],
            LogEvent.raw_log == ev.get("raw_log"),
        )
        .first()
        is not None
    )


def ingest_normalized_events(db: Session, normalized_events: List[Dict[str, Any]]):
    """Store new events, run detection + correlation, persist alerts and
    incidents. Returns (stored_logs, alerts, incidents), all NEW from this
    call only."""

    stored_logs = []
    for ev in normalized_events:
        if _already_stored(db, ev):
            continue
        log = LogEvent(**ev)
        db.add(log)
        db.flush()  # so the next duplicate check sees it too
        stored_logs.append(log)

    if not stored_logs:
        db.commit()
        return [], [], []

    new_ids = {l.id for l in stored_logs}

    # Detectors look at recent history so patterns that span ingests (e.g.
    # failures in one batch, the success in the next) are still caught.
    # Prototype scope: last 500 events; production would use a time window.
    recent_events = (
        db.query(LogEvent)
        .order_by(LogEvent.timestamp.desc())
        .limit(500)
        .all()
    )
    recent_events.sort(key=lambda e: e.timestamp)

    findings = run_all_detectors(db, recent_events)

    # Only findings that involve at least one newly arrived log are new.
    # Everything else was already reported by an earlier ingest.
    new_findings = [
        f for f in findings if new_ids.intersection(f.get("evidence_log_ids", []))
    ]

    alerts = []
    for f in new_findings:
        alert = Alert(
            alert_type=f["alert_type"],
            severity=f["severity"],
            username=f.get("username"),
            source_ip=f.get("source_ip"),
            description=f["description"],
            evidence_log_ids=f.get("evidence_log_ids", []),
        )
        db.add(alert)
        alerts.append(alert)
    db.flush()  # assign alert ids before correlation

    incidents = correlate_alerts(db, alerts)

    db.commit()
    for log in stored_logs:
        db.refresh(log)
    for alert in alerts:
        db.refresh(alert)
    for incident in incidents:
        db.refresh(incident)

    return stored_logs, alerts, incidents
