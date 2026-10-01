"""
Correlation Engine.

Takes newly created Alert rows and groups the ones that belong to the same
story into Incidents:

  1. Alerts are grouped by (username, source_ip), the anchor of an attack
     "story" in this ruleset.
  2. Within each group, alerts are clustered by time: alerts whose evidence
     falls within CORRELATION_WINDOW_MINUTES of each other are one cluster.
  3. Each cluster either
       - extends an existing open incident for the same account/IP that is
         still "live" (its timeline is within the window), so logs arriving
         in later batches (e.g. the sudo command after the login) upgrade
         the incident instead of spawning a duplicate, or
       - becomes a new incident if it contains 2+ alerts, or
       - stays as a standalone alert (a single low-signal finding is not
         yet a "story").
"""

from datetime import datetime, timedelta
from collections import defaultdict
from typing import List
from sqlalchemy.orm import Session

from app.models import LogEvent, Alert, Incident, IncidentTimelineEvent
from app.severity import classify_incident_type_and_severity, recommend_actions

CORRELATION_WINDOW_MINUTES = 20
WINDOW = timedelta(minutes=CORRELATION_WINDOW_MINUTES)


def _next_incident_code(db: Session) -> str:
    count = db.query(Incident).count() + 1
    return f"INC-{datetime.now().year}-{count:03d}"


def _timeline_description(log: LogEvent) -> str:
    return (
        f"{log.event_type.replace('_', ' ').title()} "
        f"({log.service or 'unknown service'})"
        + (f" - {log.username}" if log.username else "")
        + (f" from {log.source_ip}" if log.source_ip else "")
    )


def _find_live_incident(db: Session, user, ip, start, end):
    """An open incident for the same account/IP whose timeline is within
    the correlation window of this cluster."""
    candidates = (
        db.query(Incident)
        .filter(
            Incident.affected_account == user,
            Incident.source_ip == ip,
            Incident.status != "CLOSED",
        )
        .all()
    )
    for inc in candidates:
        times = [te.timestamp for te in inc.timeline_events]
        if not times:
            continue
        if start - max(times) <= WINDOW and min(times) - end <= WINDOW:
            return inc
    return None


def correlate_alerts(db: Session, new_alerts: List[Alert]) -> List[Incident]:
    """Correlate freshly created alerts. Returns only the incidents that
    were newly created (extended incidents are updated in place)."""
    if not new_alerts:
        return []

    all_ids = {lid for a in new_alerts for lid in (a.evidence_log_ids or [])}
    log_map = {
        l.id: l
        for l in db.query(LogEvent).filter(LogEvent.id.in_(all_ids)).all()
    }

    span = {}
    for a in new_alerts:
        times = [log_map[i].timestamp for i in a.evidence_log_ids if i in log_map]
        if times:
            span[a.id] = (min(times), max(times))

    groups = defaultdict(list)
    for a in new_alerts:
        if a.id in span:
            groups[(a.username, a.source_ip)].append(a)

    created = []

    for (user, ip), alerts in groups.items():
        alerts.sort(key=lambda a: span[a.id][0])

        clusters = []
        for a in alerts:
            s, e = span[a.id]
            if clusters and s - clusters[-1]["end"] <= WINDOW:
                clusters[-1]["alerts"].append(a)
                clusters[-1]["end"] = max(clusters[-1]["end"], e)
            else:
                clusters.append({"alerts": [a], "start": s, "end": e})

        for c in clusters:
            c_alerts = c["alerts"]
            log_ids = sorted(
                {lid for a in c_alerts for lid in a.evidence_log_ids if lid in log_map},
                key=lambda i: log_map[i].timestamp,
            )

            incident = _find_live_incident(db, user, ip, c["start"], c["end"])

            if incident is not None:
                # Extend the existing incident with this cluster.
                for a in c_alerts:
                    a.incident_id = incident.id
                have = {te.log_event_id for te in incident.timeline_events}
                for lid in log_ids:
                    if lid not in have:
                        log = log_map[lid]
                        db.add(IncidentTimelineEvent(
                            incident_id=incident.id,
                            timestamp=log.timestamp,
                            description=_timeline_description(log),
                            log_event_id=lid,
                        ))
                db.flush()
                db.refresh(incident)
                incident_type, severity = classify_incident_type_and_severity(
                    [a.alert_type for a in incident.alerts]
                )
                incident.incident_type = incident_type
                incident.severity = severity
                incident.recommended_actions = recommend_actions(incident_type)
                incident.evidence = list(incident.evidence or []) + [
                    a.description for a in c_alerts
                ]
                incident.detection_time = min(
                    incident.detection_time, c["start"]
                )
                continue

            if len(c_alerts) < 2:
                continue  # lone alert: not yet an incident

            incident_type, severity = classify_incident_type_and_severity(
                [a.alert_type for a in c_alerts]
            )
            incident = Incident(
                incident_code=_next_incident_code(db),
                incident_type=incident_type,
                severity=severity,
                status="OPEN",
                affected_account=user,
                source_ip=ip,
                detection_time=c["start"],
                evidence=[a.description for a in c_alerts],
                recommended_actions=recommend_actions(incident_type),
            )
            db.add(incident)
            db.flush()
            for a in c_alerts:
                a.incident_id = incident.id
            for lid in log_ids:
                log = log_map[lid]
                db.add(IncidentTimelineEvent(
                    incident_id=incident.id,
                    timestamp=log.timestamp,
                    description=_timeline_description(log),
                    log_event_id=lid,
                ))
            db.flush()
            created.append(incident)

    return created
