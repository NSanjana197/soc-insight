"""
ORM models.

Tables (matches the proposal's data design):
    LogEvent               -> normalized log entries
    Alert                  -> single-rule detections
    Incident               -> correlated group of alerts/events
    IncidentTimelineEvent  -> ordered events shown in an incident's timeline
"""

from datetime import datetime, timezone
from sqlalchemy import (
    Column, Integer, String, DateTime, ForeignKey, Text, JSON
)
from sqlalchemy.orm import relationship

from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class LogEvent(Base):
    __tablename__ = "log_events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    username = Column(String, nullable=True, index=True)
    source_ip = Column(String, nullable=True, index=True)
    event_type = Column(String, nullable=False, index=True)
    # LOGIN_FAILED, LOGIN_SUCCESS, PRIVILEGE_ESCALATION, SENSITIVE_ACCESS, OTHER
    service = Column(String, nullable=True)          # SSH, WebApp, VPN, etc.
    raw_log = Column(Text, nullable=True)             # original line, for evidence
    ingested_at = Column(DateTime, default=utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String, nullable=False)        # e.g. BRUTE_FORCE
    severity = Column(String, nullable=False)          # LOW/MEDIUM/HIGH/CRITICAL
    username = Column(String, nullable=True, index=True)
    source_ip = Column(String, nullable=True, index=True)
    description = Column(Text, nullable=False)
    evidence_log_ids = Column(JSON, default=list)      # list[int] of LogEvent ids
    occurred_at = Column(DateTime, nullable=True)       # when the underlying log
    # event(s) actually happened, per their own timestamps - NOT when this row
    # was inserted. Ingesting a batch of historical logs all at once (as
    # /simulate does) would otherwise make every alert look like it happened
    # at the same instant, which is wrong for any time-based view.
    created_at = Column(DateTime, default=utcnow)       # when this alert was
    # detected/recorded by the system (DB insert time) - kept for audit
    # purposes, but not what a timeline chart should bucket by.
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True)

    incident = relationship("Incident", back_populates="alerts")

    @property
    def mitre_technique(self):
        from app.mitre import get_technique
        return get_technique(self.alert_type)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_code = Column(String, unique=True, index=True)   # INC-2026-001
    incident_type = Column(String, nullable=False)             # e.g. ACCOUNT_COMPROMISE
    severity = Column(String, nullable=False)
    status = Column(String, default="OPEN")                    # OPEN/IN_PROGRESS/CLOSED
    affected_account = Column(String, nullable=True)
    source_ip = Column(String, nullable=True)
    detection_time = Column(DateTime, nullable=False)
    evidence = Column(JSON, default=list)          # list[str] human-readable evidence
    recommended_actions = Column(JSON, default=list)  # list[str]
    created_at = Column(DateTime, default=utcnow)

    alerts = relationship("Alert", back_populates="incident")
    timeline_events = relationship(
        "IncidentTimelineEvent", back_populates="incident",
        order_by="IncidentTimelineEvent.timestamp"
    )


class IncidentTimelineEvent(Base):
    __tablename__ = "incident_timeline_events"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"))
    timestamp = Column(DateTime, nullable=False)
    description = Column(String, nullable=False)
    log_event_id = Column(Integer, ForeignKey("log_events.id"), nullable=True)

    incident = relationship("Incident", back_populates="timeline_events")
