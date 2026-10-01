from datetime import datetime
from typing import Optional, List, Any
from pydantic import BaseModel, ConfigDict


class LogEventIn(BaseModel):
    """A single already-structured log event submitted via the API."""
    timestamp: datetime
    username: Optional[str] = None
    source_ip: Optional[str] = None
    event_type: str            # LOGIN_FAILED | LOGIN_SUCCESS | PRIVILEGE_ESCALATION | SENSITIVE_ACCESS | OTHER
    service: Optional[str] = "SSH"
    raw_log: Optional[str] = None


class RawLogIngest(BaseModel):
    """Raw, unstructured log text (e.g. copy-pasted syslog lines)."""
    lines: List[str]
    service: Optional[str] = "SSH"


class LogEventOut(BaseModel):
    id: int
    timestamp: datetime
    username: Optional[str]
    source_ip: Optional[str]
    event_type: str
    service: Optional[str]
    raw_log: Optional[str]

    model_config = ConfigDict(from_attributes=True)


class MitreTechnique(BaseModel):
    id: str
    name: str
    tactic: str
    url: str


class AlertOut(BaseModel):
    id: int
    alert_type: str
    severity: str
    username: Optional[str]
    source_ip: Optional[str]
    description: str
    evidence_log_ids: List[int]
    occurred_at: Optional[datetime] = None
    created_at: datetime
    incident_id: Optional[int]
    mitre_technique: Optional[MitreTechnique] = None

    model_config = ConfigDict(from_attributes=True)


class TimelineEventOut(BaseModel):
    timestamp: datetime
    description: str

    model_config = ConfigDict(from_attributes=True)


class IncidentOut(BaseModel):
    id: int
    incident_code: str
    incident_type: str
    severity: str
    status: str
    affected_account: Optional[str]
    source_ip: Optional[str]
    detection_time: datetime
    evidence: List[str]
    recommended_actions: List[str]
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class IncidentDetailOut(IncidentOut):
    timeline: List[TimelineEventOut]
    alerts: List[AlertOut]
    mitre_techniques: List[MitreTechnique] = []


class DashboardSummary(BaseModel):
    total_logs_analyzed: int
    total_alerts: int
    severity_counts: dict
    top_source_ips: List[dict]
    top_targeted_accounts: List[dict]
    active_incidents: List[IncidentOut]


class IngestResult(BaseModel):
    logs_ingested: int
    alerts_generated: int
    incidents_created: List[str]
