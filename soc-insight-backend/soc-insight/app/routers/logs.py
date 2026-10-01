from typing import List, Optional
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import LogEvent
from app.schemas import LogEventIn, RawLogIngest, LogEventOut, IngestResult
from app.normalizer import normalize_lines
from app.pipeline import ingest_normalized_events

router = APIRouter(prefix="/logs", tags=["logs"])


@router.post("/ingest/structured", response_model=IngestResult)
def ingest_structured(events: List[LogEventIn], db: Session = Depends(get_db)):
    """Ingest already-structured log events (e.g. from a source that emits
    JSON directly, like an application log)."""
    normalized = [e.model_dump() for e in events]
    logs, alerts, incidents = ingest_normalized_events(db, normalized)
    return IngestResult(
        logs_ingested=len(logs),
        alerts_generated=len(alerts),
        incidents_created=[i.incident_code for i in incidents],
    )


@router.post("/ingest/raw", response_model=IngestResult)
def ingest_raw(payload: RawLogIngest, db: Session = Depends(get_db)):
    """Ingest raw syslog-style text lines (e.g. pasted /var/log/auth.log
    content). Lines that don't match a known pattern are skipped."""
    normalized = normalize_lines(payload.lines, service=payload.service)
    logs, alerts, incidents = ingest_normalized_events(db, normalized)
    return IngestResult(
        logs_ingested=len(logs),
        alerts_generated=len(alerts),
        incidents_created=[i.incident_code for i in incidents],
    )


@router.get("/", response_model=List[LogEventOut])
def list_logs(
    limit: int = 100,
    username: Optional[str] = None,
    source_ip: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(LogEvent)
    if username:
        query = query.filter(LogEvent.username == username)
    if source_ip:
        query = query.filter(LogEvent.source_ip == source_ip)
    return query.order_by(LogEvent.timestamp.desc()).limit(limit).all()
