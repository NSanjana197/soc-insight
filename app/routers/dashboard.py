from collections import Counter
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import LogEvent, Alert, Incident
from app.schemas import DashboardSummary, IncidentOut

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary", response_model=DashboardSummary)
def get_summary(db: Session = Depends(get_db)):
    total_logs = db.query(LogEvent).count()
    alerts = db.query(Alert).all()

    severity_counts = Counter(a.severity for a in alerts)
    for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
        severity_counts.setdefault(level, 0)

    ip_counter = Counter(a.source_ip for a in alerts if a.source_ip)
    user_counter = Counter(a.username for a in alerts if a.username)

    active_incidents = (
        db.query(Incident)
        .filter(Incident.status != "CLOSED")
        .order_by(Incident.created_at.desc())
        .all()
    )

    return DashboardSummary(
        total_logs_analyzed=total_logs,
        total_alerts=len(alerts),
        severity_counts=dict(severity_counts),
        top_source_ips=[{"ip": ip, "count": c} for ip, c in ip_counter.most_common(5)],
        top_targeted_accounts=[{"username": u, "count": c} for u, c in user_counter.most_common(5)],
        active_incidents=[IncidentOut.model_validate(i) for i in active_incidents],
    )
