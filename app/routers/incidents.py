from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Incident
from app.schemas import IncidentOut, IncidentDetailOut
from app.report_generator import generate_incident_report_pdf

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("/", response_model=List[IncidentOut])
def list_incidents(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Incident)
    if severity:
        query = query.filter(Incident.severity == severity.upper())
    if status:
        query = query.filter(Incident.status == status.upper())
    return query.order_by(Incident.created_at.desc()).all()


from app.mitre import get_technique


@router.get("/{incident_id}", response_model=IncidentDetailOut)
def get_incident(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    data = IncidentOut.model_validate(incident).model_dump()
    data["timeline"] = [
        {"timestamp": te.timestamp, "description": te.description}
        for te in incident.timeline_events
    ]
    alerts_out = []
    techniques_by_id = {}
    for a in incident.alerts:
        technique = get_technique(a.alert_type)
        alerts_out.append({
            "id": a.id, "alert_type": a.alert_type, "severity": a.severity,
            "username": a.username, "source_ip": a.source_ip,
            "description": a.description, "evidence_log_ids": a.evidence_log_ids,
            "occurred_at": a.occurred_at, "created_at": a.created_at,
            "incident_id": a.incident_id,
            "mitre_technique": technique,
        })
        if technique:
            techniques_by_id[technique["id"]] = technique
    data["alerts"] = alerts_out
    data["mitre_techniques"] = list(techniques_by_id.values())
    return data


@router.get("/{incident_id}/report.pdf")
def get_incident_report(incident_id: int, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    pdf_bytes = generate_incident_report_pdf(incident)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{incident.incident_code}.pdf"'
        },
    )


@router.patch("/{incident_id}/status")
def update_status(incident_id: int, status: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    valid = {"OPEN", "IN_PROGRESS", "CLOSED"}
    status = status.upper()
    if status not in valid:
        raise HTTPException(status_code=400, detail=f"Status must be one of {valid}")
    incident.status = status
    db.commit()
    db.refresh(incident)
    return {"id": incident.id, "status": incident.status}
