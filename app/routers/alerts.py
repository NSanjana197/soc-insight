from typing import List, Optional
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Alert
from app.schemas import AlertOut

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("/", response_model=List[AlertOut])
def list_alerts(
    limit: int = 100,
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Alert)
    if severity:
        query = query.filter(Alert.severity == severity.upper())
    return query.order_by(Alert.created_at.desc()).limit(limit).all()
