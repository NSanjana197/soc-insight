from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.database import init_db, get_db
from app.routers import logs, alerts, incidents, dashboard
from app.normalizer import normalize_lines
from app.pipeline import ingest_normalized_events
from app.sample_data import generate_attack_scenario, generate_background_noise
from app.schemas import IngestResult

app = FastAPI(
    title="SOC-Insight",
    description=(
        "SOC Investigation and Automated Incident Reporting Platform. "
        "Collects auth/security logs, detects suspicious patterns, "
        "correlates related events into incidents, and generates PDF "
        "incident reports."
    ),
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten this for production
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(logs.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(dashboard.router)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/")
def root():
    return {
        "service": "SOC-Insight",
        "docs": "/docs",
        "try_it": "POST /simulate to load a sample attack scenario, "
                  "then GET /dashboard/summary and /incidents/",
    }


@app.post("/simulate", response_model=IngestResult)
def simulate_attack(db: Session = Depends(get_db)):
    """Loads the example attack scenario from the project proposal
    (brute force -> successful login -> sudo -> sensitive file access)
    plus some harmless background logins, runs it through the full
    pipeline, and returns what was detected. Use this to see the whole
    system work without needing a real log source connected."""
    lines = generate_background_noise() + generate_attack_scenario()
    normalized = normalize_lines(lines, service="SSH")
    logs_, alerts_, incidents_ = ingest_normalized_events(db, normalized)
    return IngestResult(
        logs_ingested=len(logs_),
        alerts_generated=len(alerts_),
        incidents_created=[i.incident_code for i in incidents_],
    )
