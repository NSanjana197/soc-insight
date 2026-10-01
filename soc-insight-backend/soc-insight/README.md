# SOC-Insight — Backend

A working backend for the SOC Investigation and Automated Incident Reporting
Platform: ingest auth logs → normalize → detect → correlate → incident →
PDF report. No frontend yet — this is the engine, exposed as a REST API
with interactive docs.

## 1. Setup

```bash
cd soc-insight
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## 2. Run

```bash
uvicorn app.main:app --reload
```

Then open **http://127.0.0.1:8000/docs** — full interactive Swagger UI for
every endpoint below.

A SQLite file `soc_insight.db` is created automatically on first run. Delete
it any time to reset all data.

## 3. Try it in 30 seconds

```bash
# Load the example attack scenario from the project proposal
# (brute force -> successful login -> sudo -> sensitive file access)
curl -X POST http://127.0.0.1:8000/simulate

# See the dashboard summary
curl http://127.0.0.1:8000/dashboard/summary

# List the incident(s) that got created
curl http://127.0.0.1:8000/incidents/

# Download the PDF report for incident 1
curl http://127.0.0.1:8000/incidents/1/report.pdf -o incident_1.pdf
```

You should see one `CRITICAL` `ACCOUNT_COMPROMISE` incident, with a full
timeline from the first failed login through the sensitive file access.

## 4. Feeding it real logs

Two ingestion endpoints:

- `POST /logs/ingest/raw` — paste raw syslog-style lines (e.g. copied from
  `/var/log/auth.log`). Body: `{"lines": [...], "service": "SSH"}`.
  Currently understands SSH failed/accepted logins, `sudo` privilege
  escalation, and a generic "accessed <sensitive-path>" pattern. Add more
  patterns in `app/normalizer.py`.
- `POST /logs/ingest/structured` — already-structured JSON events, for
  sources that can emit JSON directly (e.g. an application's own auth
  logging). See `LogEventIn` in `app/schemas.py` for the shape.

## 5. Project layout

```
app/
  main.py            FastAPI app, startup, /simulate demo endpoint
  database.py         SQLAlchemy engine/session (SQLite by default)
  models.py            LogEvent / Alert / Incident / IncidentTimelineEvent
  schemas.py           Pydantic request/response models
  normalizer.py        Raw log text -> structured event dicts
  detection.py         Rule-based detectors (brute force, privilege
                        escalation, unusual login time, etc.)
  correlation.py        Groups related alerts into incidents + builds
                        timelines
  severity.py           Incident type/severity classification rules
  report_generator.py   PDF incident report (reportlab)
  sample_data.py         Generates the example attack scenario for demos
  pipeline.py            Wires it all together (used by every ingest route)
  routers/
    logs.py, alerts.py, incidents.py, dashboard.py
```

## 6. Detection rules currently implemented

| Rule | Trigger | Severity |
|---|---|---|
| Brute force | 10+ failed logins, same user+IP, within 5 min | HIGH |
| Repeated failures | 5-9 failed logins, same user+IP | MEDIUM |
| Success after failures | Login succeeds within 5 min of 3+ failures | HIGH |
| Unusual login time | Successful login outside 06:00-22:00 | MEDIUM |
| Privilege escalation | `sudo`/privileged command within 15 min of login | HIGH |
| Sensitive resource access | Sensitive path accessed within 15 min of a privilege escalation | CRITICAL |

The correlation engine then groups related findings for the same
user+IP into one incident and assigns an overall severity (see
`app/severity.py` for the exact rules — this mirrors the
Critical/High/Medium/Low table in the project proposal).

Tune thresholds in `app/detection.py`.

## 7. Switching to PostgreSQL later

```bash
export SOC_DATABASE_URL="postgresql://user:password@localhost:5432/soc_insight"
pip install psycopg2-binary
```

No other code changes needed — everything goes through SQLAlchemy's ORM.

## 8. What's next (not built yet)

- React dashboard (the proposal's Module 6) — this backend's `/dashboard/summary`,
  `/incidents/`, and `/incidents/{id}` endpoints are designed to feed it directly.
- Real log source connectors (Windows Event Log, firewall, cloud logs).
- Threat-intelligence IP lookups, ML anomaly scoring, MITRE ATT&CK mapping
  (Advanced Features in the proposal) — these are optional add-ons layered
  on top of `detection.py`/`correlation.py`, not rewrites.
