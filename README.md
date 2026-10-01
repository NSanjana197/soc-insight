# SOC-Insight

**SOC Investigation and Automated Incident Reporting Platform**

SOC-Insight ingests authentication/security logs, detects suspicious
patterns with rule-based detectors, correlates related events into a single
incident instead of a pile of disconnected alerts, and generates a
structured PDF incident report — the pipeline a SOC analyst would otherwise
do by hand.

```
Log Collection → Normalization → Detection → Correlation → Investigation → Reporting
```

A live dashboard (React) sits on top of the API for browsing incidents,
inspecting timelines, and downloading reports.

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688)
![React](https://img.shields.io/badge/React-18-61DAFB)
![License](https://img.shields.io/badge/license-MIT-lightgrey)
![Tests](https://github.com/NSanjana197/soc-insight/actions/workflows/backend-tests.yml/badge.svg)

**🔗 Live Demo:** https://soc-insight-krf3.vercel.app
**🔗 API / Docs:** https://soc-insight.onrender.com/docs

> The backend runs on Render's free tier, which spins down after 15 minutes
> of inactivity. If the demo looks stuck loading, give it 30–50 seconds to
> wake back up, then click **Run Simulation** on the dashboard to see it
> populate with a sample incident.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Backend](#1-backend-setup)
  - [Frontend](#2-frontend-setup)
- [Deployment](#deployment)
- [Try It: Sample Attack Scenario](#try-it-sample-attack-scenario)
- [Detection Rules](#detection-rules)
- [Incident Severity](#incident-severity)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [API Reference](#api-reference)
- [Feeding It Real Logs](#feeding-it-real-logs)
- [Switching to PostgreSQL](#switching-to-postgresql)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Limitations](#limitations)
- [License](#license)

---

## Overview

Security tools generate more log data than any analyst can read line by
line. A single brute-force attack can produce dozens of individual log
entries — failed logins, a successful login, a privileged command, a file
access — that mean nothing in isolation but tell a clear story together.

SOC-Insight's job is to turn that pile of raw logs into that story:

1. **Normalize** logs from different sources into one common event format.
2. **Detect** suspicious patterns with a documented set of rules (not a
   black box — every alert traces back to specific rule and evidence).
3. **Correlate** related alerts for the same account/IP into a single
   incident, so an analyst investigates one story instead of ten alerts.
4. **Classify severity** using explicit rules (Critical/High/Medium/Low),
   not a single "everything unusual is an attack" heuristic.
5. **Report** — generate a structured, timeline-based PDF incident report
   ready to hand off or file.

## Features

- Rule-based detection: brute force, repeated failures, success-after-
  failures, unusual login hours, privilege escalation, sensitive resource
  access, and logins from a new source IP
- Event correlation that merges related alerts into one incident and keeps
  extending it as new related logs arrive (rather than duplicating) —
  covered by an automated test suite (see [Testing](#testing))
- Explicit severity classification spanning all four tiers (Low → Critical)
  matching a documented rules table
- MITRE ATT&CK technique mapping per alert and per incident
- Full investigation timeline per incident
- One-click PDF incident report generation (ReportLab)
- REST API with interactive OpenAPI docs (`/docs`)
- React dashboard: severity overview, alerts-over-time chart, incidents
  table, top offending IPs/accounts, incident detail panel with MITRE
  tags, status control, and report download — responsive down to mobile
- Built-in attack-scenario simulator (`POST /simulate`) for demos and
  testing without a real log source connected, with deterministic,
  clock-independent sample data spanning all severity levels

## Architecture

```
                  SECURITY LOG SOURCES
                         │
          ┌──────────────┼──────────────┐
          ↓              ↓              ↓
       Linux          Windows        Application
       Logs            Logs             Logs
          │              │              │
          └──────────────┼──────────────┘
                         ↓
                  LOG NORMALIZER
                         ↓
                DETECTION ENGINE
                         ↓
                CORRELATION ENGINE
                         ↓
              ┌──────────┴──────────┐
              ↓                     ↓
       ALERT GENERATION       INCIDENT CREATION
              │                     │
              └──────────┬──────────┘
                         ↓
                  SOC DASHBOARD
                         ↓
              INVESTIGATION TIMELINE
                         ↓
              PDF INCIDENT REPORT
```

## Tech Stack

| Layer | Technology |
|---|---|
| Backend API | Python, FastAPI |
| ORM / Database | SQLAlchemy, SQLite (swap to PostgreSQL with one env var) |
| Validation | Pydantic |
| PDF Reports | ReportLab |
| Frontend | React 18, Vite |
| Icons | lucide-react |

## Project Structure

```
soc-insight/
├── app/                          Backend (FastAPI)
│   ├── main.py                    App entrypoint, /simulate demo endpoint
│   ├── database.py                 SQLAlchemy engine/session
│   ├── models.py                    LogEvent / Alert / Incident / Timeline
│   ├── schemas.py                    Pydantic request/response models
│   ├── normalizer.py                 Raw log text -> structured events
│   ├── detection.py                   Rule-based detectors
│   ├── correlation.py                  Groups alerts into incidents
│   ├── severity.py                      Severity + recommended actions
│   ├── mitre.py                          MITRE ATT&CK technique mapping
│   ├── report_generator.py                PDF incident report
│   ├── sample_data.py                      Example attack scenario generator
│   ├── pipeline.py                          Wires it all together
│   └── routers/
│       ├── logs.py, alerts.py, incidents.py, dashboard.py
├── frontend/                     Dashboard (React + Vite)
│   └── src/
│       ├── App.jsx, api.js, styles.css
│       └── components/
│           ├── Header.jsx, SeverityStrip.jsx, SeverityBadge.jsx
│           ├── IncidentsTable.jsx, IncidentDetail.jsx
│           ├── RankedList.jsx, AlertsTimelineChart.jsx
├── tests/                        Automated test suite (pytest)
│   ├── test_normalizer.py, test_detection.py, test_severity.py
│   └── test_pipeline.py, test_api.py
├── .github/workflows/
│   └── backend-tests.yml           CI: runs tests on every push
├── requirements.txt
├── requirements-dev.txt
├── LICENSE
└── README.md
```

## Getting Started

### 1. Backend Setup

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

- API: http://127.0.0.1:8000
- Interactive docs: http://127.0.0.1:8000/docs

A SQLite file `soc_insight.db` is created automatically on first run.
Delete it anytime to reset all data.

### 2. Frontend Setup

With the backend already running:

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:5173.

By default the dashboard talks to `http://127.0.0.1:8000`. To point it
elsewhere, create `frontend/.env`:

```
VITE_API_URL=http://your-backend-host:8000
```

## Deployment

This project is deployed as two separate services:

| Service | Platform | Notes |
|---|---|---|
| Backend (FastAPI) | [Render](https://render.com) | Free web service. Build: `pip install -r requirements.txt`. Start: `uvicorn app.main:app --host 0.0.0.0 --port $PORT` |
| Frontend (React/Vite) | [Vercel](https://vercel.com) | Root directory: `frontend`. Env var: `VITE_API_URL` set to the Render backend's URL |

To deploy your own copy:

1. Push this repo to GitHub.
2. On Render: New → Web Service → connect the repo → use the build/start
   commands above → deploy. Copy the resulting URL.
3. On Vercel: Add New → Project → import the repo → set **Root Directory**
   to `frontend` → add environment variable `VITE_API_URL` set to the
   Render URL from step 2 → deploy.

**Note:** Render's free tier uses ephemeral disk, so the SQLite database
resets on every redeploy or restart after inactivity. For persistent data,
switch to Render's managed PostgreSQL (see [Switching to PostgreSQL](#switching-to-postgresql) below) — no application code changes needed beyond the connection string.

## Try It: Sample Attack Scenario

No real log source needed to see the whole pipeline work — `/simulate`
replays a scripted attack (brute force → successful login → privilege
escalation → sensitive file access) plus some harmless background traffic.

**On the live demo:** open https://soc-insight-krf3.vercel.app and click
**Run Simulation** in the top right.

**Locally, or via the API directly:**

```bash
curl -X POST https://soc-insight.onrender.com/simulate
curl https://soc-insight.onrender.com/incidents/
curl https://soc-insight.onrender.com/incidents/1/report.pdf -o incident_1.pdf
```

(Swap the host for `http://127.0.0.1:8000` when running locally.)

Expect one `CRITICAL` `ACCOUNT_COMPROMISE` incident with a full timeline
from the first failed login through the sensitive file access.

## Detection Rules

| Rule | Trigger | Severity |
|---|---|---|
| Brute force | 10+ failed logins, same user + IP, within 5 minutes | HIGH |
| Repeated failures | 5–9 failed logins, same user + IP | MEDIUM |
| Success after failures | Login succeeds within 5 min of 3+ prior failures | HIGH |
| Unusual login time | Successful login outside 06:00–22:00 | MEDIUM |
| Privilege escalation | Privileged command within 15 min of a login | HIGH |
| Sensitive resource access | Sensitive path accessed within 15 min of a privilege escalation | CRITICAL |
| New source IP | Successful login for a user from an IP not seen before for that account | LOW |

Thresholds are tunable constants in `app/detection.py`.

## Incident Severity

The correlation engine assigns an overall incident severity from the
alert types it grouped together:

| Severity | Condition |
|---|---|
| **Critical** | Sensitive resource access combined with privilege escalation or a compromised login |
| **High** | Brute-force activity, successful login after failures, or privilege escalation alone |
| **Medium** | Unusual login time, or repeated (but sub-threshold) failures |
| **Low** | A login from a previously unseen source IP, or other minor anomalies |

See `app/severity.py` for the exact rules and recommended-actions mapping.

## MITRE ATT&CK Mapping

Each alert type maps to a MITRE ATT&CK technique (per the proposal's
"Advanced Features" section), exposed on every alert and deduplicated per
incident via the API, and shown as clickable tags in the incident detail
panel:

| Alert Type | Technique |
|---|---|
| Brute force / repeated failures | [T1110 – Brute Force](https://attack.mitre.org/techniques/T1110/) |
| Success after failures / unusual login time / new source IP | [T1078 – Valid Accounts](https://attack.mitre.org/techniques/T1078/) |
| Privilege escalation | [T1548.003 – Abuse Elevation Control Mechanism: Sudo and Sudo Caching](https://attack.mitre.org/techniques/T1548/003/) |
| Sensitive resource access | [T1552.001 – Unsecured Credentials: Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) |

See `app/mitre.py` to extend the mapping as new detection rules are added.

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| POST | `/logs/ingest/raw` | Ingest raw syslog-style text lines |
| POST | `/logs/ingest/structured` | Ingest already-structured JSON log events |
| GET | `/logs/` | List stored logs (filter by user/IP) |
| GET | `/alerts/` | List alerts (filter by severity) |
| GET | `/incidents/` | List incidents (filter by severity/status) |
| GET | `/incidents/{id}` | Incident detail: evidence, timeline, alerts |
| GET | `/incidents/{id}/report.pdf` | Download the PDF incident report |
| PATCH | `/incidents/{id}/status` | Update incident status (OPEN/IN_PROGRESS/CLOSED) |
| GET | `/dashboard/summary` | Severity counts, top IPs/accounts, active incidents |
| POST | `/simulate` | Load the example attack scenario |

Full interactive schema at `/docs` (Swagger UI) or `/redoc`.

## Feeding It Real Logs

`POST /logs/ingest/raw` accepts raw syslog-style lines, e.g. pasted from
`/var/log/auth.log`:

```json
{
  "lines": [
    "Sep 27 10:31:02 server sshd: Failed password for admin from 192.168.1.25"
  ],
  "service": "SSH"
}
```

It currently understands SSH failed/accepted logins, `sudo` privilege
escalation, and a generic "accessed &lt;sensitive-path&gt;" pattern. Add more
patterns in `app/normalizer.py` — that's the single place that knows about
source-specific log formats, so adding a new source doesn't touch the rest
of the pipeline.

For sources that can emit structured data directly, use
`POST /logs/ingest/structured` instead (see `LogEventIn` in
`app/schemas.py`).

## Switching to PostgreSQL

```bash
export SOC_DATABASE_URL="postgresql://user:password@localhost:5432/soc_insight"
pip install psycopg2-binary
```

No other code changes needed — everything goes through SQLAlchemy's ORM.

## Testing

33 automated tests cover the parts of this project where correctness
actually matters: log normalization, every detection rule individually,
severity classification, and — most importantly — the correlation engine's
behavior across multiple ingests (separate attacks stay separate, a
streaming attack extends one incident instead of duplicating, re-ingesting
the same logs twice creates nothing new). API-level tests exercise the
full stack through `TestClient`, including PDF report generation.

```bash
pip install -r requirements-dev.txt
pytest tests/ -v
```

Tests run automatically on every push via GitHub Actions
(`.github/workflows/backend-tests.yml`).

## Roadmap

- Real log source connectors (Windows Event Log, firewall, cloud logs)
- Threat-intelligence IP reputation lookups
- Machine-learning anomaly detection as an additional signal
- MITRE ATT&CK technique mapping per incident
- Attack-chain relationship graph visualization
- Real-time log streaming
- Email/Slack notifications for critical incidents
- SOAR-style automated response workflows

## Limitations

This is an investigation and incident-response **assistance** platform, not
a replacement for an enterprise SIEM/SOC:

- Detection rules may produce false positives and are tuned for the
  scenarios in this project, not a specific production environment
- No built-in threat-intelligence feed (the hook for one exists in the
  architecture, but no data source is wired up)
- No real-time streaming ingestion yet — logs are ingested via API calls
- Correlation is username/IP-based; it won't catch attacks that deliberately
  avoid reusing either

## License

MIT — see `LICENSE`.
