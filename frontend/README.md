# SOC-Insight — Dashboard (Frontend)

A React dashboard for the SOC-Insight backend: severity overview, incidents
table, top offending IPs/accounts, and a slide-in incident detail panel with
timeline, evidence, recommended actions, and PDF report download.

## 1. Prerequisites

The backend must be running first (see `../README.md`):

```bash
uvicorn app.main:app --reload
```

It should be reachable at `http://127.0.0.1:8000`.

## 2. Setup

```bash
cd frontend
npm install
```

## 3. Run

```bash
npm run dev
```

Open the URL it prints (usually **http://localhost:5173**).

If you haven't loaded any data into the backend yet, click **Run Simulation**
in the top right — it loads the example attack scenario and everything
should populate immediately: severity counts, one CRITICAL incident, top
offending IP/account, and a timeline you can inspect by clicking the
incident row.

## 4. Pointing at a different backend URL

By default the dashboard talks to `http://127.0.0.1:8000`. To change that,
create a `.env` file in `frontend/`:

```
VITE_API_URL=http://your-backend-host:8000
```

## 5. Project layout

```
src/
  main.jsx               React entry point
  App.jsx                 Top-level layout, data fetching, polling
  api.js                   Fetch wrapper for every backend endpoint
  styles.css                All styling (dark security-console theme)
  components/
    Header.jsx               Title bar, connection status, actions
    SeverityStrip.jsx         Critical/High/Medium/Low + totals
    RankedList.jsx            Top Source IPs / Top Targeted Accounts
    IncidentsTable.jsx        Main incidents table
    IncidentDetail.jsx        Slide-in panel: evidence, timeline, actions,
                              status control, PDF download
    SeverityBadge.jsx         Small colored severity/status pill
```

The dashboard auto-refreshes every 8 seconds and shows a "backend
unreachable" indicator if it can't reach the API — useful if you restart
the backend while the dashboard is open.

## 6. Building for deployment

```bash
npm run build
```

Outputs static files to `dist/`, which can be served by any static host —
just make sure `VITE_API_URL` (set at build time) points at wherever the
backend actually runs.
