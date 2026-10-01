from fastapi.testclient import TestClient
from app.main import app


def test_root_endpoint():
    with TestClient(app) as client:
        r = client.get("/")
        assert r.status_code == 200
        assert r.json()["service"] == "SOC-Insight"


def test_simulate_creates_incident_with_mitre_techniques():
    with TestClient(app) as client:
        r = client.post("/simulate")
        assert r.status_code == 200
        body = r.json()
        assert body["logs_ingested"] > 0
        assert len(body["incidents_created"]) >= 1

        incidents = client.get("/incidents/").json()
        assert len(incidents) >= 1

        critical = [i for i in incidents if i["severity"] == "CRITICAL"][0]
        detail = client.get(f"/incidents/{critical['id']}").json()
        assert len(detail["timeline"]) > 0
        assert len(detail["mitre_techniques"]) > 0
        assert all("id" in t and "url" in t for t in detail["mitre_techniques"])


def test_dashboard_summary_has_all_severity_keys():
    with TestClient(app) as client:
        client.post("/simulate")
        summary = client.get("/dashboard/summary").json()
        for level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
            assert level in summary["severity_counts"]


def test_incident_report_pdf_downloads():
    with TestClient(app) as client:
        client.post("/simulate")
        incidents = client.get("/incidents/").json()
        incident_id = incidents[0]["id"]
        r = client.get(f"/incidents/{incident_id}/report.pdf")
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/pdf"
        assert r.content[:4] == b"%PDF"


def test_incident_status_update():
    with TestClient(app) as client:
        client.post("/simulate")
        incident_id = client.get("/incidents/").json()[0]["id"]
        r = client.patch(f"/incidents/{incident_id}/status?status=closed")
        assert r.status_code == 200
        assert r.json()["status"] == "CLOSED"


def test_invalid_status_rejected():
    with TestClient(app) as client:
        client.post("/simulate")
        incident_id = client.get("/incidents/").json()[0]["id"]
        r = client.patch(f"/incidents/{incident_id}/status?status=not_a_status")
        assert r.status_code == 400
