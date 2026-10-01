import { useEffect, useState, useCallback } from "react";
import Header from "./components/Header.jsx";
import SeverityStrip from "./components/SeverityStrip.jsx";
import IncidentsTable from "./components/IncidentsTable.jsx";
import RankedList from "./components/RankedList.jsx";
import IncidentDetail from "./components/IncidentDetail.jsx";
import AlertsTimelineChart from "./components/AlertsTimelineChart.jsx";
import { api } from "./api.js";

export default function App() {
  const [summary, setSummary] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [isOnline, setIsOnline] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const [summaryData, incidentsData, alertsData] = await Promise.all([
        api.getDashboardSummary(),
        api.getIncidents(),
        api.getAlerts(),
      ]);
      setSummary(summaryData);
      setIncidents(incidentsData);
      setAlerts(alertsData);
      setIsOnline(true);
      setError(null);
    } catch (err) {
      setIsOnline(false);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAll();
    const interval = setInterval(loadAll, 8000);
    return () => clearInterval(interval);
  }, [loadAll]);

  const handleSelect = async (id) => {
    try {
      const detail = await api.getIncident(id);
      setSelectedIncident(detail);
    } catch (err) {
      setError(err.message);
    }
  };

  const handleSimulate = async () => {
    setLoading(true);
    try {
      await api.runSimulation();
      await loadAll();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleStatusChange = (id, status) => {
    setIncidents((prev) =>
      prev.map((inc) => (inc.id === id ? { ...inc, status } : inc))
    );
    setSelectedIncident((prev) => (prev ? { ...prev, status } : prev));
  };

  return (
    <div className="app">
      <Header
        isOnline={isOnline}
        onRefresh={loadAll}
        onSimulate={handleSimulate}
        loading={loading}
      />

      <main className="main">
        {error && (
          <div className="error-box">
            Couldn't reach the backend at the configured API URL. Make sure
            it's running (uvicorn app.main:app --reload) — {error}
          </div>
        )}

        <SeverityStrip summary={summary} />

        <AlertsTimelineChart alerts={alerts} />

        <div className="body-grid">
          <IncidentsTable
            incidents={incidents}
            selectedId={selectedIncident?.id}
            onSelect={handleSelect}
          />

          <div style={{ display: "flex", flexDirection: "column", gap: 24 }}>
            <RankedList
              title="Top Source IPs"
              items={summary?.top_source_ips || []}
              labelKey="ip"
              countKey="count"
            />
            <RankedList
              title="Top Targeted Accounts"
              items={summary?.top_targeted_accounts || []}
              labelKey="username"
              countKey="count"
            />
          </div>
        </div>
      </main>

      {selectedIncident && (
        <IncidentDetail
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onStatusChange={handleStatusChange}
        />
      )}
    </div>
  );
}
