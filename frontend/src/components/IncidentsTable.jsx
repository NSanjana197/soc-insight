import SeverityBadge from "./SeverityBadge.jsx";
import { ShieldOff } from "lucide-react";

function formatTime(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function IncidentsTable({ incidents, selectedId, onSelect }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <h3 className="panel-title">Incidents</h3>
        <span className="panel-count">{incidents.length}</span>
      </div>

      {incidents.length === 0 ? (
        <div className="empty-state">
          <ShieldOff size={22} style={{ marginBottom: 10, opacity: 0.5 }} />
          <div className="empty-state-title">No incidents yet</div>
          No correlated incidents have been created. Run the simulation, or
          ingest logs via the API, to see one appear here.
        </div>
      ) : (
        <table className="incidents-table">
          <thead>
            <tr>
              <th>Incident</th>
              <th>Type</th>
              <th>Severity</th>
              <th>Account</th>
              <th>Source IP</th>
              <th>Detected</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {incidents.map((inc) => (
              <tr
                key={inc.id}
                className={inc.id === selectedId ? "selected" : ""}
                onClick={() => onSelect(inc.id)}
              >
                <td className="td-code">{inc.incident_code}</td>
                <td>{inc.incident_type.replaceAll("_", " ")}</td>
                <td>
                  <SeverityBadge severity={inc.severity} />
                </td>
                <td className="mono">{inc.affected_account || "-"}</td>
                <td className="mono">{inc.source_ip || "-"}</td>
                <td className="td-muted">{formatTime(inc.detection_time)}</td>
                <td>
                  <span className={`badge status ${inc.status.toLowerCase()}`}>
                    {inc.status}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
