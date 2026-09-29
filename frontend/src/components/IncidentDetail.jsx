import { useState } from "react";
import { X, Download } from "lucide-react";
import SeverityBadge from "./SeverityBadge.jsx";
import { api } from "../api.js";

function formatTime(iso) {
  if (!iso) return "-";
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function formatClock(iso) {
  if (!iso) return "-";
  return new Date(iso).toLocaleTimeString(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export default function IncidentDetail({ incident, onClose, onStatusChange }) {
  const [updating, setUpdating] = useState(false);

  if (!incident) return null;

  const handleStatusChange = async (e) => {
    const status = e.target.value;
    setUpdating(true);
    try {
      await api.updateIncidentStatus(incident.id, status);
      onStatusChange(incident.id, status);
    } catch (err) {
      console.error(err);
    } finally {
      setUpdating(false);
    }
  };

  return (
    <>
      <div className="overlay" onClick={onClose} />
      <div className="detail-panel">
        <div className="detail-header">
          <div>
            <div className="detail-code">{incident.incident_code}</div>
            <h2 className="detail-title">
              {incident.incident_type.replaceAll("_", " ")}
            </h2>
            <SeverityBadge severity={incident.severity} />
          </div>
          <button className="detail-close" onClick={onClose} aria-label="Close">
            <X size={16} />
          </button>
        </div>

        <div className="detail-body">
          <div className="detail-meta-grid">
            <div className="detail-meta-item">
              <span className="detail-meta-label">Affected Account</span>
              <span className="detail-meta-value">
                {incident.affected_account || "-"}
              </span>
            </div>
            <div className="detail-meta-item">
              <span className="detail-meta-label">Source IP</span>
              <span className="detail-meta-value">{incident.source_ip || "-"}</span>
            </div>
            <div className="detail-meta-item">
              <span className="detail-meta-label">Detection Time</span>
              <span className="detail-meta-value">
                {formatTime(incident.detection_time)}
              </span>
            </div>
            <div className="detail-meta-item">
              <span className="detail-meta-label">Status</span>
              <select
                className="status-select"
                value={incident.status}
                onChange={handleStatusChange}
                disabled={updating}
              >
                <option value="OPEN">OPEN</option>
                <option value="IN_PROGRESS">IN_PROGRESS</option>
                <option value="CLOSED">CLOSED</option>
              </select>
            </div>
          </div>

          <div>
            <h4 className="detail-section-title">Evidence</h4>
            <ul className="evidence-list">
              {incident.evidence.map((e, i) => (
                <li key={i}>{e}</li>
              ))}
            </ul>
          </div>

          <div>
            <h4 className="detail-section-title">Timeline</h4>
            <div className="timeline">
              {(incident.timeline || []).map((ev, i) => (
                <div key={i} className="timeline-row">
                  <span className="timeline-dot" />
                  <div className="timeline-time">{formatClock(ev.timestamp)}</div>
                  <div className="timeline-desc">{ev.description}</div>
                </div>
              ))}
            </div>
          </div>

          <div>
            <h4 className="detail-section-title">Recommended Actions</h4>
            <ul className="actions-list">
              {incident.recommended_actions.map((a, i) => (
                <li key={i}>{a}</li>
              ))}
            </ul>
          </div>
        </div>

        <div className="detail-footer">
          <a
            className="btn btn-primary"
            href={api.getReportUrl(incident.id)}
            download
          >
            <Download size={14} />
            Download PDF Report
          </a>
          <button className="btn" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </>
  );
}
