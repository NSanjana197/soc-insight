import { RefreshCw, Zap } from "lucide-react";

export default function Header({ isOnline, onRefresh, onSimulate, loading }) {
  return (
    <header className="header">
      <div className="header-title-group">
        <h1 className="header-title">SOC-Insight</h1>
        <span className="header-subtitle">Investigation &amp; Incident Reporting</span>
      </div>
      <div className="header-actions" style={{ alignItems: "center" }}>
        <span className={`status-pill`}>
          <span className={`status-dot ${isOnline ? "" : "offline"}`} />
          {isOnline ? "connected" : "backend unreachable"}
        </span>
        <button className="btn" onClick={onRefresh} disabled={loading}>
          <RefreshCw size={14} />
          Refresh
        </button>
        <button className="btn btn-primary" onClick={onSimulate} disabled={loading}>
          <Zap size={14} />
          Run Simulation
        </button>
      </div>
    </header>
  );
}
