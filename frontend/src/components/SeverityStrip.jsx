export default function SeverityStrip({ summary }) {
  const counts = summary?.severity_counts || {};
  const tiles = [
    { key: "CRITICAL", label: "Critical", cls: "critical" },
    { key: "HIGH", label: "High", cls: "high" },
    { key: "MEDIUM", label: "Medium", cls: "medium" },
    { key: "LOW", label: "Low", cls: "low" },
  ];

  return (
    <div className="severity-strip">
      {tiles.map((t) => (
        <div key={t.key} className={`severity-tile ${t.cls}`}>
          <span className="severity-tile-label">{t.label}</span>
          <span className="severity-tile-value">{counts[t.key] ?? 0}</span>
        </div>
      ))}
      <div className="severity-tile totals">
        <div className="totals-item">
          <span className="severity-tile-label">Logs Analyzed</span>
          <span className="severity-tile-value">{summary?.total_logs_analyzed ?? 0}</span>
        </div>
        <div className="totals-item">
          <span className="severity-tile-label">Total Alerts</span>
          <span className="severity-tile-value">{summary?.total_alerts ?? 0}</span>
        </div>
      </div>
    </div>
  );
}
