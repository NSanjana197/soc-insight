import { useMemo } from "react";

export default function AlertsOverTime({ alerts = [] }) {
  const chartData = useMemo(() => {
    const buckets = {};

    alerts.forEach((alert) => {
      if (!alert.created_at) return;

      const date = new Date(alert.created_at);

      // Group alerts by hour
      const key = `${date.getFullYear()}-${String(
        date.getMonth() + 1
      ).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")} ${String(
        date.getHours()
      ).padStart(2, "0")}:00`;

      buckets[key] = (buckets[key] || 0) + 1;
    });

    return Object.entries(buckets)
      .sort(([a], [b]) => new Date(a) - new Date(b))
      .map(([time, count]) => ({
        time,
        label: new Date(time.replace(" ", "T")).toLocaleTimeString([], {
          hour: "2-digit",
          minute: "2-digit",
        }),
        count,
      }));
  }, [alerts]);

  const maxCount = Math.max(...chartData.map((item) => item.count), 1);

  return (
    <section className="chart-card">
      <div className="chart-header">
        <div>
          <h2>Alerts Over Time</h2>
          <p>Alert generation by hour</p>
        </div>

        <span className="chart-total">
          {alerts.length} total
        </span>
      </div>

      {chartData.length === 0 ? (
        <div className="chart-empty">
          No alert activity available.
        </div>
      ) : (
        <div className="bar-chart">
          {chartData.map((item) => (
            <div className="bar-column" key={item.time}>
              <span className="bar-value">{item.count}</span>

              <div className="bar-track">
                <div
                  className="bar-fill"
                  style={{
                    height: `${(item.count / maxCount) * 100}%`,
                  }}
                />
              </div>

              <span className="bar-label">{item.label}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}