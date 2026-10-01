import { useMemo } from "react";

const BUCKET_COUNT = 12;
const SEVERITY_COLOR = {
  CRITICAL: "var(--critical)",
  HIGH: "var(--high)",
  MEDIUM: "var(--medium)",
  LOW: "var(--low)",
};
const SEVERITY_RANK = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

/**
 * Buckets alerts into BUCKET_COUNT equal time slices spanning from the
 * oldest to the newest alert, and renders one bar per bucket sized by
 * count, colored by the highest severity seen in that bucket. Built as
 * plain SVG rather than pulling in a charting library, since this is one
 * chart with one shape of data - not worth the dependency weight.
 */
export default function AlertsTimelineChart({ alerts }) {
  const { buckets, maxCount } = useMemo(() => {
    if (!alerts || alerts.length === 0) {
      return { buckets: [], maxCount: 0 };
    }
    const times = alerts.map((a) => new Date(a.created_at).getTime());
    const min = Math.min(...times);
    const max = Math.max(...times);
    const span = Math.max(max - min, 1);
    const bucketMs = span / BUCKET_COUNT;

    const slots = Array.from({ length: BUCKET_COUNT }, () => ({
      count: 0,
      topSeverity: "LOW",
    }));

    alerts.forEach((a) => {
      const t = new Date(a.created_at).getTime();
      let idx = Math.floor((t - min) / bucketMs);
      if (idx >= BUCKET_COUNT) idx = BUCKET_COUNT - 1;
      if (idx < 0) idx = 0;
      slots[idx].count += 1;
      if (SEVERITY_RANK[a.severity] > SEVERITY_RANK[slots[idx].topSeverity]) {
        slots[idx].topSeverity = a.severity;
      }
    });

    return { buckets: slots, maxCount: Math.max(...slots.map((s) => s.count), 1) };
  }, [alerts]);

  if (!alerts || alerts.length === 0) {
    return (
      <div className="panel">
        <div className="panel-header">
          <h3 className="panel-title">Alerts Over Time</h3>
        </div>
        <div className="empty-state">No alerts yet.</div>
      </div>
    );
  }

  const width = 600;
  const height = 90;
  const barGap = 4;
  const barWidth = width / BUCKET_COUNT - barGap;

  return (
    <div className="panel">
      <div className="panel-header">
        <h3 className="panel-title">Alerts Over Time</h3>
        <span className="panel-count">{alerts.length} total</span>
      </div>
      <div className="chart-wrap">
        <svg viewBox={`0 0 ${width} ${height}`} width="100%" height={height} preserveAspectRatio="none">
          {buckets.map((b, i) => {
            const barHeight = (b.count / maxCount) * (height - 4);
            const x = i * (barWidth + barGap);
            const y = height - barHeight;
            return (
              <rect
                key={i}
                x={x}
                y={y}
                width={barWidth}
                height={barHeight || 1}
                fill={b.count > 0 ? SEVERITY_COLOR[b.topSeverity] : "var(--border)"}
                opacity={b.count > 0 ? 0.85 : 0.4}
              >
                <title>{b.count} alert{b.count === 1 ? "" : "s"}</title>
              </rect>
            );
          })}
        </svg>
      </div>
    </div>
  );
}
