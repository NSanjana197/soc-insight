export default function SeverityBadge({ severity }) {
  const level = (severity || "").toLowerCase();
  return <span className={`badge ${level}`}>{severity}</span>;
}
