export default function RankedList({ title, items, labelKey, countKey }) {
  const max = items.length ? Math.max(...items.map((i) => i[countKey])) : 1;

  return (
    <div className="panel">
      <div className="panel-header">
        <h3 className="panel-title">{title}</h3>
        <span className="panel-count">{items.length}</span>
      </div>
      {items.length === 0 ? (
        <div className="empty-state">No data yet.</div>
      ) : (
        <ul className="ranked-list">
          {items.map((item, i) => (
            <li key={i} className="ranked-row">
              <span
                className="ranked-row-bar"
                style={{ width: `${(item[countKey] / max) * 100}%` }}
              />
              <span className="ranked-row-label">{item[labelKey]}</span>
              <span className="ranked-row-count">{item[countKey]}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
