export default function StatsStrip({ stats }) {
  const rate = stats.total > 0 ? ((stats.sqli_detected / stats.total) * 100).toFixed(1) : '0.0'
  return (
    <div className="stats-strip">
      <div className="stat-box"><div className="stat-label">Total Queries</div><div className="stat-value blue">{stats.total}</div><div className="stat-sub">processed</div></div>
      <div className="stat-box"><div className="stat-label">Threats</div><div className="stat-value red">{stats.sqli_detected}</div><div className="stat-sub">SQLi detected</div></div>
      <div className="stat-box"><div className="stat-label">Safe</div><div className="stat-value green">{stats.normal}</div><div className="stat-sub">normal queries</div></div>
      <div className="stat-box"><div className="stat-label">Threat Rate</div><div className="stat-value yellow">{rate}%</div><div className="stat-sub">detection rate</div></div>
    </div>
  )
}
