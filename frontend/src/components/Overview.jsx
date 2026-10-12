import { formatNumber, formatScore } from "../format.js";
import { Loading, isUnavailable } from "./Notices.jsx";

function Stat({ label, value, hint, tone }) {
  return (
    <div className={`stat ${tone ? `stat-${tone}` : ""}`}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {hint && <div className="stat-hint">{hint}</div>}
    </div>
  );
}

export default function Overview({ summary, loading, error }) {
  if (!summary && loading) return <Loading label="Loading overview…" />;
  if (!summary) {
    return <p className="muted">{isUnavailable(error) ? "Overview unavailable while the backend is down." : error?.message || "No overview data."}</p>;
  }
  const f = summary.flows_by_risk_level || {};
  return (
    <div className="stats">
      <Stat label="Total flows" value={formatNumber(summary.total_flows)} hint="scored and stored" />
      <Stat label="Total alerts" value={formatNumber(summary.total_alerts)} hint="Medium + High" />
      <Stat label="Low" value={formatNumber(f.Low)} hint="flows" tone="low" />
      <Stat label="Medium" value={formatNumber(f.Medium)} hint="flows" tone="medium" />
      <Stat label="High" value={formatNumber(f.High)} hint="flows" tone="high" />
      <Stat label="Average alert risk" value={formatScore(summary.average_alert_risk)} hint="0–100, alerts only" />
    </div>
  );
}
