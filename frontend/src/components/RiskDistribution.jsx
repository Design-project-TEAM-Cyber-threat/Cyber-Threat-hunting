import { LEVELS, formatNumber, formatPercent } from "../format.js";
import { Loading, isUnavailable } from "./Notices.jsx";

const DRIVER_NAMES = { anomaly: "Anomaly model only", deviation: "Baseline deviation only", "anomaly+deviation": "Both signals", none: "No signal" };

export default function RiskDistribution({ summary, loading, error }) {
  if (!summary && loading) return <Loading label="Loading distribution…" />;
  if (!summary) return <p className="muted">{isUnavailable(error) ? "Unavailable while the backend is down." : error?.message || "No data."}</p>;

  const flows = summary.flows_by_risk_level || {};
  const total = LEVELS.reduce((n, l) => n + (flows[l] || 0), 0);
  const drivers = Object.entries(summary.alerts_by_driver || {});
  const ports = summary.top_alert_ports || [];

  if (total === 0) {
    return <p className="muted">No flows have been scored yet, so there is no distribution to show.</p>;
  }
  return (
    <div className="dist">
      <div className="stackbar" role="img" aria-label={LEVELS.map((l) => `${l}: ${formatNumber(flows[l] || 0)} flows`).join(", ")}>
        {LEVELS.map((l) =>
          flows[l] ? <div key={l} className={`seg seg-${l.toLowerCase()}`} style={{ width: `${(flows[l] / total) * 100}%` }} title={`${l}: ${formatNumber(flows[l])}`} /> : null,
        )}
      </div>
      <table className="dist-table">
        <thead>
          <tr><th>Risk level</th><th className="num">Flows</th><th className="num">Share</th></tr>
        </thead>
        <tbody>
          {LEVELS.map((l) => (
            <tr key={l}>
              <td><span className={`badge level-${l.toLowerCase()}`}>{l}</span></td>
              <td className="num">{formatNumber(flows[l] || 0)}</td>
              <td className="num">{formatPercent(flows[l] || 0, total)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="dist-extra">
        <div>
          <h3>Alerts by contributing signal</h3>
          {drivers.length === 0 ? <p className="muted small">No alerts yet.</p> : (
            <ul className="plain">
              {drivers.map(([k, n]) => <li key={k}><span>{DRIVER_NAMES[k] || k}</span><strong>{formatNumber(n)}</strong></li>)}
            </ul>
          )}
        </div>
        <div>
          <h3>Ports with most alerts</h3>
          {ports.length === 0 ? <p className="muted small">No alerts yet.</p> : (
            <ul className="plain">
              {ports.map((p) => <li key={p.port}><span>Port {p.port}</span><strong>{formatNumber(p.alerts)}</strong></li>)}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
