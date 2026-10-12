import { MODEL_METRICS, formatMetric } from "../format.js";
import { Loading, isUnavailable } from "./Notices.jsx";

export default function ModelMetrics({ metrics, loading, error }) {
  if (!metrics && loading) return <Loading label="Loading model metrics…" />;
  if (!metrics) {
    return (
      <p className="muted">
        {isUnavailable(error)
          ? "Model metrics unavailable while the backend is down."
          : error?.message || "No model metrics."}
      </p>
    );
  }
  return (
    <>
      <div className="stats">
        {MODEL_METRICS.map(({ key, label }) => (
          <div className="stat" key={key}>
            <div className="stat-label">{label}</div>
            <div className="stat-value">{formatMetric(metrics[key])}</div>
          </div>
        ))}
      </div>
      {metrics.limitations ? <p className="caption">{metrics.limitations}</p> : null}
    </>
  );
}
