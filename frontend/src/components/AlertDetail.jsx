import { featureLabel, formatAutomatedAction, formatDateTime, formatDirection, formatDrivers, formatScore, formatValue, levelClass } from "../format.js";
import { ErrorNotice, Loading } from "./Notices.jsx";

function EvidenceMeter({ value }) {
  const v = Math.max(0, Math.min(1, Number(value) || 0));
  return (
    <div className="evidence-meter" role="img" aria-label={`Evidence ${v.toFixed(2)} out of 1`}>
      <div className="evidence-fill" style={{ width: `${v * 100}%` }} />
    </div>
  );
}

function FeatureTable({ features, extraHeader, extraCell }) {
  return (
    <table className="features">
      <thead>
        <tr><th>Behavior</th><th className="num">Observed</th><th className="num">Typical</th><th>Compared with typical</th><th className="num">{extraHeader}</th></tr>
      </thead>
      <tbody>
        {features.map((f) => (
          <tr key={f.feature}>
            <td>{featureLabel(f.feature)}</td>
            <td className="num">{formatValue(f.value)}</td>
            <td className="num">{formatValue(f.typical)}</td>
            <td>{formatDirection(f)}</td>
            <td className="num">{extraCell(f)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function EvidenceBlock({ title, caption, score, scoreLabel, evidence, children }) {
  return (
    <section className="evidence">
      <h3>{title}</h3>
      <p className="caption">{caption}</p>
      <div className="evidence-row">
        <div><span className="kv-label">{scoreLabel}</span> <strong>{score}</strong></div>
        <div className="evidence-wrap">
          <span className="kv-label">Evidence</span> <strong>{formatScore(evidence, 2)}</strong> <span className="muted small">of 1</span>
          <EvidenceMeter value={evidence} />
        </div>
      </div>
      {children}
    </section>
  );
}

export default function AlertDetail({ alertId, data, loading, error, onClose, onRetry }) {
  if (!alertId) {
    return (
      <div className="detail-empty">
        <strong>Select an alert</strong>
        <p>Click a row in the table to see why it was raised, the evidence behind it, and the suggested response.</p>
      </div>
    );
  }
  const current = data && data.id === alertId ? data : null;   // never show another alert's data while loading
  return (
    <div className="detail">
      <div className="detail-top">
        <h2>Alert #{alertId}</h2>
        <button type="button" className="btn btn-small" onClick={onClose} aria-label="Close alert details">Close</button>
      </div>
      {loading && !current && <Loading label="Loading alert…" />}
      {error && <ErrorNotice title="Could not load this alert" error={error} onRetry={onRetry} />}
      {current && <DetailBody a={current} />}
    </div>
  );
}

function DetailBody({ a }) {
  const drivers = formatDrivers(a.drivers);
  const an = a.anomaly || {};
  const dv = a.baseline_deviation || {};
  const ctx = a.context || {};
  return (
    <>
      <div className="detail-head">
        <span className={`badge badge-large ${levelClass(a.risk_level)}`}>{a.risk_level}</span>
        <div className="big-score"><span>{formatScore(a.risk_score)}</span><small>risk score / 100</small></div>
        <div className="detail-meta">
          <div><span className="kv-label">Port / service</span> <strong>{ctx.service || `port ${ctx.destination_port}`}</strong></div>
          <div><span className="kv-label">Detected</span> {formatDateTime(a.created_at)}</div>
          <div><span className="kv-label">Signals</span> {drivers.length ? drivers.join(" + ") : "—"}</div>
        </div>
      </div>

      <p className="disclaimer">Unusual behavior is not proof of a malicious attack.</p>

      <section>
        <h3>Why this alert was raised</h3>
        <p className="explanation">{a.explanation}</p>
        <p className="caption">Generated and stored when the flow was scored; it is not recalculated from the current baseline.</p>
      </section>

      <EvidenceBlock
        title="Isolation Forest anomaly evidence"
        caption="How unusual the flow is compared with the benign traffic the model learned from."
        scoreLabel="Anomaly score" score={formatScore(an.score, 3)} evidence={an.evidence}
      >
        {an.features && an.features.length > 0 ? (
          <FeatureTable features={an.features} extraHeader="Share" extraCell={(f) => `${Math.round((f.share || 0) * 100)}%`} />
        ) : (
          <p className="muted small">{Number(an.evidence) > 0 ? "No single behavior stands out; the unusualness comes from a combination of features." : "This signal did not contribute to the alert."}</p>
        )}
      </EvidenceBlock>

      <EvidenceBlock
        title="Adaptive baseline deviation evidence"
        caption="How far the flow is from what is typical for this destination service (robust z-score)."
        scoreLabel="Deviation score" score={formatScore(dv.score, 1)} evidence={dv.evidence}
      >
        {dv.features && dv.features.length > 0 ? (
          <FeatureTable features={dv.features} extraHeader="z-score" extraCell={(f) => formatScore(f.z, 1)} />
        ) : (
          <p className="muted small">This signal did not contribute to the alert.</p>
        )}
      </EvidenceBlock>

      <section className="evidence">
        <h3>Service / port context</h3>
        <p className="caption">Context scales how much the evidence matters; it is not evidence by itself.</p>
        <dl className="kv">
          <dt>Destination port</dt><dd>{ctx.destination_port ?? "—"}</dd>
          <dt>Service</dt><dd>{ctx.service || "—"}</dd>
          <dt>Type</dt><dd>{ctx.type || "—"}</dd>
          <dt>Context factor</dt><dd>× {ctx.factor ?? "—"}</dd>
        </dl>
      </section>

      <section className="response">
        <h3>Recommended response</h3>
        <p><strong>{a.recommended_action}</strong></p>
        <p>{a.recommended_response}</p>
        <p className="automated">Automated action: <strong>{formatAutomatedAction(a.automated_action)}</strong></p>
        {a.note && <p className="caption">{a.note}</p>}
      </section>

      {a.flow && (
        <section className="evidence">
          <h3>Flow record</h3>
          <dl className="kv">
            <dt>Flow ID</dt><dd>{a.flow.id}</dd>
            <dt>Isolation Forest label</dt><dd>{a.flow.anomaly_label}</dd>
          </dl>
        </section>
      )}
    </>
  );
}
