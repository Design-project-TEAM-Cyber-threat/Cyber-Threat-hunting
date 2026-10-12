
import { useEffect, useState } from "react";

const API_URL = "http://127.0.0.1:8000/api/model-metrics/";

const metricItems = [
  { key: "accuracy", label: "Accuracy" },
  { key: "precision", label: "Precision" },
  { key: "recall", label: "Recall" },
  { key: "f1_score", label: "F1-score" },
  { key: "roc_auc", label: "ROC-AUC" },
];

function percentage(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    return "N/A";
  }
  return `${(value * 100).toFixed(2)}%`;
}

export default function ModelPerformance() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();

    fetch(API_URL, { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error("Could not load model metrics.");
        return response.json();
      })
      .then(setData)
      .catch((err) => {
        if (err.name !== "AbortError") setError(err.message);
      });

    return () => controller.abort();
  }, []);

  const cardStyle = {
    padding: "16px",
    border: "1px solid var(--border, #dbe2ea)",
    borderRadius: "10px",
    background: "var(--surface, #ffffff)",
    minWidth: 0,
  };

  return (
    <section className="card" aria-labelledby="model-performance-heading">
      <h2 id="model-performance-heading">Model Performance</h2>
      <p style={{ marginTop: 0, color: "var(--muted, #64748b)" }}>
        Offline Evaluation Metrics — calculated against labelled CICIDS2017
        evaluation flows. These are not live dashboard detection metrics.
      </p>

      {error && (
        <p role="alert">
          {error} Make sure the Django backend is running.
        </p>
      )}

      {!data && !error && <p>Loading evaluation metrics…</p>}

      {data?.status === "not_evaluated" && (
        <p>{data.message || "Not evaluated yet. Run the evaluation script."}</p>
      )}

      {data?.status === "evaluated" && (
        <>
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
              gap: "12px",
              marginTop: "16px",
            }}
          >
            {metricItems.map((item) => (
              <div key={item.key} style={cardStyle}>
                <p style={{ margin: "0 0 8px", fontSize: "14px" }}>
                  {item.label}
                </p>
                <strong style={{ fontSize: "24px" }}>
                  {percentage(data[item.key])}
                </strong>
              </div>
            ))}
          </div>

          <div style={{ marginTop: "16px", fontSize: "14px" }}>
            <p>
              <strong>Evaluation samples:</strong>{" "}
              {Number(data.evaluation_samples).toLocaleString()}
            </p>
            <p>
              <strong>Benign flows:</strong>{" "}
              {Number(data.benign_samples).toLocaleString()}
            </p>
            <p>
              <strong>Attack flows:</strong>{" "}
              {Number(data.attack_samples).toLocaleString()}
            </p>
          </div>

          <details>
            <summary>Confusion matrix counts</summary>
            <ul>
              <li>True positives: {data.true_positives}</li>
              <li>False positives: {data.false_positives}</li>
              <li>True negatives: {data.true_negatives}</li>
              <li>False negatives: {data.false_negatives}</li>
            </ul>
          </details>

          <p style={{ fontSize: "13px", color: "var(--muted, #64748b)" }}>
            These metrics evaluate anomaly predictions against dataset labels.
            An anomaly is not proof of a malicious attack.
          </p>
        </>
      )}
    </section>
  );
}
