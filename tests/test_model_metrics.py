"""Evaluation-metric helpers. No CICIDS download and no saved-model training."""
import json
import sys
import tempfile
from pathlib import Path

import numpy as np
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score

sys.path.insert(0, ".")
from ml.features import FEATURE_NAMES
from ml.train_anomaly import LIMITATIONS, build_metrics_record, compute_evaluation_metrics, save_metrics

assert "Label" not in FEATURE_NAMES

y = np.array([0, 0, 0, 1, 1, 1])
scores = np.array([0.1, 0.2, 0.6, 0.3, 0.7, 0.9])
threshold = 0.5
pred = scores > threshold
m = compute_evaluation_metrics(y, scores, threshold)
assert m["accuracy"] == accuracy_score(y, pred)
assert m["precision"] == precision_score(y, pred, zero_division=0)
assert m["recall"] == recall_score(y, pred, zero_division=0)
assert m["f1_score"] == f1_score(y, pred, zero_division=0)
assert m["roc_auc"] == roc_auc_score(y, scores)
assert abs(m["accuracy"] - 4 / 6) < 1e-12
assert abs(m["precision"] - 2 / 3) < 1e-12
assert abs(m["recall"] - 2 / 3) < 1e-12
assert compute_evaluation_metrics(y.astype(bool), scores, threshold) == m

# score == threshold stays Normal; AnomalyDetector uses a strict greater-than rule.
tie = compute_evaluation_metrics(np.array([0, 1]), np.array([0.5, 0.5]), 0.5)
assert tie["precision"] == 0.0 and tie["recall"] == 0.0 and tie["roc_auc"] == 0.5

for bad, needle in (
    (np.zeros(4, dtype=int), "benign"),
    (np.ones(4, dtype=int), "attack"),
):
    try:
        compute_evaluation_metrics(bad, np.linspace(0, 1, 4), 0.5)
        raise SystemExit("expected a failure when an evaluation class is missing")
    except ValueError as exc:
        assert needle in str(exc).lower()

try:
    compute_evaluation_metrics(y, scores[:-1], threshold)
    raise SystemExit("expected a failure when shapes differ")
except ValueError as exc:
    assert "same shape" in str(exc)

record = build_metrics_record(
    m, threshold=threshold, target_fpr=0.01, training_samples=200_000,
    benign_evaluation_samples=3, attack_evaluation_samples=3,
    timestamp_utc="2026-10-12T00:00:00Z",
)
for key in (
    "accuracy", "precision", "recall", "f1_score", "roc_auc", "threshold", "threshold_rule",
    "training_samples", "evaluation_samples", "benign_evaluation_samples", "attack_evaluation_samples",
    "dataset_name", "training_method", "evaluation_method", "timestamp_utc", "limitations",
):
    assert key in record, key
assert record["accuracy"] == m["accuracy"]
assert record["roc_auc"] == m["roc_auc"]
assert record["evaluation_samples"] == 6
assert record["training_samples"] == 200_000
assert record["dataset_name"] == "CICIDS2017"
assert record["timestamp_utc"] == "2026-10-12T00:00:00Z"
assert "not model input features" in record["training_method"]
assert "continuous anomaly scores" in record["evaluation_method"]
assert "strictly greater" in record["threshold_rule"]
assert record["limitations"] == LIMITATIONS
assert "do not prove real-world zero-day detection performance" in record["limitations"]

try:
    build_metrics_record(
        m, threshold=threshold, target_fpr=0.01, training_samples=10,
        benign_evaluation_samples=0, attack_evaluation_samples=3,
    )
    raise SystemExit("expected a failure when benign evaluation rows are missing")
except ValueError as exc:
    assert "both classes" in str(exc).lower()

with tempfile.TemporaryDirectory() as folder:
    path = Path(folder) / "model_metrics.json"
    save_metrics(path, record)
    loaded = json.loads(path.read_text(encoding="utf-8"))
assert loaded["f1_score"] == record["f1_score"]
assert loaded["attack_evaluation_samples"] == 3

print("model metrics tests passed")
