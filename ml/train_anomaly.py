"""
Usage: python ml/train_anomaly.py data/ [cache.joblib]
Builds features (cached), trains Isolation Forest on a benign-only sample,
evaluates on held-out benign flows and on every attack class, saves the model
and writes the computed metrics to ml/artifacts/model_metrics.json.
Labels are used ONLY for the benign training filter and for evaluation.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
import numpy as np, pandas as pd, joblib
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ml.preprocessing import load_cicids_csvs, clean_flows
from ml.features import build_features
from ml.anomaly import AnomalyDetector, ANOMALY

TRAIN_SIZE = 200_000
DATASET_NAME = "CICIDS2017"
LIMITATIONS = (
    "Offline CICIDS2017 metrics do not prove real-world zero-day detection performance. "
    "An anomaly means unusual behavior versus benign training flows, not confirmation of an attack. "
    "The threshold is set from benign training scores, so precision and accuracy depend on the "
    "evaluation mix. Attacks that resemble normal traffic can be missed, and rare legitimate "
    "traffic can be flagged."
)


def compute_evaluation_metrics(y_true, scores, threshold):
    """Score held-out flows. Attack (True/1) is the positive class.

    ROC-AUC uses continuous anomaly scores (higher = more unusual).
    Accuracy, precision, recall, and F1 use the existing threshold rule
    from AnomalyDetector.predict: anomaly when score > threshold.
    Raises ValueError when either evaluation class is missing.
    """
    y_true = np.asarray(y_true).astype(bool)
    scores = np.asarray(scores, dtype=np.float64)
    if y_true.shape != scores.shape:
        raise ValueError(
            f"Ground truth and scores must have the same shape, got {y_true.shape} and {scores.shape}."
        )
    n_attack = int(y_true.sum())
    n_benign = int((~y_true).sum())
    if n_attack == 0 or n_benign == 0:
        raise ValueError(
            "Evaluation requires both classes: held-out benign flows and attack flows. "
            f"Got {n_benign} benign and {n_attack} attack rows."
        )
    y_pred = scores > threshold
    metrics = {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, scores)),
    }
    for name, value in metrics.items():
        if not np.isfinite(value):
            raise ValueError(f"{name} is not a finite number.")
    return metrics


def threshold_rule_text(target_fpr):
    return (
        "Predict the positive class (attack) when the anomaly score is strictly greater than "
        "the threshold. The threshold is the (1 - target_fpr) quantile of benign training "
        f"anomaly scores (target_fpr={target_fpr})."
    )


def build_metrics_record(metrics, *, threshold, target_fpr, training_samples,
                         benign_evaluation_samples, attack_evaluation_samples, timestamp_utc=None):
    required = ("accuracy", "precision", "recall", "f1_score", "roc_auc")
    missing = [key for key in required if key not in metrics]
    if missing:
        raise ValueError(f"Metrics are incomplete: {missing}")
    benign_n = int(benign_evaluation_samples)
    attack_n = int(attack_evaluation_samples)
    if benign_n == 0 or attack_n == 0:
        raise ValueError(
            "Evaluation requires both classes: held-out benign flows and attack flows. "
            f"Got {benign_n} benign and {attack_n} attack rows."
        )
    if timestamp_utc is None:
        timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "accuracy": float(metrics["accuracy"]),
        "precision": float(metrics["precision"]),
        "recall": float(metrics["recall"]),
        "f1_score": float(metrics["f1_score"]),
        "roc_auc": float(metrics["roc_auc"]),
        "threshold": float(threshold),
        "threshold_rule": threshold_rule_text(target_fpr),
        "training_samples": int(training_samples),
        "evaluation_samples": benign_n + attack_n,
        "benign_evaluation_samples": benign_n,
        "attack_evaluation_samples": attack_n,
        "dataset_name": DATASET_NAME,
        "training_method": (
            "Isolation Forest trained on benign CICIDS2017 flows only. "
            "Labels are used only to select those training rows and to build evaluation "
            "ground truth. Labels are not model input features."
        ),
        "evaluation_method": (
            "Held-out benign flows and attack flows excluded from training. "
            "ROC-AUC uses continuous anomaly scores. Accuracy, precision, recall, and "
            "F1-score use the existing threshold rule, with attack as the positive class."
        ),
        "timestamp_utc": timestamp_utc,
        "limitations": LIMITATIONS,
    }


def save_metrics(path, record):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, allow_nan=False) + "\n", encoding="utf-8")


def get_features(folder, cache):
    cache = Path(cache)
    if cache.exists():
        d = joblib.load(cache); return d["features"], d["context"]
    clean, _ = clean_flows(load_cicids_csvs(folder))
    X, ctx = build_features(clean)
    cache.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"features": X, "context": ctx}, cache, compress=3)
    return X, ctx

if __name__ == "__main__":
    folder = sys.argv[1] if len(sys.argv) > 1 else "data"
    cache = sys.argv[2] if len(sys.argv) > 2 else "data/processed/features.joblib"
    X, ctx = get_features(folder, cache)
    y = ctx["Label"].to_numpy()
    benign_idx = np.flatnonzero(y == "BENIGN")

    rng = np.random.default_rng(42)
    train_idx = rng.choice(benign_idx, TRAIN_SIZE, replace=False)
    held_benign = np.setdiff1d(benign_idx, train_idx)
    print(f"train (benign only): {len(train_idx):,} | held-out benign: {len(held_benign):,}")

    det = AnomalyDetector(target_fpr=0.01).fit(X.iloc[train_idx])
    print(f"threshold (99th pct of training scores): {det.threshold:.4f}")

    scores, labels = det.predict(X)
    flagged = labels == ANOMALY
    is_attack = y != "BENIGN"

    mask = np.zeros(len(y), bool); mask[held_benign] = True; mask |= is_attack
    try:
        metrics = compute_evaluation_metrics(is_attack[mask], scores[mask], det.threshold)
    except ValueError as exc:
        raise SystemExit(f"Evaluation failed: {exc}") from exc
    print(f"\nROC-AUC, held-out benign vs all attacks: {metrics['roc_auc']:.3f}")
    print(f"Accuracy: {metrics['accuracy']:.3f} | Precision: {metrics['precision']:.3f} | "
          f"Recall: {metrics['recall']:.3f} | F1-score: {metrics['f1_score']:.3f}")
    print(f"False-positive rate on held-out benign: {flagged[held_benign].mean():.2%}")
    tp = flagged[is_attack].sum(); fp = flagged[held_benign].sum()
    print(f"Flagged attacks: {tp:,} of {is_attack.sum():,} ({tp / is_attack.sum():.1%})")

    print("\nPer-class share flagged as Anomaly:")
    rows = (pd.DataFrame({"Label": y, "flagged": flagged, "score": scores})
            .groupby("Label").agg(flows=("flagged", "size"), flagged_pct=("flagged", "mean"),
                                  median_score=("score", "median"))
            .sort_values("flagged_pct", ascending=False))
    rows["flagged_pct"] = (rows["flagged_pct"] * 100).round(1)
    rows["median_score"] = rows["median_score"].round(3)
    print(rows.to_string())

    # Of ALL flows flagged, how many are actually attacks? (precision, depends on mix)
    print(f"\nPrecision on full dataset (anomalies that are labeled attacks): "
          f"{is_attack[flagged].mean():.1%} of {flagged.sum():,} flagged flows")
    print(f"Benign flows flagged: {(~is_attack[flagged]).sum():,} -> anomaly != attack")

    out = Path("ml/artifacts"); out.mkdir(exist_ok=True)
    det.save(out / "isolation_forest.joblib")
    print("\nsaved ml/artifacts/isolation_forest.joblib")
    record = build_metrics_record(
        metrics,
        threshold=det.threshold,
        target_fpr=det.target_fpr,
        training_samples=len(train_idx),
        benign_evaluation_samples=int((~is_attack[mask]).sum()),
        attack_evaluation_samples=int(is_attack[mask].sum()),
    )
    save_metrics(out / "model_metrics.json", record)
    print("saved ml/artifacts/model_metrics.json")
