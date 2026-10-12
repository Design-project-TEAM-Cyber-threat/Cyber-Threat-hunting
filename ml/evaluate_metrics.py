
# ml/evaluate_metrics.py

import json
from pathlib import Path

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

ROOT = Path(__file__).resolve().parent.parent
CACHE = ROOT / "data" / "processed" / "features.joblib"
MODEL = ROOT / "ml" / "artifacts" / "isolation_forest.joblib"
OUTPUT = ROOT / "ml" / "artifacts" / "model_metrics.json"
TRAIN_SIZE = 200_000


def main():
    if not CACHE.exists():
        raise FileNotFoundError(
            f"{CACHE} not found. Run ml/train_anomaly.py first."
        )
    if not MODEL.exists():
        raise FileNotFoundError(
            f"{MODEL} not found. Train the Isolation Forest first."
        )

    print("Loading cached features...")
    cached = joblib.load(CACHE)
    X = cached["features"]
    context = cached["context"]

    y_labels = context["Label"].astype(str).str.strip().to_numpy()
    benign_idx = np.flatnonzero(y_labels == "BENIGN")

    if len(benign_idx) <= TRAIN_SIZE:
        raise ValueError(
            f"Need more than {TRAIN_SIZE:,} benign flows; "
            f"found {len(benign_idx):,}."
        )

    # Reproduce the same deterministic training split used by train_anomaly.py.
    rng = np.random.default_rng(42)
    train_idx = rng.choice(benign_idx, TRAIN_SIZE, replace=False)
    held_benign = np.setdiff1d(benign_idx, train_idx)

    # Evaluate on held-out benign flows plus all attack flows.
    is_attack = y_labels != "BENIGN"
    eval_mask = np.zeros(len(y_labels), dtype=bool)
    eval_mask[held_benign] = True
    eval_mask |= is_attack

    print("Loading saved Isolation Forest...")
    detector = joblib.load(MODEL)

    print(f"Scoring {int(eval_mask.sum()):,} evaluation flows...")
    scores, predictions = detector.predict(X)

    # Treat an attack label as positive; all non-BENIGN labels are attacks.
    y_true = is_attack[eval_mask].astype(int)
    y_pred = (predictions[eval_mask] == "Anomaly").astype(int)
    eval_scores = scores[eval_mask]

    metrics = {
        "status": "evaluated",
        "evaluation_type": "Offline evaluation",
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(
            precision_score(y_true, y_pred, zero_division=0)
        ),
        "recall": float(
            recall_score(y_true, y_pred, zero_division=0)
        ),
        "f1_score": float(
            f1_score(y_true, y_pred, zero_division=0)
        ),
        "roc_auc": float(roc_auc_score(y_true, eval_scores)),
        "evaluation_samples": int(eval_mask.sum()),
        "benign_samples": int(len(held_benign)),
        "attack_samples": int(is_attack.sum()),
        "true_positives": int(((y_true == 1) & (y_pred == 1)).sum()),
        "false_positives": int(((y_true == 0) & (y_pred == 1)).sum()),
        "true_negatives": int(((y_true == 0) & (y_pred == 0)).sum()),
        "false_negatives": int(((y_true == 1) & (y_pred == 0)).sum()),
        "training_benign_samples": int(len(train_idx)),
        "threshold": float(detector.threshold),
        "positive_class": "Attack",
        "note": (
            "Attack labels are used only for evaluation, not model training. "
            "Anomaly means unusual behavior, not confirmed malicious activity."
        ),
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print("\nOffline evaluation metrics")
    for name in ("accuracy", "precision", "recall", "f1_score", "roc_auc"):
        print(f"{name}: {metrics[name] * 100:.2f}%")
    print(f"Evaluation samples: {metrics['evaluation_samples']:,}")
    print(f"Benign samples: {metrics['benign_samples']:,}")
    print(f"Attack samples: {metrics['attack_samples']:,}")
    print(f"Saved to: {OUTPUT}")


if __name__ == "__main__":
    main()
