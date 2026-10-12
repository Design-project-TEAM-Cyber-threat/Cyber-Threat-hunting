"""
Usage: python ml/train_anomaly.py data/ [cache.joblib]
Builds features (cached), trains Isolation Forest on a benign-only sample,
evaluates on held-out benign flows and on every attack class, saves the model.
Labels are used ONLY for the benign training filter and for evaluation.
"""
import sys
from pathlib import Path
import numpy as np, pandas as pd, joblib
from sklearn.metrics import roc_auc_score
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ml.preprocessing import load_cicids_csvs, clean_flows
from ml.features import build_features
from ml.anomaly import AnomalyDetector, ANOMALY

TRAIN_SIZE = 200_000

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
    print(f"\nROC-AUC, held-out benign vs all attacks: {roc_auc_score(is_attack[mask], scores[mask]):.3f}")
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
