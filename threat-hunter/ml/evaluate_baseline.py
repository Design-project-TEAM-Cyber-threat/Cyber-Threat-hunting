"""
Usage: python ml/evaluate_baseline.py [features_cache.joblib]
Compares baseline configurations (ablation) against a frozen baseline.
Replays real CICIDS2017 flows in capture-day order (Mon -> Fri) through the
adaptive baseline and compares it with a FROZEN baseline (same start, no updates).
Labels are used only to report results, never to decide what updates the baseline.
"""
import sys, copy
from pathlib import Path
import numpy as np, pandas as pd, joblib
from sklearn.metrics import roc_auc_score
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ml.anomaly import AnomalyDetector
from ml.baseline import AdaptiveBaseline

ORDER = ["monday", "tuesday", "wednesday", "thursday-workinghours-morning",
         "thursday-workinghours-afternoon", "friday-workinghours-morning",
         "friday-workinghours-afternoon-portscan", "friday-workinghours-afternoon-ddos"]
INIT_FLOWS = 100_000          # learning period: first flows of Monday (an all-benign day)

def day_rank(name):
    n = name.lower().replace("_", "-")
    return next(i for i, k in enumerate(ORDER) if n.startswith(k))

CONFIGS = {
    "A previous (window 5k, 25%/batch)": dict(window=5000, max_replace_frac=0.25),
    "B slower (window 20k, 5%/batch)":   dict(window=20000, max_replace_frac=0.05),
    "C + drift limit (3 scales)":        dict(window=20000, max_replace_frac=0.05, max_drift=3.0),
    "D + surge freeze (3% flagged)":     dict(window=20000, max_replace_frac=0.05, max_drift=3.0, surge_flag_frac=0.03),
}
RECOMMENDED = "D + surge freeze (3% flagged)"

if __name__ == "__main__":
    cache = sys.argv[1] if len(sys.argv) > 1 else "data/processed/features.joblib"
    d = joblib.load(cache); X, ctx = d["features"], d["context"]
    rank = ctx["source_file"].astype(str).map(day_rank).to_numpy()
    order = np.argsort(rank, kind="stable")                  # keeps capture order inside each file
    X, ctx = X.iloc[order].reset_index(drop=True), ctx.iloc[order].reset_index(drop=True)
    sf = ctx["source_file"].astype(str)
    ctx["day"] = sf.str.split("-").str[0].str.title() + np.where(sf.str.contains("Morning"), " AM",
                                                         np.where(sf.str.contains("Afternoon"), " PM", ""))

    det = AnomalyDetector.load("ml/artifacts/isolation_forest.joblib")
    Xi, ci = X.iloc[:INIT_FLOWS], ctx.iloc[:INIT_FLOWS]
    Xs, cs = X.iloc[INIT_FLOWS:].reset_index(drop=True), ctx.iloc[INIT_FLOWS:].reset_index(drop=True)
    print(f"Initial baseline: first {INIT_FLOWS:,} Monday flows "
          f"({ci['Label'].value_counts().to_dict()}) | streamed: {len(Xs):,} flows")
    sc, lb = det.predict(Xs); pre = (sc, lb)                 # score once, reuse for every config
    y = cs["Label"].to_numpy(); atk = y != "BENIGN"
    ben_days = [dday for dday in cs["day"].unique() if ((cs["day"] == dday).to_numpy() & ~atk).sum() >= 1000]

    def summarize(name, res):
        acc = res["accepted"].to_numpy(); dev = res["deviation_score"].to_numpy()
        per_day = {dday: (dev[(cs["day"] == dday).to_numpy() & ~atk] > 3).mean() * 100 for dday in ben_days}
        return {"config": name,
                "accepted%": acc.mean() * 100 if acc.any() else 0,
                "attack_share_in_baseline%": atk[acc].mean() * 100 if acc.any() else 0,
                "AUC_deviation": roc_auc_score(atk, dev),
                "benign_dev>3 %(avg of days)": np.mean(list(per_day.values())),
                "benign_dev>3 %(Fri PM)": per_day.get("Friday PM", np.nan)}

    rows, results, models = [], {}, {}
    for name, kw in CONFIGS.items():
        b = AdaptiveBaseline(**kw).fit(Xi, ci)
        res = b.process_stream(Xs, cs, det, precomputed=pre)
        rows.append(summarize(name, res)); results[name] = res; models[name] = b
    frozen = AdaptiveBaseline(**CONFIGS["B slower (window 20k, 5%/batch)"]).fit(Xi, ci)
    rf = frozen.process_stream(Xs, cs, det, update=False, precomputed=pre)
    rows.append(summarize("frozen (no updates)", rf))
    print(f"\nStream: attack share {atk.mean():.2%} | isolation-forest-only AUC {roc_auc_score(atk, sc):.3f}")
    print(pd.DataFrame(rows).round(2).to_string(index=False))

    best = results[RECOMMENDED]
    print(f"\nMedian deviation_score by class, {RECOMMENDED} vs frozen (BENIGN is the reference):")
    t = pd.DataFrame({"recommended": best.groupby(y)["deviation_score"].median(),
                      "frozen": rf.groupby(y)["deviation_score"].median(),
                      "accepted%": (pd.Series(best["accepted"].to_numpy()).groupby(y).mean() * 100)})
    print(t.sort_values("recommended", ascending=False).round(2).to_string())

    b = models[RECOMMENDED]; idx = {n: i for i, n in enumerate(b.feature_names)}
    print("\nBaseline drift (median value: learning period -> end of stream):")
    for svc in ["port-80", "port-443", "port-53"]:
        if svc in b.baselines:
            a, e = np.expm1(b.baselines[svc].ref_median), np.expm1(b.baselines[svc].median)
            print(f" {svc}: " + " | ".join(f"{n} {a[idx[n]]:.3g} -> {e[idx[n]]:.3g}"
                  for n in ["packets_per_sec", "flow_duration_s", "avg_packet_size"]))
    Path("ml/artifacts").mkdir(exist_ok=True)
    b.save("ml/artifacts/adaptive_baseline.joblib")
    print("\nsaved ml/artifacts/adaptive_baseline.joblib (recommended config)")
