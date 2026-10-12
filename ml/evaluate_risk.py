"""
Usage: python ml/evaluate_risk.py [features_cache.joblib] [stream_cache.joblib]
Runs IF + adaptive baseline (recommended config) over the real chronological stream,
computes the risk score, and reports distribution / evaluation.
Labels are used ONLY for reporting - never to set the risk formula or thresholds.
"""
import sys
from pathlib import Path
import numpy as np, pandas as pd, joblib
from sklearn.metrics import roc_auc_score
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ml.anomaly import AnomalyDetector
from ml.baseline import AdaptiveBaseline, RECOMMENDED_CONFIG
from ml.risk import RiskScorer, LOW_MAX, HIGH_MIN
from ml.evaluate_baseline import day_rank, INIT_FLOWS

if __name__ == "__main__":
    cache = sys.argv[1] if len(sys.argv) > 1 else "data/processed/features.joblib"
    out_cache = sys.argv[2] if len(sys.argv) > 2 else "data/processed/stream_results.joblib"
    d = joblib.load(cache); X, ctx = d["features"], d["context"]
    order = np.argsort(ctx["source_file"].astype(str).map(day_rank).to_numpy(), kind="stable")
    X, ctx = X.iloc[order].reset_index(drop=True), ctx.iloc[order].reset_index(drop=True)

    det = AnomalyDetector.load("ml/artifacts/isolation_forest.joblib")
    Xi, ci = X.iloc[:INIT_FLOWS], ctx.iloc[:INIT_FLOWS]
    Xs, cs = X.iloc[INIT_FLOWS:].reset_index(drop=True), ctx.iloc[INIT_FLOWS:].reset_index(drop=True)

    base = AdaptiveBaseline(**RECOMMENDED_CONFIG).fit(Xi, ci)
    res = base.process_stream(Xs, cs, det)                          # anomaly + deviation
    scorer = RiskScorer().fit(det.score(Xi))                        # reference = trusted Monday learning period
    risk = scorer.score(res["anomaly_score"], res["deviation_score"], cs["Destination Port"])
    out = pd.concat([res, risk], axis=1); out["Label"] = cs["Label"].to_numpy()
    out["Destination Port"] = cs["Destination Port"].to_numpy()
    Path(out_cache).parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(out, out_cache, compress=3)
    scorer.save("ml/artifacts/risk_scorer.joblib")

    y = out["Label"].to_numpy(); atk = y != "BENIGN"; r = out["risk_score"].to_numpy()
    print(f"Streamed flows: {len(out):,} | attack share {atk.mean():.2%}")
    print("\nRisk score percentiles:", {p: round(float(np.percentile(r, p)), 1) for p in [50, 75, 90, 95, 99, 99.9]})
    print(f"Share of flows with risk exactly 0: {(r == 0).mean():.1%}")

    print("\nRisk level counts and attack share within each level:")
    t = out.groupby("risk_level").agg(flows=("risk_score", "size"))
    t["share_of_flows%"] = t["flows"] / len(out) * 100
    t["attack_share%"] = out.assign(a=atk).groupby("risk_level")["a"].mean() * 100
    print(t.loc[["Low", "Medium", "High"]].round(2).to_string())
    print(f"(base rate of attack flows in the stream: {atk.mean()*100:.2f}%)")

    print("\nRisk level by class (% of that class's flows):")
    cls = pd.crosstab(out["Label"], out["risk_level"], normalize="index")[["Low", "Medium", "High"]] * 100
    cls["flows"] = out["Label"].value_counts()
    print(cls.sort_values("High", ascending=False).round(1).to_string())

    print("\nRanking quality (ROC-AUC attack vs benign) - evaluation only:")
    for name in ["risk_score", "anomaly_score", "deviation_score"]:
        print(f"  {name:16s} {roc_auc_score(atk, out[name]):.3f}")

    print("\nRisk level vs Isolation-Forest label (rows %):")
    print((pd.crosstab(out["anomaly_label"], out["risk_level"], normalize="index")[["Low", "Medium", "High"]] * 100).round(1).to_string())
    print("\nContext factor mix:", out["context_factor"].value_counts(normalize=True).mul(100).round(1).to_dict())

    hist = np.histogram(r, bins=np.arange(0, 110, 10))[0]
    hb = np.histogram(r[~atk], bins=np.arange(0, 110, 10))[0] / (~atk).sum() * 100
    ha = np.histogram(r[atk], bins=np.arange(0, 110, 10))[0] / atk.sum() * 100
    print("\nHistogram (10-pt buckets) % of benign / % of attack:")
    for i in range(10):
        print(f"  {i*10:3d}-{i*10+10:3d}: benign {hb[i]:6.2f}  attack {ha[i]:6.2f}")
    print("\nsaved ml/artifacts/risk_scorer.joblib")
