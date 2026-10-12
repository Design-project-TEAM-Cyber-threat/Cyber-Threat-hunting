"""
Usage: python ml/run_explanations.py [features_cache.joblib]
Explains a random sample of real CICIDS2017 flows with the saved models.
Labels are shown for evaluation only; they never influence scores or text.
"""
import sys, re, json, collections
from pathlib import Path
import numpy as np, pandas as pd, joblib
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ml.anomaly import AnomalyDetector
from ml.baseline import AdaptiveBaseline
from ml.risk import RiskScorer
from ml.explain import AlertExplainer
from ml.evaluate_baseline import day_rank, INIT_FLOWS

FORBIDDEN = re.compile(r"definitely|certainly|zero-day|confirmed|\b(is|are) (an? )?(attack|malicious|intrusion)\b|"
                       r"blocked|isolated|quarantined|disabled|terminated", re.I)

if __name__ == "__main__":
    cache = sys.argv[1] if len(sys.argv) > 1 else "data/processed/features.joblib"
    d = joblib.load(cache); X, ctx = d["features"], d["context"]
    order = np.argsort(ctx["source_file"].astype(str).map(day_rank).to_numpy(), kind="stable")
    X, ctx = X.iloc[order].reset_index(drop=True), ctx.iloc[order].reset_index(drop=True)
    Xs, cs = X.iloc[INIT_FLOWS:].reset_index(drop=True), ctx.iloc[INIT_FLOWS:].reset_index(drop=True)

    ex = AlertExplainer(AnomalyDetector.load("ml/artifacts/isolation_forest.joblib"),
                        AdaptiveBaseline.load("ml/artifacts/adaptive_baseline.joblib"),
                        RiskScorer.load("ml/artifacts/risk_scorer.joblib"))
    idx = np.sort(np.random.default_rng(7).choice(len(Xs), 6000, replace=False))
    alerts = ex.explain_flows(Xs.iloc[idx], cs.iloc[idx])
    for a in alerts:
        a["flow_index"] = int(idx[a["flow_index"]])
        a["evaluation_only_label"] = cs["Label"].iloc[a["flow_index"]]

    print(f"Sampled 6,000 flows -> {len(alerts)} Medium/High alerts "
          f"({collections.Counter(a['risk_level'] for a in alerts)})")
    print("Drivers:", dict(collections.Counter("+".join(a["drivers"]) for a in alerts)))
    print("Alerts with a named anomaly feature:",
          f"{np.mean([bool(a['anomaly']['features']) for a in alerts]):.0%}",
          "| with a named deviation feature:",
          f"{np.mean([bool(a['baseline_deviation']['features']) for a in alerts]):.0%}")
    top = collections.Counter(f["feature"] for a in alerts for f in a["baseline_deviation"]["features"][:1])
    print("Most common top deviating feature:", top.most_common(5))
    bad = [a for a in alerts if FORBIDDEN.search(a["explanation"] + a["recommended_response"]["text"])]
    print(f"Forbidden-claim check on all {len(alerts)} alert texts: {len(bad)} violations")
    print("Automated actions taken:", set(a["automated_action"] for a in alerts))

    def pick(pred):
        return next((a for a in alerts if pred(a)), None)
    shown = [pick(lambda a: a["risk_level"] == "High" and len(a["drivers"]) == 2 and a["context"]["factor"] > 1.2),
             pick(lambda a: a["risk_level"] == "High" and len(a["drivers"]) == 2),
             pick(lambda a: a["risk_level"] == "Medium" and len(a["drivers"]) == 2),
             pick(lambda a: a["risk_level"] == "Medium" and a["drivers"] == ["deviation"])]
    for a in [s for s in shown if s]:
        print(f"\n--- {a['risk_level']} | risk {a['risk_score']} | {a['context']['service']} | "
              f"drivers={a['drivers']} | (evaluation-only label: {a['evaluation_only_label']})")
        print(a["explanation"])
        print("Response:", a["recommended_response"]["text"])
    Path("ml/artifacts").mkdir(exist_ok=True)
    json.dump(alerts[:25], open("ml/artifacts/sample_alerts.json", "w"), indent=2)
    print("\nsaved ml/artifacts/sample_alerts.json (25 alerts)")
