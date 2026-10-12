"""
Step 7 (core) - Detection-time pipeline, independent of Django so it can be tested anywhere.

detect(flow) runs, at the moment a flow arrives:
  features -> Isolation Forest score -> baseline deviation -> Step 5 risk -> Step 6 explanation
and returns a record that the API persists AS-IS. Stored explanations are never recomputed
from a later baseline.

Optional baseline learning (learn=True): flows that look low-risk may move the baseline,
using the same update rules as Step 4. Alerts (Medium/High) never update it.
Nothing here blocks, isolates or changes anything outside this system.
"""
import numpy as np
import pandas as pd
from ml.features import REQUIRED_COLUMNS, build_features
from ml.anomaly import ANOMALY
from ml.explain import AlertExplainer, RESPONSES, ADVISORY_NOTE, service_label

MAX_FLOWS_PER_REQUEST = 1000


class ValidationError(ValueError):
    pass


def flows_to_frame(flows):
    """Validate raw CICIDS2017-style flow dicts and return a DataFrame."""
    if not isinstance(flows, list) or not flows:
        raise ValidationError("'flows' must be a non-empty list of flow objects.")
    if len(flows) > MAX_FLOWS_PER_REQUEST:
        raise ValidationError(f"At most {MAX_FLOWS_PER_REQUEST} flows per request.")
    errors = []
    for i, f in enumerate(flows):
        if not isinstance(f, dict):
            errors.append(f"flows[{i}] must be an object."); continue
        f_clean = {str(k).strip(): v for k, v in f.items()}
        missing = [c for c in REQUIRED_COLUMNS if c not in f_clean]
        if missing:
            errors.append(f"flows[{i}] is missing fields: {missing}")
            continue
        for c in REQUIRED_COLUMNS:
            v = f_clean[c]
            if isinstance(v, bool) or not isinstance(v, (int, float)) or not np.isfinite(v):
                errors.append(f"flows[{i}].{c} must be a finite number.")
        port = f_clean.get("Destination Port")
        if isinstance(port, (int, float)) and not isinstance(port, bool) and not (0 <= port <= 65535):
            errors.append(f"flows[{i}].Destination Port must be between 0 and 65535.")
        if len(errors) >= 20:
            break
    if errors:
        raise ValidationError(errors)
    df = pd.DataFrame([{str(k).strip(): v for k, v in f.items()} for f in flows])
    return df


class DetectionPipeline:
    def __init__(self, detector, baseline, scorer):
        self.detector, self.baseline, self.scorer = detector, baseline, scorer
        self.explainer = AlertExplainer(detector, baseline, scorer)

    def detect(self, flows, learn=False):
        """Returns one record per flow (all levels). Explanation is attached to Medium/High only."""
        df = flows_to_frame(flows)
        X, ctx = build_features(df)
        X, ctx = X.reset_index(drop=True), ctx.reset_index(drop=True)
        scores, labels = self.detector.predict(X)
        Z = self.baseline.robust_z(X, ctx)
        dev = self.baseline.deviation_score(Z)
        risk = self.scorer.score(scores, dev, ctx["Destination Port"])      # Step 5, unchanged
        alerts = {a["flow_index"]: a for a in self.explainer.explain_flows(X, ctx, risk=risk)}

        records = []
        for i in range(len(X)):
            rk = risk.iloc[i]
            rec = {
                "features": {k: float(v) for k, v in X.iloc[i].items()},
                "destination_port": int(ctx["Destination Port"].iloc[i]),
                "anomaly_score": float(scores[i]),
                "anomaly_label": str(labels[i]),
                "deviation_score": float(dev[i]),
                "risk_score": round(float(rk["risk_score"]), 1),
                "risk_level": str(rk["risk_level"]),
                "alert": alerts.get(i),
                "recommended_response": RESPONSES[str(rk["risk_level"])][1],
            }
            records.append(rec)

        if learn:                                           # baseline learns only from low-risk, Normal flows
            accept = (labels == "Normal") & (risk["risk_level"].to_numpy() == "Low") \
                     & (np.abs(Z).max(axis=1) <= self.baseline.max_update_z)
            self.baseline.update(X, ctx, accept)
        return records
