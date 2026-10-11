import sys, copy, numpy as np
sys.path.insert(0, ".")
from ml.synthetic_world import build_world, flow_for_level, typical_flow
from ml.detection import ValidationError, flows_to_frame, MAX_FLOWS_PER_REQUEST
import ml.risk as risk

p = build_world()

# normal / medium / high flows end-to-end (detection time: score -> risk -> explanation -> response)
low = p.detect([flow_for_level(p, "Low")])[0]
med = p.detect([flow_for_level(p, "Medium")])[0]
high = p.detect([flow_for_level(p, "High", port=22)])[0]
assert low["risk_level"] == "Low" and low["alert"] is None and low["recommended_response"].startswith("Monitor")
assert med["risk_level"] == "Medium" and med["alert"]["recommended_response"]["action"] == "Investigate / review"
assert high["risk_level"] == "High" and high["alert"]["recommended_response"]["action"] == "Investigate immediately"
for r in (med, high):
    a = r["alert"]
    assert a["automated_action"] == "none" and "not proof of malicious activity" in a["explanation"]
    assert a["risk_score"] == r["risk_score"] and a["risk_level"] == r["risk_level"]
    assert set(a) >= {"anomaly", "baseline_deviation", "context", "drivers", "explanation", "recommended_response"}
print(f"low={low['risk_score']} medium={med['risk_score']} high={high['risk_score']}")

# the pipeline's risk equals Step 5 computed directly (Step 5 unchanged)
f = flow_for_level(p, "High", port=22)
rec = p.detect([f])[0]
from ml.features import build_features
import pandas as pd
X, ctx = build_features(pd.DataFrame([f]))
direct = p.scorer.score(p.detector.score(X), p.baseline.deviation_score(p.baseline.robust_z(X, ctx)),
                        ctx["Destination Port"]).iloc[0]
assert abs(direct["risk_score"] - rec["risk_score"]) < 0.06 and direct["risk_level"] == rec["risk_level"]

# Step 5 constants locked
assert (risk.W_ANOMALY, risk.W_DEVIATION) == (0.5, 0.5)
assert (risk.ANOMALY_P_LOW, risk.ANOMALY_P_HIGH, risk.DEVIATION_LOW, risk.DEVIATION_HIGH) == (0.90, 0.999, 3.0, 10.0)
assert (risk.LOW_MAX, risk.HIGH_MIN) == (30.0, 60.0)
assert (risk.CTX_SENSITIVE, risk.CTX_UNCOMMON, risk.CTX_COMMON) == (1.3, 1.15, 1.0)
assert risk.SENSITIVE_PORTS == {21, 22, 23, 135, 139, 389, 445, 636, 1433, 3306, 3389, 5432, 5900, 5985}
assert risk.COMMON_PORTS == {25, 53, 80, 110, 123, 143, 443, 587, 993, 995, 8080, 8443}

# baseline learning: only when asked; alerts never teach the baseline
q = copy.deepcopy(p); before = q.baseline.baselines["port-22"].median.copy()
q.detect([flow_for_level(q, "High", port=22)], learn=True)
assert np.allclose(q.baseline.baselines["port-22"].median, before)
q.detect([typical_flow(np.random.default_rng(i)) for i in range(300)], learn=True)
assert q.baseline.baselines["port-443"].n_updates > 0

# validation
rng = np.random.default_rng(0); ok = typical_flow(rng)
bad = {"empty": [], "not a list": "x", "not objects": [1],
       "missing": [{k: v for k, v in ok.items() if k != "Flow IAT Max"}],
       "string": [{**ok, "Flow Duration": "abc"}], "bool": [{**ok, "Flow Duration": True}],
       "nan": [{**ok, "Flow Duration": float("nan")}], "inf": [{**ok, "Flow Bytes/s": float("inf")}],
       "port": [{**ok, "Destination Port": 70000}], "too many": [ok] * (MAX_FLOWS_PER_REQUEST + 1)}
for name, flows in bad.items():
    try:
        flows_to_frame(flows); raise SystemExit(f"validation missed: {name}")
    except ValidationError:
        pass
assert len(flows_to_frame([{" " + k + " ": v for k, v in ok.items()}])) == 1    # padded names are tolerated
print("Step 7 core tests passed")
