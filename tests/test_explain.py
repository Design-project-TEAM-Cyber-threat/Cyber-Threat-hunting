import sys, re, numpy as np, pandas as pd
sys.path.insert(0, ".")
from ml.anomaly import AnomalyDetector
from ml.baseline import AdaptiveBaseline
from ml.risk import RiskScorer
from ml.explain import AlertExplainer, build_explanation, RESPONSES

# ---- small synthetic world with real feature names -------------------------------
rng = np.random.default_rng(3)
cols = ["packets_per_sec", "flow_duration_s", "avg_packet_size"]
def make(n, port):
    X = pd.DataFrame({"packets_per_sec": rng.lognormal(3, 0.3, n),
                      "flow_duration_s": rng.lognormal(0, 0.3, n),
                      "avg_packet_size": rng.lognormal(5, 0.2, n)})
    c = pd.DataFrame({"Destination Port": port, "port_class": 0}, index=X.index)
    return X, c
Xa, ca = make(3000, 443); Xb, cb = make(3000, 22)
Xn, cn = pd.concat([Xa, Xb], ignore_index=True), pd.concat([ca, cb], ignore_index=True)
det = AnomalyDetector(target_fpr=0.01, random_state=1).fit(Xn)
base = AdaptiveBaseline(window=2000, min_service_flows=500).fit(Xn, cn)
scorer = RiskScorer().fit(det.score(Xn))
ex = AlertExplainer(det, base, scorer)

def flow(port, **over):
    X, c = make(1, port)
    for k, v in over.items():
        X[k] = v
    return X, c

def ev(a, d, ctxf=1.0, level="Medium", score=40.0):          # hand-made Step 5 output for template control
    return pd.DataFrame({"anomaly_evidence": [a], "deviation_evidence": [d], "context_factor": [ctxf],
                         "risk_score": [score], "risk_level": [level]})

FORBIDDEN = re.compile(r"definitely|certainly|zero-day|confirmed|\b(is|are) (an? )?(attack|malicious|intrusion)\b|"
                       r"blocked|isolated|quarantined|disabled|terminated", re.I)

# ---- 1. LOW alert explanation ----------------------------------------------------
X, c = flow(443)
assert ex.explain_flows(X, c) == []                           # Low flows produce no alert by default
low = ex.explain_flows(X, c, include_low=True)[0]
assert low["risk_level"] == "Low" and low["risk_score"] < 30
assert low["explanation"].startswith("Low risk") and "within the range expected" in low["explanation"]
assert low["recommended_response"]["action"] == "Monitor"
assert low["anomaly"]["features"] == [] and low["baseline_deviation"]["features"] == []

# ---- 2. MEDIUM alert explanation (controlled evidence, real feature attribution) --
X, c = flow(443, packets_per_sec=900.0)
med = ex.explain_flows(X, c, risk=ev(0.5, 0.5, 1.0, "Medium", 44.0))[0]
assert med["risk_level"] == "Medium" and med["recommended_response"]["action"] == "Investigate / review"
t = med["explanation"]
assert t.startswith("Medium risk because") and "moderately unusual" in t and "moderate deviation" in t
assert "common service" in t and "not proof of malicious activity" in t
print("MEDIUM:", t, "\n")

# ---- 3. HIGH alert explanation (natural models, no overrides) --------------------
Xh, ch = flow(22, packets_per_sec=40000.0)
hi = ex.explain_flows(Xh, ch)[0]
assert hi["risk_level"] == "High" and hi["risk_score"] >= 60
t = hi["explanation"]
assert "highly unusual compared with the learned benign behavior" in t
assert "large deviation from the port 22 (SSH) baseline" in t
assert "sensitive service" in t and "not proof of malicious activity" in t
assert hi["recommended_response"]["action"] == "Investigate immediately"
print("HIGH:", t, "\n")

# ---- 4. EVIDENCE ATTRIBUTION -----------------------------------------------------
# features: the modified feature is the top contributor in both attributions, with direction
assert hi["anomaly"]["features"][0]["feature"] == "packets_per_sec"
assert hi["baseline_deviation"]["features"][0]["feature"] == "packets_per_sec"
assert hi["baseline_deviation"]["features"][0]["direction"] == "higher"
assert hi["baseline_deviation"]["features"][0]["z"] > 10
X, c = flow(443, avg_packet_size=3.0)                         # tiny packets: LOWER than typical
lo_hi = ex.explain_flows(X, c, risk=ev(1.0, 1.0, 1.0, "High", 75.0))[0]
f0 = lo_hi["baseline_deviation"]["features"][0]
assert f0["feature"] == "avg_packet_size" and f0["direction"] == "lower" and f0["z"] < -10
assert lo_hi["anomaly"]["features"][0]["feature"] == "avg_packet_size"
# signals: only signals with evidence are credited
only_a = ex.explain_flows(*flow(443, packets_per_sec=900.0), risk=ev(1.0, 0.0))[0]
assert only_a["drivers"] == ["anomaly"] and only_a["baseline_deviation"]["features"] == []
assert "deviation from" not in only_a["explanation"] and "Only the learned-behavior model" in only_a["explanation"]
only_d = ex.explain_flows(*flow(443, packets_per_sec=900.0), risk=ev(0.0, 1.0))[0]
assert only_d["drivers"] == ["deviation"] and only_d["anomaly"]["features"] == []
assert "learned benign behavior" not in only_d["explanation"].split("Only")[0]
assert only_d["baseline_deviation"]["features"][0]["feature"] == "packets_per_sec"
both = ex.explain_flows(*flow(443, packets_per_sec=900.0), risk=ev(1.0, 1.0, 1.0, "High", 75.0))[0]
assert both["drivers"] == ["anomaly", "deviation"]
# context attribution
assert hi["context"]["type"] == "sensitive service" and hi["context"]["factor"] == 1.3
assert ex.explain_flows(*flow(55555, packets_per_sec=900.0), risk=ev(1, 1, 1.15, "High", 86.0))[0]["context"]["type"] == "uncommon port"
# the explanation layer must not alter Step 5 output
direct = scorer.score(det.score(Xh), base.deviation_score(base.robust_z(Xh, ch)), ch["Destination Port"]).iloc[0]
assert abs(direct["risk_score"] - hi["risk_score"]) < 0.1 and direct["risk_level"] == hi["risk_level"]

# ---- 5. RECOMMENDED RESPONSE: advisory only ---------------------------------------
for level, word in [("Low", "Monitor"), ("Medium", "Investigate"), ("High", "Investigate immediately")]:
    assert RESPONSES[level][1].startswith(word)
assert "consider containment according to your organization's security policy" in RESPONSES["High"][1]
assert "no automated action" in RESPONSES["High"][1]
for a in (low, med, hi, lo_hi, only_a, only_d, both):
    assert a["automated_action"] == "none" and "no blocking" in a["note"].lower()
    assert not FORBIDDEN.search(a["recommended_response"]["text"])

# ---- 6. NO FALSE CLAIMS that an anomaly is an attack ------------------------------
texts = [a["explanation"] for a in (low, med, hi, lo_hi, only_a, only_d, both)]
for level in ("Low", "Medium", "High"):                       # exhaustive template sweep
    for a_ev in (0, 0.2, 0.5, 1.0):
        for d_ev in (0, 0.2, 0.5, 1.0):
            for cf in (1.0, 1.15, 1.3):
                texts.append(build_explanation(level, 22, cf, a_ev, d_ev, [], []))
for t in texts:
    assert not FORBIDDEN.search(t), t
for a in (med, hi, lo_hi, only_a, only_d, both):              # Medium/High always carry the caveat
    assert "not proof of malicious activity" in a["explanation"]
print("Step 6 tests passed")
