import sys, numpy as np
sys.path.insert(0, ".")
from ml.risk import RiskScorer, context_factor, LOW_MAX, HIGH_MIN

ref = np.linspace(0.30, 0.60, 10000)               # stand-in for learning-period IF scores
rs = RiskScorer().fit(ref)
q = lambda p: float(np.quantile(ref, p))            # anomaly score at a given percentile

def one(anom, dev, port):
    return rs.score([anom], [dev], [port]).iloc[0]

# LOW: typical on both signals, common service
r = one(q(0.50), 1.0, 443)
assert r.risk_score < LOW_MAX and r.risk_level == "Low" and r.anomaly_evidence == 0 and r.deviation_evidence == 0
# LOW even for a sensitive service when there is no evidence (context adds no evidence)
assert one(q(0.50), 1.0, 22).risk_score == 0

# MEDIUM: both signals moderately unusual, common service
r = one(q(0.95), 6.5, 443)
assert LOW_MAX <= r.risk_score < HIGH_MIN and r.risk_level == "Medium", r.risk_score

# HIGH: both signals extreme on an SSH-type service
r = one(ref.max() + 1, 12.0, 22)
assert r.risk_score >= HIGH_MIN and r.risk_level == "High" and r.risk_score <= 100

# WEAK EVIDENCE: one signal alone, however extreme, stays Medium on a common service
only_anom = one(ref.max() + 1, 0.0, 443); only_dev = one(q(0.10), 50.0, 443)
assert only_anom.risk_level == "Medium" and only_dev.risk_level == "Medium"
assert abs(only_anom.risk_score - 50) < 1e-3
# ...and agreement of both signals scores higher than either alone
assert one(ref.max() + 1, 12.0, 443).risk_score > max(only_anom.risk_score, only_dev.risk_score)

# CONTEXT scales importance: same evidence, higher risk on sensitive service than common one
assert one(ref.max() + 1, 0.0, 22).risk_score > only_anom.risk_score
assert one(ref.max() + 1, 0.0, 22).risk_level == "High"
assert list(context_factor([22, 443, 55555])) == [1.3, 1.0, 1.15]

# MONOTONIC and bounded
a = np.linspace(ref.min(), ref.max() + 1, 200)
out = rs.score(a, np.full(200, 5.0), np.full(200, 80))
assert (np.diff(out["risk_score"].to_numpy()) >= -1e-4).all() and out["risk_score"].between(0, 100).all()
d = rs.score(np.full(200, q(0.97)), np.linspace(0, 40, 200), np.full(200, 80))
assert (np.diff(d["risk_score"].to_numpy()) >= -1e-4).all()

# SEPARATE from its inputs: same anomaly score, different deviation -> different risk,
# and vice versa; risk is not just a relabel of either signal
assert one(q(0.99), 1.0, 443).risk_score != one(q(0.99), 9.0, 443).risk_score
assert one(q(0.50), 9.0, 443).risk_score != one(q(0.99), 9.0, 443).risk_score

# batch scoring equals row-by-row scoring
b = rs.score([q(0.5), q(0.95), ref.max() + 1], [1, 6.5, 12], [443, 443, 22])
assert list(b["risk_level"]) == ["Low", "Medium", "High"]
print("Step 5 tests passed")
