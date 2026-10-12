import sys, copy, numpy as np, pandas as pd
sys.path.insert(0, ".")
from ml.baseline import AdaptiveBaseline

rng = np.random.default_rng(0)
cols = ["rate", "size"]

def flows(n, rate, size=300.0, port=443):
    X = pd.DataFrame({"rate": rng.normal(rate, rate * 0.1, n).clip(0),
                      "size": rng.normal(size, 20, n).clip(0)})
    ctx = pd.DataFrame({"Destination Port": port,
                        "port_class": 0 if port < 1024 else 1}, index=X.index)
    return X, ctx

def fresh(rate=100.0):
    X, c = flows(3000, rate)
    return AdaptiveBaseline(window=1000, min_service_flows=500, max_replace_frac=0.25).fit(X, c)

class StubDetector:                       # flags anything with rate > 1000 as Anomaly
    def predict(self, X):
        lab = np.where(X["rate"] > 1000, "Anomaly", "Normal")
        return X["rate"].to_numpy(), lab

# 1. service routing: busy port gets its own baseline, rare ports fall back to port class
X, c = flows(3000, 100)
rare = pd.DataFrame({"Destination Port": [9999] * 5, "port_class": [1] * 5})
b = fresh()
keys = b.service_keys(pd.concat([c.head(2), rare.head(2)], ignore_index=True))
assert list(keys) == ["port-443", "port-443", "class-1", "class-1"]

# 2. deviation: typical flow ~ low, outlier flow ~ high
Xn, cn = flows(500, 100); Xo, co = flows(500, 2000)
dn = b.deviation_score(b.robust_z(Xn, cn)); do = b.deviation_score(b.robust_z(Xo, co))
assert np.median(dn) < 1.5 and np.median(do) > 5   # only 2 test features, so top-k averages over both
print(f"deviation: typical median={np.median(dn):.2f}  outlier median={np.median(do):.2f}")

# 3. ADAPTATION: legitimate behavior gradually changes 100 -> 160 (e.g. a new busy period)
b = fresh(); frozen = copy.deepcopy(b)
start_dev = np.median(b.deviation_score(b.robust_z(*flows(500, 160))))
for step in range(12):
    rate = 100 + (160 - 100) * (step + 1) / 12            # slow drift, all flows legitimate
    Xb, cb = flows(400, rate)
    b.update(Xb, cb, accept=np.ones(len(Xb), bool), batch_id=step)
Xt, ct = flows(500, 160)
adapted_dev = np.median(b.deviation_score(b.robust_z(Xt, ct)))
frozen_dev = np.median(frozen.deviation_score(frozen.robust_z(Xt, ct)))
print(f"new-normal flows (rate~160): deviation before={start_dev:.2f}  adaptive={adapted_dev:.2f}  frozen={frozen_dev:.2f}")
assert adapted_dev < 0.5 * frozen_dev and adapted_dev < 1.5      # adaptive baseline caught up
assert abs(frozen_dev - start_dev) < 0.2                          # frozen baseline never changed

# 4. POISONING PROTECTION a: rejected flows never change the baseline
b = fresh(); before = b.baselines["port-443"].median.copy()
Xb, cb = flows(2000, 5000)
b.update(Xb, cb, accept=np.zeros(len(Xb), bool))
assert np.allclose(b.baselines["port-443"].median, before)

# 4b. a flagged flow stream never enters through process_stream (stub detector flags rate>1000)
b = fresh(); before = b.baselines["port-443"].median.copy()
Xb, cb = flows(5000, 5000)
res = b.process_stream(Xb, cb, StubDetector(), batch_size=1000)
assert not res["accepted"].any() and np.allclose(b.baselines["port-443"].median, before)

# 4c. even accepted data moves the baseline only gradually (<=25% of window per batch)
b = fresh(); Xb, cb = flows(5000, 300)                      # 3x jump, all "accepted"
b.update(Xb, cb, accept=np.ones(len(Xb), bool))
m = np.expm1(b.baselines["port-443"].median[0])
assert 100 < m < 200, m                                    # one batch cannot jump to 300
print(f"one huge accepted batch moves median 100 -> {m:.0f} (not 300)")

# 4d. extreme-deviation flows are gated out even if the detector called them Normal
class AlwaysNormal:
    def predict(self, X): return np.zeros(len(X)), np.array(["Normal"] * len(X))
b = fresh(); Xb, cb = flows(2000, 100000)
res = b.process_stream(Xb, cb, AlwaysNormal(), batch_size=1000)
assert res["accepted"].mean() < 0.01

# 5. normal stream is accepted at a high rate
b = fresh(); Xb, cb = flows(2000, 100)
res = b.process_stream(Xb, cb, StubDetector(), batch_size=500)
assert res["accepted"].mean() > 0.95

# 6. DRIFT GUARD: accepted-but-slowly-poisoned traffic cannot drag the baseline far
def drift_run(max_drift):
    b = AdaptiveBaseline(window=1000, min_service_flows=500, max_replace_frac=0.25,
                         max_drift=max_drift).fit(*flows(3000, 100))
    for step in range(40):                                    # keeps "accepted" while rate climbs 100 -> 1000
        Xb, cb = flows(400, 100 + 900 * (step + 1) / 40)
        b.update(Xb, cb, accept=np.ones(len(Xb), bool))
    return np.expm1(b.baselines["port-443"].median[0])
free, guarded = drift_run(None), drift_run(3.0)
print(f"slow poisoning, rate 100 -> 1000: unguarded median={free:.0f}  drift-guarded median={guarded:.0f}")
assert free > 700 and guarded < 250                           # 3 scales * 0.25 log units ~ 2.1x

# 6b. guard still allows legitimate moderate change (100 -> 160 is within the limit)
b = AdaptiveBaseline(window=1000, min_service_flows=500, max_replace_frac=0.25, max_drift=3.0).fit(*flows(3000, 100))
for step in range(12):
    Xb, cb = flows(400, 100 + 60 * (step + 1) / 12)
    b.update(Xb, cb, accept=np.ones(len(Xb), bool))
assert np.median(b.deviation_score(b.robust_z(*flows(500, 160)))) < 1.5

# 7. SURGE FREEZE: a batch where many flows are flagged does not update that service
class HalfFlagged:                                            # flags 10% of flows
    def predict(self, X):
        lab = np.array(["Normal"] * len(X), dtype=object); lab[::10] = "Anomaly"
        return np.zeros(len(X)), lab
mk = lambda sf: AdaptiveBaseline(window=1000, min_service_flows=500, surge_flag_frac=sf).fit(*flows(3000, 100))
Xb, cb = flows(2000, 140)
b = mk(0.03); before = b.baselines["port-443"].median.copy()
res = b.process_stream(Xb, cb, HalfFlagged(), batch_size=1000)
assert not res["accepted"].any() and np.allclose(b.baselines["port-443"].median, before)
b = mk(None); res = b.process_stream(Xb, cb, HalfFlagged(), batch_size=1000)
assert res["accepted"].any()                                  # without the freeze, normal-labeled flows do enter
print("Step 4 tests passed")
