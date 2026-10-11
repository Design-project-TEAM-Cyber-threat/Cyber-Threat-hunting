import sys, tempfile, os, numpy as np, pandas as pd
sys.path.insert(0, ".")
from ml.anomaly import AnomalyDetector, NORMAL, ANOMALY

rng = np.random.default_rng(0)
cols = ["a", "b", "c"]
normal = pd.DataFrame(rng.normal(0, 1, (2000, 3)), columns=cols)
odd = pd.DataFrame(rng.normal(8, 1, (50, 3)), columns=cols)       # far from normal behavior

det = AnomalyDetector(target_fpr=0.02, random_state=1).fit(normal)
s_n, l_n = det.predict(normal); s_o, l_o = det.predict(odd)

assert s_o.mean() > s_n.mean()                          # unusual flows score higher
assert (l_n == ANOMALY).mean() <= 0.03                   # FPR on training data ~ target
assert (l_o == ANOMALY).mean() > 0.9                     # obvious outliers flagged
assert set(l_n) <= {NORMAL, ANOMALY}

# column order must not matter, extra columns ignored
shuffled = odd[["c", "a", "b"]].assign(extra=1.0)
assert np.allclose(det.score(shuffled), s_o)

p = os.path.join(tempfile.mkdtemp(), "m.joblib"); det.save(p)
d2 = AnomalyDetector.load(p)
assert np.allclose(d2.score(odd), s_o) and d2.threshold == det.threshold
print("Step 3 tests passed")
