"""
Test support: a small synthetic 'world' (raw flows + trained models) so the detection
pipeline and the API can be tested quickly without the 1 GB CICIDS2017 files.
Not used in production.
"""
import numpy as np
from ml.features import REQUIRED_COLUMNS, build_features
from ml.anomaly import AnomalyDetector
from ml.baseline import AdaptiveBaseline
from ml.risk import RiskScorer
from ml.detection import DetectionPipeline


def typical_flow(rng, port=443, rate_factor=1.0):
    """One plausible raw flow (CICIDS2017 field names). rate_factor>1 makes it a high-rate burst."""
    dur = float(rng.lognormal(np.log(1e6), 0.3))                       # microseconds
    fwd, bwd = int(rng.poisson(10)) + 1, int(rng.poisson(8)) + 1
    fb, bb = fwd * float(rng.normal(100, 10)), bwd * float(rng.normal(500, 50))
    tot_p, tot_b = fwd + bwd, fb + bb
    sec = dur / 1e6
    f = {"Destination Port": port, "Flow Duration": dur,
         "Total Fwd Packets": fwd, "Total Backward Packets": bwd,
         "Total Length of Fwd Packets": fb, "Total Length of Bwd Packets": bb,
         "Flow Bytes/s": tot_b / sec * rate_factor, "Flow Packets/s": tot_p / sec * rate_factor,
         "Average Packet Size": tot_b / tot_p, "Packet Length Std": abs(float(rng.normal(100, 10))),
         "Flow IAT Mean": dur / tot_p, "Flow IAT Std": dur / tot_p * 0.5, "Flow IAT Max": dur * 0.4,
         "SYN Flag Count": 1.0, "RST Flag Count": 0.0, "FIN Flag Count": 1.0, "PSH Flag Count": 2.0,
         "ACK Flag Count": 8.0, "Init_Win_bytes_forward": 29200.0, "Init_Win_bytes_backward": 28960.0,
         "Active Mean": 0.0, "Idle Mean": 0.0}
    assert all(c in f for c in REQUIRED_COLUMNS)
    return f


def build_world(seed=11, n_per_port=3000):
    import pandas as pd
    rng = np.random.default_rng(seed)
    rows = [typical_flow(rng, p) for p in (443, 22) for _ in range(n_per_port)]
    X, ctx = build_features(pd.DataFrame(rows))
    det = AnomalyDetector(target_fpr=0.01, random_state=1).fit(X)
    base = AdaptiveBaseline(window=2000, min_service_flows=500).fit(X, ctx)
    scorer = RiskScorer().fit(det.score(X))
    return DetectionPipeline(det, base, scorer)


def flow_for_level(pipeline, level, port=443, seed=5):
    """Find (by sweeping burst intensity) a raw flow the pipeline scores at `level`.
    Note: High needs a sensitive port (e.g. 22) in this synthetic world because the
    Isolation Forest score saturates for pure rate bursts."""
    rng = np.random.default_rng(seed)
    if level == "Low":
        return typical_flow(rng, port)
    hits = []
    for factor in np.geomspace(1.05, 2e4, 120):
        f = typical_flow(np.random.default_rng(seed), port, rate_factor=float(factor))
        if pipeline.detect([f])[0]["risk_level"] == level:
            hits.append(f)
    if not hits:
        raise AssertionError(f"no flow found for level {level} on port {port}")
    return hits[len(hits) // 2]            # middle of the range: away from the level boundaries
