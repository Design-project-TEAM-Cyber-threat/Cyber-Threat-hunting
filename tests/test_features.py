import sys, numpy as np, pandas as pd
sys.path.insert(0, ".")
from ml.features import build_features, REQUIRED_COLUMNS, FEATURE_NAMES, port_class

def row(**kw):
    base = {c: 0.0 for c in REQUIRED_COLUMNS}
    base.update(kw); return base

df = pd.DataFrame([
    # normal-looking web flow
    row(**{"Destination Port": 443, "Flow Duration": 2_000_000, "Total Fwd Packets": 10,
           "Total Backward Packets": 9, "Total Length of Fwd Packets": 1000,
           "Total Length of Bwd Packets": 9000, "SYN Flag Count": 1, "Flow Packets/s": 9.5}),
    # one-way flood-like flow: no replies, only SYNs
    row(**{"Destination Port": 80, "Flow Duration": 1000, "Total Fwd Packets": 4,
           "Total Backward Packets": 0, "Total Length of Fwd Packets": 0,
           "Total Length of Bwd Packets": 0, "SYN Flag Count": 4}),
    # capture artifact: negative duration, -1 window, zero packets
    row(**{"Destination Port": 55000, "Flow Duration": -5, "Init_Win_bytes_forward": -1}),
])
df["Label"] = ["BENIGN", "DoS", "BENIGN"]

X, ctx = build_features(df)
assert list(X.columns) == FEATURE_NAMES and X.dtypes.eq("float32").all()
assert np.isfinite(X.to_numpy()).all() and (X.to_numpy() >= 0).all()
assert abs(X.loc[0, "flow_duration_s"] - 2.0) < 1e-6
assert abs(X.loc[0, "fwd_bwd_pkt_ratio"] - 11/10) < 1e-5
assert X.loc[1, "fwd_bwd_pkt_ratio"] == 5.0                  # 4 fwd, 0 bwd -> (4+1)/(0+1)
assert X.loc[1, "syn_per_packet"] == 1.0
assert X.loc[2, "init_win_fwd"] == 0 and X.loc[2, "flow_duration_s"] == 0
assert list(ctx["port_class"]) == [0, 0, 2] and list(port_class([1023, 1024, 49151, 49152])) == [0, 1, 1, 2]
assert list(ctx["Label"]) == ["BENIGN", "DoS", "BENIGN"]

try:
    build_features(df.drop(columns=["Flow IAT Max"])); raise SystemExit("should fail")
except ValueError as e:
    assert "Flow IAT Max" in str(e)
print("Step 2 tests passed")
