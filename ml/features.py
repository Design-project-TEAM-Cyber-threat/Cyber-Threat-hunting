"""
Step 2 - Behavioral feature engineering for CICIDS2017 flows.

Turns raw flow statistics into a small set of interpretable behavioral
features (rates, ratios, sizes, timing, TCP-flag behavior). These feed the
Isolation Forest (Step 3) and are later used to explain alerts (Step 6),
so every feature has a plain-language description.

Context columns (destination port, port class, label) are returned
separately: they are NOT model inputs. Port context is used later by the
risk scorer; Label is used only for evaluation.
"""
import numpy as np
import pandas as pd

REQUIRED_COLUMNS = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Flow Bytes/s", "Flow Packets/s",
    "Average Packet Size", "Packet Length Std", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "SYN Flag Count", "RST Flag Count",
    "FIN Flag Count", "PSH Flag Count", "ACK Flag Count",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "Active Mean", "Idle Mean",
]

# Used by the explainable-alert module (Step 6).
FEATURE_DESCRIPTIONS = {
    "flow_duration_s":    "connection duration (seconds)",
    "total_packets":      "total packets in the flow",
    "total_bytes":        "total bytes transferred",
    "packets_per_sec":    "packet rate",
    "bytes_per_sec":      "data rate",
    "fwd_bwd_pkt_ratio":  "outbound-to-inbound packet ratio (traffic asymmetry)",
    "fwd_bwd_byte_ratio": "outbound-to-inbound byte ratio (data asymmetry)",
    "avg_packet_size":    "average packet size",
    "packet_size_std":    "variability of packet sizes",
    "iat_mean_ms":        "average gap between packets (ms)",
    "iat_std_ms":         "variability of packet timing (ms)",
    "iat_max_s":          "longest pause between packets (seconds)",
    "syn_per_packet":     "share of packets carrying SYN (connection setup)",
    "rst_per_packet":     "share of packets carrying RST (connection reset)",
    "fin_per_packet":     "share of packets carrying FIN (connection close)",
    "psh_per_packet":     "share of packets carrying PSH (push data)",
    "ack_per_packet":     "share of packets carrying ACK",
    "init_win_fwd":       "initial TCP window size, outbound",
    "init_win_bwd":       "initial TCP window size, inbound",
    "active_mean_s":      "average active period (seconds)",
    "idle_mean_s":        "average idle period (seconds)",
}
FEATURE_NAMES = list(FEATURE_DESCRIPTIONS)


def port_class(port):
    """0 = well-known (<1024), 1 = registered (1024-49151), 2 = dynamic."""
    port = np.asarray(port)
    return np.where(port < 1024, 0, np.where(port < 49152, 1, 2)).astype(np.int8)


def build_features(df):
    """
    df: cleaned flow DataFrame (output of Step 1).
    Returns (features, context):
      features - float32 DataFrame with FEATURE_NAMES columns
      context  - DataFrame with Destination Port, port_class and (if present) Label
    """
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    f64 = lambda c: df[c].to_numpy(dtype="float64")
    fwd_p, bwd_p = f64("Total Fwd Packets"), f64("Total Backward Packets")
    fwd_b, bwd_b = f64("Total Length of Fwd Packets"), f64("Total Length of Bwd Packets")
    total_p = fwd_p + bwd_p
    safe_p = np.maximum(total_p, 1.0)          # avoid divide-by-zero

    # CICIDS2017 stores times in microseconds.
    feats = {
        "flow_duration_s":    f64("Flow Duration") / 1e6,
        "total_packets":      total_p,
        "total_bytes":        fwd_b + bwd_b,
        "packets_per_sec":    f64("Flow Packets/s"),
        "bytes_per_sec":      f64("Flow Bytes/s"),
        # +1 smoothing keeps ratios finite when one direction is silent
        "fwd_bwd_pkt_ratio":  (fwd_p + 1) / (bwd_p + 1),
        "fwd_bwd_byte_ratio": (fwd_b + 1) / (bwd_b + 1),
        "avg_packet_size":    f64("Average Packet Size"),
        "packet_size_std":    f64("Packet Length Std"),
        "iat_mean_ms":        f64("Flow IAT Mean") / 1e3,
        "iat_std_ms":         f64("Flow IAT Std") / 1e3,
        "iat_max_s":          f64("Flow IAT Max") / 1e6,
        "syn_per_packet":     f64("SYN Flag Count") / safe_p,
        "rst_per_packet":     f64("RST Flag Count") / safe_p,
        "fin_per_packet":     f64("FIN Flag Count") / safe_p,
        "psh_per_packet":     f64("PSH Flag Count") / safe_p,
        "ack_per_packet":     f64("ACK Flag Count") / safe_p,
        # -1 in the raw data means "no TCP window observed" -> treat as 0
        "init_win_fwd":       np.maximum(f64("Init_Win_bytes_forward"), 0),
        "init_win_bwd":       np.maximum(f64("Init_Win_bytes_backward"), 0),
        "active_mean_s":      f64("Active Mean") / 1e6,
        "idle_mean_s":        f64("Idle Mean") / 1e6,
    }
    features = pd.DataFrame(feats, index=df.index)[FEATURE_NAMES]

    # Raw data contains a few negative durations/rates (capture artifacts).
    # Rates, times and sizes cannot be negative, so clip at 0.
    features = features.clip(lower=0)
    features = features.replace([np.inf, -np.inf], 0).fillna(0).astype("float32")

    context = pd.DataFrame({
        "Destination Port": df["Destination Port"].to_numpy(),
        "port_class": port_class(df["Destination Port"].to_numpy()),
    }, index=df.index)
    if "Label" in df.columns:
        context["Label"] = df["Label"].to_numpy()
    if "source_file" in df.columns:
        context["source_file"] = df["source_file"].to_numpy()
    return features, context
