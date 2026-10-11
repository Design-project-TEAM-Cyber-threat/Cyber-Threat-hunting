"""
Generates a SMALL SYNTHETIC file shaped like CICIDS2017 (same dirty quirks),
only so the pipeline can be tested without the 1GB+ real dataset.
Replace with the real CSVs from the CICIDS2017 'MachineLearningCVE' folder.
"""
import numpy as np
import pandas as pd

rng = np.random.default_rng(42)


def make(n, attack=False):
    scale = 8 if attack else 1
    return pd.DataFrame({
        " Destination Port": rng.choice([80, 443, 53, 22, 8080], n),
        " Flow Duration": rng.exponential(50000 * (0.1 if attack else 1), n).astype(int),
        " Total Fwd Packets": rng.poisson(10 * scale, n),
        " Total Backward Packets": rng.poisson(8 if not attack else 1, n),
        "Total Length of Fwd Packets": rng.exponential(800 * scale, n),
        " Total Length of Bwd Packets": rng.exponential(1500 if not attack else 50, n),
        " Flow Bytes/s": rng.exponential(20000 * scale, n),
        " Flow Packets/s": rng.exponential(100 * scale, n),
        " SYN Flag Count": rng.poisson(1 if not attack else 6, n),
        " Label": ["DoS" if attack else "BENIGN"] * n,
    })


df = pd.concat([make(2000), make(100, attack=True)], ignore_index=True)
df.loc[5, " Flow Bytes/s"] = np.inf          # real-data quirk
df.loc[9, " Flow Packets/s"] = np.nan        # real-data quirk
df = pd.concat([df, df.iloc[[0, 1]]])        # duplicates
df.sample(frac=1, random_state=1).to_csv("data/sample_cicids.csv", index=False)
print("wrote data/sample_cicids.csv", df.shape)
