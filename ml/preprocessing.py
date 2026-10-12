"""
Step 1 - Data loading and preprocessing for CICIDS2017 network-flow CSVs.

CICIDS2017 quirks handled here:
  * column names have leading/trailing spaces (" Flow Duration")
  * Flow Bytes/s and Flow Packets/s contain inf and NaN
  * duplicated rows exist
  * the 'Label' column holds BENIGN or an attack name
    (kept only for evaluation - the Isolation Forest never trains on it)
"""
from pathlib import Path
import numpy as np
import pandas as pd


def _read_one(f):
    """Read one CSV (UTF-8, falling back to latin-1) and shrink numeric dtypes."""
    try:
        df = pd.read_csv(f, low_memory=False)
    except UnicodeDecodeError:
        df = pd.read_csv(f, low_memory=False, encoding="latin-1")
    df.columns = df.columns.str.strip()
    # Real metadata: the file name identifies the capture day. Needed in Step 4
    # to replay flows in true chronological order (the CSVs have no timestamps).
    df["source_file"] = Path(f).name
    # The full dataset is ~2.8M rows x 79 columns; downcasting keeps it
    # within a few GB of RAM. Integers are downcast losslessly; floats -> float32.
    for c in df.select_dtypes(include=["int64"]).columns:
        df[c] = pd.to_numeric(df[c], downcast="integer")
    for c in df.select_dtypes(include=["float64"]).columns:
        df[c] = df[c].astype("float32")
    return df


def load_cicids_csvs(path):
    """Load one CSV file, or every CSV inside a folder, into one DataFrame."""
    path = Path(path)
    files = [path] if path.is_file() else sorted(path.glob("*.csv"))
    if not files:
        raise FileNotFoundError(f"No CSV files found at {path}")
    frames = [_read_one(f) for f in files]
    out = pd.concat(frames, ignore_index=True)
    out["source_file"] = out["source_file"].astype("category")
    return out


def clean_flows(df):
    """Clean raw CICIDS2017 data. Returns (clean_df, report dict).
    Note: strips column names of the DataFrame passed in (in place)."""
    report = {"rows_in": len(df)}

    # 1. normalise column names
    df.columns = df.columns.str.strip()

    # 2. mark exact duplicates
    content_cols = [c for c in df.columns if c != "source_file"]
    dup = df.duplicated(subset=content_cols).to_numpy()
    report["duplicates_removed"] = int(dup.sum())

    # 3. mark rows with inf / NaN in any numeric column (column by column,
    #    so no full-frame copy is made)
    bad = np.zeros(len(df), dtype=bool)
    for c in df.select_dtypes(include=[np.number]).columns:
        v = df[c].to_numpy()
        if v.dtype.kind == "f":
            bad |= ~np.isfinite(v)
    report["invalid_rows_removed"] = int((bad & ~dup).sum())

    df = df.loc[~(dup | bad)].reset_index(drop=True)

    # 4. normalise label text (kept for evaluation only); the dataset
    #    contains a stray replacement character in 'Web Attack \ufffd ...'
    if "Label" in df.columns:
        df["Label"] = (df["Label"].astype(str).str.strip()
                       .str.replace("\ufffd", "-", regex=False))

    report["rows_out"] = len(df)
    return df, report


def split_benign_for_training(df, benign_label="BENIGN"):
    """
    Return (benign_df, all_df). Training the baseline model on benign-only
    traffic is a common anomaly-detection setup; labels are never used as
    model features.
    """
    return df[df["Label"] == benign_label].reset_index(drop=True), df


if __name__ == "__main__":
    import sys
    raw = load_cicids_csvs(sys.argv[1])
    clean, rep = clean_flows(raw)
    print(rep)
    print(clean["Label"].value_counts())
