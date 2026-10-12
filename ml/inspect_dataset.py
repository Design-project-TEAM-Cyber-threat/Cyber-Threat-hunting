"""
Read-only inspection report for CICIDS2017 CSVs (does not change any data).
Usage:  python ml/inspect_dataset.py data/
Per-file stats are computed one file at a time (low memory); the combined
load + Step 1 cleaning then validates the real pipeline.
"""
import sys
from pathlib import Path
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ml.preprocessing import _read_one, load_cicids_csvs, clean_flows


def main(folder):
    files = sorted(Path(folder).glob("*.csv"))
    if not files:
        sys.exit(f"No CSV files in {folder}")

    print("=== PER FILE (raw) ===")
    cols, tot_rows, tot_inf, tot_nan = {}, 0, 0, 0
    col_bad = {}
    labels = {}
    for f in files:
        df = _read_one(f)
        num = df.select_dtypes(include=[np.number])
        inf = nan = 0
        for c in num.columns:
            v = num[c].to_numpy()
            if v.dtype.kind == "f":
                i, n = int(np.isinf(v).sum()), int(np.isnan(v).sum())
                inf += i; nan += n
                if i or n:
                    a, b = col_bad.get(c, (0, 0)); col_bad[c] = (a + i, b + n)
        print(f"{f.name}: rows={len(df):,} cols={df.shape[1]} inf={inf:,} nan={nan:,}")
        cols[f.name] = tuple(df.columns)
        tot_rows += len(df); tot_inf += inf; tot_nan += nan
        for k, v in df["Label"].astype(str).str.strip().value_counts().items():
            labels[k] = labels.get(k, 0) + int(v)
        del df, num

    print("\n=== COMBINED RAW ===")
    print("Same columns in every file:", len(set(cols.values())) == 1)
    print(f"rows={tot_rows:,} columns={len(next(iter(cols.values())))}")
    print(f"inf cells={tot_inf:,} | NaN cells={tot_nan:,}")
    print("columns with inf/NaN (inf, nan):", col_bad)
    print("\nLabels (raw):")
    for k, v in sorted(labels.items(), key=lambda x: -x[1]):
        print(f"  {k!r}: {v:,}")

    print("\n=== STEP 1 PREPROCESSING (full dataset) ===")
    raw = load_cicids_csvs(folder)
    clean, rep = clean_flows(raw)
    del raw
    print(rep)
    n = clean.select_dtypes(include=[np.number])
    left = sum(int((~np.isfinite(n[c].to_numpy())).sum())
               for c in n.columns if n[c].dtype.kind == "f")
    print("inf/NaN left:", left)
    print("memory (MB):", round(clean.memory_usage(deep=True).sum() / 1e6))
    print("\nLabels (clean):")
    for k, v in clean["Label"].value_counts().items():
        print(f"  {k!r}: {v:,}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "data")
