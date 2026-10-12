import sys, numpy as np
sys.path.insert(0, ".")
from ml.preprocessing import load_cicids_csvs, clean_flows, split_benign_for_training

raw = load_cicids_csvs("data/sample_cicids.csv")
assert "Flow Duration" in raw.columns           # loader strips column names

clean, rep = clean_flows(raw)
print(rep)

assert "Flow Duration" in clean.columns         # stripped
assert rep["duplicates_removed"] >= 2
assert rep["invalid_rows_removed"] >= 2
num = clean.select_dtypes(include=[np.number])
assert not np.isinf(num.values).any() and not num.isna().any().any()

benign, _ = split_benign_for_training(clean)
assert set(benign["Label"]) == {"BENIGN"}
print(clean["Label"].value_counts().to_dict())
print("Step 1 tests passed")
