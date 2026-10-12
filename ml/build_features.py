"""
Usage: python ml/build_features.py data/        (CICIDS2017 CSV folder)
Runs Step 1 + Step 2 and saves data/processed/features.joblib
"""
import sys
from pathlib import Path
import joblib
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ml.preprocessing import load_cicids_csvs, clean_flows
from ml.features import build_features

if __name__ == "__main__":
    folder = sys.argv[1] if len(sys.argv) > 1 else "data"
    clean, rep = clean_flows(load_cicids_csvs(folder))
    print("Step 1:", rep)
    X, ctx = build_features(clean)
    out = Path("data/processed"); out.mkdir(parents=True, exist_ok=True)
    joblib.dump({"features": X, "context": ctx}, out / "features.joblib", compress=3)
    print("Step 2:", X.shape, "->", out / "features.joblib")
