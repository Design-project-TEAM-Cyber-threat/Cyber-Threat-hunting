"""Loads the trained models once and shares one DetectionPipeline across requests."""
import threading
from pathlib import Path
from django.conf import settings

_pipeline = None
_lock = threading.Lock()
detect_lock = threading.Lock()          # detect() can update the in-memory baseline when learn=true


class PipelineUnavailable(RuntimeError):
    pass


def get_pipeline():
    global _pipeline
    with _lock:
        if _pipeline is None:
            from ml.anomaly import AnomalyDetector
            from ml.baseline import AdaptiveBaseline
            from ml.risk import RiskScorer
            from ml.detection import DetectionPipeline
            d = Path(settings.ML_ARTIFACTS_DIR)
            try:
                _pipeline = DetectionPipeline(
                    AnomalyDetector.load(d / "isolation_forest.joblib"),
                    AdaptiveBaseline.load(d / "adaptive_baseline.joblib"),
                    RiskScorer.load(d / "risk_scorer.joblib"))
            except FileNotFoundError as e:
                raise PipelineUnavailable(f"Model files not found in {d}: {e.filename}") from e
        return _pipeline


def set_pipeline(pipeline):
    """Used by tests (and tools) to inject a pipeline; None forces a reload."""
    global _pipeline
    with _lock:
        _pipeline = pipeline
