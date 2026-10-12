"""
Step 3 - Isolation Forest anomaly detector.

What this module does (and does not do):
  * It learns what MOST benign flows look like and scores how unusual a flow is.
  * An anomaly means "statistically unusual versus the training data".
    It does NOT mean "attack". Rare-but-legitimate traffic is flagged too,
    and attacks that resemble normal traffic can be missed.
  * The anomaly score is only one input to the later, separate risk score.
"""
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

NORMAL, ANOMALY = "Normal", "Anomaly"


class AnomalyDetector:
    def __init__(self, n_estimators=100, max_samples=256, target_fpr=0.01, random_state=42):
        """
        target_fpr: share of the (benign) training data allowed to be flagged.
                    The decision threshold is set from the training scores,
                    not from sklearn's 'contamination' guess.
        """
        self.target_fpr = target_fpr
        self.model = IsolationForest(n_estimators=n_estimators, max_samples=max_samples,
                                     random_state=random_state, n_jobs=-1)
        self.threshold = None
        self.feature_names = None

    def fit(self, X):
        """X: DataFrame of behavioral features (benign-only for the baseline)."""
        self.feature_names = list(X.columns)
        self.model.fit(X)
        train_scores = self.score(X)
        self.threshold = float(np.quantile(train_scores, 1 - self.target_fpr))
        return self

    def score(self, X):
        """Anomaly score: higher = more unusual (range roughly 0.3 - 0.8)."""
        return -self.model.score_samples(X[self.feature_names])

    def predict(self, X):
        """Returns (scores, labels) where labels are 'Normal' / 'Anomaly'."""
        s = self.score(X)
        return s, np.where(s > self.threshold, ANOMALY, NORMAL)

    def save(self, path):
        joblib.dump(self, path, compress=3)

    @staticmethod
    def load(path):
        return joblib.load(path)
