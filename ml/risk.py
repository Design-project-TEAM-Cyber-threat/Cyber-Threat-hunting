"""
Step 5 - Contextual risk score (0-100), separate from the anomaly score and
from the baseline deviation.

Inputs are treated as WEAK EVIDENCE, not proof of an attack:
  1. anomaly_score    (Isolation Forest, Step 3)   - "unusual vs. benign traffic overall"
  2. deviation_score  (adaptive baseline, Step 4)  - "unusual vs. this service's recent behavior"
  3. service/port context                           - "how much would it matter if this were bad"

How they are combined
  anomaly_evidence   in [0,1]: where the flow's anomaly score sits among scores of the
                     trusted learning-period traffic (0 below its 90th percentile,
                     1 at/above its 99.9th). No attack labels involved.
  deviation_evidence in [0,1]: robust z-score units are interpretable, so a fixed mapping
                     is used: 0 up to 3 sigma, 1 from 10 sigma.
  evidence           = 1 - (1 - 0.5*anomaly_evidence) * (1 - 0.5*deviation_evidence)
                     Each signal alone is capped at 0.5; reaching a high score needs the
                     two independent signals to agree (or a sensitive service).
  context_factor     a prior set by security convention (NOT learned from data):
                     sensitive/admin services 1.3, uncommon ports 1.15, common services 1.0.
                     Context scales the importance of the evidence; it adds no evidence itself.
  risk_score         = 100 * min(1, evidence * context_factor)

All constants below are fixed by design reasoning, not tuned on labels.
Risk is a triage priority for an analyst, not a verdict. No blocking is done here.
"""
import numpy as np
import pandas as pd
import joblib

W_ANOMALY, W_DEVIATION = 0.5, 0.5
ANOMALY_P_LOW, ANOMALY_P_HIGH = 0.90, 0.999       # percentiles of learning-period scores
DEVIATION_LOW, DEVIATION_HIGH = 3.0, 10.0          # robust z units
LOW_MAX, HIGH_MIN = 30.0, 60.0                     # level boundaries

SENSITIVE_PORTS = {21, 22, 23, 135, 139, 389, 445, 636, 1433, 3306, 3389, 5432, 5900, 5985}
COMMON_PORTS = {25, 53, 80, 110, 123, 143, 443, 587, 993, 995, 8080, 8443}
CTX_SENSITIVE, CTX_UNCOMMON, CTX_COMMON = 1.3, 1.15, 1.0
CONTEXT_NAMES = {CTX_SENSITIVE: "sensitive service", CTX_UNCOMMON: "uncommon port",
                 CTX_COMMON: "common service"}


def context_factor(ports):
    ports = np.asarray(ports).astype(int)
    return np.where(np.isin(ports, list(SENSITIVE_PORTS)), CTX_SENSITIVE,
                    np.where(np.isin(ports, list(COMMON_PORTS)), CTX_COMMON, CTX_UNCOMMON))


def risk_level(risk):
    risk = np.asarray(risk)
    return np.where(risk >= HIGH_MIN, "High", np.where(risk >= LOW_MAX, "Medium", "Low"))


class RiskScorer:
    def __init__(self):
        self.reference = None

    def fit(self, reference_anomaly_scores):
        """reference_anomaly_scores: Isolation Forest scores of trusted learning-period flows."""
        self.reference = np.sort(np.asarray(reference_anomaly_scores, dtype="float64"))
        return self

    def anomaly_evidence(self, anomaly_score):
        p = np.searchsorted(self.reference, np.asarray(anomaly_score), side="right") / len(self.reference)
        return np.clip((p - ANOMALY_P_LOW) / (ANOMALY_P_HIGH - ANOMALY_P_LOW), 0, 1)

    @staticmethod
    def deviation_evidence(deviation_score):
        return np.clip((np.asarray(deviation_score) - DEVIATION_LOW) / (DEVIATION_HIGH - DEVIATION_LOW), 0, 1)

    def score(self, anomaly_score, deviation_score, ports):
        """Returns a DataFrame with the risk score and every component (for explanations)."""
        a = self.anomaly_evidence(anomaly_score)
        d = self.deviation_evidence(deviation_score)
        evidence = 1 - (1 - W_ANOMALY * a) * (1 - W_DEVIATION * d)
        ctx = context_factor(ports)
        risk = 100 * np.minimum(1.0, evidence * ctx)
        return pd.DataFrame({"anomaly_evidence": a.astype("float32"),
                             "deviation_evidence": d.astype("float32"),
                             "context_factor": ctx.astype("float32"),
                             "risk_score": risk.astype("float32"),
                             "risk_level": risk_level(risk)})

    def save(self, path):
        joblib.dump(self, path, compress=3)

    @staticmethod
    def load(path):
        return joblib.load(path)
