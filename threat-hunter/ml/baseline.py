"""
Step 4 - Adaptive behavioral baseline, kept per destination service.

The CICIDS2017 CSVs contain no host addresses and no timestamps, so a
per-host baseline is not possible. Instead each destination service
(e.g. port 443, port 22) gets its own baseline of "typical flow behavior".
Flows are replayed in capture order (row order within a file, files in
capture-day order).

How it works
  * Each service keeps a rolling window of its most recent ACCEPTED flows
    (log1p-transformed features).
  * Robust statistics (median, MAD) over that window define "typical".
    deviation = robust z-score = (value - median) / scale
  * Adaptive: after each batch the window moves forward, so the median and
    spread follow legitimate behavior changes.
  * Safe update: a flow enters the baseline only if the Isolation Forest
    called it Normal AND its deviation is not extreme. Flagged flows never
    teach the baseline, and one batch can replace at most a limited
    fraction of the window, so change is gradual.

Safer-update guards (optional, see constructor): drift limit around the
learning-period reference, and a surge freeze for services with many flags.

Honest limitation: attack flows that look normal are NOT flagged, so some
can enter the baseline. The evaluation script measures how many.
This module produces deviation scores only. It does not decide what is an
attack, and it does not compute the risk score (Step 5).
"""
import numpy as np
import pandas as pd
import joblib

# Configuration chosen from the real-data comparison in ml/evaluate_baseline.py (config D)
RECOMMENDED_CONFIG = dict(window=20000, max_replace_frac=0.05, max_drift=3.0, surge_flag_frac=0.03)

SCALE_FLOOR = 0.25      # minimum scale (log units) so near-constant features don't explode
MAD_TO_SIGMA = 1.4826


def _transform(X):
    return np.log1p(np.clip(X, 0, None)).astype("float32")


class _ServiceBaseline:
    def __init__(self, window_rows, max_drift=None):
        self.window = window_rows
        self.max_drift = max_drift
        self.n_updates = 0
        self.ref_median = self.ref_scale = None
        self._recompute()
        self.ref_median, self.ref_scale = self.median.copy(), self.scale.copy()  # learning-period reference

    def _recompute(self):
        w = self.window
        med = np.median(w, axis=0)
        dev = np.abs(w - med)
        mad = np.median(dev, axis=0)
        mean_ad = dev.mean(axis=0)
        # MAD can be 0 for sparse features; fall back to mean absolute deviation
        scale = np.maximum.reduce([MAD_TO_SIGMA * mad, 1.2533 * mean_ad,
                                   np.full_like(mad, SCALE_FLOOR)])
        if self.max_drift is not None and self.ref_median is not None:
            # Drift guard: the baseline may follow real change, but never wander
            # more than max_drift reference-scales from the learning-period
            # reference, and its spread may only change within 0.5x-2x.
            lim = self.max_drift * self.ref_scale
            med = np.clip(med, self.ref_median - lim, self.ref_median + lim)
            scale = np.clip(scale, 0.5 * self.ref_scale, 2.0 * self.ref_scale)
        self.median, self.scale = med, scale


class AdaptiveBaseline:
    def __init__(self, window=5000, min_service_flows=500, max_update_z=10.0,
                 max_replace_frac=0.25, max_drift=None, surge_flag_frac=None):
        """
        max_drift:       drift guard (see _ServiceBaseline); None = off
        surge_flag_frac: if more than this share of a service's flows in a batch
                         are flagged Anomaly, that service's baseline is NOT
                         updated from that batch (under-attack freeze); None = off
        """
        self.max_drift = max_drift
        self.surge_flag_frac = surge_flag_frac
        self.window = window
        self.min_service_flows = min_service_flows
        self.max_update_z = max_update_z
        self.max_replace_frac = max_replace_frac
        self.feature_names = None
        self.service_ports = set()
        self.baselines = {}
        self.history = []          # (batch, service, median) snapshots

    # ---- service keys -------------------------------------------------
    def service_keys(self, ctx):
        ports = ctx["Destination Port"].to_numpy().astype(int)
        pc = ctx["port_class"].to_numpy().astype(int)
        own = np.isin(ports, list(self.service_ports))
        return np.where(own, np.char.add("port-", ports.astype(str)),
                        np.char.add("class-", pc.astype(str)))

    def _get(self, key):
        return self.baselines.get(key, self.baselines["global"])

    # ---- fit ----------------------------------------------------------
    def fit(self, X, ctx):
        """Initial baseline from a trusted learning period (e.g. first day)."""
        self.feature_names = list(X.columns)
        T = _transform(X.to_numpy())
        counts = ctx["Destination Port"].value_counts()
        self.service_ports = set(int(p) for p in counts[counts >= self.min_service_flows].index)
        keys = self.service_keys(ctx)
        self.baselines = {"global": _ServiceBaseline(T[-self.window:], self.max_drift)}
        for k in np.unique(keys):
            rows = T[keys == k]
            if len(rows) >= 50:
                self.baselines[k] = _ServiceBaseline(rows[-self.window:], self.max_drift)
        return self

    # ---- scoring ------------------------------------------------------
    def robust_z(self, X, ctx):
        """Signed robust z-score per flow and feature (n x F)."""
        T = _transform(X[self.feature_names].to_numpy())
        keys = self.service_keys(ctx)
        Z = np.empty_like(T)
        for k in np.unique(keys):
            idx = np.flatnonzero(keys == k)
            b = self._get(k)
            Z[idx] = (T[idx] - b.median) / b.scale
        return Z

    @staticmethod
    def deviation_score(Z, top=3):
        """Mean of the `top` largest |z| per flow (a flow usually deviates in few features)."""
        A = np.abs(Z)
        top = min(top, A.shape[1])
        return np.partition(A, A.shape[1] - top, axis=1)[:, -top:].mean(axis=1)

    # ---- adaptation ---------------------------------------------------
    def update(self, X, ctx, accept, batch_id=0):
        """Move the baseline forward using only the accepted flows."""
        accept = np.asarray(accept, bool)
        if not accept.any():
            return 0
        T = _transform(X[self.feature_names].to_numpy())
        keys = self.service_keys(ctx)
        cap = max(1, int(self.max_replace_frac * self.window))
        used = 0
        for k in np.unique(keys[accept]):
            if k not in self.baselines:
                continue
            new = T[(keys == k) & accept][-cap:]          # at most 25% of window per batch
            b = self.baselines[k]
            b.window = np.vstack([b.window, new])[-self.window:]
            b.n_updates += 1
            b._recompute()
            self.history.append((batch_id, k, b.median.copy()))
            used += len(new)
        return used

    # ---- stream replay ------------------------------------------------
    def process_stream(self, X, ctx, detector, batch_size=20000, update=True, precomputed=None):
        """
        Replay flows in order. For each batch: score against the CURRENT
        baseline, then (if update) let low-risk flows move the baseline.
        precomputed: optional (scores, labels) arrays to skip re-scoring.
        Returns a DataFrame aligned with X.
        """
        n = len(X)
        out = {"anomaly_score": np.empty(n, "float32"), "anomaly_label": np.empty(n, object),
               "deviation_score": np.empty(n, "float32"), "max_abs_z": np.empty(n, "float32"),
               "accepted": np.zeros(n, bool)}
        for b, s in enumerate(range(0, n, batch_size)):
            e = min(s + batch_size, n)
            Xb, cb = X.iloc[s:e], ctx.iloc[s:e]
            if precomputed is not None:
                scores, labels = precomputed[0][s:e], precomputed[1][s:e]
            else:
                scores, labels = detector.predict(Xb)
            Z = self.robust_z(Xb, cb)
            maxz = np.abs(Z).max(axis=1)
            accept = (labels == "Normal") & (maxz <= self.max_update_z)
            if self.surge_flag_frac is not None:
                keys = self.service_keys(cb)
                for k in np.unique(keys):
                    m = keys == k
                    if m.sum() >= 50 and (labels[m] == "Anomaly").mean() > self.surge_flag_frac:
                        accept[m] = False            # service looks under attack: freeze it
            out["anomaly_score"][s:e] = scores
            out["anomaly_label"][s:e] = labels
            out["deviation_score"][s:e] = self.deviation_score(Z)
            out["max_abs_z"][s:e] = maxz
            out["accepted"][s:e] = accept
            if update:
                self.update(Xb, cb, accept, batch_id=b)
        return pd.DataFrame(out, index=X.index)

    def save(self, path):
        joblib.dump(self, path, compress=3)

    @staticmethod
    def load(path):
        return joblib.load(path)
