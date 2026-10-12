"""
Step 6 - Explainable alerts and advisory responses.

This layer only EXPLAINS and RECOMMENDS. It never changes the risk score
(Step 5) and takes no action: no blocking, isolation, account changes, etc.

For each Medium/High alert it records:
  * risk score / level and the evidence behind it
  * Isolation Forest anomaly evidence + the features that drive it
  * adaptive-baseline deviation evidence + the features that deviate
  * service/port context
  * a short plain-language explanation and an advisory recommended response

How features are attributed
  deviation   : the features with the largest robust z-score against the
                service baseline (direction + observed vs typical value).
  anomaly     : counterfactual test - replace ONE feature with the service's
                typical value and see how much the Isolation Forest score drops.
                Only features whose replacement lowers the score are reported.
                This misses effects that need several features together; if no
                single feature stands out, the explanation says so.

Wording rule: an alert says behavior is UNUSUAL. It never says an attack
or zero-day was detected.
"""
import numpy as np
import pandas as pd
from ml.features import FEATURE_DESCRIPTIONS
from ml.risk import CONTEXT_NAMES, CTX_SENSITIVE, CTX_UNCOMMON, DEVIATION_LOW

PORT_NAMES = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3",
              123: "NTP", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 389: "LDAP", 443: "HTTPS",
              445: "SMB", 587: "SMTP submission", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
              1433: "SQL Server", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
              5900: "VNC", 8080: "HTTP alt", 8443: "HTTPS alt"}

RESPONSES = {
    "Low": ("Monitor",
            "Monitor: no action needed now; keep watching this service for repeated or growing unusual behavior."),
    "Medium": ("Investigate / review",
               "Investigate / review: compare this flow and related traffic for this service with expected "
               "activity (maintenance, approved scanners, new applications) and decide whether to escalate."),
    "High": ("Investigate immediately",
             "Investigate immediately and consider containment according to your organization's security "
             "policy. This system takes no automated action; any containment decision is made by a person."),
}
CAVEAT = ("This indicates unusual behavior, not proof of malicious activity; "
          "it can also come from legitimate but rare activity.")
ADVISORY_NOTE = "Advisory only: no blocking, isolation or other automated action has been taken."


def _fmt(v):
    v = float(v)
    if v == 0:
        return "0"
    a = abs(v)
    if a >= 1000:
        return f"{v:,.0f}"
    if a >= 10:
        return f"{v:.0f}"
    return f"{v:.2g}"


def service_label(port):
    port = int(port)
    return f"port {port} ({PORT_NAMES[port]})" if port in PORT_NAMES else f"port {port}"


def _anomaly_phrase(a):
    if a >= 0.75:
        return "is highly unusual compared with the learned benign behavior"
    if a >= 0.25:
        return "is moderately unusual compared with the learned benign behavior"
    return "is slightly unusual compared with the learned benign behavior"


def _deviation_phrase(d, svc):
    if d >= 0.75:
        return f"shows a large deviation from the {svc} baseline"
    if d >= 0.25:
        return f"shows a moderate deviation from the {svc} baseline"
    return f"shows a small deviation from the {svc} baseline"


def _feature_phrase(f):
    desc = FEATURE_DESCRIPTIONS.get(f["feature"], f["feature"])
    return (f"{desc}: {_fmt(f['value'])} vs typical {_fmt(f['typical'])}, "
            f"{f['magnitude']} {f['direction']}")


def build_explanation(level, port, ctx_factor, a_ev, d_ev, anomaly_features, deviation_features):
    """Plain-language explanation from the recorded evidence (pure function, easy to test)."""
    svc = service_label(port)
    if a_ev <= 0 and d_ev <= 0:
        parts = [f"{level} risk: the flow is within the range expected for {svc}; "
                 "neither the learned benign behavior nor the service baseline shows meaningful unusualness."]
    else:
        clauses = []
        if a_ev > 0:
            clauses.append(_anomaly_phrase(a_ev))
        if d_ev > 0:
            clauses.append(_deviation_phrase(d_ev, svc))
        parts = [f"{level} risk because the network flow " + " and ".join(clauses) + "."]
        if (a_ev > 0) != (d_ev > 0):
            src = "the learned-behavior model" if a_ev > 0 else "the service baseline"
            parts.append(f"Only {src} contributed, so treat the evidence as weaker.")
        if a_ev > 0:
            if anomaly_features:
                parts.append("Behaviors driving the unusualness: "
                             + "; ".join(_feature_phrase(f) for f in anomaly_features) + ".")
            else:
                parts.append("No single behavior stands out; the unusualness comes from a combination of features.")
        if d_ev > 0 and deviation_features:
            parts.append("Largest deviations from the service baseline: "
                         + "; ".join(_feature_phrase(f) for f in deviation_features) + ".")
    if ctx_factor >= CTX_SENSITIVE:
        parts.append(f"The destination is a sensitive service, {svc}, so this activity is prioritized higher.")
    elif ctx_factor >= CTX_UNCOMMON:
        parts.append(f"The destination, {svc}, is an uncommon port, which slightly raises priority.")
    else:
        parts.append(f"The destination is a common service, {svc}.")
    if level != "Low":
        parts.append(CAVEAT)
    return " ".join(parts)


def _magnitude(z):
    z = abs(z)
    return "far" if z >= 10 else "much" if z >= 5 else "somewhat"


class AlertExplainer:
    def __init__(self, detector, baseline, scorer, top_k=3, min_share=0.10, min_abs_z=2.0):
        self.detector, self.baseline, self.scorer = detector, baseline, scorer
        self.top_k, self.min_share, self.min_abs_z = top_k, min_share, min_abs_z
        self.names = list(baseline.feature_names)

    def _typical_matrix(self, X, ctx):
        """Per-flow service-typical feature values, in original units."""
        keys = self.baseline.service_keys(ctx)
        T = np.empty((len(X), len(self.names)), dtype="float64")
        for k in np.unique(keys):
            T[keys == k] = np.expm1(self.baseline._get(k).median)
        return T

    def _anomaly_contrib(self, X, anom, typical):
        C = np.zeros((len(X), len(self.names)))
        for j, col in enumerate(self.names):
            Xm = X.copy()
            Xm[col] = typical[:, j]
            C[:, j] = anom - self.detector.score(Xm)
        return C

    def explain_flows(self, X, ctx, risk=None, include_low=False):
        """
        Returns a list of alert dicts (Medium/High; Low too if include_low).
        risk: optional precomputed Step 5 output; if None it is computed with the scorer.
        The risk score itself is never modified here.
        """
        X = X.reset_index(drop=True); ctx = ctx.reset_index(drop=True)
        anom = self.detector.score(X)
        Z = self.baseline.robust_z(X, ctx)
        dev = self.baseline.deviation_score(Z)
        risk = (self.scorer.score(anom, dev, ctx["Destination Port"]) if risk is None
                else risk.reset_index(drop=True))
        keep = np.flatnonzero(include_low | (risk["risk_level"].to_numpy() != "Low"))
        if len(keep) == 0:
            return []
        Xk, ck = X.iloc[keep].reset_index(drop=True), ctx.iloc[keep].reset_index(drop=True)
        typical = self._typical_matrix(Xk, ck)
        contrib = self._anomaly_contrib(Xk, anom[keep], typical)

        alerts = []
        for r, i in enumerate(keep):
            rk = risk.iloc[i]
            a_ev, d_ev = float(rk["anomaly_evidence"]), float(rk["deviation_evidence"])
            port = int(ck["Destination Port"].iloc[r])
            vals = Xk.iloc[r]

            a_feats = []
            if a_ev > 0:
                pos = np.clip(contrib[r], 0, None)
                if pos.sum() > 0:
                    for j in np.argsort(-pos)[: self.top_k]:
                        share = pos[j] / pos.sum()
                        z = Z[i, j]
                        if share >= self.min_share and abs(z) >= self.min_abs_z:
                            a_feats.append({"feature": self.names[j], "share": round(float(share), 3),
                                            "value": float(vals[self.names[j]]),
                                            "typical": float(typical[r, j]),
                                            "direction": "higher" if vals[self.names[j]] >= typical[r, j] else "lower",
                                            "magnitude": _magnitude(z)})
            d_feats = []
            if d_ev > 0:
                order = np.argsort(-np.abs(Z[i]))[: self.top_k]
                chosen = [j for j in order if abs(Z[i, j]) >= DEVIATION_LOW] or [order[0]]
                for j in chosen:
                    d_feats.append({"feature": self.names[j], "z": round(float(Z[i, j]), 2),
                                    "value": float(vals[self.names[j]]), "typical": float(typical[r, j]),
                                    "direction": "higher" if Z[i, j] > 0 else "lower",
                                    "magnitude": _magnitude(Z[i, j])})
            level = str(rk["risk_level"])
            ctxf = round(float(rk["context_factor"]), 2)
            action, text = RESPONSES[level]
            drivers = (["anomaly", "deviation"] if a_ev > 0 and d_ev > 0 else
                       ["anomaly"] if a_ev > 0 else ["deviation"] if d_ev > 0 else [])
            alerts.append({
                "flow_index": int(i),
                "risk_score": round(float(rk["risk_score"]), 1),
                "risk_level": level,
                "anomaly": {"score": round(float(anom[i]), 4), "evidence": round(a_ev, 3),
                            "features": a_feats},
                "baseline_deviation": {"score": round(float(dev[i]), 2), "evidence": round(d_ev, 3),
                                       "features": d_feats},
                "context": {"destination_port": port, "service": service_label(port),
                            "type": CONTEXT_NAMES.get(ctxf, "common service"),
                            "factor": round(ctxf, 2)},
                "drivers": drivers,
                "explanation": build_explanation(level, port, ctxf, a_ev, d_ev, a_feats, d_feats),
                "recommended_response": {"action": action, "text": text},
                "automated_action": "none",
                "note": ADVISORY_NOTE,
            })
        return alerts
