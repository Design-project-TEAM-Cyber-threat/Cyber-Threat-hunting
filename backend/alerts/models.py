from django.db import models


class Flow(models.Model):
    """One scored network flow (every flow submitted to the API is stored)."""
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    destination_port = models.PositiveIntegerField(db_index=True)
    features = models.JSONField()                      # the 21 behavioral features used for scoring
    anomaly_score = models.FloatField()                # Isolation Forest (Step 3)
    anomaly_label = models.CharField(max_length=10)    # Normal / Anomaly
    deviation_score = models.FloatField()              # adaptive baseline (Step 4)
    risk_score = models.FloatField(db_index=True)      # contextual risk (Step 5)
    risk_level = models.CharField(max_length=6, db_index=True)   # Low / Medium / High

    class Meta:
        ordering = ["-id"]


class Alert(models.Model):
    """
    Medium/High alert, stored exactly as generated AT DETECTION TIME.
    Alerts are immutable: the explanation is never recomputed from a later baseline.
    """
    flow = models.OneToOneField(Flow, on_delete=models.CASCADE, related_name="alert")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    risk_score = models.FloatField(db_index=True)
    risk_level = models.CharField(max_length=6, db_index=True)
    drivers = models.JSONField(default=list)           # which signals contributed
    anomaly = models.JSONField()                       # score, evidence, driving features
    baseline_deviation = models.JSONField()            # score, evidence, deviating features
    context = models.JSONField()                       # port, service, type, factor
    explanation = models.TextField()
    recommended_action = models.CharField(max_length=40)
    recommended_response = models.TextField()          # advisory text only
    automated_action = models.CharField(max_length=10, default="none")
    note = models.TextField()

    class Meta:
        ordering = ["-id"]

    def save(self, *args, **kwargs):
        if not self._state.adding:
            raise ValueError("Alerts are immutable: they keep the evidence generated at detection time.")
        super().save(*args, **kwargs)
