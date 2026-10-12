from django.db import transaction
from django.db.models import Avg, Count
from rest_framework import generics, status
from rest_framework.exceptions import ValidationError
from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView

from ml.detection import ValidationError as FlowValidationError, flows_to_frame
from .models import Alert, Flow
from .pipeline_loader import PipelineUnavailable, detect_lock, get_pipeline
from .serializers import (AlertDetailSerializer, AlertListSerializer, ScoreRequestSerializer)

LEVELS = ("Low", "Medium", "High")
DISCLAIMER = ("Alerts indicate unusual behavior that deserves review. They are not confirmation "
              "of an attack, and the system takes no automated action.")


def error(message, details=None, http_status=status.HTTP_400_BAD_REQUEST):
    body = {"error": message}
    if details is not None:
        body["details"] = details
    return Response(body, status=http_status)


class HealthView(APIView):
    def get(self, request):
        return Response({"status": "ok"})


class ScoreView(APIView):
    """
    POST {"flows": [<raw CICIDS2017 flow fields>...], "learn": false}
    Scores each flow at detection time (anomaly -> baseline deviation -> risk -> explanation ->
    advisory response) and persists the flow, and for Medium/High the alert exactly as generated.
    """

    def post(self, request):
        if not isinstance(request.data, dict):
            return error("Request body must be a JSON object with a 'flows' list.")
        ser = ScoreRequestSerializer(data=request.data)
        if not ser.is_valid():
            return error("Invalid request.", ser.errors)
        try:                                   # validate the flow data before touching the models
            flows_to_frame(ser.validated_data["flows"])
        except FlowValidationError as e:
            return error("Invalid flow data.", e.args[0] if e.args else str(e))
        try:
            pipeline = get_pipeline()
        except PipelineUnavailable as e:
            return error("Scoring models are not available.", str(e), status.HTTP_503_SERVICE_UNAVAILABLE)

        try:
            with detect_lock:
                records = pipeline.detect(ser.validated_data["flows"], learn=ser.validated_data["learn"])
        except FlowValidationError as e:
            details = e.args[0] if e.args else str(e)
            return error("Invalid flow data.", details)

        results = []
        with transaction.atomic():
            for rec in records:
                flow = Flow.objects.create(
                    destination_port=rec["destination_port"], features=rec["features"],
                    anomaly_score=rec["anomaly_score"], anomaly_label=rec["anomaly_label"],
                    deviation_score=rec["deviation_score"], risk_score=rec["risk_score"],
                    risk_level=rec["risk_level"])
                alert_id = None
                a = rec["alert"]
                if a is not None:
                    alert = Alert.objects.create(
                        flow=flow, risk_score=a["risk_score"], risk_level=a["risk_level"],
                        drivers=a["drivers"], anomaly=a["anomaly"],
                        baseline_deviation=a["baseline_deviation"], context=a["context"],
                        explanation=a["explanation"],
                        recommended_action=a["recommended_response"]["action"],
                        recommended_response=a["recommended_response"]["text"],
                        automated_action=a["automated_action"], note=a["note"])
                    alert_id = alert.id
                results.append({
                    "flow_id": flow.id, "risk_score": rec["risk_score"], "risk_level": rec["risk_level"],
                    "anomaly_score": rec["anomaly_score"], "anomaly_label": rec["anomaly_label"],
                    "deviation_score": rec["deviation_score"], "alert_id": alert_id,
                    "explanation": a["explanation"] if a else None,
                    "recommended_response": rec["recommended_response"]})
        counts = {lvl: sum(1 for r in results if r["risk_level"] == lvl) for lvl in LEVELS}
        return Response({"results": results, "counts": counts, "disclaimer": DISCLAIMER},
                        status=status.HTTP_201_CREATED)


class AlertPagination(PageNumberPagination):
    page_size = 25
    page_size_query_param = "page_size"
    max_page_size = 200


class AlertListView(generics.ListAPIView):
    """GET /api/alerts/?level=High&port=22&min_risk=50&ordering=risk&page=1  (read-only)"""
    serializer_class = AlertListSerializer
    pagination_class = AlertPagination

    def get_queryset(self):
        qs = Alert.objects.select_related("flow")
        p = self.request.query_params
        if "level" in p:
            level = p["level"].strip().title()
            if level not in ("Medium", "High"):
                raise ValidationError({"level": "Must be 'Medium' or 'High'."})
            qs = qs.filter(risk_level=level)
        if "port" in p:
            try:
                port = int(p["port"])
            except ValueError:
                raise ValidationError({"port": "Must be an integer."})
            qs = qs.filter(flow__destination_port=port)
        if "min_risk" in p:
            try:
                qs = qs.filter(risk_score__gte=float(p["min_risk"]))
            except ValueError:
                raise ValidationError({"min_risk": "Must be a number."})
        ordering = p.get("ordering", "newest")
        if ordering not in ("newest", "risk"):
            raise ValidationError({"ordering": "Must be 'newest' or 'risk'."})
        return qs.order_by("-risk_score", "-id") if ordering == "risk" else qs.order_by("-id")


class AlertDetailView(generics.RetrieveAPIView):
    """GET /api/alerts/<id>/ - the alert exactly as stored at detection time (read-only)."""
    queryset = Alert.objects.select_related("flow")
    serializer_class = AlertDetailSerializer


class SummaryView(APIView):
    """GET /api/summary/ - counts for the dashboard."""

    def get(self, request):
        def by_level(qs):
            got = {lvl: n for lvl, n in qs.order_by().values_list("risk_level").annotate(n=Count("id"))}
            return {lvl: got.get(lvl, 0) for lvl in LEVELS}

        alerts = Alert.objects.all()
        driver_counts = {}
        for drivers in alerts.values_list("drivers", flat=True):
            key = "+".join(drivers) if drivers else "none"
            driver_counts[key] = driver_counts.get(key, 0) + 1
        top_ports = list(alerts.order_by().values("flow__destination_port")
                         .annotate(n=Count("id")).order_by("-n")[:5])
        return Response({
            "total_flows": Flow.objects.count(),
            "total_alerts": alerts.count(),
            "flows_by_risk_level": by_level(Flow.objects.all()),
            "alerts_by_risk_level": by_level(alerts),
            "alerts_by_driver": driver_counts,
            "top_alert_ports": [{"port": r["flow__destination_port"], "alerts": r["n"]} for r in top_ports],
            "average_alert_risk": alerts.aggregate(a=Avg("risk_score"))["a"],
            "disclaimer": DISCLAIMER,
        })
