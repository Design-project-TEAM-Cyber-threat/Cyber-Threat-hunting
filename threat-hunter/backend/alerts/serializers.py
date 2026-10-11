from rest_framework import serializers
from .models import Alert, Flow


class ScoreRequestSerializer(serializers.Serializer):
    flows = serializers.ListField(child=serializers.DictField(), allow_empty=False, max_length=1000)
    learn = serializers.BooleanField(default=False, required=False)


class FlowSerializer(serializers.ModelSerializer):
    class Meta:
        model = Flow
        fields = ["id", "created_at", "destination_port", "features", "anomaly_score",
                  "anomaly_label", "deviation_score", "risk_score", "risk_level"]


class AlertListSerializer(serializers.ModelSerializer):
    destination_port = serializers.IntegerField(source="flow.destination_port", read_only=True)
    service = serializers.SerializerMethodField()

    class Meta:
        model = Alert
        fields = ["id", "created_at", "risk_score", "risk_level", "destination_port", "service",
                  "drivers", "explanation", "recommended_action"]

    def get_service(self, obj):
        return obj.context.get("service")


class AlertDetailSerializer(serializers.ModelSerializer):
    flow = FlowSerializer(read_only=True)

    class Meta:
        model = Alert
        fields = ["id", "created_at", "risk_score", "risk_level", "drivers", "anomaly",
                  "baseline_deviation", "context", "explanation", "recommended_action",
                  "recommended_response", "automated_action", "note", "flow"]
