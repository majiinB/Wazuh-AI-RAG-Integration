"""
logs/serializers.py
"""

from rest_framework import serializers
from .models import Alert, IntegratorIngest


class AlertSerializer(serializers.ModelSerializer):
    severity_label = serializers.ReadOnlyField()

    class Meta:
        model = Alert
        fields = [
            "id",
            "wazuh_alert_id",
            "wazuh_rule_id",
            "rule_level",
            "severity_label",
            "rule_description",
            "rule_groups",
            "rule_mitre",
            "agent_id",
            "agent_name",
            "agent_ip",
            "manager_name",
            "alert_timestamp",
            "received_at",
            "is_acknowledged",
            "acknowledged_by",
            "acknowledged_at",
            "notes",
        ]
        read_only_fields = [
            "id", "received_at", "severity_label",
            "acknowledged_by", "acknowledged_at",
        ]


class AlertAcknowledgeSerializer(serializers.ModelSerializer):
    """Used for PATCH /alerts/{id}/acknowledge/"""

    class Meta:
        model = Alert
        fields = ["is_acknowledged", "notes"]


class IntegratorIngestSerializer(serializers.ModelSerializer):
    class Meta:
        model = IntegratorIngest
        fields = ["id", "received_at", "remote_ip", "was_stored", "skip_reason"]


class OpenSearchAlertSerializer(serializers.Serializer):
    """
    Serializes raw OpenSearch hits from the Wazuh Indexer.
    Fields mirror the Wazuh alert schema.
    """
    timestamp = serializers.CharField(source="timestamp", default=None)
    rule_id = serializers.SerializerMethodField()
    rule_level = serializers.SerializerMethodField()
    rule_description = serializers.SerializerMethodField()
    rule_groups = serializers.SerializerMethodField()
    agent_id = serializers.SerializerMethodField()
    agent_name = serializers.SerializerMethodField()
    agent_ip = serializers.SerializerMethodField()
    manager_name = serializers.SerializerMethodField()
    full_log = serializers.CharField(default=None)

    def get_rule_id(self, obj):
        return obj.get("rule", {}).get("id")

    def get_rule_level(self, obj):
        return obj.get("rule", {}).get("level")

    def get_rule_description(self, obj):
        return obj.get("rule", {}).get("description")

    def get_rule_groups(self, obj):
        return obj.get("rule", {}).get("groups", [])

    def get_agent_id(self, obj):
        return obj.get("agent", {}).get("id")

    def get_agent_name(self, obj):
        return obj.get("agent", {}).get("name")

    def get_agent_ip(self, obj):
        return obj.get("agent", {}).get("ip")

    def get_manager_name(self, obj):
        return obj.get("manager", {}).get("name")