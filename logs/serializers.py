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
    # Tier 1: baseline fields expected on almost all alerts.
    timestamp = serializers.CharField(default=None)
    rule_id = serializers.SerializerMethodField()
    rule_level = serializers.SerializerMethodField()
    rule_description = serializers.SerializerMethodField()
    rule_groups = serializers.SerializerMethodField()
    agent_id = serializers.SerializerMethodField()
    agent_name = serializers.SerializerMethodField()
    full_log = serializers.CharField(default=None)
    decoder_name = serializers.SerializerMethodField()

    # Tier 2: common enrichments, optional by alert type.
    rule_mitre_id = serializers.SerializerMethodField()
    rule_mitre_technique = serializers.SerializerMethodField()
    rule_mitre_tactic = serializers.SerializerMethodField()
    src_ip = serializers.SerializerMethodField()
    dst_ip = serializers.SerializerMethodField()
    src_user = serializers.SerializerMethodField()
    dst_user = serializers.SerializerMethodField()
    src_port = serializers.SerializerMethodField()
    dst_port = serializers.SerializerMethodField()

    # Tier 3: decoder-specific fields.
    clamav_source_file = serializers.SerializerMethodField()
    clamav_malware_name = serializers.SerializerMethodField()
    audit_file_name = serializers.SerializerMethodField()
    audit_command = serializers.SerializerMethodField()
    syscheck_path = serializers.SerializerMethodField()
    syscheck_md5_after = serializers.SerializerMethodField()
    syscheck_sha256_after = serializers.SerializerMethodField()
    command = serializers.SerializerMethodField()
    falco_proc_name = serializers.SerializerMethodField()
    falco_container_id = serializers.SerializerMethodField()
    agent_ip = serializers.SerializerMethodField()
    manager_name = serializers.SerializerMethodField()

    @staticmethod
    def _deep_get(obj, *path, default=None):
        current = obj
        for key in path:
            if not isinstance(current, dict):
                return default
            current = current.get(key)
            if current is None:
                return default
        return current

    def to_representation(self, instance):
        data = super().to_representation(instance)
        if self.context.get("include_empty_fields", False):
            return data
        return {
            key: value
            for key, value in data.items()
            if value not in (None, "", [], {})
        }

    def get_rule_id(self, obj):
        return self._deep_get(obj, "rule", "id")

    def get_rule_level(self, obj):
        return self._deep_get(obj, "rule", "level")

    def get_rule_description(self, obj):
        return self._deep_get(obj, "rule", "description")

    def get_rule_groups(self, obj):
        return self._deep_get(obj, "rule", "groups", default=[])

    def get_agent_id(self, obj):
        return self._deep_get(obj, "agent", "id")

    def get_agent_name(self, obj):
        return self._deep_get(obj, "agent", "name")

    def get_agent_ip(self, obj):
        return self._deep_get(obj, "agent", "ip")

    def get_manager_name(self, obj):
        return self._deep_get(obj, "manager", "name")

    def get_decoder_name(self, obj):
        return self._deep_get(obj, "decoder", "name")

    def get_rule_mitre_id(self, obj):
        return self._deep_get(obj, "rule", "mitre", "id")

    def get_rule_mitre_technique(self, obj):
        return self._deep_get(obj, "rule", "mitre", "technique")

    def get_rule_mitre_tactic(self, obj):
        return self._deep_get(obj, "rule", "mitre", "tactic")

    def get_src_ip(self, obj):
        return self._deep_get(obj, "data", "srcip")

    def get_dst_ip(self, obj):
        return self._deep_get(obj, "data", "dstip")

    def get_src_user(self, obj):
        return self._deep_get(obj, "data", "srcuser")

    def get_dst_user(self, obj):
        return self._deep_get(obj, "data", "dstuser")

    def get_src_port(self, obj):
        return self._deep_get(obj, "data", "srcport")

    def get_dst_port(self, obj):
        return self._deep_get(obj, "data", "dstport")

    def get_clamav_source_file(self, obj):
        return self._deep_get(obj, "data", "virustotal", "source", "file")

    def get_clamav_malware_name(self, obj):
        virustotal = self._deep_get(obj, "data", "virustotal", default={})
        if isinstance(virustotal, dict):
            for key in virustotal:
                if key.startswith("malware"):
                    name = self._deep_get(virustotal, key, "name")
                    if name:
                        return name
        return None

    def get_audit_file_name(self, obj):
        return self._deep_get(obj, "data", "audit", "file", "name")

    def get_audit_command(self, obj):
        return self._deep_get(obj, "data", "audit", "command")

    def get_syscheck_path(self, obj):
        return self._deep_get(obj, "syscheck", "path")

    def get_syscheck_md5_after(self, obj):
        return self._deep_get(obj, "syscheck", "md5_after")

    def get_syscheck_sha256_after(self, obj):
        return self._deep_get(obj, "syscheck", "sha256_after")

    def get_command(self, obj):
        return self._deep_get(obj, "data", "command")

    def get_falco_proc_name(self, obj):
        return self._deep_get(obj, "data", "falco", "proc_name")

    def get_falco_container_id(self, obj):
        return self._deep_get(obj, "data", "falco", "container_id")