"""
logs/admin.py
"""

from django.contrib import admin
from django.utils.html import format_html
from .models import Alert, IntegratorIngest


@admin.register(Alert)
class AlertAdmin(admin.ModelAdmin):
    list_display = [
        "id", "severity_badge", "rule_description", "agent_name",
        "agent_ip", "alert_timestamp", "is_acknowledged",
    ]
    list_filter = ["rule_level", "is_acknowledged", "agent_name"]
    search_fields = ["rule_description", "agent_name", "wazuh_alert_id", "wazuh_rule_id"]
    readonly_fields = [
        "wazuh_alert_id", "received_at", "alert_timestamp",
        "acknowledged_by", "acknowledged_at", "raw_data",
    ]
    ordering = ["-alert_timestamp"]
    date_hierarchy = "alert_timestamp"

    def severity_badge(self, obj):
        colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#d97706",
            "LOW": "#65a30d",
        }
        color = colors.get(obj.severity_label, "#6b7280")
        return format_html(
            '<span style="background:{};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px">{} L{}</span>',
            color, obj.severity_label, obj.rule_level,
        )
    severity_badge.short_description = "Severity"


@admin.register(IntegratorIngest)
class IntegratorIngestAdmin(admin.ModelAdmin):
    list_display = ["id", "received_at", "remote_ip", "was_stored", "skip_reason"]
    list_filter = ["was_stored"]
    readonly_fields = ["received_at", "remote_ip", "payload", "was_stored", "skip_reason"]
    ordering = ["-received_at"]