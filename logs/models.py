from django.db import models

class SeverityLevel(models.IntegerChoices):
    LOW = 1
    MEDIUM = 7
    HIGH = 10
    CRITICAL = 13


class Alert(models.Model):
    """
    Stores high-severity alerts pushed by the Wazuh Integrator in real-time.
    Only alerts with rule.level >= 10 are persisted here.
    """

    # --- Wazuh identifiers ---
    wazuh_alert_id = models.CharField(max_length=255, unique=True, db_index=True)
    wazuh_rule_id = models.CharField(max_length=64, db_index=True)

    # --- Rule info ---
    rule_level = models.PositiveSmallIntegerField(db_index=True)
    rule_description = models.TextField()
    rule_groups = models.JSONField(default=list)  # e.g. ["authentication", "sshd"]
    rule_mitre = models.JSONField(default=dict)   # MITRE ATT&CK mapping if present

    # --- Agent (source host) ---
    agent_id = models.CharField(max_length=64, db_index=True)
    agent_name = models.CharField(max_length=255)
    agent_ip = models.GenericIPAddressField(null=True, blank=True)

    # --- Manager ---
    manager_name = models.CharField(max_length=255, blank=True)

    # --- Timestamps ---
    alert_timestamp = models.DateTimeField(db_index=True)   # from Wazuh
    received_at = models.DateTimeField(auto_now_add=True)    # when Django received it

    # --- Raw payload ---
    raw_data = models.JSONField()   # full original alert JSON for reference

    # --- Status / triage ---
    is_acknowledged = models.BooleanField(default=False)
    acknowledged_by = models.ForeignKey(
        "auth.User",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="acknowledged_alerts",
    )
    acknowledged_at = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)

    class Meta:
        ordering = ["-alert_timestamp"]
        indexes = [
            models.Index(fields=["rule_level", "alert_timestamp"]),
            models.Index(fields=["agent_id", "alert_timestamp"]),
        ]

    def __str__(self):
        return f"[L{self.rule_level}] {self.rule_description} — {self.agent_name}"

    @property
    def severity_label(self):
        if self.rule_level >= 13:
            return "CRITICAL"
        elif self.rule_level >= 10:
            return "HIGH"
        elif self.rule_level >= 7:
            return "MEDIUM"
        return "LOW"


class IntegratorIngest(models.Model):
    """
    Audit log of every raw payload received from the Wazuh Integrator.
    Useful for debugging and replay.
    """
    received_at = models.DateTimeField(auto_now_add=True)
    remote_ip = models.GenericIPAddressField(null=True, blank=True)
    payload = models.JSONField()
    was_stored = models.BooleanField(default=False)   # True if it became an Alert
    skip_reason = models.CharField(max_length=255, blank=True)  # e.g. "below_threshold"

    class Meta:
        ordering = ["-received_at"]

    def __str__(self):
        return f"Ingest @ {self.received_at} | stored={self.was_stored}"
