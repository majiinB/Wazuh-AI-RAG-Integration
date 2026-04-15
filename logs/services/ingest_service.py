"""
logs/services/ingest_service.py

Processes raw payloads from the Wazuh Integrator webhook.
Filters by severity, normalizes fields, and saves to the DB.

Wazuh Integrator sends a JSON payload like:
{
    "rule": { "id": "...", "level": 10, "description": "...", "groups": [...] },
    "agent": { "id": "001", "name": "web-server", "ip": "10.0.0.5" },
    "manager": { "name": "wazuh-manager" },
    "id": "1716000000.12345",
    "timestamp": "2024-05-18T10:00:00.000+0000",
    "full_log": "...",
    ...
}
"""

import logging
from datetime import datetime

from django.utils.dateparse import parse_datetime
from django.utils import timezone

from logs.models import Alert, IntegratorIngest

logger = logging.getLogger(__name__)

# Only persist alerts at or above this rule level
HIGH_SEVERITY_THRESHOLD = 10


def process_integrator_payload(payload: dict, remote_ip: str = None) -> dict:
    """
    Main entry point called by the webhook view.

    1. Saves raw payload to IntegratorIngest (audit log).
    2. Checks severity threshold.
    3. If high severity, normalizes and creates an Alert.

    Returns:
        { "stored": bool, "alert_id": int|None, "skip_reason": str|None }
    """

    # --- Step 1: Audit log ---
    ingest_record = IntegratorIngest(
        payload=payload,
        remote_ip=remote_ip,
    )

    rule = payload.get("rule", {})
    level = rule.get("level", 0)

    # --- Step 2: Threshold check ---
    if level < HIGH_SEVERITY_THRESHOLD:
        # Uncomment if you want to save low-severity ingests for auditing:
        # ingest_record.was_stored = False
        # ingest_record.skip_reason = f"below_threshold (level={level})"
        # ingest_record.save()
        logger.debug(f"Skipped alert level={level} — below threshold {HIGH_SEVERITY_THRESHOLD}")
        return {"stored": False, "alert_id": None, "skip_reason": ingest_record.skip_reason}

    # --- Step 3: Normalize and save Alert ---
    try:
        alert = _normalize_and_save(payload)
        ingest_record.was_stored = True
        ingest_record.save()
        logger.info(f"Stored Alert id={alert.id} level={level} agent={alert.agent_name}")
        return {"stored": True, "alert_id": alert.id, "skip_reason": None}

    except Exception as e:
        ingest_record.was_stored = False
        ingest_record.skip_reason = f"error: {str(e)}"
        ingest_record.save()
        logger.error(f"Failed to save alert: {e}", exc_info=True)
        raise


def _normalize_and_save(payload: dict) -> Alert:
    """
    Maps Wazuh integrator JSON fields to the Alert model.
    Uses update_or_create to avoid duplicates on replay.
    """
    rule = payload.get("rule", {})
    agent = payload.get("agent", {})
    manager = payload.get("manager", {})

    wazuh_alert_id = payload.get("id", "")
    timestamp_raw = payload.get("timestamp", "")
    alert_timestamp = _parse_timestamp(timestamp_raw)

    mitre = rule.get("mitre", {})

    alert, created = Alert.objects.update_or_create(
        wazuh_alert_id=wazuh_alert_id,
        defaults={
            "wazuh_rule_id": str(rule.get("id", "")),
            "rule_level": int(rule.get("level", 0)),
            "rule_description": rule.get("description", ""),
            "rule_groups": rule.get("groups", []),
            "rule_mitre": mitre if isinstance(mitre, dict) else {},
            "agent_id": str(agent.get("id", "")),
            "agent_name": agent.get("name", "unknown"),
            "agent_ip": agent.get("ip") or None,
            "manager_name": manager.get("name", ""),
            "alert_timestamp": alert_timestamp,
            "raw_data": payload,
        },
    )
    return alert


def _parse_timestamp(ts: str) -> datetime:
    """Parse Wazuh ISO timestamp, falling back to now()."""
    if not ts:
        return timezone.now()
    try:
        dt = parse_datetime(ts)
        if dt is None:
            # Try stripping timezone suffix and re-parse
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if timezone.is_naive(dt):
            dt = timezone.make_aware(dt)
        return dt
    except Exception:
        logger.warning(f"Could not parse timestamp '{ts}', using now()")
        return timezone.now()