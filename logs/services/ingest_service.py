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
from time import sleep
from typing import Any

from django.utils.dateparse import parse_datetime
from django.utils import timezone

from logs.models import Alert, IntegratorIngest
from logs.services.opensearch_service import build_attack_sessions, search_alerts_by_iocs

logger = logging.getLogger(__name__)

# Only persist alerts at or above this rule level
HIGH_SEVERITY_THRESHOLD = 10

# Correlation retries to absorb indexer ingest lag after webhook trigger.
CORRELATION_BACKOFF_SCHEDULE_SECONDS = (0.75, 1.5, 3.0)


def process_integrator_payload(payload: dict, remote_ip: str = None) -> dict:
    """
    Main entry point called by the webhook view.

    1. Extracts IOC/context fields from payload using tiered mapping.
    2. Constructs a retrieval query for correlated alerts.
    3. Returns IOC payload and constructed retrieval query.

    Returns:
        {
            "stored": bool,
            "alert_id": int|None,
            "skip_reason": str|None,
            "iocs": dict,
            "constructed_query": str,
        }
    """

    # --- Step 1: Audit log ---
    # ingest_record = IntegratorIngest(
    #     payload=payload,
    #     remote_ip=remote_ip,
    # )

    # --- Step 2: IOC extraction ---
    iocs = extract_iocs(payload)
    constructed_query = build_constructed_query(iocs)

    correlation = {
        "total": 0,
        "count": 0,
        "results": [],
    }
    attack_sessions = []
    llm_story_skeleton = {
        "sessions": [],
        "kept_session_count": 0,
        "total_session_count": 0,
    }
    try:
        correlated = _search_correlated_with_backoff(iocs=iocs, size=100)
        correlation = {
            "total": correlated["total"],
            "hit_count": len(correlated["hits"]),
            "results": {
                "unique_event_types": correlated["unique_event_types"],
                "dedup_correlated": correlated["deduplicated"],
                "ranked_hits_deduplicated": correlated.get("ranked_hits_deduplicated", []),
                "min_should_match_used": correlated.get("min_should_match_used"),
            },
        }

        attack_sessions = build_attack_sessions(
            deduplicated=correlated["deduplicated"],
            tactics_progression=correlated["tactics_progression"],
        )
        llm_story_skeleton = build_llm_story_skeleton(attack_sessions)
    except Exception as exc:
        logger.warning("IOC correlation query failed: %s", exc)
        correlation["error"] = str(exc)

    # --- Step 3: Save ingest audit and return IOC-centric response ---
    # ingest_record.was_stored = False
    # ingest_record.skip_reason = "ioc_extraction_only"
    # ingest_record.save()

    return {
        "stored": False,
        "alert_id": None,
        "iocs": iocs,
        "constructed_query": constructed_query,
        "correlation": correlation,
        "attack_sessions": attack_sessions,
        "llm_story_skeleton": llm_story_skeleton,
    }


def _search_correlated_with_backoff(iocs: dict, size: int = 100) -> dict:
    """
    Retry correlation query with exponential-ish backoff to allow indexer refresh.

    Stops early as soon as the trigger rule appears in correlated deduplicated hits.
    """
    trigger_rule_id = str((iocs.get("tier_1") or {}).get("rule_id") or "")
    attempts = len(CORRELATION_BACKOFF_SCHEDULE_SECONDS) + 1
    last_result = None

    for attempt in range(attempts):
        correlated = search_alerts_by_iocs(iocs=iocs, size=size)
        last_result = correlated

        if not trigger_rule_id or _has_trigger_rule(correlated=correlated, trigger_rule_id=trigger_rule_id):
            if attempt > 0:
                logger.info(
                    "Trigger rule %s became visible after %s correlation retry attempt(s)",
                    trigger_rule_id,
                    attempt,
                )
            return correlated

        if attempt < len(CORRELATION_BACKOFF_SCHEDULE_SECONDS):
            delay_seconds = CORRELATION_BACKOFF_SCHEDULE_SECONDS[attempt]
            logger.info(
                "Trigger rule %s not yet visible in correlation results; retrying in %.2fs",
                trigger_rule_id,
                delay_seconds,
            )
            sleep(delay_seconds)

    return last_result


def _has_trigger_rule(correlated: dict, trigger_rule_id: str) -> bool:
    """Check if deduplicated correlated results include the triggering rule id."""
    for group in correlated.get("deduplicated", []):
        if str(group.get("rule_id") or "") == trigger_rule_id:
            return True
    return False


def build_llm_story_skeleton(attack_sessions: list) -> dict:
    """
    Build an LLM-ready narrative skeleton from attack sessions.

    Filtering rules:
    - Keep sessions with confidence in {high, medium}
    - OR keep sessions with max_severity >= 5

    Output intentionally excludes raw/debug retrieval fields.
    """

    def summarize_event_group(group: dict) -> str:
        """
        Build a generic, alert-agnostic event sentence for LLM narrative input.
        """
        count = group.get("occurrences", 1) or 1
        description = (group.get("rule_description") or "Unknown event").strip()

        context_parts = []
        src_user = group.get("src_user")
        dst_user = group.get("dst_user")
        src_ip = group.get("src_ip")
        dst_ip = group.get("dst_ip")
        command = group.get("command")
        tactics = group.get("mitre_tactic") or []

        if src_user and dst_user:
            context_parts.append(f"actor={src_user} target={dst_user}")
        elif src_user:
            context_parts.append(f"actor={src_user}")
        elif dst_user:
            context_parts.append(f"target={dst_user}")

        if src_ip and dst_ip:
            context_parts.append(f"network={src_ip}->{dst_ip}")
        elif src_ip:
            context_parts.append(f"src_ip={src_ip}")
        elif dst_ip:
            context_parts.append(f"dst_ip={dst_ip}")

        if command:
            context_parts.append(f"command={command}")

        if tactics:
            context_parts.append("tactic=" + ", ".join(str(t) for t in tactics))

        if context_parts:
            return f"{count}x {description} ({'; '.join(context_parts)})"
        return f"{count}x {description}"

    total_sessions = len(attack_sessions or [])
    kept_sessions = []

    for session in attack_sessions or []:
        confidence = (session.get("confidence") or "").lower()
        max_level = session.get("max_severity") or 0
        if confidence not in {"high", "medium"} and max_level < 5:
            continue

        event_groups = session.get("event_groups") or []
        event_summary = [summarize_event_group(group) for group in event_groups]

        kept_sessions.append({
            "actor": session.get("actor"),
            "host": session.get("host"),
            "time_window": {
                "start": session.get("start_time"),
                "end": session.get("end_time"),
                "duration_minutes": session.get("duration_minutes"),
            },
            "severity": {
                "max_level": max_level,
                "confidence": session.get("confidence"),
            },
            "attack_chain": session.get("attack_chain") or [],
            "mitre_ids": session.get("mitre_ids") or [],
            "event_summary": event_summary,
        })

    return {
        "sessions": kept_sessions,
        "kept_session_count": len(kept_sessions),
        "total_session_count": total_sessions,
    }


def extract_iocs(payload: dict) -> dict:
    """
    Extract IOC/context fields from Wazuh alert payload.
    Missing values are omitted for graceful degradation.
    """
    tier_1 = {
        "rule_description": _deep_get(payload, "rule", "description"),
        "rule_level": _deep_get(payload, "rule", "level"),
        "rule_id": _deep_get(payload, "rule", "id"),
        "rule_groups": _deep_get(payload, "rule", "groups", default=[]),
        "agent_id": _deep_get(payload, "agent", "id"),
        "agent_name": _deep_get(payload, "agent", "name"),
        "timestamp": payload.get("timestamp"),
        "full_log": payload.get("full_log"),
        "decoder_name": _deep_get(payload, "decoder", "name"),
    }

    tier_2 = {
        "rule_mitre_id": _deep_get(payload, "rule", "mitre", "id"),
        "rule_mitre_technique": _deep_get(payload, "rule", "mitre", "technique"),
        "rule_mitre_tactic": _deep_get(payload, "rule", "mitre", "tactic"),
        "agent_ip": _deep_get(payload, "agent", "ip"),
        "location": payload.get("location"),
        "src_ip": _deep_get(payload, "data", "srcip"),
        "dst_ip": _deep_get(payload, "data", "dstip"),
        "src_user": _deep_get(payload, "data", "srcuser"),
        "dst_user": _deep_get(payload, "data", "dstuser"),
        "src_port": _deep_get(payload, "data", "srcport"),
        "dst_port": _deep_get(payload, "data", "dstport"),
    }

    tier_3_candidates = {
        "clamav_source_file": _deep_get(payload, "data", "virustotal", "source", "file"),
        "clamav_malware_name": _extract_first_malware_name(payload),
        "audit_file_name": _deep_get(payload, "data", "audit", "file", "name"),
        "audit_command": _deep_get(payload, "data", "audit", "command"),
        "syscheck_path": _deep_get(payload, "syscheck", "path"),
        "syscheck_md5_after": _deep_get(payload, "syscheck", "md5_after"),
        "syscheck_sha256_after": _deep_get(payload, "syscheck", "sha256_after"),
        "command": _deep_get(payload, "data", "command"),
        "tty": _deep_get(payload, "data", "tty"),
        "pwd": _deep_get(payload, "data", "pwd"),
        "ufw_src_ip": _deep_get(payload, "data", "srcip"),
        "ufw_dst_ip": _deep_get(payload, "data", "dstip"),
        "ufw_dst_port": _deep_get(payload, "data", "dstport"),
        "falco_proc_name": _deep_get(payload, "data", "falco", "proc_name"),
        "falco_container_id": _deep_get(payload, "data", "falco", "container_id"),
    }

    decoder_name = (tier_1.get("decoder_name") or "").lower()
    decoder_field_map = {
        "clamav": {"clamav_source_file", "clamav_malware_name"},
        "auditd": {"audit_file_name", "audit_command"},
        "syscheck": {"syscheck_path", "syscheck_md5_after", "syscheck_sha256_after"},
        "sudo": {"command", "src_user", "dst_user", "tty", "pwd"},
        "ufw": {"ufw_src_ip", "ufw_dst_ip", "ufw_dst_port"},
        "falco": {"falco_proc_name", "falco_container_id"},
    }

    selected_tier_3_keys = decoder_field_map.get(decoder_name, set())
    tier_3 = {
        key: value
        for key, value in tier_3_candidates.items()
        if key in selected_tier_3_keys and _has_value(value)
    }

    return {
        "tier_1": _drop_empty(tier_1),
        "tier_2": _drop_empty(tier_2),
        "tier_3": tier_3,
    }


def build_constructed_query(iocs: dict) -> str:
    """
    Build a natural-language query from extracted IOC fields.
    Degrades gracefully when only baseline fields are available.
    """
    t1 = iocs.get("tier_1", {})
    t2 = iocs.get("tier_2", {})
    t3 = iocs.get("tier_3", {})

    parts = []
    if t1.get("rule_description"):
        parts.append(f"{t1['rule_description']}.")
    if t1.get("rule_groups"):
        groups = ", ".join(str(g) for g in t1["rule_groups"])
        parts.append(f"Groups: {groups}.")
    if t2.get("rule_mitre_technique"):
        parts.append(f"Technique: {_stringify_value(t2['rule_mitre_technique'])}.")
    if t2.get("rule_mitre_tactic"):
        parts.append(f"Tactic: {_stringify_value(t2['rule_mitre_tactic'])}.")
    if t2.get("rule_mitre_id"):
        parts.append(f"MITRE: {_stringify_value(t2['rule_mitre_id'])}.")
    if t2.get("src_user"):
        parts.append(f"Source user: {t2['src_user']}.")
    if t2.get("dst_user"):
        parts.append(f"Target user: {t2['dst_user']}.")
    if t3.get("command"):
        parts.append(f"Command: {t3['command']}.")

    return " ".join(parts) if parts else "No IOC context extracted from payload."


def _deep_get(payload: dict, *path: str, default: Any = None) -> Any:
    current: Any = payload
    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def _extract_first_malware_name(payload: dict) -> Any:
    virustotal = _deep_get(payload, "data", "virustotal", default={})
    if not isinstance(virustotal, dict):
        return None
    for key, value in virustotal.items():
        if key.startswith("malware") and isinstance(value, dict) and value.get("name"):
            return value.get("name")
    return None


def _has_value(value: Any) -> bool:
    return value not in (None, "", [], {})


def _drop_empty(data: dict) -> dict:
    return {k: v for k, v in data.items() if _has_value(v)}


def _stringify_value(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return str(value)


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