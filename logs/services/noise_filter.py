import logging
import os
from pathlib import Path
from typing import Optional

import yaml
from django.conf import settings

logger = logging.getLogger(__name__)

_FILTER_CONFIG: Optional[dict] = None


def _resolve_filter_path() -> Path:
    default_path = Path(settings.BASE_DIR) / "config" / "exclude_in_query.yaml"
    env_path = os.getenv("NOISE_FILTER_CONFIG_PATH", "").strip()
    if not env_path:
        return default_path

    configured_path = Path(env_path).expanduser()
    if configured_path.is_absolute():
        return configured_path
    return Path(settings.BASE_DIR) / configured_path


_FILTER_PATH = _resolve_filter_path()


def _load_config() -> dict:
    global _FILTER_CONFIG
    if _FILTER_CONFIG is None:
        try:
            with open(_FILTER_PATH, "r", encoding="utf-8") as f:
                _FILTER_CONFIG = yaml.safe_load(f) or {}
                logger.info("Noise filter config loaded from %s", _FILTER_PATH)
        except FileNotFoundError:
            logger.warning("No noise filter config at %s — skipping", _FILTER_PATH)
            _FILTER_CONFIG = {}
        except Exception as exc:
            logger.warning("Failed loading noise filter config at %s: %s", _FILTER_PATH, exc)
            _FILTER_CONFIG = {}
    return _FILTER_CONFIG


def reload_config():
    global _FILTER_CONFIG
    _FILTER_CONFIG = None
    _load_config()


def build_query_exclusions() -> list[dict]:
    """
    Read the YAML and return OpenSearch must_not clauses
    for all entries marked query_level: true.

    Call this inside search_alerts_by_iocs and extend must_not_clauses.
    """
    config = _load_config()
    if not config:
        return []

    filters = config.get("filters", {})
    must_not = []

    for entry in filters.get("rules", {}).get("ignore_rule_ids", []):
        if entry.get("query_level"):
            must_not.append({"term": {"rule.id": str(entry["id"])}})

    for entry in filters.get("actors", {}).get("ignore_src_users", []):
        if entry.get("query_level"):
            must_not.append({"term": {"data.srcuser": entry["user"]}})

    for entry in filters.get("actors", {}).get("ignore_dst_users", []):
        if entry.get("query_level"):
            must_not.append({"term": {"data.dstuser": entry["user"]}})

    for entry in filters.get("commands", {}).get("ignore_commands", []):
        if entry.get("query_level"):
            must_not.append({"term": {"data.command": entry["command"]}})

    for entry in filters.get("hosts", {}).get("ignore_agent_names", []):
        if entry.get("query_level"):
            must_not.append({"term": {"agent.name": entry["name"]}})

    for entry in filters.get("hosts", {}).get("ignore_agent_ids", []):
        if entry.get("query_level"):
            must_not.append({"term": {"agent.id": str(entry["id"])}})

    logger.debug("Built %d query-level must_not exclusions from YAML", len(must_not))
    return must_not


def should_exclude_query(iocs: dict) -> tuple[bool, str]:
    """
    Evaluate extracted IOC fields against query-level exclusions.

    This is used as an early shield before correlation, RAG, or AI work.
    """
    config = _load_config()
    if not config:
        return False, ""

    filters = config.get("filters", {})
    tier_1 = iocs.get("tier_1", {}) if isinstance(iocs, dict) else {}
    tier_2 = iocs.get("tier_2", {}) if isinstance(iocs, dict) else {}
    tier_3 = iocs.get("tier_3", {}) if isinstance(iocs, dict) else {}

    checks = (
        ("rule_id", str(tier_1.get("rule_id") or "").strip(), filters.get("rules", {}).get("ignore_rule_ids", []), "id"),
        ("src_user", str(tier_2.get("src_user") or "").strip(), filters.get("actors", {}).get("ignore_src_users", []), "user"),
        ("dst_user", str(tier_2.get("dst_user") or "").strip(), filters.get("actors", {}).get("ignore_dst_users", []), "user"),
        ("command", str(tier_3.get("command") or "").strip(), filters.get("commands", {}).get("ignore_commands", []), "command"),
        ("agent_name", str(tier_1.get("agent_name") or "").strip(), filters.get("hosts", {}).get("ignore_agent_names", []), "name"),
        ("agent_id", str(tier_1.get("agent_id") or "").strip(), filters.get("hosts", {}).get("ignore_agent_ids", []), "id"),
    )

    for field_name, current_value, entries, entry_key in checks:
        if not current_value:
            continue

        for entry in entries:
            if not entry.get("query_level"):
                continue

            entry_value = str(entry.get(entry_key) or "").strip()
            if current_value == entry_value:
                reason = entry.get("reason", "")
                if reason:
                    return True, f"{field_name} '{current_value}' matched query-level exclusion — {reason}"
                return True, f"{field_name} '{current_value}' matched query-level exclusion"

    return False, ""


def should_suppress(group: dict) -> tuple[bool, str]:
    """
    Evaluate a deduplicated group against post-retrieval filters.
    Only evaluates entries where query_level: false (or composites).
    query_level: true entries are already excluded at the query.
    """
    config = _load_config()
    if not config:
        return False, ""

    filters = config.get("filters", {})

    rule_id = str(group.get("rule_id") or "")
    src_user = str(group.get("src_user") or "").strip()
    command = str(group.get("command") or "").strip()
    agent_name = str(group.get("agent_name") or "").strip()
    dst_user = str(group.get("dst_user") or "").strip()
    agent_id = str(group.get("agent_id") or "").strip()

    for entry in filters.get("rules", {}).get("ignore_rule_ids", []):
        if not entry.get("query_level") and rule_id == str(entry["id"]):
            return True, f"rule_id {rule_id} — {entry.get('reason', '')}"

    for entry in filters.get("actors", {}).get("ignore_src_users", []):
        if not entry.get("query_level") and src_user == entry["user"]:
            return True, f"src_user '{src_user}' in post-retrieval ignore list"

    for entry in filters.get("actors", {}).get("ignore_dst_users", []):
        if not entry.get("query_level") and dst_user == entry["user"]:
            return True, f"dst_user '{dst_user}' in post-retrieval ignore list"

    for entry in filters.get("commands", {}).get("ignore_commands", []):
        if not entry.get("query_level") and command == entry["command"]:
            return True, f"command '{command}' in post-retrieval ignore list"

    for entry in filters.get("hosts", {}).get("ignore_agent_names", []):
        if not entry.get("query_level") and agent_name == entry["name"]:
            return True, f"agent_name '{agent_name}' in post-retrieval ignore list"

    for entry in filters.get("hosts", {}).get("ignore_agent_ids", []):
        if not entry.get("query_level") and agent_id == str(entry["id"]):
            return True, f"agent_id '{agent_id}' in post-retrieval ignore list"

    for composite in filters.get("composite", []):
        match_all = composite.get("match_all", {})
        name = composite.get("name", "unnamed")
        matched = all(
            str(group.get(field) or "").strip() == str(value)
            for field, value in match_all.items()
        )
        if matched:
            return True, f"composite filter '{name}' matched"

    return False, ""


def apply_noise_filter(deduplicated: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Apply post-retrieval filters to deduplicated alert groups.

    Returns:
        kept       — passes to LLM
        suppressed — audit log only
    """
    kept = []
    suppressed = []

    for group in deduplicated:
        suppress, reason = should_suppress(group)
        if suppress:
            logger.info(
                "Suppressed group: rule_id=%s src_user=%s command=%s | %s",
                group.get("rule_id"),
                group.get("src_user"),
                group.get("command"),
                reason,
            )
            suppressed.append({**group, "_suppressed_reason": reason})
        else:
            kept.append(group)

    return kept, suppressed
