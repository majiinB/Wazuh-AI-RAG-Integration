"""
logs/services/opensearch_service.py

Handles all direct queries to the Wazuh Indexer (OpenSearch).
Used for search, filtering, and AI reasoning over historical logs.

Requires:
    pip install opensearch-py

Settings expected in Django settings.py:
    WAZUH_INDEXER = {
        "HOST": "192.168.x.x",      # your Wazuh Indexer IP
        "PORT": 9200,
        "USER": "admin",
        "PASSWORD": "your_password",
        "USE_SSL": True,
        "VERIFY_CERTS": False,       # set True in production with proper certs
        "INDEX": "wazuh-alerts-*",
    }
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from django.conf import settings
from opensearchpy import OpenSearch, OpenSearchException

logger = logging.getLogger(__name__)


def _get_client() -> OpenSearch:
    """Create and return an OpenSearch client using Django settings."""
    cfg = settings.WAZUH_INDEXER
    return OpenSearch(
        hosts=[{"host": cfg["HOST"], "port": cfg["PORT"]}],
        http_auth=(cfg["USER"], cfg["PASSWORD"]),
        use_ssl=cfg.get("USE_SSL", True),
        verify_certs=cfg.get("VERIFY_CERTS", False),
        ssl_show_warn=False,
    )


def search_alerts(
    query_string: Optional[str] = None,
    min_level: int = 0,
    max_level: int = 15,
    agent_id: Optional[str] = None,
    agent_name: Optional[str] = None,
    rule_id: Optional[str] = None,
    rule_groups: Optional[list] = None,
    from_dt: Optional[datetime] = None,
    to_dt: Optional[datetime] = None,
    size: int = 100,
    sort_by: str = "timestamp",
    sort_order: str = "desc",
) -> dict:
    """
    Query the Wazuh Indexer with flexible filters.

    Returns:
        {
            "total": int,
            "hits": [ { ...alert fields... }, ... ]
        }
    """
    client = _get_client()
    index = settings.WAZUH_INDEXER.get("INDEX", "wazuh-alerts-*")

    must_clauses = []
    filter_clauses = []

    # Full-text search
    if query_string:
        must_clauses.append({"query_string": {"query": query_string}})

    # Rule level range
    filter_clauses.append({
        "range": {
            "rule.level": {"gte": min_level, "lte": max_level}
        }
    })

    # Agent filters
    if agent_id:
        filter_clauses.append({"term": {"agent.id": agent_id}})
    if agent_name:
        filter_clauses.append({"match": {"agent.name": agent_name}})

    # Rule filters
    if rule_id:
        filter_clauses.append({"term": {"rule.id": rule_id}})
    if rule_groups:
        filter_clauses.append({"terms": {"rule.groups": rule_groups}})

    # Time range
    time_range = {}
    if from_dt:
        time_range["gte"] = from_dt.astimezone(timezone.utc).isoformat()
    if to_dt:
        time_range["lte"] = to_dt.astimezone(timezone.utc).isoformat()
    if time_range:
        filter_clauses.append({"range": {"timestamp": time_range}})

    body = {
        "query": {
            "bool": {
                "must": must_clauses,
                "filter": filter_clauses,
            }
        },
        "sort": [{sort_by: {"order": sort_order}}],
        "size": size,
    }

    try:
        response = client.search(index=index, body=body)
        hits = response["hits"]["hits"]
        total = response["hits"]["total"]["value"]
        return {
            "total": total,
            "hits": [h["_source"] for h in hits],
        }
    except OpenSearchException as e:
        logger.error(f"OpenSearch query failed: {e}")
        raise


def search_alerts_by_iocs(
    iocs: dict,
    size: int = 50,
    hours_back: int = 1,
    exclude_alert_id: str = None
) -> dict:
    """
    Query OpenSearch for alerts correlated with extracted IOC fields.
    
    Improvements over previous version:
    - Boosted should clauses (stronger signals ranked higher)
    - Dynamic minimum_should_match (prevents weak single-field matches)
    - Anchor-first strategy (agent.id heavily boosted as anchor)
    - Better dedup signature (agent + src_user + mitre_tactic, not rule.id)
    - Time-bucketed dedup (5-min buckets prevent cross-incident grouping)
    """
    client = _get_client()
    index = settings.WAZUH_INDEXER.get("INDEX", "wazuh-alerts-*")

    tier_1 = iocs.get("tier_1", {})
    tier_2 = iocs.get("tier_2", {})
    tier_3 = iocs.get("tier_3", {})

    must_clauses = []
    must_not_clauses = []
    should_clauses = []

    # ----------------------------------------------------------------
    # MUST — time window only hard constraint
    # ----------------------------------------------------------------
    must_clauses.append({
        "range": {
            "timestamp": {
                "gte": f"now-{hours_back}h",
                "lte": "now"
            }
        }
    })

    if exclude_alert_id:
        must_not_clauses.append({"term": {"_id": exclude_alert_id}})

    # ----------------------------------------------------------------
    # SHOULD — BOOSTED clauses
    #
    # Boost hierarchy rationale:
    #   5 — src_user: specific human actor, strongest behavioral signal
    #   5 — src_ip: specific external actor, equally strong
    #   4 — agent.id: anchor — same machine, most alerts will share this
    #       boosted high so multi-field matches on same host rank first
    #   3 — dst_user: target account (root, admin) — strong priv esc signal
    #   3 — MITRE technique: cross-rule behavioral correlation
    #   2 — MITRE tactic: broader but still meaningful
    #   2 — rule.groups: alert family correlation
    #   2 — dst_ip: destination correlation (lateral movement)
    #   1 — command: specific tool use, narrows but can be too specific
    #   1 — agent.name: redundant with agent.id but catches name-keyed indices
    # ----------------------------------------------------------------

    # Tier 2 — actor fields (highest boost)
    src_user = tier_2.get("src_user")
    if src_user:
        should_clauses.append({
            "term": {"data.srcuser": {"value": src_user, "boost": 5}}
        })

    src_ip = tier_2.get("src_ip")
    if src_ip:
        should_clauses.append({
            "term": {"data.srcip": {"value": src_ip, "boost": 5}}
        })

    dst_user = tier_2.get("dst_user")
    if dst_user:
        should_clauses.append({
            "term": {"data.dstuser": {"value": dst_user, "boost": 3}}
        })

    dst_ip = tier_2.get("dst_ip")
    if dst_ip:
        should_clauses.append({
            "term": {"data.dstip": {"value": dst_ip, "boost": 2}}
        })

    # MITRE fields — technique stronger than tactic (more specific)
    mitre_ids = tier_2.get("rule_mitre_id")
    if mitre_ids:
        values = mitre_ids if isinstance(mitre_ids, list) else [mitre_ids]
        should_clauses.append({
            "terms": {"rule.mitre.id": values, "boost": 3}
        })

    mitre_techniques = tier_2.get("rule_mitre_technique")
    if mitre_techniques:
        values = mitre_techniques if isinstance(mitre_techniques, list) else [mitre_techniques]
        should_clauses.append({
            "terms": {"rule.mitre.technique": values, "boost": 3}
        })

    mitre_tactics = tier_2.get("rule_mitre_tactic")
    if mitre_tactics:
        values = mitre_tactics if isinstance(mitre_tactics, list) else [mitre_tactics]
        should_clauses.append({
            "terms": {"rule.mitre.tactic": values, "boost": 2}
        })

    # Tier 1 — anchor fields
    agent_id = tier_1.get("agent_id")
    if agent_id:
        should_clauses.append({
            "term": {"agent.id": {"value": str(agent_id), "boost": 4}}
        })

    agent_name = tier_1.get("agent_name")
    if agent_name:
        should_clauses.append({
            "term": {"agent.name": {"value": agent_name, "boost": 1}}
        })

    rule_groups = tier_1.get("rule_groups") or []
    if rule_groups:
        should_clauses.append({
            "terms": {"rule.groups": rule_groups, "boost": 2}
        })

    # TRIGGER RULE — the rule that fired, gets highest boost to surface it first
    # This helps rank the exact triggering alert above adjacent context alerts
    rule_id = tier_1.get("rule_id")
    if rule_id:
        should_clauses.append({
              "term": {"rule.id": {"value": str(rule_id), "boost": 3}}
        })

    # Tier 3 — specific tool use (lowest boost, too narrow to anchor on)
    command = tier_3.get("command")
    if command:
        should_clauses.append({
            "term": {"data.command": {"value": command, "boost": 1}}
        })

    if not should_clauses:
        logger.warning("search_alerts_by_iocs called with no correlatable IOC fields")
        return {
            "total": 0, "hits": [], "unique_event_types": 0,
            "deduplicated": [], "tactics_progression": []
        }

    # ----------------------------------------------------------------
    # DYNAMIC minimum_should_match — prevents AppArmor noise
    #
    # The problem: agent.id alone + rule.groups matches everything on that agent.
    # The solution: Require more fields to align, forcing behavioral correlation.
    #
    # Adaptive strictness: balance between filtering noise and catching attack chains.
    # ----------------------------------------------------------------
    if len(should_clauses) >= 8:
        min_should = 3
    elif len(should_clauses) >= 5:
        min_should = 2
    else:
        min_should = 1

    logger.debug(
        f"search_alerts_by_iocs: {len(should_clauses)} clauses, "
        f"min_should_match={min_should}"
    )

    body = {
        "query": {
            "bool": {
                "must": must_clauses,
                "must_not": must_not_clauses,
                "should": should_clauses,
                "minimum_should_match": min_should
            }
        },
        # Rank by correlation score first so the most relevant events are returned.
        # Timestamp is used only as a tiebreaker among similarly scored hits.
        "sort": [
            {"_score": {"order": "desc"}},
            {"timestamp": {"order": "desc"}},
        ],
        "_source": [
            "timestamp",
            "rule.id", "rule.level", "rule.description", "rule.groups",
            "rule.mitre.id", "rule.mitre.tactic", "rule.mitre.technique",
            "agent.id", "agent.name",
            "data.srcuser", "data.dstuser",
            "data.srcip", "data.dstip",
            "data.command",
            "decoder.name",
            "location"
        ],
        "size": size,
    }

    try:
        response = client.search(index=index, body=body)
        hits = response["hits"]["hits"]
        total = response["hits"]["total"]["value"]
        sources = [h["_source"] for h in hits]

        # ----------------------------------------------------------------
        # FIELD ACCESSOR — handles both dotted keys and nested dicts
        # ----------------------------------------------------------------
        def get_field(alert: dict, dotted_path: str, default=None):
            if dotted_path in alert:
                return alert.get(dotted_path, default)
            current = alert
            for part in dotted_path.split("."):
                if not isinstance(current, dict):
                    return default
                current = current.get(part)
                if current is None:
                    return default
            return current

        # ----------------------------------------------------------------
        # ROLLING WINDOW — groups repeated events by proximity instead of
        # fixed buckets.
        #
        # Why: fixed 5-minute buckets split the same sudo burst when it crosses
        # a boundary. A rolling window keeps adjacent events together as long as
        # the gap between them stays within the configured window.
        # ----------------------------------------------------------------
        def parse_timestamp(timestamp: str):
            if not timestamp:
                return None
            try:
                from datetime import datetime
                ts = timestamp.replace("Z", "+00:00")
                return datetime.fromisoformat(ts)
            except Exception:
                return None

        # ----------------------------------------------------------------
        # DEDUPLICATION SIGNATURE
        #
        # Old: rule.id + agent.id + src_user + command
        # Problem: attacker changing command or triggering different rule
        #          split the same attack into multiple groups.
        #
        # New: agent.id + src_user + mitre_tactic
        # Why: groups by BEHAVIOR (who did what tactic on what machine)
        #      not by exact rule fired or exact command used.
        #      A rolling window prevents the same burst from splitting across
        #      hard bucket boundaries.
        #
        # Edge case — no mitre_tactic (e.g. AppArmor DENIED):
        #      falls back to rule.id so these still group correctly.
        # ----------------------------------------------------------------
        def make_signature(alert: dict) -> str:
            tactics = get_field(alert, "rule.mitre.tactic", []) or []
            tactic_key = ",".join(sorted(tactics)) if tactics else get_field(alert, "rule.id", "")
            return "|".join([
                str(get_field(alert, "agent.id", "")),
                str(get_field(alert, "data.srcuser", "")),
                tactic_key,
            ])

        # Rolling-window grouping requires chronological traversal.
        # Keep query ranking for retrieval, then sort selected hits by time for grouping.
        sources_sorted = sorted(
            sources,
            key=lambda alert: get_field(alert, "timestamp", "") or "",
        )

        window_minutes = 15
        groups: dict = {}

        for alert in sources_sorted:
            sig = make_signature(alert)
            current_ts = parse_timestamp(get_field(alert, "timestamp", ""))

            if sig not in groups:
                groups[sig] = []

            matched_group = None
            if groups[sig] and current_ts:
                previous_group = groups[sig][-1]
                previous_ts = previous_group.get("last_seen_dt")
                if previous_ts:
                    delta_seconds = (current_ts - previous_ts).total_seconds()
                    if delta_seconds <= window_minutes * 60:
                        matched_group = previous_group

            if matched_group:
                matched_group["occurrences"] += 1
                matched_group["last_seen_dt"] = current_ts or matched_group["last_seen_dt"]
                matched_group["last_seen"] = get_field(alert, "timestamp")
                rule_id = get_field(alert, "rule.id")
                if rule_id:
                    matched_group["_rule_ids_seen"].add(rule_id)
            else:
                groups[sig].append({
                    "representative": alert,
                    "first_seen": get_field(alert, "timestamp"),
                    "last_seen": get_field(alert, "timestamp"),
                    "first_seen_dt": current_ts,
                    "last_seen_dt": current_ts,
                    "occurrences": 1,
                    "rule_id": get_field(alert, "rule.id"),
                    "rule_description": get_field(alert, "rule.description"),
                    "rule_level": get_field(alert, "rule.level"),
                    "agent_name": get_field(alert, "agent.name"),
                    "src_user": get_field(alert, "data.srcuser"),
                    "dst_user": get_field(alert, "data.dstuser"),
                    "src_ip": get_field(alert, "data.srcip"),
                    "command": get_field(alert, "data.command"),
                    "mitre_tactic": get_field(alert, "rule.mitre.tactic", []),
                    "mitre_id": get_field(alert, "rule.mitre.id", []),
                    # track unique rules seen within this group
                    # so we can surface "this group spans 3 different rules"
                    "_rule_ids_seen": {get_field(alert, "rule.id")},
                })

        # ----------------------------------------------------------------
        # BUILD OUTPUT
        # ----------------------------------------------------------------
        deduplicated = []
        for sig, group_list in groups.items():
            for group in group_list:
                count = group["occurrences"]
                unique_rules = len(group["_rule_ids_seen"])

                if count == 1:
                    summary = group["rule_description"]
                else:
                    summary = (
                        f"{count} occurrences of: {group['rule_description']}"
                        f" (first: {group['first_seen']}, last: {group['last_seen']})"
                    )

                # flag groups that span multiple rules — strong attack chain signal
                # e.g. "sudo attempt" + "sudo success" both grouped under same actor+tactic
                is_chain = unique_rules > 1

                deduplicated.append({
                    "summary": summary,
                    "occurrences": count,
                    "first_seen": group["first_seen"],
                    "last_seen": group["last_seen"],
                    "rule_id": group["rule_id"],
                    "rule_description": group["rule_description"],
                    "rule_level": group["rule_level"],
                    "agent_name": group["agent_name"],
                    "src_user": group["src_user"],
                    "dst_user": group["dst_user"],
                    "src_ip": group["src_ip"],
                    "command": group["command"],
                    "mitre_tactic": group["mitre_tactic"],
                    "mitre_id": group["mitre_id"],
                    "spans_multiple_rules": is_chain,
                    "unique_rule_count": unique_rules,
                })

        # sort deduplicated by rule_level descending so highest severity first
        deduplicated.sort(key=lambda x: x.get("rule_level") or 0, reverse=True)

        # tactics progression from deduped groups (chronological)
        tactics_seen = []
        # re-sort by first_seen for progression ordering before extracting tactics
        chrono_groups = sorted(
            deduplicated,
            key=lambda x: x.get("first_seen") or ""
        )
        for group in chrono_groups:
            for tactic in group.get("mitre_tactic") or []:
                if tactic not in tactics_seen:
                    tactics_seen.append(tactic)

        # Keep score metadata so ranking can be inspected during debugging.
        ranked_hits = []
        for hit in hits:
            src = hit.get("_source", {})
            ranked_hits.append({
                "score": hit.get("_score"),
                "timestamp": get_field(src, "timestamp"),
                "rule_id": get_field(src, "rule.id"),
                "rule_description": get_field(src, "rule.description"),
                "rule_level": get_field(src, "rule.level"),
                "agent_name": get_field(src, "agent.name"),
                "src_user": get_field(src, "data.srcuser"),
                "dst_user": get_field(src, "data.dstuser"),
                "mitre_tactic": get_field(src, "rule.mitre.tactic", []),
            })

        # Deduplicate ranked hits so repeated alerts don't dominate score debug.
        # Uses the same behavioral signature + rolling window logic as main dedup.
        ranked_groups: dict = {}
        for hit in hits:
            src = hit.get("_source", {})
            score = hit.get("_score") or 0.0
            sig = make_signature(src)
            current_ts = parse_timestamp(get_field(src, "timestamp", ""))

            if sig not in ranked_groups:
                ranked_groups[sig] = []

            matched_group = None
            if ranked_groups[sig] and current_ts:
                previous_group = ranked_groups[sig][-1]
                previous_ts = previous_group.get("last_seen_dt")
                if previous_ts:
                    delta_seconds = (current_ts - previous_ts).total_seconds()
                    if delta_seconds <= window_minutes * 60:
                        matched_group = previous_group

            if matched_group:
                matched_group["occurrences"] += 1
                matched_group["score_sum"] += score
                matched_group["max_score"] = max(matched_group["max_score"], score)
                matched_group["last_seen"] = get_field(src, "timestamp")
                matched_group["last_seen_dt"] = current_ts or matched_group["last_seen_dt"]
            else:
                ranked_groups[sig].append({
                    "occurrences": 1,
                    "score_sum": score,
                    "max_score": score,
                    "first_seen": get_field(src, "timestamp"),
                    "last_seen": get_field(src, "timestamp"),
                    "first_seen_dt": current_ts,
                    "last_seen_dt": current_ts,
                    "rule_id": get_field(src, "rule.id"),
                    "rule_description": get_field(src, "rule.description"),
                    "rule_level": get_field(src, "rule.level"),
                    "agent_name": get_field(src, "agent.name"),
                    "src_user": get_field(src, "data.srcuser"),
                    "dst_user": get_field(src, "data.dstuser"),
                    "mitre_tactic": get_field(src, "rule.mitre.tactic", []),
                })

        ranked_hits_deduplicated = []
        for sig, group_list in ranked_groups.items():
            for group in group_list:
                occurrences = group["occurrences"]
                ranked_hits_deduplicated.append({
                    "max_score": group["max_score"],
                    "avg_score": (group["score_sum"] / occurrences) if occurrences else 0,
                    "occurrences": occurrences,
                    "first_seen": group["first_seen"],
                    "last_seen": group["last_seen"],
                    "rule_id": group["rule_id"],
                    "rule_description": group["rule_description"],
                    "rule_level": group["rule_level"],
                    "agent_name": group["agent_name"],
                    "src_user": group["src_user"],
                    "dst_user": group["dst_user"],
                    "mitre_tactic": group["mitre_tactic"],
                })

        ranked_hits_deduplicated.sort(
            key=lambda x: (x.get("max_score") or 0, x.get("last_seen") or ""),
            reverse=True,
        )

        return {
            "total": total,
            "unique_event_types": len(deduplicated),
            "hits": sources,
            "ranked_hits": ranked_hits,
            "ranked_hits_deduplicated": ranked_hits_deduplicated,
            "deduplicated": deduplicated,
            "tactics_progression": tactics_seen,
            "min_should_match_used": min_should,  # useful for debugging
        }

    except OpenSearchException as e:
        logger.error(f"OpenSearch IOC correlation query failed: {e}")
        raise

def build_attack_sessions(deduplicated: list, tactics_progression: list) -> list:
    """
    Layer 2: Attack Session Grouping.

    Takes the dedup output from search_alerts_by_iocs and groups
    event groups into attack sessions by actor + host.

    One session = one actor on one host within a continuous activity window.
    Multiple sessions can exist for the same actor if there's a long gap
    between activity bursts.

    Returns a list of attack sessions sorted by start_time ascending.
    """

    # ----------------------------------------------------------------
    # MITRE ATT&CK tactic order — used to validate chain progression
    # An observed sequence that follows this order is a confirmed chain.
    # A sequence that skips or reverses is still reported but flagged.
    # ----------------------------------------------------------------
    TACTIC_ORDER = [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact",
    ]

    def tactic_index(tactic: str) -> int:
        try:
            return TACTIC_ORDER.index(tactic)
        except ValueError:
            return 999  # unknown tactic — sort to end

    def parse_ts(ts: Optional[str]) -> Optional[datetime]:
        if not ts:
            return None
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return None

    def confidence_score(session: dict) -> str:
        """
        Simple confidence rating based on what we know about the session.

        HIGH   — has MITRE chain + multiple rules + actor identified
        MEDIUM — has MITRE tactics but single rule or no actor
        LOW    — no MITRE data, only agent-level correlation
        """
        has_actor = bool(session.get("actor"))
        has_chain = len(session.get("attack_chain", [])) >= 2
        has_mitre = bool(session.get("mitre_ids"))
        multi_rule = session.get("total_unique_rules", 0) > 1

        if has_actor and has_chain and multi_rule:
            return "high"
        elif has_mitre and (has_chain or has_actor):
            return "medium"
        else:
            return "low"

    # ----------------------------------------------------------------
    # GROUP by actor + host
    # Key: (agent_name, src_user) — two different users on same host
    # are separate sessions. Same user on two hosts is also separate.
    # ----------------------------------------------------------------
    session_map: dict = {}

    for group in deduplicated:
        actor = group.get("src_user") or "unknown"
        host = group.get("agent_name") or "unknown"
        key = f"{host}|{actor}"

        if key not in session_map:
            session_map[key] = {
                "actor": actor if actor != "unknown" else None,
                "host": host,
                "event_groups": [],
                "all_tactics": [],
                "all_mitre_ids": [],
                "all_rule_ids": set(),
                "start_time": None,
                "end_time": None,
                "total_occurrences": 0,
                "max_severity": 0,
            }

        s = session_map[key]
        s["event_groups"].append(group)
        s["total_occurrences"] += group.get("occurrences", 1)

        # track max severity across all groups in this session
        level = group.get("rule_level") or 0
        if level > s["max_severity"]:
            s["max_severity"] = level

        # accumulate tactics (preserve order of first appearance)
        for tactic in group.get("mitre_tactic") or []:
            if tactic not in s["all_tactics"]:
                s["all_tactics"].append(tactic)

        # accumulate MITRE IDs
        for mid in group.get("mitre_id") or []:
            if mid not in s["all_mitre_ids"]:
                s["all_mitre_ids"].append(mid)

        # accumulate rule IDs
        rule_id = group.get("rule_id")
        if rule_id:
            s["all_rule_ids"].add(rule_id)

        # track session time bounds
        first = parse_ts(group.get("first_seen"))
        last = parse_ts(group.get("last_seen"))

        if first:
            if not s["start_time"] or first < s["start_time"]:
                s["start_time"] = first
        if last:
            if not s["end_time"] or last > s["end_time"]:
                s["end_time"] = last

    # ----------------------------------------------------------------
    # BUILD ATTACK CHAIN per session
    # Sort tactics by their first observed timestamp across event groups,
    # then check if the order follows ATT&CK progression.
    # ----------------------------------------------------------------
    sessions = []

    for key, s in session_map.items():

        # sort event groups chronologically for timeline
        event_groups_sorted = sorted(
            s["event_groups"],
            key=lambda g: g.get("first_seen") or ""
        )

        # build tactic timeline — ordered by first time each tactic was seen
        # not just alphabetically or by MITRE order
        tactic_timeline = []
        for group in event_groups_sorted:
            for tactic in group.get("mitre_tactic") or []:
                if tactic not in tactic_timeline:
                    tactic_timeline.append(tactic)

        # check if the observed tactic order follows ATT&CK progression
        # (allows skips — not every step needs to be present)
        tactic_indices = [tactic_index(t) for t in tactic_timeline]
        is_ordered = all(
            tactic_indices[i] <= tactic_indices[i + 1]
            for i in range(len(tactic_indices) - 1)
        ) if len(tactic_indices) > 1 else True

        # build human-readable event summaries for the timeline
        event_summaries = []
        for group in event_groups_sorted:
            count = group.get("occurrences", 1)
            desc = group.get("rule_description") or "Unknown event"
            level = group.get("rule_level") or 0

            # short human label e.g. "5x PAM: User login failed (lvl 5)"
            label = f"{count}x {desc} (lvl {level})"
            event_summaries.append(label)

        # session duration
        duration_minutes = None
        if s["start_time"] and s["end_time"]:
            delta = s["end_time"] - s["start_time"]
            duration_minutes = round(delta.total_seconds() / 60, 1)

        total_unique_rules = len(s["all_rule_ids"])

        session_obj = {
            "actor": s["actor"],
            "host": s["host"],
            "start_time": s["start_time"].isoformat() if s["start_time"] else None,
            "end_time": s["end_time"].isoformat() if s["end_time"] else None,
            "duration_minutes": duration_minutes,
            "total_occurrences": s["total_occurrences"],
            "max_severity": s["max_severity"],
            "attack_chain": tactic_timeline,       # ordered by first observed
            "chain_follows_attack_order": is_ordered,
            "mitre_ids": s["all_mitre_ids"],
            "total_unique_rules": total_unique_rules,
            "event_groups": event_groups_sorted,   # full dedup groups
            "event_summaries": event_summaries,    # compact for LLM
        }

        # add confidence after building the full session object
        session_obj["confidence"] = confidence_score(session_obj)

        sessions.append(session_obj)

    # sort sessions by start_time — earliest first
    sessions.sort(key=lambda s: s.get("start_time") or "")

    return sessions


def get_alert_by_id(alert_id: str) -> Optional[dict]:
    """Fetch a single alert from the Wazuh Indexer by its _id."""
    client = _get_client()
    index = settings.WAZUH_INDEXER.get("INDEX", "wazuh-alerts-*")
    try:
        body = {
            "query": {"term": {"_id": alert_id}},
            "size": 1,
        }
        response = client.search(index=index, body=body)
        hits = response["hits"]["hits"]
        return hits[0]["_source"] if hits else None
    except OpenSearchException as e:
        logger.error(f"OpenSearch get_by_id failed: {e}")
        raise


def get_top_agents(size: int = 10, from_dt: Optional[datetime] = None) -> list:
    """
    Aggregate: top agents by alert count.
    Useful for dashboards and AI reasoning.
    """
    client = _get_client()
    index = settings.WAZUH_INDEXER.get("INDEX", "wazuh-alerts-*")

    filter_clauses = []
    if from_dt:
        filter_clauses.append({
            "range": {
                "timestamp": {"gte": from_dt.astimezone(timezone.utc).isoformat()}
            }
        })

    body = {
        "query": {"bool": {"filter": filter_clauses}} if filter_clauses else {"match_all": {}},
        "aggs": {
            "top_agents": {
                "terms": {"field": "agent.name", "size": size}
            }
        },
        "size": 0,
    }

    try:
        response = client.search(index=index, body=body)
        buckets = response["aggregations"]["top_agents"]["buckets"]
        return [{"agent": b["key"], "count": b["doc_count"]} for b in buckets]
    except OpenSearchException as e:
        logger.error(f"OpenSearch aggregation failed: {e}")
        raise


def get_rule_level_distribution(from_dt: Optional[datetime] = None) -> list:
    """
    Aggregate: count of alerts per rule level.
    Useful for severity distribution charts and AI context.
    """
    client = _get_client()
    index = settings.WAZUH_INDEXER.get("INDEX", "wazuh-alerts-*")

    filter_clauses = []
    if from_dt:
        filter_clauses.append({
            "range": {
                "timestamp": {"gte": from_dt.astimezone(timezone.utc).isoformat()}
            }
        })

    body = {
        "query": {"bool": {"filter": filter_clauses}} if filter_clauses else {"match_all": {}},
        "aggs": {
            "by_level": {
                "terms": {"field": "rule.level", "size": 15, "order": {"_key": "asc"}}
            }
        },
        "size": 0,
    }

    try:
        response = client.search(index=index, body=body)
        buckets = response["aggregations"]["by_level"]["buckets"]
        return [{"level": b["key"], "count": b["doc_count"]} for b in buckets]
    except OpenSearchException as e:
        logger.error(f"OpenSearch level distribution failed: {e}")
        raise


def check_connection() -> bool:
    """Health check — returns True if the Wazuh Indexer is reachable."""
    try:
        client = _get_client()
        return client.ping()
    except Exception:
        return False