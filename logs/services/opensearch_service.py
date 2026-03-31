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