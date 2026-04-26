"""
logs/views.py

Endpoints:
  POST /api/logs/ingest/                  — Wazuh Integrator webhook (real-time)
    POST /api/logs/nl-query/                — Natural language query -> correlation + narrative
  GET  /api/logs/alerts/                  — List stored high-severity alerts (DB)
  GET  /api/logs/alerts/{id}/             — Single alert detail
  PATCH /api/logs/alerts/{id}/acknowledge/ — Acknowledge an alert
  GET  /api/logs/search/                  — Query OpenSearch (historical/full)
  GET  /api/logs/search/top-agents/       — Top agents by alert count (OpenSearch)
  GET  /api/logs/search/level-distribution/ — Alert counts per rule level
  GET  /api/logs/health/                  — OpenSearch connection health check
"""

import json
import logging

from django.conf import settings
from django.utils import timezone
from django.utils.dateparse import parse_datetime

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.generics import ListAPIView, RetrieveAPIView
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework.filters import SearchFilter, OrderingFilter

from alerts.services.analysis_notification_service import notify_client_analysis_complete
from ai.service import GeminiAIService
from knowledge_base.services.file_summary_service import search_similar_summaries
from .models import Alert
from .serializers import (
    AlertSerializer,
    AlertAcknowledgeSerializer,
    OpenSearchAlertSerializer,
    NaturalLanguageCorrelationQueryRequestSerializer,
)
from .services.ingest_service import extract_iocs, process_integrator_payload, build_llm_story_skeleton
from .services.noise_filter import should_exclude_query
from .services.opensearch_service import (
    search_alerts,
    search_alerts_by_iocs,
    build_attack_sessions,
    get_top_agents,
    get_rule_level_distribution,
    check_connection,
)



logger = logging.getLogger(__name__)

HARD_LIMITS = {
    "max_raw_events_to_correlation": 10_000,
    "max_events_to_llm": 150,
    "min_rule_level": 3,
    "max_time_range_minutes": 60,
}

BROAD_QUERY_SUGGESTIONS = [
    "Filter by severity (level >= 7)",
    "Filter by specific agent or host",
    "Filter by rule group (authentication, malware, etc.)",
    "Narrow time range to under 10 minutes",
]


# ---------------------------------------------------------------------------
#  Wazuh Integrator Webhook  (real-time push)
# ---------------------------------------------------------------------------

class IntegratorIngestView(APIView):
    """
    Receives POST from the Wazuh Integrator.
    No auth required at this layer — protect via network firewall / secret header instead.

    Wazuh integrator config (custom-integrations):
        <hook_url>http://your-django-server/api/logs/ingest/</hook_url>
    """
    permission_classes = [AllowAny]

    def post(self, request):
        remote_ip = _get_client_ip(request)
        payload = request.data

        # Uncomment to log full request context for troubleshooting (be cautious of sensitive data):
        # _log_ingest_request(request=request, remote_ip=remote_ip, payload=payload)

        if not payload:
            return Response({"error": "Empty payload"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            iocs = extract_iocs(payload)
            # Check query-level noise filter before doing any further processing or lookups.
            excluded, reason = should_exclude_query(iocs)
            if excluded:
                logger.info("Wazuh ingest excluded by shield: %s", reason)
                return Response(
                    {
                        "status": "excluded",
                        "reason": reason,
                    },
                    status=status.HTTP_200_OK,
                )

            # Extract IOCs and context, construct retrieval query, and (optionally) persist high-severity alerts.
            payload_result = process_integrator_payload(payload, remote_ip=remote_ip)
            # logger.info("Wazuh ingest processed result: %s", json.dumps(payload_result, default=str))

            rag_query = payload_result.get("constructed_query")
            rag_context = {
                "query": rag_query,
                "total_results": 0,
                "results": [],
            }
            if rag_query:
                try:
                    rag_matches = search_similar_summaries(query=rag_query, top_k=2)
                    rag_context["results"] = [
                        {
                            "id": item.id,
                            "title": item.title,
                            "source_file_name": item.source_file_name,
                            "source_url": item.source_url,
                            "file_kind": item.file_kind,
                            "summary_excerpt": item.summary_excerpt,
                            "metadata": item.metadata,
                        }
                        for item in rag_matches
                    ]
                    rag_context["total_results"] = len(rag_context["results"])
                except Exception as rag_exc:
                    logger.warning("RAG summary retrieval failed: %s", rag_exc, exc_info=True)
                    rag_context["error"] = str(rag_exc)

            payload_result["rag_context"] = rag_context

            llm_narrative = None
            try:
                trigger_alert = _build_trigger_alert_for_llm(payload_result)
                session = _pick_session_for_llm(payload_result)
                if session:
                    llm_narrative = GeminiAIService().generate_security_event_narrative(
                        trigger_alert=trigger_alert,
                        attack_session=session,
                        rag_context=rag_context,
                    )
                    # logger.info("LLM narrative generated: %s", llm_narrative)
                else:
                    logger.info("LLM narrative skipped: no eligible session in llm_story_skeleton")

                
            except Exception as llm_exc:
                logger.warning("LLM narrative generation failed: %s", llm_exc, exc_info=True)

            if llm_narrative:
                payload_result["llm_narrative"] = llm_narrative

            notification_result = notify_client_analysis_complete(
                payload_result=payload_result,
                llm_narrative=llm_narrative,
            )
            payload_result["analysis_notification"] = notification_result
            logger.info("Client analysis notification result: %s", json.dumps(notification_result, default=str))

    
            return Response(payload_result, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Ingest error: {e}", exc_info=True)
            return Response(
                {"error": "Failed to process alert"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class NaturalLanguageCorrelationQueryView(APIView):
    """Compile a natural-language query and run IOC correlation + narrative generation."""

    permission_classes = [AllowAny]

    def post(self, request):
        serializer = NaturalLanguageCorrelationQueryRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        query_text = serializer.validated_data["query"]
        strict_mode = bool(getattr(settings, "NL_QUERY_STRICT_MODE", True))

        try:
            ai_service = GeminiAIService()
            compiled_query = ai_service.compile_natural_language_query(query_text)
            iocs = _build_iocs_from_compiled_query(compiled_query)

            time_cfg = compiled_query.get("time") or {}
            from_dt = None
            to_dt = None
            hours_back = 1.0

            if time_cfg.get("type") == "absolute":
                from_dt = _parse_dt(time_cfg.get("start"))
                to_dt = _parse_dt(time_cfg.get("end"))
            else:
                try:
                    minutes = float(time_cfg.get("last_minutes") or 60)
                    if minutes <= 0:
                        minutes = 60
                except (TypeError, ValueError):
                    minutes = 60
                hours_back = max(minutes / 60.0, 1.0 / 60.0)

            scope_result = _scope_guard_for_nl_query(
                compiled_query=compiled_query,
                iocs=iocs,
                from_dt=from_dt,
                to_dt=to_dt,
                hours_back=hours_back,
                strict_mode=strict_mode,
            )
            if scope_result.get("blocked"):
                return Response(
                    {
                        "query": query_text,
                        "compiled_query": compiled_query,
                        "scope_guard": scope_result,
                    },
                    status=status.HTTP_200_OK,
                )

            correlated = search_alerts_by_iocs(
                iocs=iocs,
                size=100,
                hours_back=hours_back,
                from_dt=from_dt,
                to_dt=to_dt,
                min_rule_level=HARD_LIMITS["min_rule_level"],
            )

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

            deduplicated_for_llm = (correlated["deduplicated"] or [])[: HARD_LIMITS["max_events_to_llm"]]

            attack_sessions = build_attack_sessions(
                deduplicated=deduplicated_for_llm,
                tactics_progression=correlated["tactics_progression"],
            )
            llm_story_skeleton = build_llm_story_skeleton(attack_sessions, iocs=iocs)

            payload_result = {
                "stored": False,
                "alert_id": None,
                "iocs": iocs,
                "constructed_query": query_text,
                "correlation": correlation,
                "attack_sessions": attack_sessions,
                "llm_story_skeleton": llm_story_skeleton,
            }

            rag_context = {
                "query": query_text,
                "total_results": 0,
                "results": [],
            }
            try:
                rag_matches = search_similar_summaries(query=query_text, top_k=2)
                rag_context["results"] = [
                    {
                        "id": item.id,
                        "title": item.title,
                        "source_file_name": item.source_file_name,
                        "source_url": item.source_url,
                        "file_kind": item.file_kind,
                        "summary_excerpt": item.summary_excerpt,
                        "metadata": item.metadata,
                    }
                    for item in rag_matches
                ]
                rag_context["total_results"] = len(rag_context["results"])
            except Exception as rag_exc:
                logger.warning("RAG summary retrieval failed for nl-query: %s", rag_exc, exc_info=True)
                rag_context["error"] = str(rag_exc)

            payload_result["rag_context"] = rag_context

            llm_narrative = None
            try:
                trigger_alert = _build_trigger_alert_for_llm(payload_result)
                session = _pick_session_for_llm(payload_result)
                if session:
                    llm_narrative = ai_service.generate_security_event_narrative(
                        trigger_alert=trigger_alert,
                        attack_session=session,
                        rag_context=rag_context,
                    )
                else:
                    logger.info("LLM narrative skipped for nl-query: no eligible session")
            except Exception as llm_exc:
                logger.warning("LLM narrative generation failed for nl-query: %s", llm_exc, exc_info=True)

            if llm_narrative:
                payload_result["llm_narrative"] = llm_narrative

            return Response(
                {
                    "query": query_text,
                    "compiled_query": compiled_query,
                    "scope_guard": {
                        "blocked": False,
                        "estimated": scope_result.get("estimated"),
                        "limits": HARD_LIMITS,
                        "strict_mode": strict_mode,
                    },
                    **payload_result,
                },
                status=status.HTTP_200_OK,
            )
        except Exception as exc:
            logger.error("Natural language correlation query failed: %s", exc, exc_info=True)
            return Response(
                {"error": "Failed to process natural language query"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

# ---------------------------------------------------------------------------
#  Health check
# ---------------------------------------------------------------------------

@api_view(["GET"])
@permission_classes([AllowAny])
def health_check(request):
    """GET /api/logs/health/"""
    opensearch_ok = check_connection()
    return Response({
        "status": "ok" if opensearch_ok else "degraded",
        "opensearch": "connected" if opensearch_ok else "unreachable",
    })


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_client_ip(request):
    x_forwarded = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def _parse_dt(value):
    if not value:
        return None
    try:
        dt = parse_datetime(value)
        if dt and timezone.is_naive(dt):
            dt = timezone.make_aware(dt)
        return dt
    except Exception:
        return None


def _log_ingest_request(request, remote_ip, payload):
    """Log full webhook request context for troubleshooting."""
    try:
        raw_body = request.body.decode("utf-8", errors="replace") if request.body else ""
    except Exception:
        raw_body = "<unavailable>"

    request_snapshot = {
        "method": request.method,
        "path": request.path,
        "query_params": dict(request.query_params),
        "remote_ip": remote_ip,
        "content_type": request.content_type,
        "headers": dict(request.headers),
        "raw_body": raw_body,
        "parsed_payload": payload,
    }

    logger.info(
        "Wazuh ingest request received: %s",
        json.dumps(request_snapshot, default=str),
    )


def _build_iocs_from_compiled_query(compiled_query):
    """Map compiled nl-query JSON into IOC tiers consumed by correlation search."""
    filters = (compiled_query or {}).get("filters") or {}
    return {
        "tier_1": {
            "agent_name": filters.get("agent_name"),
            "rule_groups": [],
        },
        "tier_2": {
            "src_user": filters.get("src_user"),
            "src_ip": filters.get("src_ip"),
        },
        "tier_3": {},
    }


def _scope_guard_for_nl_query(compiled_query, iocs, from_dt, to_dt, hours_back, strict_mode=True):
    """Block overly broad natural-language queries before heavy correlation + LLM work."""
    filters = ((compiled_query or {}).get("filters") or {}) if isinstance(compiled_query, dict) else {}
    has_filter = any(
        filters.get(key)
        for key in ("src_user", "agent_name", "src_ip")
    )

    time_cfg = ((compiled_query or {}).get("time") or {}) if isinstance(compiled_query, dict) else {}
    if time_cfg.get("type") == "absolute" and from_dt and to_dt:
        span_minutes = (to_dt - from_dt).total_seconds() / 60.0
    else:
        span_minutes = (float(hours_back) if hours_back else 1.0) * 60.0

    if strict_mode and span_minutes > HARD_LIMITS["max_time_range_minutes"]:
        return {
            "blocked": True,
            "reason": (
                f"Requested time range is about {round(span_minutes, 1)} minutes, "
                f"which exceeds the {HARD_LIMITS['max_time_range_minutes']}-minute maximum."
            ),
            "suggestions": BROAD_QUERY_SUGGESTIONS,
            "strict_mode": strict_mode,
        }

    if strict_mode and not has_filter:
        return {
            "blocked": True,
            "reason": "Query is too broad; add at least one filter (src_user, agent_name, or src_ip).",
            "suggestions": BROAD_QUERY_SUGGESTIONS,
            "strict_mode": strict_mode,
        }

    estimate = search_alerts_by_iocs(
        iocs=iocs,
        size=0,
        hours_back=hours_back,
        from_dt=from_dt,
        to_dt=to_dt,
        min_rule_level=HARD_LIMITS["min_rule_level"],
    )
    estimated = int(estimate.get("total") or 0)

    if strict_mode and estimated > HARD_LIMITS["max_raw_events_to_correlation"]:
        return {
            "blocked": True,
            "reason": f"Query matches ~{estimated} events. Add filters to continue.",
            "suggestions": BROAD_QUERY_SUGGESTIONS,
            "estimated": estimated,
            "strict_mode": strict_mode,
        }

    return {
        "blocked": False,
        "estimated": estimated,
        "strict_mode": strict_mode,
    }


def _build_trigger_alert_for_llm(payload_result):
    """Extract trigger-alert fields for AI narrative prompt input."""
    iocs = payload_result.get("iocs", {})
    tier_1 = iocs.get("tier_1", {})
    tier_2 = iocs.get("tier_2", {})
    tier_3 = iocs.get("tier_3", {})
    return {
        "rule_description": tier_1.get("rule_description"),
        "rule_level": tier_1.get("rule_level"),
        "timestamp": tier_1.get("timestamp"),
        "src_user": tier_2.get("src_user"),
        "dst_user": tier_2.get("dst_user"),
        "command": tier_3.get("command"),
        "mitre_technique": tier_2.get("rule_mitre_technique"),
        "mitre_tactic": tier_2.get("rule_mitre_tactic"),
    }


def _pick_session_for_llm(payload_result):
    """Pick the highest-confidence, highest-severity session for narrative generation."""
    sessions = ((payload_result.get("llm_story_skeleton") or {}).get("sessions") or [])
    if not sessions:
        return None

    confidence_rank = {"high": 3, "medium": 2, "low": 1}

    def session_key(session):
        severity = ((session.get("severity") or {}).get("max_level") or 0)
        confidence = ((session.get("severity") or {}).get("confidence") or "").lower()
        return (confidence_rank.get(confidence, 0), severity)

    return sorted(sessions, key=session_key, reverse=True)[0]