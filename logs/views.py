"""
logs/views.py

Endpoints:
  POST /api/logs/ingest/                  — Wazuh Integrator webhook (real-time)
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
)
from .services.ingest_service import process_integrator_payload
from .services.opensearch_service import (
    search_alerts,
    search_alerts_by_iocs,
    get_top_agents,
    get_rule_level_distribution,
    check_connection,
)



logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# 1. Wazuh Integrator Webhook  (real-time push)
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
            # Extract IOCs and context, construct retrieval query, and (optionally) persist high-severity alerts.
            payload_result = process_integrator_payload(payload, remote_ip=remote_ip)
            logger.info("Wazuh ingest processed result: %s", json.dumps(payload_result, default=str))

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
                    logger.info("LLM narrative generated: %s", llm_narrative)
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


# ---------------------------------------------------------------------------
# 2. Stored Alerts (Django DB — high severity only)
# ---------------------------------------------------------------------------

class AlertListView(ListAPIView):
    """
    GET /api/logs/alerts/
    Query params:
        min_level=10          filter by minimum rule level
        agent_id=001
        agent_name=web-server
        is_acknowledged=false
        ordering=-alert_timestamp
        search=ssh brute force
    """
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_fields = ["rule_level", "agent_id", "agent_name", "is_acknowledged"]
    search_fields = ["rule_description", "agent_name", "wazuh_rule_id"]
    ordering_fields = ["alert_timestamp", "rule_level", "received_at"]
    ordering = ["-alert_timestamp"]

    def get_queryset(self):
        qs = Alert.objects.select_related("acknowledged_by")
        min_level = self.request.query_params.get("min_level")
        if min_level:
            qs = qs.filter(rule_level__gte=int(min_level))
        return qs


class AlertDetailView(RetrieveAPIView):
    """GET /api/logs/alerts/{id}/"""
    serializer_class = AlertSerializer
    permission_classes = [IsAuthenticated]
    queryset = Alert.objects.select_related("acknowledged_by")


class AlertAcknowledgeView(APIView):
    """
    PATCH /api/logs/alerts/{pk}/acknowledge/
    Body: { "is_acknowledged": true, "notes": "Investigated, false positive" }
    """
    permission_classes = [AllowAny]

    def patch(self, request, pk):
        try:
            alert = Alert.objects.get(pk=pk)
        except Alert.DoesNotExist:
            return Response({"error": "Alert not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = AlertAcknowledgeSerializer(alert, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save(
                acknowledged_by=request.user,
                acknowledged_at=timezone.now(),
            )
            return Response(AlertSerializer(alert).data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# ---------------------------------------------------------------------------
# 3. OpenSearch Query Views (historical search + reasoning)
# ---------------------------------------------------------------------------

class OpenSearchQueryView(APIView):
    """
    GET /api/logs/search/
    Query params:
        q=ssh failed login       full-text search
        min_level=7
        max_level=15
        agent_id=001
        agent_name=web-server
        rule_id=5710
        rule_groups=authentication,sshd   (comma-separated)
        from=2024-05-01T00:00:00
        to=2024-05-31T23:59:59
        size=50
        sort_by=timestamp
        sort_order=desc
    """
    permission_classes = [AllowAny]

    def get(self, request):
        params = request.query_params

        rule_groups = None
        if params.get("rule_groups"):
            rule_groups = [g.strip() for g in params["rule_groups"].split(",")]

        from_dt = _parse_dt(params.get("from"))
        to_dt = _parse_dt(params.get("to"))

        try:
            result = search_alerts(
                query_string=params.get("q"),
                min_level=int(params.get("min_level", 0)),
                max_level=int(params.get("max_level", 15)),
                agent_id=params.get("agent_id"),
                agent_name=params.get("agent_name"),
                rule_id=params.get("rule_id"),
                rule_groups=rule_groups,
                from_dt=from_dt,
                to_dt=to_dt,
                size=int(params.get("size", 100)),
                sort_by=params.get("sort_by", "timestamp"),
                sort_order=params.get("sort_order", "desc"),
            )
            serializer = OpenSearchAlertSerializer(result["hits"], many=True)
            return Response({
                "total": result["total"],
                "count": len(result["hits"]),
                "results": serializer.data,
            })
        except Exception as e:
            logger.error(f"OpenSearch query error: {e}", exc_info=True)
            return Response(
                {"error": "Search failed", "detail": str(e)},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )


class OpenSearchTopAgentsView(APIView):
    """
    GET /api/logs/search/top-agents/?size=10&from=2024-05-01T00:00:00
    Returns top agents by alert count from the Wazuh Indexer.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        from_dt = _parse_dt(request.query_params.get("from"))
        size = int(request.query_params.get("size", 10))
        try:
            data = get_top_agents(size=size, from_dt=from_dt)
            return Response({"results": data})
        except Exception as e:
            logger.error(f"Top agents query error: {e}", exc_info=True)
            return Response({"error": str(e)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


class OpenSearchLevelDistributionView(APIView):
    """
    GET /api/logs/search/level-distribution/?from=2024-05-01T00:00:00
    Returns alert count per severity level.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from_dt = _parse_dt(request.query_params.get("from"))
        try:
            data = get_rule_level_distribution(from_dt=from_dt)
            return Response({"results": data})
        except Exception as e:
            logger.error(f"Level distribution error: {e}", exc_info=True)
            return Response({"error": str(e)}, status=status.HTTP_503_SERVICE_UNAVAILABLE)


# ---------------------------------------------------------------------------
# 4. Health check
# ---------------------------------------------------------------------------

@api_view(["GET"])
@permission_classes([IsAuthenticated])
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