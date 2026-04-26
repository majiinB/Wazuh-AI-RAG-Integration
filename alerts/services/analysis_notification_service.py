"""Helpers for notifying a client application when analysis completes."""

import json
import logging

import requests
from django.conf import settings


logger = logging.getLogger(__name__)


def _parse_incident_payload(llm_narrative):
    """Return a dictionary payload from Gemini JSON narrative output."""
    if isinstance(llm_narrative, dict):
        return llm_narrative

    if not isinstance(llm_narrative, str):
        return None

    text = llm_narrative.strip()
    if not text:
        return None

    if text.startswith("```"):
        # Handle optional fenced output from model responses.
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else None
    except (json.JSONDecodeError, TypeError, ValueError):
        return None


def build_analysis_notification_payload(payload_result: dict, llm_narrative: str = None) -> dict:
    """Build webhook payload in the strict incident schema expected by the client app."""
    incident_payload = _parse_incident_payload(llm_narrative)

    if incident_payload is None:
        incident_payload = _parse_incident_payload(payload_result.get("llm_narrative"))

    if incident_payload is not None:
        incident_payload["iocs"] = payload_result.get("iocs", {})
        return incident_payload

    logger.warning("LLM narrative is unavailable or invalid JSON; sending minimal fallback payload")
    return {
        "what_happened": "Unable to generate structured incident narrative.",
        "observed_activity": {
            "summary": "No structured incident activity was produced.",
            "event_timeline": [],
            "actors_and_targets": {
                "source_user": "unknown",
                "target_user": "unknown",
                "affected_hosts": [],
            },
        },
        "interpretation": {
            "possible_explanations": [],
        },
        "related_events": [],
        "ai_assessment": {
            "severity": "low",
            "confidence": "low",
            "confidence_justification": "Structured AI output was unavailable at notification time.",
            "hypothesis": "No incident hypothesis could be generated from current data.",
            "requires_validation": True,
            "was_successful": "unknown",
            "indicators_of_success": [],
        },
        "recommended_actions": [
            "Review AI generation logs and retry incident narrative generation.",
        ],
        "analyst_guidance": {
            "priority": "Validate AI output pipeline before triage decisions.",
            "next_best_action": "Inspect backend logs for model or parsing errors.",
        },
        "questions_for_investigation": [],
        "missing_data_for_confidence": [
            "Structured incident narrative from AI service.",
        ],
        "retrieved_references": [],
        "iocs": payload_result.get("iocs", {}),
    }


def notify_client_analysis_complete(payload_result: dict, llm_narrative: str = None) -> dict:
    """POST a compact analysis-complete message to the configured client callback URL."""
    callback_url = getattr(settings, "ALERTS_CLIENT_CALLBACK_URL", "")
    timeout = getattr(settings, "ALERTS_CLIENT_CALLBACK_TIMEOUT", 5.0)

    if not callback_url:
        logger.info("Client callback not configured; skipping analysis notification")
        return {
            "sent": False,
            "reason": "callback_url_not_configured",
        }

    payload = build_analysis_notification_payload(
        payload_result=payload_result,
        llm_narrative=llm_narrative,
    )
    logger.info("Sending analysis notification to client: %s", json.dumps(payload, default=str))


    try:
        response = requests.post(callback_url, json=payload, timeout=timeout)
        response.raise_for_status()
        return {
            "sent": True,
            "status_code": response.status_code,
            "callback_url": callback_url,
        }
    except Exception as exc:
        logger.warning("Client callback notification failed: %s", exc, exc_info=True)
        return {
            "sent": False,
            "reason": str(exc),
            "callback_url": callback_url,
        }