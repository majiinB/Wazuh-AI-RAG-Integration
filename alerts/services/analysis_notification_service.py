"""Helpers for notifying a client application when analysis completes."""

import logging

import requests
from django.conf import settings
from django.utils import timezone


logger = logging.getLogger(__name__)


def build_analysis_notification_payload(payload_result: dict, llm_narrative: str = None) -> dict:
    """Build a compact payload suitable for a frontend callback."""
    iocs = payload_result.get("iocs", {})
    trigger = iocs.get("tier_1", {})
    session = (payload_result.get("llm_story_skeleton") or {}).get("sessions", [])

    selected_session = session[0] if session else {}
    return {
        "event_type": "analysis_complete",
        "generated_at": timezone.now().isoformat(),
        "trigger_alert": {
            "rule_description": trigger.get("rule_description"),
            "rule_level": trigger.get("rule_level"),
            "timestamp": trigger.get("timestamp"),
            "agent_name": trigger.get("agent_name"),
            "decoder_name": trigger.get("decoder_name"),
        },
        "attack_session": {
            "actor": selected_session.get("actor"),
            "host": selected_session.get("host"),
            "confidence": (selected_session.get("severity") or {}).get("confidence"),
            "max_level": (selected_session.get("severity") or {}).get("max_level"),
            "attack_chain": selected_session.get("attack_chain") or [],
            "event_summary": selected_session.get("event_summary") or [],
        },
        "llm_narrative": llm_narrative,
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