import logging

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
import google.genai as genai


logger = logging.getLogger(__name__)


class GeminiAIService:
	"""Service class responsible for Gemini AI processing."""

	STRICT_SECURITY_JSON_SCHEMA = """{
"what_happened": "string",

"observed_activity": {
  "summary": "factual summary of observed events only — no interpretation",
  "event_timeline": ["event 1", "event 2"],
  "actors_and_targets": {
    "source_user": "string",
    "target_user": "string",
    "affected_hosts": ["host1", "host2"]
  }
},

"interpretation": {
  "possible_explanations": [
    {
      "type": "potentially_malicious",
      "description": "activity pattern consistent with...",
			"mitre_relevance": "TXX.XXX",
			"confidence": "low | moderate | high"
    },
    {
      "type": "benign_alternative",
      "description": "activity could also indicate...",
			"likelihood": "why this explanation is plausible",
			"confidence": "low | moderate | high"
    }
  ]
},

"related_events": [
{
"event": "string",
"count": number,
"description": "string"
}
],

"ai_assessment": {
"severity": "low | medium | high | critical (critical only for confirmed malicious impact)",
"confidence": "low | medium | high",
"confidence_justification": "why this confidence level was assigned; list key signals",
"hypothesis": "statement of observed pattern as hypothesis, NOT conclusion",
"requires_validation": true,
"was_successful": "unknown",
"indicators_of_success": [
	"signal that may indicate successful execution without confirming compromise"
]
},

"recommended_actions": [
"context-specific investigation step tailored to the observed activity"
],

"analyst_guidance": {
	"priority": "case-specific validation priority based on this incident",
	"next_best_action": "most useful immediate validation step for this incident"
},

"questions_for_investigation": [
  {
    "question": "concrete, specific question",
    "why": "what this answer tells us",
    "data_source": "where to look (logs, access patterns, etc.)"
  }
],

"missing_data_for_confidence": [
  "additional signals or context that would increase confidence"
],

"retrieved_references": [
{
"title": "string",
"source_url": "string",
"file_kind": "string"
}
]

}"""

	def __init__(self, model_name=None):
		self.model_name = model_name or getattr(
			settings, "GEMINI_MODEL", "gemini-3-flash-preview"
		)
		self.embedding_model = getattr(
			settings, "GEMINI_EMBEDDING_MODEL", "gemini-embedding-001"
		)
		self.client = None

	def generate_content(self, prompt):
		"""Generate text from a prompt using Gemini."""
		if not prompt or not str(prompt).strip():
			raise ValueError("Prompt cannot be empty.")

		if not getattr(settings, "GEMINI_API_KEY", None):
			raise ImproperlyConfigured(
				"GEMINI_API_KEY is not configured. Set it in environment variables."
			)

		if self.client is None:
			self.client = genai.Client(api_key=settings.GEMINI_API_KEY)

		try:
			response = self.client.models.generate_content(
				model=self.model_name,
				contents=str(prompt).strip(),
			)
			return (response.text or "").strip()
		except Exception:
			logger.exception("Gemini content generation failed")
			raise


	def embed_content(self, text, model_name=None):
		"""Generate embeddings for input text using Gemini."""
		if not text or not str(text).strip():
			raise ValueError("Text cannot be empty.")

		if not getattr(settings, "GEMINI_API_KEY", None):
			raise ImproperlyConfigured(
				"GEMINI_API_KEY is not configured. Set it in environment variables."
			)

		if self.client is None:
			self.client = genai.Client(api_key=settings.GEMINI_API_KEY)

		target_model = model_name or self.embedding_model

		try:
			result = self.client.models.embed_content(
				model=target_model,
				contents=str(text).strip(),
			)

			embeddings = []
			for item in getattr(result, "embeddings", []) or []:
				values = getattr(item, "values", None)
				if values is not None:
					embeddings.append(values)

			if embeddings:
				return embeddings

			return getattr(result, "embeddings", [])
		except Exception:
			logger.exception("Gemini embedding generation failed")
			raise

	def build_security_event_prompt(self, trigger_alert, attack_session, rag_context=None):
		"""Build a strict JSON-output prompt for cybersecurity narrative analysis."""
		if not isinstance(trigger_alert, dict):
			raise ValueError("trigger_alert must be a dictionary.")
		if not isinstance(attack_session, dict):
			raise ValueError("attack_session must be a dictionary.")
		if rag_context is not None and not isinstance(rag_context, dict):
			raise ValueError("rag_context must be a dictionary when provided.")

		def _string(value, fallback="unknown"):
			if value is None:
				return fallback
			text = str(value).strip()
			return text if text else fallback

		def _csv(value):
			if isinstance(value, list):
				clean = [str(v).strip() for v in value if str(v).strip()]
				return ", ".join(clean) if clean else "unknown"
			return _string(value)

		def _list_block(value):
			if isinstance(value, list):
				clean = [str(v).strip() for v in value if str(v).strip()]
				return "\n".join(f"- {item}" for item in clean) if clean else "- unknown"
			text = _string(value)
			return f"- {text}" if text else "- unknown"

		def _rag_block(value):
			items = (value or {}).get("results") or []
			if not items:
				return "- none"

			lines = []
			for item in items:
				title = _string(item.get("title"))
				kind = _string(item.get("file_kind"))
				excerpt = _string(item.get("summary_excerpt"))
				source_url = _string(item.get("source_url"))
				lines.append(
					f"- title={title}; file_kind={kind}; source_url={source_url}; excerpt={excerpt}"
				)
			return "\n".join(lines)

		def _network_block(value):
			if not isinstance(value, dict) or not value:
				return "- none"

			lines = []
			for key in ("agent_ip", "src_ip", "dst_ip"):
				entry = value.get(key)
				if entry:
					lines.append(f"- {key}={_string(entry)}")

			session_source_ips = value.get("session_source_ips") or []
			if session_source_ips:
				lines.append(f"- session_source_ips={_csv(session_source_ips)}")

			return "\n".join(lines) if lines else "- none"

		time_window = attack_session.get("time_window") or {}
		severity = attack_session.get("severity") or {}
		network_context = attack_session.get("network_context") or {}

		return f"""You are a cybersecurity analyst.

Analyze the security event and correlated activity below.

Your task is to return a STRICT JSON object following the exact schema provided. Do NOT include explanations outside the JSON. Do NOT add extra fields.

---

[CRITICAL FRAMING]

You are NOT an intrusion detection system and must NOT assert that an attack definitively occurred.

Your role is to:
- Summarize observed activity based ONLY on the provided structured incident data
- Interpret patterns as POSSIBLE security-relevant behavior, not confirmed attacks
- Express uncertainty clearly using probabilistic or conditional language

Strict language rules:
- DO NOT use: "the attacker did", "the system was compromised", "attack in progress"
- DO use: "activity consistent with", "may indicate", "could suggest", "requires validation"
- Treat all conclusions as working hypotheses, not facts
- Separate observed facts from interpretation

For EVERY potentially malicious interpretation, include at least one plausible benign explanation:
  - Legitimate admin activity or testing
  - Scripted provisioning or automation
  - Misconfiguration or expected system behavior
  - User error or routine maintenance

---

[TRIGGER ALERT]

* Description: {_string(trigger_alert.get("rule_description"))}
* Severity Level: {_string(trigger_alert.get("rule_level"))}
* Timestamp: {_string(trigger_alert.get("timestamp"))}
* Source User: {_string(trigger_alert.get("src_user"))}
* Target User: {_string(trigger_alert.get("dst_user"))}
* Command: {_string(trigger_alert.get("command"))}
* MITRE Technique: {_csv(trigger_alert.get("mitre_technique"))}
* MITRE Tactic: {_csv(trigger_alert.get("mitre_tactic"))}

---

[CORRELATED ATTACK SESSION]

* Actor: {_string(attack_session.get("actor"))}
* Host: {_string(attack_session.get("host"))}

Time Window:

* Start: {_string(time_window.get("start"))}
* End: {_string(time_window.get("end"))}
* Duration: {_string(time_window.get("duration_minutes"))} minutes

Severity:

* Max Alert Level: {_string(severity.get("max_level"))}
* Confidence: {_string(severity.get("confidence"))}

Network Context:

{_network_block(network_context)}

Attack Chain:
{_list_block(attack_session.get("attack_chain"))}

MITRE Techniques:
{_list_block(attack_session.get("mitre_ids"))}

Observed Events:
{_list_block(attack_session.get("event_summary"))}

---

[RETRIEVED KNOWLEDGE CONTEXT]
{_rag_block(rag_context)}

---

[OUTPUT FORMAT - STRICT JSON]

{self.STRICT_SECURITY_JSON_SCHEMA}

---

[INSTRUCTIONS]

1. observed_activity: Summarize ONLY the factual events from the input. No speculation.
2. interpretation: List multiple possible explanations, including at least one potentially_malicious and one benign_alternative hypothesis. Assign confidence (low/moderate/high) to EACH hypothesis.
3. ai_assessment:
   - confidence_justification: Explain WHY you assigned this confidence level. List key signals.
   - hypothesis: Frame as a working hypothesis ("activity pattern suggests...", NOT "attack occurred")
	- requires_validation: Always true unless activity is routine/normal
	- severity must reflect impact x certainty:
	  * suspicious but unconfirmed -> medium or high
	  * strong pattern match + high confidence (still unconfirmed) -> high
	  * confirmed malicious impact only -> critical
	- was_successful must remain "unknown" unless success is directly evidenced; use indicators_of_success for supporting signals.
4. recommended_actions: Frame as investigation steps using neutral language. Prefer phrasing like "review ... to determine whether ...". Include "refer to the references provded" where relevant.
5. analyst_guidance: Provide concise priority and next_best_action focused on validation before escalation, and make both fields specific to this exact case.
6. questions_for_investigation: Provide 4–8 concrete, specific questions an analyst should ask. Make them actionable.
7. missing_data_for_confidence: List what additional context or logs would increase your confidence in this assessment.
8. retrieved_references: Include title and source_url from knowledge base when available.
9. Ensure valid JSON output. Do NOT include any explanatory text outside the JSON object.
10. Use the provided schema EXACTLY. Do NOT add, remove, or rename fields.
11. Do NOT copy placeholder/sample wording from this schema into the final answer; generate incident-specific wording.
12. Avoid role inference from naming conventions (usernames, hostnames, labels) unless explicitly provided in the input data.
13. If retrieved_references exist, acknowledge them naturally in actions/guidance, but do not repeat the same sentence in every item.

---

CONFIDENCE GUIDANCE:

- HIGH: Multiple signals converge on a known attack pattern. Still frame as hypothesis + require validation.
- MEDIUM: Pattern suggests possible malicious activity. Benign explanations are plausible.
- LOW: Insufficient signals. Could be routine activity. Suggest more data before escalation.

TONE: Neutral, analytical, non-alarmist. Empower investigation, not panic.
"""

	def generate_security_event_narrative(self, trigger_alert, attack_session, rag_context=None):
		"""Build the security-analysis prompt and send it to Gemini."""
		prompt = self.build_security_event_prompt(
			trigger_alert=trigger_alert,
			attack_session=attack_session,
			rag_context=rag_context,
		)
		return self.generate_content(prompt)
