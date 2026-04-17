import logging

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
import google.genai as genai


logger = logging.getLogger(__name__)


class GeminiAIService:
	"""Service class responsible for Gemini AI processing."""

	STRICT_SECURITY_JSON_SCHEMA = """{
"what_happened": "string",

"attack_progression": [
"step 1 description",
"step 2 description"
],

"related_events": [
{
"event": "string",
"count": number,
"description": "string"
}
],

"ai_assessment": {
"severity": "low | medium | high | critical",
"confidence": "low | medium | high",
"likely_intent": "string",
"was_successful": true | false | "unknown",
"summary": "short risk summary"
},

"recommended_actions": [
"action 1",
"action 2"
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

	def build_security_event_prompt(self, trigger_alert, attack_session):
		"""Build a strict JSON-output prompt for cybersecurity narrative analysis."""
		if not isinstance(trigger_alert, dict):
			raise ValueError("trigger_alert must be a dictionary.")
		if not isinstance(attack_session, dict):
			raise ValueError("attack_session must be a dictionary.")

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

		time_window = attack_session.get("time_window") or {}
		severity = attack_session.get("severity") or {}

		return f"""You are a cybersecurity analyst.

Analyze the security event and correlated activity below.

Your task is to return a STRICT JSON object following the exact schema provided. Do NOT include explanations outside the JSON. Do NOT add extra fields.

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

Attack Chain:
{_list_block(attack_session.get("attack_chain"))}

MITRE Techniques:
{_list_block(attack_session.get("mitre_ids"))}

Observed Events:
{_list_block(attack_session.get("event_summary"))}

---

[OUTPUT FORMAT - STRICT JSON]

{self.STRICT_SECURITY_JSON_SCHEMA}

---

[INSTRUCTIONS]

* Base your answer ONLY on the provided data
* Do NOT hallucinate missing steps
* If information is uncertain, state "unknown"
* Keep explanations concise but clear
* Ensure valid JSON (no trailing commas, no comments)
"""

	def generate_security_event_narrative(self, trigger_alert, attack_session):
		"""Build the security-analysis prompt and send it to Gemini."""
		prompt = self.build_security_event_prompt(
			trigger_alert=trigger_alert,
			attack_session=attack_session,
		)
		return self.generate_content(prompt)
