import logging
import json
from datetime import datetime, timezone

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
import google.genai as genai


logger = logging.getLogger(__name__)


class GeminiAIService:
	"""Service class responsible for Gemini AI processing."""

	STRICT_QUERY_COMPILER_SCHEMA = """{
	"time": {
		"type": "relative | absolute",
		"last_minutes": "number | null",
		"start": "ISO 8601 string | null",
		"end": "ISO 8601 string | null"
	},
	"filters": {
		"src_user": "string | null",
		"agent_name": "string | null",
		"src_ip": "string | null"
	},
	"intent": ["timeline", "attack_assessment"]
}"""

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

	def build_query_extractor_prompt(self, user_query: str, now_iso: str) -> str:
		"""Build strict JSON compiler prompt for natural-language security queries."""
		return f"""You are a query compiler for a security analytics system.

Your task is to convert a natural language query into STRICT structured JSON.

You MUST follow the schema exactly. Do NOT explain. Do NOT add extra fields. Do NOT output anything except valid JSON.

Current UTC time for temporal normalization: {now_iso}

----------------------------------------
SCHEMA

{self.STRICT_QUERY_COMPILER_SCHEMA}

----------------------------------------
INSTRUCTIONS

1. TIME EXTRACTION

- Convert ALL time expressions into ONE of the following:

A. Relative time:
  - Examples:
    "last 20 minutes"
    "past hour"
    "last 5 mins"
    "past two hours"
  -> Use:
    "type": "relative"
    "last_minutes": <number>

  Rules:
  - Normalize words to numbers
  - Convert hours to minutes
  - Convert seconds to minutes

B. Absolute time:
  - Examples:
    "yesterday"
    "today at 3pm"
    "between 1am and 4am"
  -> Use:
    "type": "absolute"
    "start": ISO 8601 timestamp
    "end": ISO 8601 timestamp

- If no time is specified:
  -> Use:
    "type": "relative"
    "last_minutes": 60

- NEVER leave both relative and absolute populated at the same time.

----------------------------------------
2. FILTER EXTRACTION

Extract the following if present:
- src_user
- agent_name
- src_ip

If not present, set to null.

----------------------------------------
3. INTENT DETECTION

- "timeline" for what happened/activity/logs/events intent.
- "attack_assessment" for malicious/suspicious/attack-assessment intent.
- If both appear, return both.

----------------------------------------
4. NORMALIZATION RULES

- Convert all numbers to numeric form.
- Lowercase all extracted string values.

----------------------------------------
5. STRICT OUTPUT RULES

- Output ONLY valid JSON
- NO explanations
- NO comments
- NO trailing commas
- NO extra keys

----------------------------------------
Now process this user query:
{user_query}
"""

	def compile_natural_language_query(self, user_query: str) -> dict:
		"""Compile natural language into normalized strict query JSON."""
		if not user_query or not str(user_query).strip():
			raise ValueError("user_query cannot be empty")

		now_iso = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
		prompt = self.build_query_extractor_prompt(user_query=str(user_query).strip(), now_iso=now_iso)
		max_attempts = 3
		last_parsed = {}

		for attempt in range(1, max_attempts + 1):
			attempt_prompt = prompt
			if attempt > 1:
				attempt_prompt = (
					f"{prompt}\n\n"
					"Previous output was invalid or schema-noncompliant. "
					"Retry and return only strict valid JSON that exactly matches the schema keys and value types."
				)

			raw = self.generate_content(attempt_prompt)
			if isinstance(raw, str) and raw.strip().startswith("```"):
				lines = raw.strip().splitlines()
				if lines and lines[0].startswith("```"):
					lines = lines[1:]
				if lines and lines[-1].strip().startswith("```"):
					lines = lines[:-1]
				raw = "\n".join(lines).strip()

			try:
				parsed = json.loads(raw)
			except Exception:
				logger.warning("Query compiler attempt %s/%s returned invalid JSON", attempt, max_attempts)
				continue

			last_parsed = parsed
			if self._is_compiled_query_structurally_valid(parsed):
				return self._normalize_compiled_query(parsed)

			logger.warning(
				"Query compiler attempt %s/%s returned schema-invalid JSON",
				attempt,
				max_attempts,
			)

		logger.warning("Query compiler exhausted retries; using normalized safe fallback")
		return self._normalize_compiled_query(last_parsed)

	def _is_compiled_query_structurally_valid(self, data: dict) -> bool:
		"""Validate strict structure before accepting AI-compiled query output."""
		if not isinstance(data, dict):
			return False

		if set(data.keys()) != {"time", "filters", "intent"}:
			return False

		time = data.get("time")
		filters = data.get("filters")
		intent = data.get("intent")

		if not isinstance(time, dict) or set(time.keys()) != {"type", "last_minutes", "start", "end"}:
			return False
		if not isinstance(filters, dict) or set(filters.keys()) != {"src_user", "agent_name", "src_ip"}:
			return False
		if not isinstance(intent, list):
			return False

		time_type = str(time.get("type") or "").strip().lower()
		if time_type not in {"relative", "absolute"}:
			return False

		last_minutes = time.get("last_minutes")
		start = time.get("start")
		end = time.get("end")

		if time_type == "relative":
			try:
				float(last_minutes)
			except (TypeError, ValueError):
				return False
			if start is not None or end is not None:
				return False
		else:
			if last_minutes is not None:
				return False
			if not (isinstance(start, str) and start.strip() and isinstance(end, str) and end.strip()):
				return False

		for field in ("src_user", "agent_name", "src_ip"):
			value = filters.get(field)
			if value is not None and not isinstance(value, str):
				return False

		allowed_intents = {"timeline", "attack_assessment"}
		if not intent:
			return False
		for item in intent:
			if not isinstance(item, str):
				return False
			if item.strip().lower() not in allowed_intents:
				return False

		return True

	def _normalize_compiled_query(self, data: dict) -> dict:
		"""Validate, normalize, and enforce strict query schema defaults."""
		default = {
			"time": {
				"type": "relative",
				"last_minutes": 60,
				"start": None,
				"end": None,
			},
			"filters": {
				"src_user": None,
				"agent_name": None,
				"src_ip": None,
			},
			"intent": ["timeline"],
		}

		if not isinstance(data, dict):
			return default

		time = data.get("time") if isinstance(data.get("time"), dict) else {}
		filters = data.get("filters") if isinstance(data.get("filters"), dict) else {}
		intent = data.get("intent") if isinstance(data.get("intent"), list) else []

		time_type = str(time.get("type") or "").strip().lower()
		if time_type not in {"relative", "absolute"}:
			time_type = "relative"

		last_minutes = None
		if time_type == "relative":
			try:
				last_minutes = float(time.get("last_minutes"))
			except (TypeError, ValueError):
				last_minutes = 60.0
			if last_minutes <= 0:
				last_minutes = 60.0

		start = time.get("start") if time_type == "absolute" else None
		end = time.get("end") if time_type == "absolute" else None
		if time_type == "absolute":
			if not (isinstance(start, str) and start.strip() and isinstance(end, str) and end.strip()):
				time_type = "relative"
				last_minutes = 60.0
				start = None
				end = None

		def _lower_or_none(value):
			if value is None:
				return None
			text = str(value).strip().lower()
			return text if text else None

		allowed_intents = {"timeline", "attack_assessment"}
		normalized_intent = []
		for item in intent:
			value = str(item).strip().lower()
			if value in allowed_intents and value not in normalized_intent:
				normalized_intent.append(value)
		if not normalized_intent:
			normalized_intent = ["timeline"]

		return {
			"time": {
				"type": time_type,
				"last_minutes": last_minutes if time_type == "relative" else None,
				"start": start if time_type == "absolute" else None,
				"end": end if time_type == "absolute" else None,
			},
			"filters": {
				"src_user": _lower_or_none(filters.get("src_user")),
				"agent_name": _lower_or_none(filters.get("agent_name")),
				"src_ip": _lower_or_none(filters.get("src_ip")),
			},
			"intent": normalized_intent,
		}
