import logging

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from google import genai


logger = logging.getLogger(__name__)


class GeminiAIService:
	"""Service class responsible for Gemini AI processing."""

	def __init__(self, model_name=None):
		self.model_name = model_name or getattr(
			settings, "GEMINI_MODEL", "gemini-3-flash-preview"
		)
		self.client = genai.Client()

	def generate_content(self, prompt):
		"""Generate text from a prompt using Gemini."""
		if not prompt or not str(prompt).strip():
			raise ValueError("Prompt cannot be empty.")

		if not getattr(settings, "GEMINI_API_KEY", None):
			raise ImproperlyConfigured(
				"GEMINI_API_KEY is not configured. Set it in environment variables."
			)

		try:
			response = self.client.models.generate_content(
				model=self.model_name,
				contents=str(prompt).strip(),
			)
			return (response.text or "").strip()
		except Exception:
			logger.exception("Gemini content generation failed")
			raise

	def explain_ai_in_few_words(self):
		"""Convenience method mirroring your sample prompt."""
		return self.generate_content("Explain how AI works in a few words")
