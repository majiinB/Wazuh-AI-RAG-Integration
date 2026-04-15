import logging

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
import google.genai as genai


logger = logging.getLogger(__name__)


class GeminiAIService:
	"""Service class responsible for Gemini AI processing."""

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
