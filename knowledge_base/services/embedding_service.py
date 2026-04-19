"""
knowledge_base/services/embedding_service.py

Generates vector embeddings using the Gemini Embedding API.

Model: models/gemini-embedding-001
Dimensions: 768
Docs: https://ai.google.dev/gemini-api/docs/embeddings

pip install google-generativeai
"""

import logging
import time
from typing import List

import google.genai as genai
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured

logger = logging.getLogger(__name__)

# Gemini embedding model. We request a projected 768-dim vector
# so it matches pgvector fields in this app.
EMBEDDING_MODEL = "models/gemini-embedding-001"
EMBEDDING_MODEL_FALLBACKS = ["gemini-embedding-001", "models/gemini-embedding-001"]
EMBEDDING_DIMENSIONS = 768

# Rate limiting — Gemini free tier allows 1500 requests/min
# Add a small delay between batch calls to be safe
BATCH_DELAY_SECONDS = 0.1

_CLIENT = None


def _get_client():
    """Configure and return Gemini client."""
    global _CLIENT
    if _CLIENT is not None:
        return _CLIENT

    api_key = getattr(settings, "GEMINI_API_KEY", None)
    if not api_key:
        raise ImproperlyConfigured(
            "GEMINI_API_KEY is not configured. Set it in environment variables."
        )

    _CLIENT = genai.Client(api_key=api_key)
    return _CLIENT


def _extract_embedding_values(result):
    values = None

    # New SDK shape: response.embeddings[0].values
    embeddings = getattr(result, "embeddings", None)
    if embeddings:
        first = embeddings[0]
        values = getattr(first, "values", None)

    # Fallback for dict-like shapes.
    if values is None and isinstance(result, dict):
        values = result.get("embedding")

    if not isinstance(values, list):
        raise ValueError("Unexpected embedding payload format.")
    if len(values) != EMBEDDING_DIMENSIONS:
        raise ValueError(
            f"Embedding dimension mismatch: expected {EMBEDDING_DIMENSIONS}, got {len(values)}"
        )
    return values


def _embed_with_fallback(text: str, task_type: str):
    client = _get_client()
    model_candidates = [EMBEDDING_MODEL] + [m for m in EMBEDDING_MODEL_FALLBACKS if m != EMBEDDING_MODEL]
    last_error = None

    for model_name in model_candidates:
        try:
            # Preferred path: request output dimensionality that matches pgvector.
            result = client.models.embed_content(
                model=model_name,
                contents=text,
                config={
                    "task_type": task_type,
                    "output_dimensionality": EMBEDDING_DIMENSIONS,
                },
            )
            return _extract_embedding_values(result)
        except Exception as exc:
            last_error = exc
            logger.warning("Embedding model '%s' failed: %s", model_name, exc)

    raise last_error


def embed_text(text: str, task_type: str = "RETRIEVAL_DOCUMENT") -> List[float]:
    """
    Generate an embedding for a single text string.

    task_type options:
        RETRIEVAL_DOCUMENT  — use when embedding documents to store
        RETRIEVAL_QUERY     — use when embedding a search query
        SEMANTIC_SIMILARITY — use for general similarity comparison

    Returns:
        List of 768 floats
    """
    _get_client()

    try:
        return _embed_with_fallback(text=text, task_type=task_type)
    except Exception as e:
        logger.error(f"Gemini embedding failed: {e}")
        raise


def embed_texts_batch(texts: List[str], task_type: str = "RETRIEVAL_DOCUMENT") -> List[List[float]]:
    """
    Embed multiple texts, one by one with rate limit protection.

    Returns:
        List of embeddings in the same order as input texts
    """
    _get_client()
    embeddings = []

    for i, text in enumerate(texts):
        try:
            embeddings.append(_embed_with_fallback(text=text, task_type=task_type))
            logger.debug(f"Embedded chunk {i + 1}/{len(texts)}")

            # Small delay to respect rate limits
            if i < len(texts) - 1:
                time.sleep(BATCH_DELAY_SECONDS)

        except Exception as e:
            logger.error(f"Failed to embed chunk {i}: {e}")
            raise

    return embeddings


def embed_alert_query(alert_text: str) -> List[float]:
    """
    Embed an alert for RAG search.
    Uses RETRIEVAL_QUERY task type for better search accuracy.
    """
    return embed_text(alert_text, task_type="RETRIEVAL_QUERY")