"""
knowledge_base/services/embedding_service.py

Generates vector embeddings using the Gemini Embedding API.

Model: models/text-embedding-004
Dimensions: 768
Docs: https://ai.google.dev/gemini-api/docs/embeddings

pip install google-generativeai
"""

import logging
import time
from typing import List

import google.genai as genai
from django.conf import settings

logger = logging.getLogger(__name__)

# Gemini embedding model
EMBEDDING_MODEL = "models/text-embedding-004"
EMBEDDING_DIMENSIONS = 768

# Rate limiting — Gemini free tier allows 1500 requests/min
# Add a small delay between batch calls to be safe
BATCH_DELAY_SECONDS = 0.1


def _get_client():
    """Configure and return Gemini client."""
    genai.configure(api_key=settings.GEMINI_API_KEY)
    return genai


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
        result = genai.embed_content(
            model=EMBEDDING_MODEL,
            content=text,
            task_type=task_type,
        )
        return result["embedding"]

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
            result = genai.embed_content(
                model=EMBEDDING_MODEL,
                content=text,
                task_type=task_type,
            )
            embeddings.append(result["embedding"])
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