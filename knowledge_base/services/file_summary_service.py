"""
knowledge_base/services/file_summary_service.py

Service helpers for storing and embedding file summaries/excerpts for RAG.
"""

import logging

from django.utils import timezone
from pgvector.django import L2Distance

from knowledge_base.models import KnowledgeFileSummary
from knowledge_base.services.embedding_service import embed_text

logger = logging.getLogger(__name__)

EXPECTED_EMBEDDING_DIMS = 768


def _extract_first_embedding(embeddings):
    """Normalize AI service output to one vector."""
    if not embeddings:
        raise ValueError("No embeddings returned by AI service.")

    first = embeddings[0]

    # Defensive fallback if the API client shape changes.
    if hasattr(first, "values"):
        first = list(first.values)

    if not isinstance(first, list):
        raise ValueError("Unexpected embedding format returned by AI service.")

    if len(first) != EXPECTED_EMBEDDING_DIMS:
        raise ValueError(
            f"Embedding dimension mismatch: expected {EXPECTED_EMBEDDING_DIMS}, got {len(first)}"
        )

    return first


def embed_summary_excerpt(text: str):
    """Generate a single embedding vector for a summary/excerpt."""
    values = embed_text(text, task_type="RETRIEVAL_DOCUMENT")
    return _extract_first_embedding([values])


def create_summary_with_embedding(*, title: str, source_file_name: str, source_url: str, file_kind: str, summary_excerpt: str, metadata: dict):
    """Create a summary row and immediately embed it for RAG."""
    vector = embed_summary_excerpt(summary_excerpt)

    obj = KnowledgeFileSummary.objects.create(
        title=title,
        source_file_name=source_file_name,
        source_url=source_url or "",
        file_kind=file_kind,
        summary_excerpt=summary_excerpt,
        metadata=metadata or {},
        embedding=vector,
        embedded_at=timezone.now(),
    )

    return obj


def reembed_summary(summary: KnowledgeFileSummary) -> KnowledgeFileSummary:
    """Recompute embedding for an existing summary row."""
    vector = embed_summary_excerpt(summary.summary_excerpt)
    summary.embedding = vector
    summary.embedded_at = timezone.now()
    summary.save(update_fields=["embedding", "embedded_at", "updated_at"])
    return summary


def search_similar_summaries(*, query: str, top_k: int = 5, file_kind: str = None):
    """Vector search over embedded summaries using pgvector L2 distance."""
    query_vector = embed_summary_excerpt(query)

    qs = KnowledgeFileSummary.objects.exclude(embedding=None)
    if file_kind:
        qs = qs.filter(file_kind=file_kind)

    return qs.order_by(L2Distance("embedding", query_vector))[:top_k]
