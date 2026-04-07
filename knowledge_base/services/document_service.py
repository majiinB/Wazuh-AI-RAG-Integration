"""
knowledge_base/services/document_service.py

Orchestrates the full pipeline:
1. Fetch content from Google Docs
2. Chunk the text
3. Generate Gemini embeddings
4. Save chunks to pgvector

This is called explicitly by an admin/user — never automatically.
Documents must be manually approved for embedding.
"""

import logging
from django.utils import timezone
from django.contrib.auth.models import User

from knowledge_base.models import KnowledgeDocument, DocumentChunk
from knowledge_base.services.google_docs_service import fetch_document
from knowledge_base.services.chunking_service import chunk_document_by_paragraphs
from knowledge_base.services.embedding_service import embed_texts_batch

logger = logging.getLogger(__name__)


def sync_document_from_google(document: KnowledgeDocument) -> KnowledgeDocument:
    """
    Step 1 — Fetch latest content from Google Docs.
    Updates raw_content and marks status as 'draft' (not yet embedded).
    Does NOT embed — embedding must be triggered separately.
    """
    logger.info(f"Syncing Google Doc: {document.google_doc_id}")

    data = fetch_document(document.google_doc_id)

    document.title = data["title"]
    document.raw_content = data["content"]
    document.google_doc_url = data["url"]
    document.last_fetched_at = timezone.now()

    # If it was previously embedded, mark as outdated since content changed
    if document.status == "embedded":
        document.status = "outdated"

    document.save()
    logger.info(f"Synced '{document.title}' ({len(data['content'])} chars)")
    return document


def embed_document(document: KnowledgeDocument, user: User = None) -> KnowledgeDocument:
    """
    Step 2 — Chunk and embed a document into pgvector.
    Only call this when the document is finalized and ready.

    This:
    1. Deletes old chunks (re-embed from scratch)
    2. Chunks the raw_content
    3. Generates Gemini embeddings for all chunks
    4. Saves DocumentChunk records to pgvector
    5. Marks document as 'embedded'
    """
    if not document.raw_content:
        raise ValueError(f"Document '{document.title}' has no content. Sync it first.")

    logger.info(f"Embedding document: '{document.title}'")

    # 1. Delete old chunks if re-embedding
    old_count = document.chunks.count()
    if old_count > 0:
        document.chunks.all().delete()
        logger.info(f"Deleted {old_count} old chunks")

    # 2. Chunk the text
    chunks = chunk_document_by_paragraphs(document.raw_content)
    if not chunks:
        raise ValueError(f"Document '{document.title}' produced no chunks after splitting.")

    logger.info(f"Split into {len(chunks)} chunks")

    # 3. Generate embeddings for all chunks
    embeddings = embed_texts_batch(chunks, task_type="RETRIEVAL_DOCUMENT")

    # 4. Save chunks to DB
    chunk_objects = [
        DocumentChunk(
            document=document,
            chunk_index=i,
            content=chunk,
            embedding=embedding,
        )
        for i, (chunk, embedding) in enumerate(zip(chunks, embeddings))
    ]
    DocumentChunk.objects.bulk_create(chunk_objects)

    # 5. Update document status
    document.status = "embedded"
    document.last_embedded_at = timezone.now()
    document.chunk_count = len(chunks)
    document.embedded_by = user
    document.save()

    logger.info(f"Successfully embedded '{document.title}' into {len(chunks)} chunks")
    return document


def search_similar_chunks(query_embedding: list, top_k: int = 5, doc_type: str = None):
    """
    Search pgvector for the most similar chunks to a query embedding.
    Used by the RAG service when an alert comes in.

    Args:
        query_embedding: embedding vector of the alert text
        top_k: number of top results to return
        doc_type: optional filter — 'runbook' or 'incident_report'

    Returns:
        QuerySet of DocumentChunk ordered by similarity
    """
    from pgvector.django import L2Distance

    qs = DocumentChunk.objects.select_related("document").filter(
        document__status="embedded"
    )

    if doc_type:
        qs = qs.filter(document__doc_type=doc_type)

    return qs.order_by(L2Distance("embedding", query_embedding))[:top_k]