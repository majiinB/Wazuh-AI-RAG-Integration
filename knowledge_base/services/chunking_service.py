"""
knowledge_base/services/chunking_service.py

Splits document text into overlapping chunks for embedding.

Why chunking?
- Embedding models have token limits
- Smaller chunks = more precise similarity search
- Overlap ensures context isn't lost at chunk boundaries
"""

import logging
from typing import List

logger = logging.getLogger(__name__)

# Tune these based on your document sizes
CHUNK_SIZE = 500        # characters per chunk
CHUNK_OVERLAP = 100     # overlap between consecutive chunks


def chunk_text(text: str, chunk_size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> List[str]:
    """
    Split text into overlapping chunks.

    Example with chunk_size=20, overlap=5:
    "The quick brown fox jumps over the lazy dog"
     chunk 0: "The quick brown fox "
     chunk 1: "fox jumps over the l"  ← starts 5 chars back
     chunk 2: "the lazy dog"

    Returns:
        List of text chunks
    """
    if not text or not text.strip():
        return []

    text = text.strip()
    chunks = []
    start = 0

    while start < len(text):
        end = start + chunk_size
        chunk = text[start:end].strip()

        if chunk:
            chunks.append(chunk)

        # Move forward by (chunk_size - overlap)
        start += chunk_size - overlap

        # Prevent infinite loop on very small texts
        if chunk_size <= overlap:
            break

    logger.debug(f"Split text ({len(text)} chars) into {len(chunks)} chunks")
    return chunks


def chunk_document_by_paragraphs(text: str, max_chunk_size: int = CHUNK_SIZE) -> List[str]:
    """
    Alternative chunking strategy — split by paragraphs first,
    then merge small paragraphs together up to max_chunk_size.

    Better for structured documents like runbooks with clear sections.
    """
    if not text or not text.strip():
        return []

    paragraphs = [p.strip() for p in text.split("\n\n") if p.strip()]
    chunks = []
    current_chunk = ""

    for paragraph in paragraphs:
        # If adding this paragraph exceeds the limit, save current chunk
        if current_chunk and len(current_chunk) + len(paragraph) + 2 > max_chunk_size:
            chunks.append(current_chunk.strip())
            current_chunk = paragraph
        else:
            current_chunk = f"{current_chunk}\n\n{paragraph}".strip() if current_chunk else paragraph

    # Don't forget the last chunk
    if current_chunk.strip():
        chunks.append(current_chunk.strip())

    logger.debug(f"Split into {len(chunks)} paragraph-based chunks")
    return chunks