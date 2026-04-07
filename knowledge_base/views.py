"""
knowledge_base/views.py

Endpoints:
  POST /api/knowledge/documents/              Add a Google Doc to track
  GET  /api/knowledge/documents/              List all documents
  GET  /api/knowledge/documents/{id}/         Document detail
  POST /api/knowledge/documents/{id}/sync/    Fetch latest content from Google Docs
  POST /api/knowledge/documents/{id}/embed/   Chunk + embed into pgvector (explicit trigger)
  DELETE /api/knowledge/documents/{id}/       Remove document + all its chunks
  GET  /api/knowledge/search/                 Search chunks by text query (for testing RAG)
"""

import logging

from rest_framework import status
from rest_framework.views import APIView
from rest_framework.generics import ListCreateAPIView, RetrieveDestroyAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import KnowledgeDocument, DocumentChunk
from .serializers import KnowledgeDocumentSerializer, DocumentChunkSerializer
from .services.document_service import (
    sync_document_from_google,
    embed_document,
    search_similar_chunks,
)
from .services.embedding_service import embed_alert_query

logger = logging.getLogger(__name__)


class KnowledgeDocumentListCreateView(ListCreateAPIView):
    """
    GET  /api/knowledge/documents/   — list all tracked documents
    POST /api/knowledge/documents/   — add a new Google Doc to track

    POST body:
    {
        "google_doc_id": "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgVE2upms",
        "doc_type": "runbook",
        "description": "SSH brute force response runbook"
    }
    """
    serializer_class = KnowledgeDocumentSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = KnowledgeDocument.objects.all()
        doc_type = self.request.query_params.get("doc_type")
        status_filter = self.request.query_params.get("status")
        if doc_type:
            qs = qs.filter(doc_type=doc_type)
        if status_filter:
            qs = qs.filter(status=status_filter)
        return qs


class KnowledgeDocumentDetailView(RetrieveDestroyAPIView):
    """
    GET    /api/knowledge/documents/{id}/  — document detail + chunk count
    DELETE /api/knowledge/documents/{id}/  — remove document and all its chunks
    """
    serializer_class = KnowledgeDocumentSerializer
    permission_classes = [IsAuthenticated]
    queryset = KnowledgeDocument.objects.all()


class SyncDocumentView(APIView):
    """
    POST /api/knowledge/documents/{pk}/sync/

    Fetches the latest content from Google Docs.
    Does NOT embed — just updates raw_content.
    Safe to call anytime, even on draft documents.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            document = KnowledgeDocument.objects.get(pk=pk)
        except KnowledgeDocument.DoesNotExist:
            return Response({"error": "Document not found"}, status=status.HTTP_404_NOT_FOUND)

        try:
            document = sync_document_from_google(document)
            return Response({
                "message": f"Synced '{document.title}' successfully",
                "status": document.status,
                "content_length": len(document.raw_content),
                "last_fetched_at": document.last_fetched_at,
            })
        except Exception as e:
            logger.error(f"Sync failed for document {pk}: {e}", exc_info=True)
            return Response(
                {"error": f"Failed to sync from Google Docs: {str(e)}"},
                status=status.HTTP_502_BAD_GATEWAY,
            )


class EmbedDocumentView(APIView):
    """
    POST /api/knowledge/documents/{pk}/embed/

    Explicitly triggers chunking + embedding of a document.
    Only call this when the document is finalized.

    This will:
    - Delete old chunks if re-embedding
    - Split content into chunks
    - Generate Gemini embeddings
    - Store in pgvector
    - Mark document as 'embedded'
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        try:
            document = KnowledgeDocument.objects.get(pk=pk)
        except KnowledgeDocument.DoesNotExist:
            return Response({"error": "Document not found"}, status=status.HTTP_404_NOT_FOUND)

        if not document.raw_content:
            return Response(
                {"error": "Document has no content. Run /sync/ first."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            document = embed_document(document, user=request.user)
            return Response({
                "message": f"'{document.title}' embedded successfully",
                "status": document.status,
                "chunk_count": document.chunk_count,
                "last_embedded_at": document.last_embedded_at,
            })
        except Exception as e:
            logger.error(f"Embedding failed for document {pk}: {e}", exc_info=True)
            return Response(
                {"error": f"Embedding failed: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class KnowledgeSearchView(APIView):
    """
    GET /api/knowledge/search/?q=ssh+brute+force&top_k=5&doc_type=runbook

    Test the RAG search — converts query to embedding and searches pgvector.
    Useful for verifying your knowledge base is working before wiring to alerts.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        query = request.query_params.get("q")
        if not query:
            return Response({"error": "q parameter is required"}, status=status.HTTP_400_BAD_REQUEST)

        top_k = int(request.query_params.get("top_k", 5))
        doc_type = request.query_params.get("doc_type")

        try:
            # Embed the query
            query_embedding = embed_alert_query(query)

            # Search pgvector
            chunks = search_similar_chunks(
                query_embedding=query_embedding,
                top_k=top_k,
                doc_type=doc_type,
            )

            results = [
                {
                    "document_title": chunk.document.title,
                    "doc_type": chunk.document.doc_type,
                    "chunk_index": chunk.chunk_index,
                    "content": chunk.content,
                    "google_doc_url": chunk.document.google_doc_url,
                }
                for chunk in chunks
            ]

            return Response({
                "query": query,
                "total_results": len(results),
                "results": results,
            })

        except Exception as e:
            logger.error(f"Knowledge search failed: {e}", exc_info=True)
            return Response(
                {"error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )