"""
knowledge_base/serializers.py
"""
from rest_framework import serializers
from .models import KnowledgeDocument, DocumentChunk


class KnowledgeDocumentSerializer(serializers.ModelSerializer):
    embedded_by_username = serializers.SerializerMethodField()

    class Meta:
        model = KnowledgeDocument
        fields = [
            "id",
            "google_doc_id",
            "google_doc_url",
            "title",
            "doc_type",
            "description",
            "status",
            "chunk_count",
            "last_fetched_at",
            "last_embedded_at",
            "embedded_by_username",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "title", "google_doc_url", "status", "chunk_count",
            "last_fetched_at", "last_embedded_at", "embedded_by_username",
            "created_at", "updated_at",
        ]

    def get_embedded_by_username(self, obj):
        return obj.embedded_by.username if obj.embedded_by else None


class DocumentChunkSerializer(serializers.ModelSerializer):
    document_title = serializers.CharField(source="document.title", read_only=True)

    class Meta:
        model = DocumentChunk
        fields = ["id", "document_title", "chunk_index", "content", "created_at"]