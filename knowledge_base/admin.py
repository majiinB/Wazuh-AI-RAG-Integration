"""
knowledge_base/admin.py

Adds "Sync from Google Docs" and "Embed this document" actions in Django Admin.
"""
from django.contrib import admin, messages
from django.utils.html import format_html
from .models import KnowledgeDocument, DocumentChunk
from .services.document_service import sync_document_from_google, embed_document


@admin.register(KnowledgeDocument)
class KnowledgeDocumentAdmin(admin.ModelAdmin):
    list_display = [
        "title", "doc_type", "status_badge", "chunk_count",
        "last_fetched_at", "last_embedded_at", "embedded_by",
    ]
    list_filter = ["doc_type", "status"]
    search_fields = ["title", "google_doc_id", "description"]
    readonly_fields = [
        "title", "google_doc_url", "status", "chunk_count",
        "last_fetched_at", "last_embedded_at", "embedded_by", "raw_content",
    ]
    actions = ["sync_documents", "embed_documents"]

    def status_badge(self, obj):
        colors = {
            "draft": "#6b7280",
            "embedded": "#16a34a",
            "outdated": "#d97706",
        }
        color = colors.get(obj.status, "#6b7280")
        return format_html(
            '<span style="background:{};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px">{}</span>',
            color, obj.status.upper(),
        )
    status_badge.short_description = "Status"

    @admin.action(description="Sync selected documents from Google Docs")
    def sync_documents(self, request, queryset):
        success, failed = 0, 0
        for doc in queryset:
            try:
                sync_document_from_google(doc)
                success += 1
            except Exception as e:
                failed += 1
                self.message_user(request, f"Failed to sync '{doc.title}': {e}", messages.ERROR)
        if success:
            self.message_user(request, f"Successfully synced {success} document(s).", messages.SUCCESS)

    @admin.action(description="Embed selected documents into pgvector (only finalized docs!)")
    def embed_documents(self, request, queryset):
        success, failed = 0, 0
        for doc in queryset:
            try:
                embed_document(doc, user=request.user)
                success += 1
            except Exception as e:
                failed += 1
                self.message_user(request, f"Failed to embed '{doc.title}': {e}", messages.ERROR)
        if success:
            self.message_user(request, f"Successfully embedded {success} document(s).", messages.SUCCESS)


@admin.register(DocumentChunk)
class DocumentChunkAdmin(admin.ModelAdmin):
    list_display = ["id", "document", "chunk_index", "short_content", "created_at"]
    list_filter = ["document__doc_type"]
    search_fields = ["content", "document__title"]
    readonly_fields = ["document", "chunk_index", "content", "created_at"]

    def short_content(self, obj):
        return obj.content[:80] + "..." if len(obj.content) > 80 else obj.content
    short_content.short_description = "Content preview"