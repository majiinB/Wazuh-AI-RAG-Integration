from django.db import models
from pgvector.django import VectorField


class KnowledgeDocument(models.Model):
    """
    Represents a Google Doc (runbook or incident report).
    Content is fetched from Google Docs API.
    Embedding is only triggered manually — documents may still be drafts.
    """

    DOC_TYPES = [
        ("runbook", "Runbook"),
        ("incident_report", "Incident Report"),
    ]

    STATUS_CHOICES = [
        ("draft", "Draft"),           # fetched but not embedded yet
        ("embedded", "Embedded"),     # chunked and embedded into pgvector
        ("outdated", "Outdated"),     # doc changed since last embed
    ]

    # --- Google Docs ---
    google_doc_id = models.CharField(max_length=255, unique=True, db_index=True)
    title = models.CharField(max_length=500)
    doc_type = models.CharField(max_length=20, choices=DOC_TYPES)
    google_doc_url = models.URLField(blank=True)

    # --- Content ---
    raw_content = models.TextField(blank=True)       # full text fetched from Google Docs
    last_fetched_at = models.DateTimeField(null=True, blank=True)

    # --- Embedding status ---
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="draft")
    last_embedded_at = models.DateTimeField(null=True, blank=True)
    embedded_by = models.ForeignKey(
        "auth.User",
        null=True, blank=True,
        on_delete=models.SET_NULL,
        related_name="embedded_documents",
    )
    chunk_count = models.PositiveIntegerField(default=0)

    # --- Metadata ---
    description = models.TextField(blank=True)   # optional notes about the doc
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]

    def __str__(self):
        return f"[{self.get_doc_type_display()}] {self.title} ({self.status})"


class DocumentChunk(models.Model):
    """
    A chunk of a KnowledgeDocument with its vector embedding.
    This is what gets searched during RAG.
    """
    document = models.ForeignKey(
        KnowledgeDocument,
        on_delete=models.CASCADE,
        related_name="chunks",
    )
    chunk_index = models.PositiveIntegerField()   # order within the document
    content = models.TextField()                  # the actual text chunk
    embedding = VectorField(dimensions=768)       # Gemini embedding-004 = 768 dims
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["document", "chunk_index"]
        unique_together = ["document", "chunk_index"]

    def __str__(self):
        return f"{self.document.title} — chunk {self.chunk_index}"


class KnowledgeFileSummary(models.Model):
    """
    Stores a short summary/excerpt of an external file and its embedding for RAG.
    Typical sources: runbooks, threat intelligence docs, reports.
    """

    FILE_KINDS = [
        ("runbook", "Runbook"),
        ("threat_intelligence", "Threat Intelligence"),
        ("other", "Other"),
    ]

    title = models.CharField(max_length=255)
    source_file_name = models.CharField(max_length=500)
    source_url = models.URLField(blank=True)
    file_kind = models.CharField(max_length=32, choices=FILE_KINDS, default="other")
    summary_excerpt = models.TextField()
    metadata = models.JSONField(default=dict, blank=True)
    embedding = VectorField(dimensions=768, null=True, blank=True)
    embedded_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]

    def __str__(self):
        return f"[{self.get_file_kind_display()}] {self.title}"