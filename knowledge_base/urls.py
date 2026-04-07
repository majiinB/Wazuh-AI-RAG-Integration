"""
knowledge_base/urls.py
"""
from django.urls import path
from .views import (
    KnowledgeDocumentListCreateView,
    KnowledgeDocumentDetailView,
    SyncDocumentView,
    EmbedDocumentView,
    KnowledgeSearchView,
)

urlpatterns = [
    path("documents/", KnowledgeDocumentListCreateView.as_view(), name="kb-document-list"),
    path("documents/<int:pk>/", KnowledgeDocumentDetailView.as_view(), name="kb-document-detail"),
    path("documents/<int:pk>/sync/", SyncDocumentView.as_view(), name="kb-document-sync"),
    path("documents/<int:pk>/embed/", EmbedDocumentView.as_view(), name="kb-document-embed"),
    path("search/", KnowledgeSearchView.as_view(), name="kb-search"),
]