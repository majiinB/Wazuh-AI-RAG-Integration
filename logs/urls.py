"""
logs/urls.py
"""

from django.urls import path
from .views import (
    IntegratorIngestView,
    AlertListView,
    AlertDetailView,
    AlertAcknowledgeView,
    OpenSearchQueryView,
    OpenSearchTopAgentsView,
    OpenSearchLevelDistributionView,
    health_check,
)

urlpatterns = [
    # --- Wazuh Integrator webhook ---
    path("ingest/", IntegratorIngestView.as_view(), name="logs-ingest"),

    # --- Stored alerts (Django DB) ---
    path("alerts/", AlertListView.as_view(), name="alert-list"),
    path("alerts/<int:pk>/", AlertDetailView.as_view(), name="alert-detail"),
    path("alerts/<int:pk>/acknowledge/", AlertAcknowledgeView.as_view(), name="alert-acknowledge"),

    # --- OpenSearch queries ---
    path("search/", OpenSearchQueryView.as_view(), name="logs-search"),
    path("search/top-agents/", OpenSearchTopAgentsView.as_view(), name="logs-top-agents"),
    path("search/level-distribution/", OpenSearchLevelDistributionView.as_view(), name="logs-level-dist"),

    # --- Health ---
    path("health/", health_check, name="logs-health"),
]