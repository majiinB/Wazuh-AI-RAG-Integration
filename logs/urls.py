"""
logs/urls.py
"""

from django.urls import path
from .views import (
    IntegratorIngestView,
    NaturalLanguageCorrelationQueryView,
    health_check,
)

urlpatterns = [
    # --- Wazuh Integrator webhook ---
    path("ingest/", IntegratorIngestView.as_view(), name="logs-ingest"),
    path("nl-query/", NaturalLanguageCorrelationQueryView.as_view(), name="logs-nl-query"),

    # --- Health ---
    path("health/", health_check, name="logs-health"),
]