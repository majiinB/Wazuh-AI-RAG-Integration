"""
logs/urls.py
"""

from django.urls import path
from .views import (
    IntegratorIngestView,
    health_check,
)

urlpatterns = [
    # --- Wazuh Integrator webhook ---
    path("ingest/", IntegratorIngestView.as_view(), name="logs-ingest"),

    # --- Health ---
    path("health/", health_check, name="logs-health"),
]