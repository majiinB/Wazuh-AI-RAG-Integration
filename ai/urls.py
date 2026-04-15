from django.urls import path

from .views import GeminiGenerateView


urlpatterns = [
	path("generate/", GeminiGenerateView.as_view(), name="gemini-generate"),
]
