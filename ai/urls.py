from django.urls import path

from .views import GeminiEmbedView, GeminiGenerateView


urlpatterns = [
	path("generate/", GeminiGenerateView.as_view(), name="gemini-generate"),
	path("embed/", GeminiEmbedView.as_view(), name="gemini-embed"),
]
