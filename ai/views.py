from django.core.exceptions import ImproperlyConfigured

from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .service import GeminiAIService


class GeminiGenerateView(APIView):
	"""Test endpoint for Gemini text generation."""

	permission_classes = [AllowAny]

	def post(self, request):
		prompt = request.data.get("prompt")

		if not prompt or not str(prompt).strip():
			return Response(
				{"error": "'prompt' is required."},
				status=status.HTTP_400_BAD_REQUEST,
			)

		try:
			service = GeminiAIService()
			text = service.generate_content(prompt)
			return Response(
				{
					"prompt": str(prompt).strip(),
					"response": text,
				},
				status=status.HTTP_200_OK,
			)
		except ImproperlyConfigured as exc:
			return Response(
				{"error": str(exc)},
				status=status.HTTP_500_INTERNAL_SERVER_ERROR,
			)
		except ValueError as exc:
			return Response(
				{"error": str(exc)},
				status=status.HTTP_400_BAD_REQUEST,
			)
		except Exception:
			return Response(
				{"error": "Gemini generation failed."},
				status=status.HTTP_502_BAD_GATEWAY,
			)
