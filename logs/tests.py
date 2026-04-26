from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIRequestFactory

from .views import IntegratorIngestView

# Create your tests here.


class IntegratorIngestShieldTests(TestCase):
	def setUp(self):
		self.factory = APIRequestFactory()

	@patch("logs.views.process_integrator_payload")
	def test_query_level_exclusion_returns_early_200(self, mock_process_integrator_payload):
		payload = {
			"rule": {
				"id": "5715",
				"level": 10,
				"description": "PAM session opened",
				"groups": [],
			},
			"agent": {
				"id": "001",
				"name": "any-agent",
			},
			"timestamp": "2024-05-18T10:00:00.000+0000",
		}

		request = self.factory.post("/api/logs/ingest/", payload, format="json")
		response = IntegratorIngestView.as_view()(request)

		self.assertEqual(response.status_code, 200)
		self.assertEqual(response.data["status"], "excluded")
		self.assertIn("query-level exclusion", response.data["reason"])
		mock_process_integrator_payload.assert_not_called()
