from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIClient

from apps.integrations.models import (
    AuthenticationType,
    Integration,
    IntegrationOperation,
)
from apps.security.models import (
    Service,
    ServiceCredential,
    ServiceTechnicalEndpoint,
    TechnicalEndpoint,
)
from apps.security.services.service_credentials import (
    ServiceCredentialService,
)


class IntegrationExecuteApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()

        self.service = Service.objects.create(
            name="Composition Engine",
        )

        self.credential, self.token = (
            ServiceCredentialService.create(
                name="Test Credential",
                service=self.service,
            )
        )

        self.integration = Integration.objects.create(
            name="Scraper",
            base_url="http://127.0.0.1:8002",
            authentication_type=AuthenticationType.NONE,
            timeout=10,
        )

        self.operation = IntegrationOperation.objects.create(
            integration=self.integration,
            name="Buscar itens",
            http_method="GET",
            path="/itens/",
            request_schema={},
        )

        self.endpoint = TechnicalEndpoint.objects.create(
            name="Buscar itens do Scraper",
            http_method=TechnicalEndpoint.HttpMethod.GET,
            path="/api/integrations/scraper/buscar-itens/",
        )

        self.authorization = ServiceTechnicalEndpoint.objects.create(
            service=self.service,
            endpoint=self.endpoint,
        )

        self.url = (
            "/api/integrations/"
            f"{self.integration.slug}/"
            f"{self.operation.slug}/"
        )

    def authenticate(self):
        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

    @patch("apps.integrations.api.views.IntegrationGateway.execute")
    def test_authorized_service_can_execute_integration(
        self,
        mock_execute,
    ):
        mock_execute.return_value = {
            "count": 1,
            "results": [],
        }

        self.authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data,
            {
                "count": 1,
                "results": [],
            },
        )

        mock_execute.assert_called_once()

    @patch("apps.integrations.api.views.IntegrationGateway.execute")
    def test_service_without_endpoint_authorization_is_rejected(
        self,
        mock_execute,
    ):
        self.authorization.enabled = False
        self.authorization.save(
            update_fields=("enabled",),
        )

        self.authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 403)
        mock_execute.assert_not_called()

    @patch("apps.integrations.api.views.IntegrationGateway.execute")
    def test_disabled_service_is_rejected(
        self,
        mock_execute,
    ):
        self.service.enabled = False
        self.service.save(
            update_fields=("enabled",),
        )

        self.authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 403)
        mock_execute.assert_not_called()

    @patch("apps.integrations.api.views.IntegrationGateway.execute")
    def test_disabled_endpoint_is_rejected(
        self,
        mock_execute,
    ):
        self.endpoint.enabled = False
        self.endpoint.save(
            update_fields=("enabled",),
        )

        self.authenticate()

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 403)
        mock_execute.assert_not_called()

    @patch("apps.integrations.api.views.IntegrationGateway.execute")
    def test_invalid_service_credential_is_rejected(
        self,
        mock_execute,
    ):
        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer token-invalido",
        )

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 401)
        mock_execute.assert_not_called()

    @patch("apps.integrations.api.views.IntegrationGateway.execute")
    def test_missing_service_credential_is_rejected(
        self,
        mock_execute,
    ):
        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 401)
        mock_execute.assert_not_called()

    @patch("apps.integrations.api.views.IntegrationGateway.execute")
    def test_unauthorized_service_does_not_execute_gateway(
        self,
        mock_execute,
    ):
        other_service = Service.objects.create(
            name="Another Service",
        )

        _, other_token = ServiceCredentialService.create(
            name="Other Credential",
            service=other_service,
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {other_token}",
        )

        response = self.client.get(self.url)

        self.assertEqual(response.status_code, 403)
        mock_execute.assert_not_called()
