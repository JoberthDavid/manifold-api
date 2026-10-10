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


class IntegrationApiSecurityTests(TestCase):
    VGEO_PARAMETERS = {
        "lng": "-47.479219436645515",
        "lat": "-16.15699518819505",
        "r": "250",
        "data": "2026-10-9",
    }

    VGEO_RESPONSE = [
        {
            "id": "1",
            "br": "251",
            "sg_tp_trecho": "B",
            "uf": "GO",
            "versao": "202607A",
            "id_trecho": "",
            "km": "19.922263025124039",
            "lat": "-16.157000928668985",
            "lng": "-47.479239940917772",
        }
    ]

    def setUp(self):
        self.client = APIClient()

        self.service = Service.objects.create(
            name="Security Test Client",
        )

        self.credential, self.token = (
            ServiceCredentialService.create(
                name="Security Test Credential",
                service=self.service,
            )
        )

        self.integration = Integration.objects.create(
            name="VGEO DNIT",
            base_url=(
                "https://servicos.dnit.gov.br/"
                "sgplan/apigeo"
            ),
            authentication_type=AuthenticationType.NONE,
            timeout=30,
        )

        self.operation = IntegrationOperation.objects.create(
            integration=self.integration,
            name="Localizar KM",
            http_method="GET",
            path="/rotas/localizarkm",
            request_schema={
                "query": {
                    "lng": "lng",
                    "lat": "lat",
                    "r": "r",
                    "data": "data",
                }
            },
        )

        self.endpoint = TechnicalEndpoint.objects.create(
            name="Localizar KM - VGEO DNIT",
            http_method=TechnicalEndpoint.HttpMethod.GET,
            path=(
                "/api/integrations/"
                "vgeo-dnit/"
                "localizar-km/"
            ),
        )

        ServiceTechnicalEndpoint.objects.create(
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

    def test_without_credentials_returns_401(self):
        response = self.client.get(
            self.url,
            data=self.VGEO_PARAMETERS,
        )

        self.assertEqual(
            response.status_code,
            401,
        )

    def test_invalid_token_returns_401(self):
        self.client.credentials(
            HTTP_AUTHORIZATION="Bearer token-invalido",
        )

        response = self.client.get(
            self.url,
            data=self.VGEO_PARAMETERS,
        )

        self.assertEqual(
            response.status_code,
            401,
        )

    def test_unauthorized_service_returns_403(self):
        unauthorized_service = Service.objects.create(
            name="Unauthorized Service",
        )

        credential, token = ServiceCredentialService.create(
            name="Unauthorized Credential",
            service=unauthorized_service,
        )

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        response = self.client.get(
            self.url,
            data=self.VGEO_PARAMETERS,
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_disabled_endpoint_returns_403(self):
        self.endpoint.enabled = False
        self.endpoint.save(update_fields=["enabled"])

        self.authenticate()

        response = self.client.get(
            self.url,
            data=self.VGEO_PARAMETERS,
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_disabled_service_returns_403(self):
        self.service.enabled = False
        self.service.save(update_fields=["enabled"])

        self.authenticate()

        response = self.client.get(
            self.url,
            data=self.VGEO_PARAMETERS,
        )

        self.assertEqual(
            response.status_code,
            403,
        )

    def test_nonexistent_integration_returns_404(self):
        self.authenticate()

        response = self.client.get(
            "/api/integrations/"
            "integracao-inexistente/"
            f"{self.operation.slug}/",
            data=self.VGEO_PARAMETERS,
        )

        self.assertEqual(
            response.status_code,
            404,
        )

    def test_nonexistent_operation_returns_404(self):
        self.authenticate()

        response = self.client.get(
            "/api/integrations/"
            f"{self.integration.slug}/"
            "operacao-inexistente/",
            data=self.VGEO_PARAMETERS,
        )

        self.assertEqual(
            response.status_code,
            404,
        )

    def test_disabled_integration_returns_404(self):
        self.integration.enabled = False
        self.integration.save(update_fields=["enabled"])

        self.authenticate()

        response = self.client.get(
            self.url,
            data=self.VGEO_PARAMETERS,
        )

        self.assertEqual(
            response.status_code,
            404,
        )

    def test_disabled_operation_returns_404(self):
        self.operation.enabled = False
        self.operation.save(update_fields=["enabled"])

        self.authenticate()

        response = self.client.get(
            self.url,
            data=self.VGEO_PARAMETERS,
        )

        self.assertEqual(
            response.status_code,
            404,
        )

    def test_expired_credential_returns_401(self):
        from datetime import timedelta

        from django.utils import timezone

        self.credential.expires_at = (
            timezone.now() - timedelta(minutes=1)
        )
        self.credential.save(
            update_fields=["expires_at"],
        )

        self.authenticate()

        response = self.client.get(
            self.url,
            data=self.VGEO_PARAMETERS,
        )

        self.assertEqual(
            response.status_code,
            401,
        )

    @patch("apps.integrations.gateway.requests.request")
    def test_authorized_request_reaches_gateway(
        self,
        mock_request,
    ):
        response_object = type(
            "MockResponse",
            (),
            {},
        )()

        response_object.status_code = 200
        response_object.headers = {
            "Content-Type": "application/json",
        }
        response_object.content = b'{"mock": true}'
        response_object.raise_for_status = lambda: None
        response_object.json = lambda: self.VGEO_RESPONSE

        mock_request.return_value = response_object

        self.authenticate()

        response = self.client.get(
            self.url,
            data=self.VGEO_PARAMETERS,
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response.data,
            self.VGEO_RESPONSE,
        )

        mock_request.assert_called_once()