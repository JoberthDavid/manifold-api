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
    ServiceTechnicalEndpoint,
    TechnicalEndpoint,
)
from apps.security.services.service_credentials import (
    ServiceCredentialService,
)


class VgeoIntegrationTests(TestCase):
    """
    Testes determinísticos da integração VGEO/DNIT.

    Os parâmetros utilizados são reais e correspondem a uma consulta
    previamente validada contra o VGEO/DNIT.
    """

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
            name="VGEO Test Client",
        )

        self.credential, self.token = ServiceCredentialService.create(
            name="VGEO Test Credential",
            service=self.service,
        )

        self.integration = Integration.objects.create(
            name="VGEO DNIT",
            base_url="https://servicos.dnit.gov.br/sgplan/apigeo",
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
            path="/api/integrations/vgeo-dnit/localizar-km/",
            description=(
                "Endpoint técnico para consulta de localização "
                "quilométrica no VGEO/DNIT."
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

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )

    def _mock_response(self):
        response = type("MockResponse", (), {})()

        response.status_code = 200
        response.headers = {
            "Content-Type": "application/json",
        }
        response.content = b'{"mock": true}'
        response.raise_for_status = lambda: None
        response.json = lambda: self.VGEO_RESPONSE

        return response
    
    @patch("apps.integrations.gateway.requests.request")
    def test_vgeo_request_uses_real_parameters(
        self,
        mock_request,
    ):
        mock_request.return_value = self._mock_response()

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

        args, kwargs = mock_request.call_args

        self.assertEqual(kwargs["method"], "GET")
        self.assertEqual(kwargs["params"], self.VGEO_PARAMETERS)

    @patch("apps.integrations.gateway.requests.request")
    def test_vgeo_response_is_returned_unchanged(
        self,
        mock_request,
    ):
        mock_request.return_value = self._mock_response()

        response = self.client.get(
            self.url,
            data=self.VGEO_PARAMETERS,
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertEqual(
            response.data[0]["br"],
            "251",
        )

        self.assertEqual(
            response.data[0]["uf"],
            "GO",
        )

        self.assertEqual(
            response.data[0]["km"],
            "19.922263025124039",
        )

    @patch("apps.integrations.gateway.requests.request")
    def test_vgeo_url_is_built_from_integration_configuration(
        self,
        mock_request,
    ):
        mock_request.return_value = self._mock_response()

        response = self.client.get(
            self.url,
            data=self.VGEO_PARAMETERS,
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        args, kwargs = mock_request.call_args

        self.assertEqual(kwargs["method"], "GET")
        self.assertEqual(
            kwargs["url"],
            "https://servicos.dnit.gov.br/sgplan/apigeo/rotas/localizarkm",
        )
        self.assertEqual(kwargs["params"], self.VGEO_PARAMETERS)