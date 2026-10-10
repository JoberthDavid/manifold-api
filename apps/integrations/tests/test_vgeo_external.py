import os
import unittest

from django.test import TestCase, override_settings
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


@override_settings(ROOT_URLCONF="config.urls")
@unittest.skipUnless(
    os.getenv("RUN_EXTERNAL_INTEGRATION_TESTS") == "1",
    "Teste externo desabilitado. Use RUN_EXTERNAL_INTEGRATION_TESTS=1.",
)
class VgeoExternalIntegrationTests(TestCase):
    """
    Teste E2E contra o VGEO/DNIT real.

    Este teste somente é executado quando:

        RUN_EXTERNAL_INTEGRATION_TESTS=1

    O teste percorre a arquitetura completa:

        ServiceCredential
            ↓
        TechnicalEndpoint
            ↓
        ServiceTechnicalEndpoint
            ↓
        Integration
            ↓
        IntegrationOperation
            ↓
        IntegrationGateway
            ↓
        VGEO/DNIT
    """

    VGEO_PARAMETERS = {
        "lng": "-47.479219436645515",
        "lat": "-16.15699518819505",
        "r": "250",
        "data": "2026-10-9",
    }

    def setUp(self):
        self.client = APIClient()

        self.service = Service.objects.create(
            name="VGEO External Test Client",
        )

        self.credential, self.token = (
            ServiceCredentialService.create(
                name="VGEO External Test Credential",
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
            description=(
                "Endpoint técnico para consulta de "
                "localização quilométrica no VGEO/DNIT."
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

    def test_vgeo_real_api(self):
        response = self.client.get(
            self.url,
            data=self.VGEO_PARAMETERS,
        )

        self.assertEqual(
            response.status_code,
            200,
            msg=f"Resposta inesperada do VGEO: {response.data}",
        )

        self.assertIsInstance(
            response.data,
            list,
        )

        self.assertGreater(
            len(response.data),
            0,
        )

        result = response.data[0]

        self.assertEqual(
            result["br"],
            "251",
        )

        self.assertEqual(
            result["uf"],
            "GO",
        )

        self.assertEqual(
            result["id"],
            "1",
        )

        self.assertEqual(
            result["versao"],
            "202607A",
        )

        self.assertEqual(
            result["km"],
            "19.922263025124039",
        )