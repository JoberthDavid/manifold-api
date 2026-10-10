from django.test import TestCase

from apps.security.models import (
    Service,
    ServiceTechnicalEndpoint,
    TechnicalEndpoint,
)
from apps.security.services.technical_endpoint_authorization import (
    TechnicalEndpointAuthorizationService,
)


class TechnicalEndpointAuthorizationServiceTests(TestCase):
    def setUp(self):
        self.service = Service.objects.create(
            name="Composition Engine",
        )

        self.endpoint = TechnicalEndpoint.objects.create(
            name="Buscar itens",
            http_method=TechnicalEndpoint.HttpMethod.GET,
            path="/api/integrations/scraper/buscar-itens/",
        )

    def test_authorized_service_can_access_endpoint(self):
        ServiceTechnicalEndpoint.objects.create(
            service=self.service,
            endpoint=self.endpoint,
        )

        self.assertTrue(
            TechnicalEndpointAuthorizationService.is_authorized(
                service=self.service,
                endpoint=self.endpoint,
            )
        )

    def test_service_without_authorization_is_denied(self):
        self.assertFalse(
            TechnicalEndpointAuthorizationService.is_authorized(
                service=self.service,
                endpoint=self.endpoint,
            )
        )

    def test_disabled_authorization_is_denied(self):
        ServiceTechnicalEndpoint.objects.create(
            service=self.service,
            endpoint=self.endpoint,
            enabled=False,
        )

        self.assertFalse(
            TechnicalEndpointAuthorizationService.is_authorized(
                service=self.service,
                endpoint=self.endpoint,
            )
        )

    def test_disabled_service_is_denied(self):
        ServiceTechnicalEndpoint.objects.create(
            service=self.service,
            endpoint=self.endpoint,
        )

        self.service.enabled = False
        self.service.save(update_fields=("enabled",))

        self.assertFalse(
            TechnicalEndpointAuthorizationService.is_authorized(
                service=self.service,
                endpoint=self.endpoint,
            )
        )

    def test_disabled_endpoint_is_denied(self):
        ServiceTechnicalEndpoint.objects.create(
            service=self.service,
            endpoint=self.endpoint,
        )

        self.endpoint.enabled = False
        self.endpoint.save(update_fields=("enabled",))

        self.assertFalse(
            TechnicalEndpointAuthorizationService.is_authorized(
                service=self.service,
                endpoint=self.endpoint,
            )
        )

    def test_invalid_service_is_denied(self):
        self.assertFalse(
            TechnicalEndpointAuthorizationService.is_authorized(
                service=None,
                endpoint=self.endpoint,
            )
        )

    def test_invalid_endpoint_is_denied(self):
        self.assertFalse(
            TechnicalEndpointAuthorizationService.is_authorized(
                service=self.service,
                endpoint=None,
            )
        )