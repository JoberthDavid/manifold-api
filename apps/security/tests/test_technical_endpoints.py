from django.db import IntegrityError
from django.test import TestCase

from apps.security.models import (
    Service,
    ServiceTechnicalEndpoint,
    TechnicalEndpoint,
)


class TechnicalEndpointModelTests(TestCase):
    def test_creates_endpoint_with_slug(self):
        endpoint = TechnicalEndpoint.objects.create(
            name="Buscar itens do Scraper",
            http_method=TechnicalEndpoint.HttpMethod.GET,
            path="/api/integrations/scraper/buscar-itens/",
        )

        self.assertEqual(endpoint.slug, "buscar-itens-do-scraper")
        self.assertEqual(
            endpoint.path,
            "/api/integrations/scraper/buscar-itens/",
        )

    def test_adds_leading_slash_to_path(self):
        endpoint = TechnicalEndpoint.objects.create(
            name="Buscar itens",
            http_method=TechnicalEndpoint.HttpMethod.GET,
            path="api/integrations/scraper/buscar-itens/",
        )

        self.assertEqual(
            endpoint.path,
            "/api/integrations/scraper/buscar-itens/",
        )

    def test_generates_unique_slug(self):
        first = TechnicalEndpoint.objects.create(
            name="Buscar itens",
            http_method=TechnicalEndpoint.HttpMethod.GET,
            path="/api/integrations/scraper/buscar-itens/",
        )

        second = TechnicalEndpoint.objects.create(
            name="Buscar itens",
            http_method=TechnicalEndpoint.HttpMethod.POST,
            path="/api/integrations/scraper/buscar-itens/",
        )

        self.assertEqual(first.slug, "buscar-itens")
        self.assertEqual(second.slug, "buscar-itens-2")

    def test_same_method_and_path_are_unique(self):
        TechnicalEndpoint.objects.create(
            name="Buscar itens",
            http_method=TechnicalEndpoint.HttpMethod.GET,
            path="/api/integrations/scraper/buscar-itens/",
        )

        with self.assertRaises(IntegrityError):
            TechnicalEndpoint.objects.create(
                name="Outro nome",
                http_method=TechnicalEndpoint.HttpMethod.GET,
                path="/api/integrations/scraper/buscar-itens/",
            )

    def test_different_methods_can_use_same_path(self):
        get_endpoint = TechnicalEndpoint.objects.create(
            name="Buscar itens GET",
            http_method=TechnicalEndpoint.HttpMethod.GET,
            path="/api/integrations/scraper/buscar-itens/",
        )

        post_endpoint = TechnicalEndpoint.objects.create(
            name="Buscar itens POST",
            http_method=TechnicalEndpoint.HttpMethod.POST,
            path="/api/integrations/scraper/buscar-itens/",
        )

        self.assertNotEqual(get_endpoint.pk, post_endpoint.pk)

    def test_service_technical_endpoint_authorizes_service(self):
        service = Service.objects.create(
            name="Composition Engine",
        )

        endpoint = TechnicalEndpoint.objects.create(
            name="Buscar itens",
            http_method=TechnicalEndpoint.HttpMethod.GET,
            path="/api/integrations/scraper/buscar-itens/",
        )

        authorization = ServiceTechnicalEndpoint.objects.create(
            service=service,
            endpoint=endpoint,
        )

        self.assertEqual(authorization.service, service)
        self.assertEqual(authorization.endpoint, endpoint)

    def test_same_service_and_endpoint_are_unique(self):
        service = Service.objects.create(
            name="Composition Engine",
        )

        endpoint = TechnicalEndpoint.objects.create(
            name="Buscar itens",
            http_method=TechnicalEndpoint.HttpMethod.GET,
            path="/api/integrations/scraper/buscar-itens/",
        )

        ServiceTechnicalEndpoint.objects.create(
            service=service,
            endpoint=endpoint,
        )

        with self.assertRaises(IntegrityError):
            ServiceTechnicalEndpoint.objects.create(
                service=service,
                endpoint=endpoint,
            )

    def test_deleting_service_deletes_authorizations(self):
        service = Service.objects.create(
            name="Composition Engine",
        )

        endpoint = TechnicalEndpoint.objects.create(
            name="Buscar itens",
            http_method=TechnicalEndpoint.HttpMethod.GET,
            path="/api/integrations/scraper/buscar-itens/",
        )

        authorization = ServiceTechnicalEndpoint.objects.create(
            service=service,
            endpoint=endpoint,
        )

        authorization_id = authorization.pk

        service.delete()

        self.assertFalse(
            ServiceTechnicalEndpoint.objects.filter(
                pk=authorization_id
            ).exists()
        )

        self.assertTrue(
            TechnicalEndpoint.objects.filter(
                pk=endpoint.pk
            ).exists()
        )

    def test_deleting_endpoint_deletes_authorizations(self):
        service = Service.objects.create(
            name="Composition Engine",
        )

        endpoint = TechnicalEndpoint.objects.create(
            name="Buscar itens",
            http_method=TechnicalEndpoint.HttpMethod.GET,
            path="/api/integrations/scraper/buscar-itens/",
        )

        authorization = ServiceTechnicalEndpoint.objects.create(
            service=service,
            endpoint=endpoint,
        )

        authorization_id = authorization.pk

        endpoint.delete()

        self.assertFalse(
            ServiceTechnicalEndpoint.objects.filter(
                pk=authorization_id
            ).exists()
        )

    def test_endpoint_str(self):
        endpoint = TechnicalEndpoint.objects.create(
            name="Buscar itens",
            http_method=TechnicalEndpoint.HttpMethod.GET,
            path="/api/integrations/scraper/buscar-itens/",
        )

        self.assertEqual(
            str(endpoint),
            "GET /api/integrations/scraper/buscar-itens/",
        )

    def test_service_technical_endpoint_str(self):
        service = Service.objects.create(
            name="Composition Engine",
        )

        endpoint = TechnicalEndpoint.objects.create(
            name="Buscar itens",
            http_method=TechnicalEndpoint.HttpMethod.GET,
            path="/api/integrations/scraper/buscar-itens/",
        )

        authorization = ServiceTechnicalEndpoint.objects.create(
            service=service,
            endpoint=endpoint,
        )

        self.assertEqual(
            str(authorization),
            "Composition Engine → GET /api/integrations/scraper/buscar-itens/",
        )