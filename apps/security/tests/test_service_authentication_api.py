from django.test import RequestFactory, TestCase
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.security.api.authentication import (
    ServiceCredentialAuthentication,
)
from apps.security.api.permissions import (
    IsServiceAuthenticated,
)
from apps.security.models import Service
from apps.security.services.service_credentials import (
    ServiceCredentialService,
)


class ServiceProtectedView(APIView):
    authentication_classes = (
        ServiceCredentialAuthentication,
    )
    permission_classes = (
        IsServiceAuthenticated,
    )

    def get(self, request):
        return Response(
            {
                "authenticated": True,
                "service": request.user.service.slug,
            }
        )


class ServiceCredentialAuthenticationApiTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.authentication = ServiceCredentialAuthentication()
        self.service = Service.objects.create(
            name="Composition Engine",
        )
        self.view = ServiceProtectedView.as_view()

    def test_valid_service_credential_is_authenticated(self):
        _, token = ServiceCredentialService.create(
            name="Teste",
            service=self.service,
        )

        request = self.factory.get(
            "/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        response = self.view(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.data["authenticated"],
            True,
        )
        self.assertEqual(
            response.data["service"],
            "composition-engine",
        )

    def test_missing_service_credential_is_rejected(self):
        request = self.factory.get("/")

        response = self.view(request)

        self.assertEqual(response.status_code, 401)

    def test_invalid_service_credential_is_rejected(self):
        request = self.factory.get(
            "/",
            HTTP_AUTHORIZATION="Bearer token-invalido",
        )

        response = self.view(request)

        self.assertEqual(response.status_code, 401)