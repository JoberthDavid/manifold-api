from django.test import RequestFactory, TestCase
from django.utils import timezone
from rest_framework.exceptions import AuthenticationFailed

from apps.security.api.authentication import (
    ServiceCredentialAuthentication,
)
from apps.security.models import Service
from apps.security.services.service_credentials import (
    ServiceCredentialService,
)


class ServiceCredentialAuthenticationTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.authentication = ServiceCredentialAuthentication()
        self.service = Service.objects.create(
            name="Composition Engine",
        )

    def test_authenticate_returns_none_without_authorization_header(self):
        request = self.factory.get("/")

        result = self.authentication.authenticate(request)

        self.assertIsNone(result)

    def test_authenticate_rejects_invalid_authorization_format(self):
        request = self.factory.get(
            "/",
            HTTP_AUTHORIZATION="Basic token",
        )

        with self.assertRaises(AuthenticationFailed):
            self.authentication.authenticate(request)

    def test_authenticate_rejects_empty_bearer_token(self):
        request = self.factory.get(
            "/",
            HTTP_AUTHORIZATION="Bearer ",
        )

        with self.assertRaises(AuthenticationFailed):
            self.authentication.authenticate(request)

    def test_authenticate_rejects_invalid_token(self):
        request = self.factory.get(
            "/",
            HTTP_AUTHORIZATION="Bearer token-invalido",
        )

        with self.assertRaises(AuthenticationFailed):
            self.authentication.authenticate(request)

    def test_authenticate_returns_service_credential_for_valid_token(self):
        credential, token = ServiceCredentialService.create(
            name="Teste",
            service=self.service,
        )

        request = self.factory.get(
            "/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        result = self.authentication.authenticate(request)

        self.assertIsNotNone(result)

        authenticated_credential, authenticated_token = result

        self.assertEqual(
            authenticated_credential,
            credential,
        )

        self.assertEqual(
            authenticated_token,
            token,
        )

    def test_authenticate_rejects_disabled_credential(self):
        credential, token = ServiceCredentialService.create(
            name="Teste",
            service=self.service,
        )

        ServiceCredentialService.disable(credential)

        request = self.factory.get(
            "/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        with self.assertRaises(AuthenticationFailed):
            self.authentication.authenticate(request)

    def test_authenticate_rejects_expired_credential(self):
        credential, token = ServiceCredentialService.create(
            name="Teste",
            service=self.service,
            expires_at=timezone.now() + timezone.timedelta(minutes=5),
        )

        credential.expires_at = timezone.now() - timezone.timedelta(minutes=1)
        credential.save(update_fields=("expires_at",))

        request = self.factory.get(
            "/",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        with self.assertRaises(AuthenticationFailed):
            self.authentication.authenticate(request)

    def test_authenticate_header_returns_bearer(self):
        self.assertEqual(
            self.authentication.authenticate_header(None),
            "Bearer",
        )