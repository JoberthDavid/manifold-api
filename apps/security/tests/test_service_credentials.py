from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.security.models import Service, ServiceCredential
from apps.security.services.service_credentials import (
    ServiceCredentialError,
    ServiceCredentialService,
)


class ServiceCredentialServiceTests(TestCase):
    def setUp(self):
        self.service = Service.objects.create(
            name="Composition Engine",
        )

    def test_create_returns_credential_and_plain_token(self):
        credential, token = ServiceCredentialService.create(
            name="Teste",
            service=self.service,
        )

        self.assertIsInstance(
            credential,
            ServiceCredential,
        )

        self.assertTrue(token)

        self.assertGreaterEqual(
            len(token),
            40,
        )

        self.assertEqual(
            credential.service,
            self.service,
        )

        self.assertEqual(
            credential.service.name,
            "Composition Engine",
        )

        self.assertNotEqual(
            credential.token_hash,
            token,
        )

        self.assertEqual(
            ServiceCredential.objects.count(),
            1,
        )

    def test_authenticate_returns_valid_credential(self):
        credential, token = ServiceCredentialService.create(
            name="Teste",
            service=self.service,
        )

        authenticated = ServiceCredentialService.authenticate(
            token=token,
        )

        self.assertEqual(
            authenticated,
            credential,
        )

        credential.refresh_from_db()

        self.assertIsNotNone(
            credential.last_used_at,
        )

    def test_authenticate_rejects_invalid_token(self):
        ServiceCredentialService.create(
            name="Teste",
            service=self.service,
        )

        authenticated = ServiceCredentialService.authenticate(
            token="token-invalido",
        )

        self.assertIsNone(
            authenticated,
        )

    def test_authenticate_rejects_empty_token(self):
        authenticated = ServiceCredentialService.authenticate(
            token="",
        )

        self.assertIsNone(
            authenticated,
        )

    def test_authenticate_rejects_disabled_credential(self):
        credential, token = ServiceCredentialService.create(
            name="Teste",
            service=self.service,
        )

        ServiceCredentialService.disable(
            credential,
        )

        authenticated = ServiceCredentialService.authenticate(
            token=token,
        )

        self.assertIsNone(
            authenticated,
        )

    def test_authenticate_accepts_credential_when_service_is_disabled(self):
        credential, token = ServiceCredentialService.create(
            name="Teste",
            service=self.service,
        )

        self.service.enabled = False
        self.service.save(
            update_fields=("enabled",),
        )

        authenticated = ServiceCredentialService.authenticate(
            token=token,
        )

        self.assertEqual(
            authenticated,
            credential,
        )

        credential.refresh_from_db()

        self.assertIsNotNone(
            credential.last_used_at,
        )

    def test_authenticate_rejects_expired_credential(self):
        credential, token = ServiceCredentialService.create(
            name="Teste",
            service=self.service,
            expires_at=timezone.now() + timedelta(minutes=5),
        )

        credential.expires_at = timezone.now() - timedelta(minutes=1)
        credential.save(
            update_fields=("expires_at",),
        )

        authenticated = ServiceCredentialService.authenticate(
            token=token,
        )

        self.assertIsNone(
            authenticated,
        )

        credential.refresh_from_db()

        self.assertIsNone(
            credential.last_used_at,
        )

    def test_create_rejects_expiration_in_the_past(self):
        with self.assertRaises(
            ServiceCredentialError,
        ):
            ServiceCredentialService.create(
                name="Teste",
                service=self.service,
                expires_at=timezone.now() - timedelta(minutes=1),
            )

    def test_create_rejects_empty_name(self):
        with self.assertRaises(
            ServiceCredentialError,
        ):
            ServiceCredentialService.create(
                name="",
                service=self.service,
            )

    def test_create_rejects_invalid_service(self):
        with self.assertRaises(
            ServiceCredentialError,
        ):
            ServiceCredentialService.create(
                name="Teste",
                service=None,
            )

    def test_create_rejects_disabled_service(self):
        self.service.enabled = False
        self.service.save(
            update_fields=("enabled",),
        )

        with self.assertRaises(
            ServiceCredentialError,
        ):
            ServiceCredentialService.create(
                name="Teste",
                service=self.service,
            )

    def test_disable_and_enable(self):
        credential, token = ServiceCredentialService.create(
            name="Teste",
            service=self.service,
        )

        ServiceCredentialService.disable(
            credential,
        )

        self.assertIsNone(
            ServiceCredentialService.authenticate(
                token=token,
            )
        )

        ServiceCredentialService.enable(
            credential,
        )

        authenticated = ServiceCredentialService.authenticate(
            token=token,
        )

        self.assertEqual(
            authenticated,
            credential,
        )