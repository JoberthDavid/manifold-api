from datetime import timedelta

from cryptography.fernet import Fernet
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.integrations.exceptions import IntegrationCredentialError
from apps.integrations.models import (
    CredentialType,
    Integration,
)
from apps.integrations.services.integration_credentials import (
    IntegrationCredentialService,
)


TEST_ENCRYPTION_KEY = Fernet.generate_key().decode()


@override_settings(
    MANIFOLD_CREDENTIAL_ENCRYPTION_KEY=TEST_ENCRYPTION_KEY
)
class IntegrationCredentialServiceTests(TestCase):
    def setUp(self):
        self.integration = Integration.objects.create(
            code="SICRO",
            name="SICRO API",
            base_url="https://example.com",
        )

    def test_create_credential_encrypts_secret(self):
        secret = "sicro-secret-api-key"

        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Chave principal",
            credential_type=CredentialType.API_KEY,
            secret=secret,
        )

        self.assertEqual(credential.integration, self.integration)
        self.assertEqual(credential.name, "Chave principal")
        self.assertEqual(
            credential.credential_type,
            CredentialType.API_KEY,
        )
        self.assertNotEqual(
            credential.encrypted_value,
            secret,
        )

        self.assertEqual(
            IntegrationCredentialService.get_secret(credential),
            secret,
        )

    def test_create_credential_rejects_empty_name(self):
        with self.assertRaises(IntegrationCredentialError):
            IntegrationCredentialService.create(
                integration=self.integration,
                name=" ",
                credential_type=CredentialType.API_KEY,
                secret="secret",
            )

    def test_create_credential_rejects_invalid_type(self):
        with self.assertRaises(IntegrationCredentialError):
            IntegrationCredentialService.create(
                integration=self.integration,
                name="Chave principal",
                credential_type="INVALID",
                secret="secret",
            )

    def test_get_secret_rejects_disabled_credential(self):
        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Chave principal",
            credential_type=CredentialType.API_KEY,
            secret="secret",
        )

        IntegrationCredentialService.disable(credential)

        with self.assertRaises(IntegrationCredentialError):
            IntegrationCredentialService.get_secret(credential)

    def test_get_secret_rejects_expired_credential(self):
        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Chave expirada",
            credential_type=CredentialType.API_KEY,
            secret="secret",
            expires_at=timezone.now() - timedelta(minutes=1),
        )

        with self.assertRaises(IntegrationCredentialError):
            IntegrationCredentialService.get_secret(credential)

    def test_update_secret_replaces_encrypted_value(self):
        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Chave principal",
            credential_type=CredentialType.API_KEY,
            secret="old-secret",
        )

        old_encrypted_value = credential.encrypted_value

        IntegrationCredentialService.update_secret(
            credential,
            "new-secret",
        )

        credential.refresh_from_db()

        self.assertNotEqual(
            credential.encrypted_value,
            old_encrypted_value,
        )
        self.assertEqual(
            IntegrationCredentialService.get_secret(credential),
            "new-secret",
        )

    def test_enable_and_disable_credential(self):
        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Chave principal",
            credential_type=CredentialType.API_KEY,
            secret="secret",
        )

        IntegrationCredentialService.disable(credential)
        credential.refresh_from_db()

        self.assertFalse(credential.enabled)

        IntegrationCredentialService.enable(credential)
        credential.refresh_from_db()

        self.assertTrue(credential.enabled)