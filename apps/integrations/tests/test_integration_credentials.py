from datetime import timedelta

from cryptography.fernet import Fernet
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.integrations.exceptions import IntegrationCredentialError
from apps.integrations.models import (
    CredentialType,
    Integration,
)
from apps.integrations.services.api_key_fingerprint import ApiKeyFingerprintService
from apps.integrations.services.integration_credentials import (
    IntegrationCredentialService,
)
import hashlib


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

    def test_create_generates_fingerprint(self):
        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="composition-engine",
            credential_type=CredentialType.API_KEY,
            secret="a" * 64,
        )

        self.assertEqual(
            credential.fingerprint,
            ApiKeyFingerprintService.generate("a" * 64),
        )

    def test_create_does_not_store_plain_secret(self):
        secret = "a" * 64

        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="composition-engine",
            credential_type=CredentialType.API_KEY,
            secret=secret,
        )

        self.assertNotEqual(
            credential.encrypted_value,
            secret,
        )

        self.assertNotEqual(
            credential.fingerprint,
            secret,
        )

    def test_same_secret_generates_same_fingerprint(self):
        secret = "a" * 64

        first = ApiKeyFingerprintService.generate(secret)
        second = ApiKeyFingerprintService.generate(secret)

        self.assertEqual(first, second)

    def test_different_secrets_generate_different_fingerprints(self):
        first = ApiKeyFingerprintService.generate("a" * 64)
        second = ApiKeyFingerprintService.generate("b" * 64)

        self.assertNotEqual(first, second)

    def test_update_secret_updates_fingerprint(self):
        old_secret = "a" * 64
        new_secret = "b" * 64

        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="composition-engine",
            credential_type=CredentialType.API_KEY,
            secret=old_secret,
        )

        IntegrationCredentialService.update_secret(
            credential,
            new_secret,
        )

        credential.refresh_from_db()

        self.assertEqual(
            credential.fingerprint,
            ApiKeyFingerprintService.generate(new_secret),
        )

    def test_create_generates_credential_fingerprint(self):
        secret = "super-secret-api-key"

        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Composition Engine",
            credential_type=CredentialType.API_KEY,
            secret=secret,
        )

        expected_fingerprint = hashlib.sha256(
            secret.encode("utf-8")
        ).hexdigest()

        self.assertEqual(
            credential.fingerprint,
            expected_fingerprint,
        )

    def test_create_does_not_store_secret_in_plaintext(self):
        secret = "super-secret-api-key"

        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Composition Engine",
            credential_type=CredentialType.API_KEY,
            secret=secret,
        )

        self.assertNotEqual(
            credential.encrypted_value,
            secret,
        )

        self.assertNotIn(
            secret,
            credential.encrypted_value,
        )

    def test_get_secret_returns_original_secret(self):
        secret = "super-secret-api-key"

        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Composition Engine",
            credential_type=CredentialType.API_KEY,
            secret=secret,
        )

        self.assertEqual(
            IntegrationCredentialService.get_secret(credential),
            secret,
        )

    def test_update_secret_updates_fingerprint(self):
        old_secret = "old-secret"
        new_secret = "new-secret"

        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Composition Engine",
            credential_type=CredentialType.API_KEY,
            secret=old_secret,
        )

        old_fingerprint = credential.fingerprint

        IntegrationCredentialService.update_secret(
            credential,
            new_secret,
        )

        credential.refresh_from_db()

        expected_fingerprint = hashlib.sha256(
            new_secret.encode("utf-8")
        ).hexdigest()

        self.assertNotEqual(
            credential.fingerprint,
            old_fingerprint,
        )

        self.assertEqual(
            credential.fingerprint,
            expected_fingerprint,
        )

        self.assertEqual(
            IntegrationCredentialService.get_secret(credential),
            new_secret,
        )