from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.integrations.exceptions import IntegrationCredentialError
from apps.integrations.models import (
    CredentialType,
    Integration,
    IntegrationCredential,
)
from apps.integrations.services.api_key_fingerprint import (
    ApiKeyFingerprintService,
)
from apps.integrations.services.credentials import (
    CredentialEncryptionService,
)
from apps.integrations.services.integration_credentials import (
    IntegrationCredentialService,
)


class IntegrationCredentialServiceTests(TestCase):

    def setUp(self):
        self.integration = Integration.objects.create(
            name="SICRO",
            base_url="https://example.com",
        )

    def test_create_credential_encrypts_secret(self):
        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret="super-secret",
        )

        self.assertIsInstance(credential, IntegrationCredential)
        self.assertEqual(credential.name, "Production")
        self.assertEqual(
            credential.credential_type,
            CredentialType.API_KEY,
        )
        self.assertNotEqual(
            credential.encrypted_value,
            "super-secret",
        )

    def test_create_credential_rejects_empty_name(self):
        with self.assertRaises(IntegrationCredentialError):
            IntegrationCredentialService.create(
                integration=self.integration,
                name="   ",
                credential_type=CredentialType.API_KEY,
                secret="super-secret",
            )

    def test_create_credential_rejects_invalid_type(self):
        with self.assertRaises(IntegrationCredentialError):
            IntegrationCredentialService.create(
                integration=self.integration,
                name="Production",
                credential_type="INVALID",
                secret="super-secret",
            )

    def test_create_does_not_store_plain_secret(self):
        secret = "super-secret"

        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret=secret,
        )

        self.assertNotIn(
            secret,
            credential.encrypted_value,
        )

    def test_create_does_not_store_secret_in_plaintext(self):
        secret = "another-super-secret"

        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret=secret,
        )

        self.assertNotEqual(
            credential.encrypted_value,
            secret,
        )

    def test_create_generates_credential_fingerprint(self):
        secret = "fingerprint-secret"

        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret=secret,
        )

        expected = ApiKeyFingerprintService.generate(secret)

        self.assertEqual(
            credential.fingerprint,
            expected,
        )

    def test_create_generates_fingerprint(self):
        secret = "another-fingerprint-secret"

        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret=secret,
        )

        self.assertEqual(
            len(credential.fingerprint),
            64,
        )

    def test_same_secret_generates_same_fingerprint(self):
        secret = "same-secret"

        fingerprint_one = ApiKeyFingerprintService.generate(
            secret
        )

        fingerprint_two = ApiKeyFingerprintService.generate(
            secret
        )

        self.assertEqual(
            fingerprint_one,
            fingerprint_two,
        )

    def test_different_secrets_generate_different_fingerprints(self):
        credential_one = IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret="secret-one",
        )

        integration_two = Integration.objects.create(
            name="SICRO Homologação",
            base_url="https://example.org",
        )

        credential_two = IntegrationCredentialService.create(
            integration=integration_two,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret="secret-two",
        )

        self.assertNotEqual(
            credential_one.fingerprint,
            credential_two.fingerprint,
        )

    def test_get_secret_returns_original_secret(self):
        secret = "recoverable-secret"

        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret=secret,
        )

        recovered = IntegrationCredentialService.get_secret(
            credential
        )

        self.assertEqual(
            recovered,
            secret,
        )

    def test_get_secret_rejects_disabled_credential(self):
        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret="secret",
        )

        IntegrationCredentialService.disable(credential)

        with self.assertRaises(IntegrationCredentialError):
            IntegrationCredentialService.get_secret(credential)

    def test_get_secret_rejects_expired_credential(self):
        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret="secret",
            expires_at=timezone.now() - timedelta(seconds=1),
        )

        with self.assertRaises(IntegrationCredentialError):
            IntegrationCredentialService.get_secret(credential)

    def test_enable_and_disable_credential(self):
        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret="secret",
        )

        IntegrationCredentialService.disable(credential)

        credential.refresh_from_db()

        self.assertFalse(
            credential.enabled,
        )

        IntegrationCredentialService.enable(credential)

        credential.refresh_from_db()

        self.assertTrue(
            credential.enabled,
        )

    def test_update_secret_replaces_encrypted_value(self):
        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
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

    def test_update_secret_updates_fingerprint(self):
        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret="old-secret",
        )

        old_fingerprint = credential.fingerprint

        IntegrationCredentialService.update_secret(
            credential,
            "new-secret",
        )

        credential.refresh_from_db()

        self.assertNotEqual(
            credential.fingerprint,
            old_fingerprint,
        )

        self.assertEqual(
            credential.fingerprint,
            ApiKeyFingerprintService.generate(
                "new-secret"
            ),
        )