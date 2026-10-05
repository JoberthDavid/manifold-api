from django.test import TestCase

from apps.integrations.models import (
    CredentialType,
    Integration,
    IntegrationCredential,
    IntegrationType,
)
from apps.integrations.services.api_key_fingerprint import (
    ApiKeyFingerprintService,
)


class IntegrationModelTests(TestCase):
    def test_create_integration(self):
        integration = Integration.objects.create(
            code="SICRO",
            name="SICRO API",
            integration_type=IntegrationType.REST_API,
            base_url="https://example.com",
        )

        self.assertIsNotNone(integration.id)
        self.assertEqual(integration.code, "SICRO")
        self.assertEqual(integration.base_url, "https://example.com")
        self.assertTrue(integration.enabled)
        self.assertEqual(integration.timeout, 10)

    def test_integration_code_must_be_unique(self):
        Integration.objects.create(
            code="SICRO",
            name="SICRO API",
            base_url="https://example.com",
        )

        with self.assertRaises(Exception):
            Integration.objects.create(
                code="SICRO",
                name="Outra SICRO API",
                base_url="https://other.example.com",
            )

    def test_create_integration_credential(self):
        integration = Integration.objects.create(
            code="SICRO",
            name="SICRO API",
            base_url="https://example.com",
        )

        credential = IntegrationCredential.objects.create(
            integration=integration,
            name="Chave principal",
            credential_type=CredentialType.API_KEY,
            encrypted_value="encrypted-value",
        )

        self.assertIsNotNone(credential.id)
        self.assertEqual(credential.integration, integration)
        self.assertEqual(credential.credential_type, CredentialType.API_KEY)
        self.assertTrue(credential.enabled)

    def test_integration_can_have_multiple_credentials(self):
        integration = Integration.objects.create(
            code="SICRO",
            name="SICRO API",
            base_url="https://example.com",
        )

        secret_1 = "secret-1"
        secret_2 = "secret-2"

        IntegrationCredential.objects.create(
            integration=integration,
            name="Credencial 1",
            credential_type=CredentialType.API_KEY,
            encrypted_value="encrypted-secret-1",
            fingerprint=ApiKeyFingerprintService.generate(secret_1),
        )

        IntegrationCredential.objects.create(
            integration=integration,
            name="Credencial 2",
            credential_type=CredentialType.API_KEY,
            encrypted_value="encrypted-secret-2",
            fingerprint=ApiKeyFingerprintService.generate(secret_2),
        )

        self.assertEqual(integration.credentials.count(), 2)