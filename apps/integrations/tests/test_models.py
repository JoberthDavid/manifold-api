from django.db import IntegrityError
from django.test import TestCase

from apps.integrations.models import (
    CredentialType,
    HttpMethod,
    Integration,
    IntegrationCredential,
    IntegrationOperation,
    IntegrationType,
)
from apps.integrations.services.api_key_fingerprint import (
    ApiKeyFingerprintService,
)


class IntegrationModelTests(TestCase):
    def test_create_integration(self):
        integration = Integration.objects.create(
            name="SICRO API",
            integration_type=IntegrationType.REST_API,
            base_url="https://example.com",
        )

        self.assertIsNotNone(integration.id)
        self.assertEqual(integration.name, "SICRO API")
        self.assertEqual(integration.slug, "sicro-api")
        self.assertEqual(
            integration.authentication_type,
            "NONE",
        )
        self.assertEqual(integration.base_url, "https://example.com")
        self.assertTrue(integration.enabled)
        self.assertEqual(integration.timeout, 10)

    def test_integration_slug_is_generated_automatically(self):
        integration = Integration.objects.create(
            name="Composition Engine",
            base_url="https://example.com",
        )

        self.assertEqual(integration.slug, "composition-engine")

    def test_integration_slug_is_unique(self):
        first = Integration.objects.create(
            name="SICRO API",
            base_url="https://example.com",
        )

        second = Integration.objects.create(
            name="SICRO API",
            base_url="https://other.example.com",
        )

        self.assertEqual(first.slug, "sicro-api")
        self.assertEqual(second.slug, "sicro-api-2")

    def test_integration_slug_is_stable_after_name_change(self):
        integration = Integration.objects.create(
            name="SICRO API",
            base_url="https://example.com",
        )

        self.assertEqual(integration.slug, "sicro-api")

        integration.name = "SICRO API Produção"
        integration.save()

        integration.refresh_from_db()

        self.assertEqual(integration.name, "SICRO API Produção")
        self.assertEqual(integration.slug, "sicro-api")

    def test_integration_slug_falls_back_when_name_has_no_slug(self):
        integration = Integration.objects.create(
            name="!!!",
            base_url="https://example.com",
        )

        self.assertEqual(integration.slug, "integration")

    def test_create_integration_credential(self):
        integration = Integration.objects.create(
            name="SICRO API",
            base_url="https://example.com",
        )

        credential = IntegrationCredential.objects.create(
            integration=integration,
            name="Chave principal",
            credential_type=CredentialType.API_KEY,
            encrypted_value="encrypted-value",
            fingerprint=ApiKeyFingerprintService.generate("secret"),
        )

        self.assertIsNotNone(credential.id)
        self.assertEqual(credential.integration, integration)
        self.assertEqual(credential.credential_type, CredentialType.API_KEY)
        self.assertTrue(credential.enabled)

    def test_integration_can_have_multiple_credentials(self):
        integration = Integration.objects.create(
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

    def test_credential_fingerprint_must_be_unique(self):
        integration = Integration.objects.create(
            name="SICRO API",
            base_url="https://example.com",
        )

        fingerprint = ApiKeyFingerprintService.generate("same-secret")

        IntegrationCredential.objects.create(
            integration=integration,
            name="Credencial 1",
            credential_type=CredentialType.API_KEY,
            encrypted_value="encrypted-secret-1",
            fingerprint=fingerprint,
        )

        with self.assertRaises(IntegrityError):
            IntegrationCredential.objects.create(
                integration=integration,
                name="Credencial 2",
                credential_type=CredentialType.API_KEY,
                encrypted_value="encrypted-secret-2",
                fingerprint=fingerprint,
            )


class IntegrationOperationModelTests(TestCase):
    def test_create_operation(self):
        integration = Integration.objects.create(
            name="Composition Engine",
            base_url="https://example.com",
        )

        operation = IntegrationOperation.objects.create(
            integration=integration,
            name="Calcular composição",
            http_method=HttpMethod.POST,
            path="/compositions/{composition_code}/calculate",
        )

        self.assertIsNotNone(operation.id)
        self.assertEqual(operation.name, "Calcular composição")
        self.assertEqual(operation.slug, "calcular-composicao")
        self.assertEqual(operation.http_method, HttpMethod.POST)
        self.assertEqual(
            operation.path,
            "/compositions/{composition_code}/calculate",
        )
        self.assertEqual(operation.request_schema, {})
        self.assertTrue(operation.enabled)

    def test_operation_slug_is_generated_automatically(self):
        integration = Integration.objects.create(
            name="Composition Engine",
            base_url="https://example.com",
        )

        operation = IntegrationOperation.objects.create(
            integration=integration,
            name="Explosão da composição",
            http_method=HttpMethod.GET,
            path="/compositions/{composition_code}/explosion",
        )

        self.assertEqual(operation.slug, "explosao-da-composicao")

    def test_operation_slug_is_unique_within_integration(self):
        integration = Integration.objects.create(
            name="Composition Engine",
            base_url="https://example.com",
        )

        first = IntegrationOperation.objects.create(
            integration=integration,
            name="Calcular composição",
            http_method=HttpMethod.POST,
            path="/compositions/{composition_code}/calculate",
        )

        second = IntegrationOperation.objects.create(
            integration=integration,
            name="Calcular composição",
            http_method=HttpMethod.POST,
            path="/compositions/{composition_code}/calculate-v2",
        )

        self.assertEqual(first.slug, "calcular-composicao")
        self.assertEqual(second.slug, "calcular-composicao-2")

    def test_same_operation_slug_can_exist_in_different_integrations(self):
        first_integration = Integration.objects.create(
            name="Composition Engine",
            base_url="https://composition.example.com",
        )

        second_integration = Integration.objects.create(
            name="Another Engine",
            base_url="https://another.example.com",
        )

        first_operation = IntegrationOperation.objects.create(
            integration=first_integration,
            name="Calcular",
            http_method=HttpMethod.POST,
            path="/calculate",
        )

        second_operation = IntegrationOperation.objects.create(
            integration=second_integration,
            name="Calcular",
            http_method=HttpMethod.POST,
            path="/calculate",
        )

        self.assertEqual(first_operation.slug, "calcular")
        self.assertEqual(second_operation.slug, "calcular")

    def test_operation_slug_is_stable_after_name_change(self):
        integration = Integration.objects.create(
            name="Composition Engine",
            base_url="https://example.com",
        )

        operation = IntegrationOperation.objects.create(
            integration=integration,
            name="Calcular composição",
            http_method=HttpMethod.POST,
            path="/calculate",
        )

        self.assertEqual(operation.slug, "calcular-composicao")

        operation.name = "Calcular composição completa"
        operation.save()

        operation.refresh_from_db()

        self.assertEqual(operation.name, "Calcular composição completa")
        self.assertEqual(operation.slug, "calcular-composicao")

    def test_operation_slug_falls_back_when_name_has_no_slug(self):
        integration = Integration.objects.create(
            name="Composition Engine",
            base_url="https://example.com",
        )

        operation = IntegrationOperation.objects.create(
            integration=integration,
            name="!!!",
            http_method=HttpMethod.GET,
            path="/health",
        )

        self.assertEqual(operation.slug, "operation")

    def test_integration_has_related_operations(self):
        integration = Integration.objects.create(
            name="Composition Engine",
            base_url="https://example.com",
        )

        IntegrationOperation.objects.create(
            integration=integration,
            name="Calcular composição",
            http_method=HttpMethod.POST,
            path="/calculate",
        )

        IntegrationOperation.objects.create(
            integration=integration,
            name="Explosão",
            http_method=HttpMethod.GET,
            path="/explosion",
        )

        self.assertEqual(integration.operations.count(), 2)