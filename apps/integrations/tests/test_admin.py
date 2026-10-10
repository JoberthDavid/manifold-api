from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.integrations.models import (
    CredentialType,
    HttpMethod,
    Integration,
    IntegrationCredential,
    IntegrationOperation,
)
from apps.integrations.services.integration_credentials import (
    IntegrationCredentialService,
)


TEST_ENCRYPTION_KEY = Fernet.generate_key().decode()


@override_settings(
    MANIFOLD_CREDENTIAL_ENCRYPTION_KEY=TEST_ENCRYPTION_KEY
)
class IntegrationAdminTests(TestCase):

    def setUp(self):
        self.user = get_user_model().objects.create_user(
            email="admin@example.com",
            password="StrongPassword123!",
            is_staff=True,
            is_active=True,
        )

        integration_permissions = Permission.objects.filter(
            content_type__app_label="integrations",
            content_type__model__in=(
                "integration",
                "integrationoperation",
            ),
            codename__in=(
                "add_integration",
                "change_integration",
                "delete_integration",
                "view_integration",
                "add_integrationoperation",
                "change_integrationoperation",
                "delete_integrationoperation",
                "view_integrationoperation",
            ),
        )

        self.user.user_permissions.set(integration_permissions)

        self.client.force_login(self.user)

        self.integration = Integration.objects.create(
            name="SICRO API",
            base_url="https://example.com",
        )

    def test_integration_admin_page_is_accessible(self):
        url = reverse(
            "admin:integrations_integration_change",
            args=[self.integration.id],
        )

        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.integration.name)

    def test_credential_add_page_is_accessible(self):
        url = reverse(
            "admin:integrations_integration_credential_add",
            args=[self.integration.id],
        )

        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            "Adicionar credencial",
        )
        self.assertContains(
            response,
            self.integration.name,
        )

    def test_create_credential_through_admin(self):
        url = reverse(
            "admin:integrations_integration_credential_add",
            args=[self.integration.id],
        )

        response = self.client.post(
            url,
            {
                "name": "Chave principal",
                "credential_type": CredentialType.API_KEY,
                "secret": "sicro-secret-api-key",
                "enabled": "on",
            },
        )

        self.assertEqual(response.status_code, 302)

        credential = IntegrationCredential.objects.get(
            integration=self.integration,
            name="Chave principal",
        )

        self.assertNotEqual(
            credential.encrypted_value,
            "sicro-secret-api-key",
        )

        self.assertEqual(
            IntegrationCredentialService.get_secret(credential),
            "sicro-secret-api-key",
        )

    def test_create_disabled_credential_through_admin(self):
        url = reverse(
            "admin:integrations_integration_credential_add",
            args=[self.integration.id],
        )

        response = self.client.post(
            url,
            {
                "name": "Chave reserva",
                "credential_type": CredentialType.API_KEY,
                "secret": "backup-secret",
            },
        )

        self.assertEqual(response.status_code, 302)

        credential = IntegrationCredential.objects.get(
            integration=self.integration,
            name="Chave reserva",
        )

        self.assertFalse(credential.enabled)

    def test_secret_is_not_exposed_in_form_response(self):
        url = reverse(
            "admin:integrations_integration_credential_add",
            args=[self.integration.id],
        )

        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)

        self.assertNotContains(
            response,
            "sicro-secret-api-key",
        )

        self.assertNotContains(
            response,
            "encrypted_value",
        )

    def test_credential_admin_crud_is_disabled(self):
        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Chave principal",
            credential_type=CredentialType.API_KEY,
            secret="sicro-secret-api-key",
        )

        change_url = reverse(
            "admin:integrations_integrationcredential_change",
            args=[credential.id],
        )

        response = self.client.get(change_url)

        self.assertEqual(response.status_code, 403)

        delete_url = reverse(
            "admin:integrations_integrationcredential_delete",
            args=[credential.id],
        )

        response = self.client.get(delete_url)

        self.assertEqual(response.status_code, 403)

    def test_operation_is_displayed_in_integration_admin(self):
        operation = IntegrationOperation.objects.create(
            integration=self.integration,
            name="Consultar item",
            http_method=HttpMethod.GET,
            path="/itens/",
        )

        url = reverse(
            "admin:integrations_integration_change",
            args=[self.integration.id],
        )

        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, operation.name)
        self.assertContains(response, operation.slug)
        self.assertContains(response, operation.path)