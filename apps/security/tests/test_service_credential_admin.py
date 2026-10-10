from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from apps.security.models import Service, ServiceCredential
from apps.security.services.service_credentials import (
    ServiceCredentialService,
)


User = get_user_model()


class ServiceCredentialAdminTests(TestCase):
    def setUp(self):
        self.admin_user = User.objects.create_superuser(
            email="admin@example.com",
            password="admin-password-123",
        )

        self.client.force_login(self.admin_user)

        self.service = Service.objects.create(
            name="Composition Engine",
        )

        self.add_url = reverse(
            "admin:security_servicecredential_add",
        )

    def test_admin_add_form_displays_generate_token_field(self):
        response = self.client.get(self.add_url)

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertContains(
            response,
            "Gerar token de acesso",
        )

        self.assertContains(
            response,
            "O token será exibido uma única vez",
        )

    def test_admin_creation_generates_and_displays_token(self):
        response = self.client.post(
            self.add_url,
            {
                "service": str(self.service.pk),
                "name": "Production",
                "enabled": "on",
                "expires_at": "",
                "generate_token": "on",
                "_save": "Salvar",
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        credential = ServiceCredential.objects.get(
            service=self.service,
            name="Production",
        )

        self.assertContains(
            response,
            "Token de acesso gerado",
        )

        token = getattr(
            response.wsgi_request,
            "_generated_service_credential_token",
            None,
        )

        self.assertTrue(token)

        self.assertNotEqual(
            credential.token_hash,
            token,
        )

    def test_admin_creation_token_is_authenticable(self):
        response = self.client.post(
            self.add_url,
            {
                "service": str(self.service.pk),
                "name": "Production",
                "enabled": "on",
                "expires_at": "",
                "generate_token": "on",
                "_save": "Salvar",
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        credential = ServiceCredential.objects.get(
            service=self.service,
            name="Production",
        )

        token = getattr(
            response.wsgi_request,
            "_generated_service_credential_token",
            None,
        )

        self.assertTrue(token)

        authenticated = ServiceCredentialService.authenticate(
            token=token,
        )

        self.assertEqual(
            authenticated,
            credential,
        )

    def test_admin_does_not_store_plaintext_token(self):
        response = self.client.post(
            self.add_url,
            {
                "service": str(self.service.pk),
                "name": "Production",
                "enabled": "on",
                "expires_at": "",
                "generate_token": "on",
                "_save": "Salvar",
            },
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        token = getattr(
            response.wsgi_request,
            "_generated_service_credential_token",
            None,
        )

        credential = ServiceCredential.objects.get(
            service=self.service,
            name="Production",
        )

        self.assertTrue(token)
        self.assertTrue(credential.token_hash)

        self.assertNotEqual(
            credential.token_hash,
            token,
        )

    def test_admin_creation_without_generate_token_does_not_display_token(
        self,
    ):
        response = self.client.post(
            self.add_url,
            {
                "service": str(self.service.pk),
                "name": "Production",
                "enabled": "on",
                "expires_at": "",
                "_save": "Salvar",
            },
        )

        self.assertEqual(
            response.status_code,
            302,
        )

        credential = ServiceCredential.objects.get(
            service=self.service,
            name="Production",
        )

        self.assertTrue(
            credential.token_hash,
        )

        self.assertNotIn(
            "_generated_service_credential_token",
            response.wsgi_request.__dict__,
        )

    def test_admin_does_not_expose_token_on_change_form(self):
        credential, token = ServiceCredentialService.create(
            name="Production",
            service=self.service,
        )

        change_url = reverse(
            "admin:security_servicecredential_change",
            args=(credential.pk,),
        )

        response = self.client.get(
            change_url,
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertNotContains(
            response,
            token,
        )

    def test_admin_does_not_expose_token_in_changelist(self):
        credential, token = ServiceCredentialService.create(
            name="Production",
            service=self.service,
        )

        list_url = reverse(
            "admin:security_servicecredential_changelist",
        )

        response = self.client.get(
            list_url,
        )

        self.assertEqual(
            response.status_code,
            200,
        )

        self.assertNotContains(
            response,
            token,
        )

    def test_generated_token_is_different_for_each_credential(self):
        first_response = self.client.post(
            self.add_url,
            {
                "service": str(self.service.pk),
                "name": "Production",
                "enabled": "on",
                "expires_at": "",
                "generate_token": "on",
                "_save": "Salvar",
            },
        )

        first_token = getattr(
            first_response.wsgi_request,
            "_generated_service_credential_token",
            None,
        )

        second_response = self.client.post(
            self.add_url,
            {
                "service": str(self.service.pk),
                "name": "Homologation",
                "enabled": "on",
                "expires_at": "",
                "generate_token": "on",
                "_save": "Salvar",
            },
        )

        second_token = getattr(
            second_response.wsgi_request,
            "_generated_service_credential_token",
            None,
        )

        self.assertTrue(first_token)
        self.assertTrue(second_token)

        self.assertNotEqual(
            first_token,
            second_token,
        )

    def test_token_is_not_present_in_database_as_plaintext(self):
        response = self.client.post(
            self.add_url,
            {
                "service": str(self.service.pk),
                "name": "Production",
                "enabled": "on",
                "expires_at": "",
                "generate_token": "on",
                "_save": "Salvar",
            },
        )

        token = getattr(
            response.wsgi_request,
            "_generated_service_credential_token",
            None,
        )

        credential = ServiceCredential.objects.get(
            name="Production",
            service=self.service,
        )

        self.assertTrue(token)

        self.assertNotEqual(
            credential.token_hash,
            token,
        )

        self.assertNotIn(
            token,
            credential.token_hash,
        )