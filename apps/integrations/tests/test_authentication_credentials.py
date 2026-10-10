from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.integrations.authentication import (
    IntegrationAuthenticationResolver,
)
from apps.integrations.exceptions import (
    IntegrationCredentialError,
)
from apps.integrations.models import (
    AuthenticationType,
    CredentialType,
    Integration,
)
from apps.integrations.services.integration_credentials import (
    IntegrationCredentialService,
)


class IntegrationAuthenticationCredentialsTests(TestCase):

    def setUp(self):
        self.integration = Integration.objects.create(
            name="Protected API",
            base_url="https://api.example.com",
            authentication_type=AuthenticationType.API_KEY,
            timeout=10,
        )

        self.resolver = IntegrationAuthenticationResolver(
            self.integration
        )

    def test_api_key_can_be_created_and_retrieved(self):
        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret="secret-api-key",
        )

        self.assertEqual(
            IntegrationCredentialService.get_secret(credential),
            "secret-api-key",
        )

    def test_api_key_is_stored_encrypted(self):
        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret="secret-api-key",
        )

        self.assertNotEqual(
            credential.encrypted_value,
            "secret-api-key",
        )

    def test_resolver_should_use_integration_credential(self):
        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret="secret-api-key",
        )

        result = self.resolver.resolve(
            authentication_config={
                "credential": credential.name,
                "header": "X-API-Key",
            },
            parameters={},
        )

        self.assertEqual(
            result["headers"],
            {
                "X-API-Key": "secret-api-key",
            },
        )

    def test_resolver_should_not_require_secret_in_parameters(self):
        IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret="secret-api-key",
        )

        result = self.resolver.resolve(
            authentication_config={
                "credential": "Production",
                "header": "X-API-Key",
            },
            parameters={},
        )

        self.assertEqual(
            result["headers"]["X-API-Key"],
            "secret-api-key",
        )

    def test_resolver_rejects_missing_credential(self):
        with self.assertRaises(IntegrationCredentialError):
            self.resolver.resolve(
                authentication_config={
                    "credential": "Production",
                    "header": "X-API-Key",
                },
                parameters={},
            )

    def test_resolver_rejects_disabled_credential(self):
        credential = IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret="secret-api-key",
        )

        IntegrationCredentialService.disable(credential)

        with self.assertRaises(IntegrationCredentialError):
            self.resolver.resolve(
                authentication_config={
                    "credential": credential.name,
                    "header": "X-API-Key",
                },
                parameters={},
            )

    def test_resolver_rejects_expired_credential(self):
        IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret="secret-api-key",
            expires_at=timezone.now() - timedelta(minutes=1),
        )

        with self.assertRaises(IntegrationCredentialError):
            self.resolver.resolve(
                authentication_config={
                    "credential": "Production",
                    "header": "X-API-Key",
                },
                parameters={},
            )

    def test_credential_must_belong_to_integration(self):
        other_integration = Integration.objects.create(
            name="Other API",
            base_url="https://other.example.com",
            authentication_type=AuthenticationType.API_KEY,
        )

        IntegrationCredentialService.create(
            integration=other_integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret="other-secret",
        )

        with self.assertRaises(IntegrationCredentialError):
            self.resolver.resolve(
                authentication_config={
                    "credential": "Production",
                    "header": "X-API-Key",
                },
                parameters={},
            )

    def test_credential_type_must_match_authentication_type(self):
        IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.BEARER_TOKEN,
            secret="token",
        )

        with self.assertRaises(IntegrationCredentialError):
            self.resolver.resolve(
                authentication_config={
                    "credential": "Production",
                },
                parameters={},
            )

    def test_bearer_token_uses_stored_credential(self):
        self.integration.authentication_type = (
            AuthenticationType.BEARER_TOKEN
        )
        self.integration.save(
            update_fields=["authentication_type"]
        )

        IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.BEARER_TOKEN,
            secret="secret-token",
        )

        result = self.resolver.resolve(
            authentication_config={
                "credential": "Production",
            },
            parameters={},
        )

        self.assertEqual(
            result["headers"],
            {
                "Authorization": "Bearer secret-token",
            },
        )

    def test_basic_auth_uses_stored_credential(self):
        self.integration.authentication_type = (
            AuthenticationType.BASIC_AUTH
        )
        self.integration.save(
            update_fields=["authentication_type"]
        )

        IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.BASIC_AUTH,
            secret='{"username":"admin","password":"secret"}',
        )

        result = self.resolver.resolve(
            authentication_config={
                "credential": "Production",
            },
            parameters={},
        )

        self.assertEqual(
            result["auth"],
            (
                "admin",
                "secret",
            ),
        )
