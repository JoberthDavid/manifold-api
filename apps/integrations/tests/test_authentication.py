from django.test import TestCase

from apps.integrations.authentication import (
    IntegrationAuthenticationResolver,
)
from apps.integrations.exceptions import (
    IntegrationCredentialError,
    IntegrationNotConfiguredError,
)
from apps.integrations.models import (
    AuthenticationType,
    CredentialType,
    Integration,
)
from apps.integrations.services.integration_credentials import (
    IntegrationCredentialService,
)


class IntegrationAuthenticationResolverTests(TestCase):

    def make_integration(self, authentication_type):
        return Integration.objects.create(
            name="Test Integration",
            base_url="https://api.example.com",
            authentication_type=authentication_type,
            timeout=10,
        )

    def create_credential(
        self,
        integration,
        credential_type,
        secret,
        name="Production",
    ):
        return IntegrationCredentialService.create(
            integration=integration,
            name=name,
            credential_type=credential_type,
            secret=secret,
        )

    def test_none_authentication(self):
        integration = self.make_integration(
            AuthenticationType.NONE
        )

        result = IntegrationAuthenticationResolver(
            integration
        ).resolve()

        self.assertEqual(
            result,
            {
                "headers": {},
                "auth": None,
            },
        )

    def test_api_key_authentication(self):
        integration = self.make_integration(
            AuthenticationType.API_KEY
        )

        self.create_credential(
            integration,
            CredentialType.API_KEY,
            "secret-key",
        )

        result = IntegrationAuthenticationResolver(
            integration
        ).resolve(
            authentication_config={
                "credential": "Production",
                "header": "X-API-Key",
            },
        )

        self.assertEqual(
            result["headers"],
            {
                "X-API-Key": "secret-key",
            },
        )

        self.assertIsNone(result["auth"])

    def test_api_key_uses_default_header(self):
        integration = self.make_integration(
            AuthenticationType.API_KEY
        )

        self.create_credential(
            integration,
            CredentialType.API_KEY,
            "secret-key",
        )

        result = IntegrationAuthenticationResolver(
            integration
        ).resolve(
            authentication_config={
                "credential": "Production",
            },
        )

        self.assertEqual(
            result["headers"],
            {
                "X-API-Key": "secret-key",
            },
        )

    def test_api_key_without_credential_configuration_raises_error(self):
        integration = self.make_integration(
            AuthenticationType.API_KEY
        )

        with self.assertRaises(IntegrationNotConfiguredError):
            IntegrationAuthenticationResolver(
                integration
            ).resolve(
                authentication_config={},
            )

    def test_bearer_token_authentication(self):
        integration = self.make_integration(
            AuthenticationType.BEARER_TOKEN
        )

        self.create_credential(
            integration,
            CredentialType.BEARER_TOKEN,
            "abc123",
        )

        result = IntegrationAuthenticationResolver(
            integration
        ).resolve(
            authentication_config={
                "credential": "Production",
            },
        )

        self.assertEqual(
            result["headers"],
            {
                "Authorization": "Bearer abc123",
            },
        )

    def test_bearer_token_missing_credential_raises_error(self):
        integration = self.make_integration(
            AuthenticationType.BEARER_TOKEN
        )

        with self.assertRaises(IntegrationNotConfiguredError):
            IntegrationAuthenticationResolver(
                integration
            ).resolve(
                authentication_config={},
            )

    def test_basic_authentication(self):
        integration = self.make_integration(
            AuthenticationType.BASIC_AUTH
        )

        self.create_credential(
            integration,
            CredentialType.BASIC_AUTH,
            '{"username":"admin","password":"secret"}',
        )

        result = IntegrationAuthenticationResolver(
            integration
        ).resolve(
            authentication_config={
                "credential": "Production",
            },
        )

        self.assertEqual(
            result["auth"],
            (
                "admin",
                "secret",
            ),
        )

    def test_basic_auth_invalid_json_raises_error(self):
        integration = self.make_integration(
            AuthenticationType.BASIC_AUTH
        )

        self.create_credential(
            integration,
            CredentialType.BASIC_AUTH,
            "invalid-json",
        )

        with self.assertRaises(IntegrationCredentialError):
            IntegrationAuthenticationResolver(
                integration
            ).resolve(
                authentication_config={
                    "credential": "Production",
                },
            )

    def test_basic_auth_missing_username_raises_error(self):
        integration = self.make_integration(
            AuthenticationType.BASIC_AUTH
        )

        self.create_credential(
            integration,
            CredentialType.BASIC_AUTH,
            '{"password":"secret"}',
        )

        with self.assertRaises(IntegrationCredentialError):
            IntegrationAuthenticationResolver(
                integration
            ).resolve(
                authentication_config={
                    "credential": "Production",
                },
            )

    def test_basic_auth_missing_password_raises_error(self):
        integration = self.make_integration(
            AuthenticationType.BASIC_AUTH
        )

        self.create_credential(
            integration,
            CredentialType.BASIC_AUTH,
            '{"username":"admin"}',
        )

        with self.assertRaises(IntegrationCredentialError):
            IntegrationAuthenticationResolver(
                integration
            ).resolve(
                authentication_config={
                    "credential": "Production",
                },
            )

    def test_oauth2_is_not_implemented_yet(self):
        integration = self.make_integration(
            AuthenticationType.OAUTH2
        )

        with self.assertRaises(IntegrationNotConfiguredError):
            IntegrationAuthenticationResolver(
                integration
            ).resolve()

    def test_manifold_jwt_requires_audience(self):
        integration = self.make_integration(
            AuthenticationType.MANIFOLD_JWT
        )

        with self.assertRaises(IntegrationNotConfiguredError):
            IntegrationAuthenticationResolver(
                integration
            ).resolve(
                authentication_config={
                    "scopes": ["composition:calculate"],
                },
                subject="user:123",
            )

    def test_manifold_jwt_requires_scopes(self):
        integration = self.make_integration(
            AuthenticationType.MANIFOLD_JWT
        )

        with self.assertRaises(IntegrationNotConfiguredError):
            IntegrationAuthenticationResolver(
                integration
            ).resolve(
                authentication_config={
                    "audience": "composition-engine",
                },
                subject="user:123",
            )

    def test_manifold_jwt_resolves_configuration(self):
        integration = self.make_integration(
            AuthenticationType.MANIFOLD_JWT
        )

        result = IntegrationAuthenticationResolver(
            integration
        ).resolve(
            authentication_config={
                "audience": "composition-engine",
                "scopes": [
                    "composition:calculate",
                    "composition:explosion",
                ],
            },
            subject="user:123",
        )

        self.assertEqual(
            result["jwt"],
            {
                "subject": "user:123",
                "audience": "composition-engine",
                "scopes": [
                    "composition:calculate",
                    "composition:explosion",
                ],
            },
        )

    def test_invalid_integration_raises_error(self):
        with self.assertRaises(IntegrationNotConfiguredError):
            IntegrationAuthenticationResolver(None)