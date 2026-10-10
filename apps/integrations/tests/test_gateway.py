import jwt

from unittest.mock import Mock, patch

from django.test import TestCase

from apps.integrations.exceptions import (
    IntegrationCredentialError,
    IntegrationNotConfiguredError,
)
from apps.integrations.gateway import IntegrationGateway
from apps.integrations.services.integration_credentials import (
    IntegrationCredentialService,
)
from apps.integrations.models import (
    AuthenticationType,
    CredentialType,
    HttpMethod,
    Integration,
    IntegrationOperation,
)
from apps.security.services.jwt_keys import JwtSigningKeyService
from django.test import LiveServerTestCase
from django.test.utils import override_settings

from apps.security.services.jwks_client import JwksClient


class IntegrationGatewayTests(LiveServerTestCase):

    def setUp(self):
        self.signing_key = JwtSigningKeyService.generate()

        self.jwks_url = (
            f"{self.live_server_url}"
            "/.well-known/jwks.json"
        )

        self.override_jwks_url = override_settings(
            MANIFOLD_JWKS_URL=self.jwks_url
        )
        self.override_jwks_url.enable()
        self.addCleanup(self.override_jwks_url.disable)
        self.integration = Integration.objects.create(
            name="Test API",
            base_url="https://api.example.com",
            authentication_type=AuthenticationType.NONE,
            timeout=10,
        )

        self.operation = IntegrationOperation.objects.create(
            integration=self.integration,
            name="Get Resource",
            http_method=HttpMethod.GET,
            path="/resources/{resource_id}",
            request_schema={
                "query": {
                    "page": "page",
                    "limit": "limit",
                },
                "headers": {
                    "X-Test": "test_header",
                },
            },
        )

        self.gateway = IntegrationGateway(self.integration)

    @staticmethod
    def _response(
        *,
        status_code=200,
        content=b'{"result": "ok"}',
        headers=None,
        json_data=None,
    ):
        response = Mock()
        response.status_code = status_code
        response.content = content
        response.headers = headers or {
            "Content-Type": "application/json",
        }

        if json_data is None:
            response.json.return_value = {
                "result": "ok",
            }
        else:
            response.json.return_value = json_data

        response.raise_for_status.side_effect = (
            None
            if status_code < 400
            else __import__("requests").HTTPError(
                f"HTTP {status_code}"
            )
        )

        return response

    @patch("apps.integrations.gateway.requests.request")
    def test_get_request_builds_path_query_and_headers(
        self,
        request,
    ):
        request.return_value = self._response()

        result = self.gateway.execute(
            operation=self.operation,
            parameters={
                "resource_id": "123",
                "page": "2",
                "limit": "20",
                "test_header": "abc",
            },
        )

        request.assert_called_once_with(
            method="GET",
            url="https://api.example.com/resources/123",
            timeout=10,
            params={
                "page": "2",
                "limit": "20",
            },
            headers={
                "X-Test": "abc",
            },
        )

        self.assertEqual(
            result,
            {
                "result": "ok",
            },
        )

    @patch("apps.integrations.gateway.requests.request")
    def test_post_request_builds_json_body(
        self,
        request,
    ):
        operation = IntegrationOperation.objects.create(
            integration=self.integration,
            name="Create Resource",
            http_method=HttpMethod.POST,
            path="/resources",
            request_schema={
                "body": {
                    "name": "name",
                    "value": "value",
                },
            },
        )

        request.return_value = self._response()

        self.gateway.execute(
            operation=operation,
            parameters={
                "name": "Example",
                "value": "100",
            },
        )

        request.assert_called_once_with(
            method="POST",
            url="https://api.example.com/resources",
            timeout=10,
            params={},
            headers={},
            json={
                "name": "Example",
                "value": "100",
            },
        )

    @patch("apps.integrations.gateway.requests.request")
    def test_request_without_optional_sections(
        self,
        request,
    ):
        operation = IntegrationOperation.objects.create(
            integration=self.integration,
            name="Health",
            http_method=HttpMethod.GET,
            path="/health",
            request_schema={},
        )

        request.return_value = self._response()

        self.gateway.execute(
            operation=operation,
            parameters={},
        )

        request.assert_called_once_with(
            method="GET",
            url="https://api.example.com/health",
            timeout=10,
            params={},
            headers={},
        )

    def test_missing_path_parameter(self):
        with self.assertRaises(IntegrationNotConfiguredError):
            self.gateway.execute(
                operation=self.operation,
                parameters={
                    "page": "1",
                    "limit": "10",
                    "test_header": "abc",
                },
            )

    def test_missing_query_parameter(self):
        with self.assertRaises(IntegrationNotConfiguredError):
            self.gateway.execute(
                operation=self.operation,
                parameters={
                    "resource_id": "123",
                    "limit": "10",
                    "test_header": "abc",
                },
            )

    def test_missing_header_parameter(self):
        with self.assertRaises(IntegrationNotConfiguredError):
            self.gateway.execute(
                operation=self.operation,
                parameters={
                    "resource_id": "123",
                    "page": "1",
                    "limit": "10",
                },
            )

    def test_operation_belongs_to_another_integration(self):
        other_integration = Integration.objects.create(
            name="Other API",
            base_url="https://other.example.com",
        )

        operation = IntegrationOperation.objects.create(
            integration=other_integration,
            name="Other Operation",
            http_method=HttpMethod.GET,
            path="/other",
        )

        with self.assertRaises(IntegrationNotConfiguredError):
            self.gateway.execute(
                operation=operation,
            )

    def test_disabled_integration(self):
        self.integration.enabled = False
        self.integration.save(update_fields=["enabled"])

        with self.assertRaises(IntegrationNotConfiguredError):
            IntegrationGateway(self.integration)

    def test_disabled_operation(self):
        self.operation.enabled = False
        self.operation.save(update_fields=["enabled"])

        with self.assertRaises(IntegrationNotConfiguredError):
            self.gateway.execute(
                operation=self.operation,
                parameters={
                    "resource_id": "123",
                    "page": "1",
                    "limit": "10",
                    "test_header": "abc",
                },
            )

    @patch("apps.integrations.gateway.requests.request")
    def test_timeout(
        self,
        request,
    ):
        import requests

        request.side_effect = requests.Timeout()

        with self.assertRaises(IntegrationNotConfiguredError):
            self.gateway.execute(
                operation=self.operation,
                parameters={
                    "resource_id": "123",
                    "page": "1",
                    "limit": "10",
                    "test_header": "abc",
                },
            )

    @patch("apps.integrations.gateway.requests.request")
    def test_request_exception(
        self,
        request,
    ):
        import requests

        request.side_effect = requests.RequestException()

        with self.assertRaises(IntegrationNotConfiguredError):
            self.gateway.execute(
                operation=self.operation,
                parameters={
                    "resource_id": "123",
                    "page": "1",
                    "limit": "10",
                    "test_header": "abc",
                },
            )

    @patch("apps.integrations.gateway.requests.request")
    def test_401_raises_credential_error(
        self,
        request,
    ):
        request.return_value = self._response(
            status_code=401,
            content=b"",
        )

        with self.assertRaises(IntegrationCredentialError):
            self.gateway.execute(
                operation=self.operation,
                parameters={
                    "resource_id": "123",
                    "page": "1",
                    "limit": "10",
                    "test_header": "abc",
                },
            )

    @patch("apps.integrations.gateway.requests.request")
    def test_403_raises_credential_error(
        self,
        request,
    ):
        request.return_value = self._response(
            status_code=403,
            content=b"",
        )

        with self.assertRaises(IntegrationCredentialError):
            self.gateway.execute(
                operation=self.operation,
                parameters={
                    "resource_id": "123",
                    "page": "1",
                    "limit": "10",
                    "test_header": "abc",
                },
            )

    @patch("apps.integrations.gateway.requests.request")
    def test_other_http_error(
        self,
        request,
    ):
        request.return_value = self._response(
            status_code=500,
            content=b"",
        )

        with self.assertRaises(IntegrationNotConfiguredError):
            self.gateway.execute(
                operation=self.operation,
                parameters={
                    "resource_id": "123",
                    "page": "1",
                    "limit": "10",
                    "test_header": "abc",
                },
            )

    @patch("apps.integrations.gateway.requests.request")
    def test_json_response(
        self,
        request,
    ):
        request.return_value = self._response(
            json_data={
                "id": 123,
            },
        )

        result = self.gateway.execute(
            operation=self.operation,
            parameters={
                "resource_id": "123",
                "page": "1",
                "limit": "10",
                "test_header": "abc",
            },
        )

        self.assertEqual(
            result,
            {
                "id": 123,
            },
        )

    @patch("apps.integrations.gateway.requests.request")
    def test_text_response(
        self,
        request,
    ):
        response = self._response(
            content=b"OK",
            headers={
                "Content-Type": "text/plain",
            },
        )
        response.text = "OK"
        response.json.side_effect = ValueError()

        request.return_value = response

        result = self.gateway.execute(
            operation=self.operation,
            parameters={
                "resource_id": "123",
                "page": "1",
                "limit": "10",
                "test_header": "abc",
            },
        )

        self.assertEqual(result, "OK")

    @patch("apps.integrations.gateway.requests.request")
    def test_empty_response(
        self,
        request,
    ):
        request.return_value = self._response(
            content=b"",
        )

        result = self.gateway.execute(
            operation=self.operation,
            parameters={
                "resource_id": "123",
                "page": "1",
                "limit": "10",
                "test_header": "abc",
            },
        )

        self.assertIsNone(result)

    @patch("apps.integrations.gateway.requests.request")
    def test_api_key_authentication_is_added_to_headers(
        self,
        request,
    ):
        self.integration.authentication_type = AuthenticationType.API_KEY
        IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret="secret-key",
        )

        self.integration.save(
            update_fields=["authentication_type"]
        )

        operation = IntegrationOperation.objects.create(
            integration=self.integration,
            name="API Key Operation",
            http_method=HttpMethod.GET,
            path="/protected",
            request_schema={
                "authentication": {
                    "credential": "Production",
                    "header": "X-API-Key",
                },
                "headers": {
                    "X-Test": "test_header",
                },
            },
        )

        request.return_value = self._response()

        self.gateway.execute(
            operation=operation,
            parameters={
                "test_header": "abc",
            }
        )

        request.assert_called_once_with(
            method="GET",
            url="https://api.example.com/protected",
            timeout=10,
            params={},
            headers={
                "X-Test": "abc",
                "X-API-Key": "secret-key",
            },
        )

    @patch("apps.integrations.gateway.requests.request")
    def test_bearer_token_authentication_is_added_to_headers(
        self,
        request,
    ):
        self.integration.authentication_type = (
            AuthenticationType.BEARER_TOKEN
        )
        IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.BEARER_TOKEN,
            secret="abc123",
        )
        self.integration.save(
            update_fields=["authentication_type"]
        )

        operation = IntegrationOperation.objects.create(
            integration=self.integration,
            name="Bearer Operation",
            http_method=HttpMethod.GET,
            path="/protected",
            request_schema={
                "authentication": {
                    "credential": "Production",
                },
            }
        )

        request.return_value = self._response()

        self.gateway.execute(
            operation=operation,
            parameters={},
        )

        request.assert_called_once_with(
            method="GET",
            url="https://api.example.com/protected",
            timeout=10,
            params={},
            headers={
                "Authorization": "Bearer abc123",
            },
        )

    @patch("apps.integrations.gateway.requests.request")
    def test_basic_authentication_is_added_to_request(
        self,
        request,
    ):
        self.integration.authentication_type = (
            AuthenticationType.BASIC_AUTH
        )
        IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.BASIC_AUTH,
            secret='{"username":"admin","password":"secret"}',
        )
        self.integration.save(
            update_fields=["authentication_type"]
        )

        operation = IntegrationOperation.objects.create(
            integration=self.integration,
            name="Basic Operation",
            http_method=HttpMethod.GET,
            path="/protected",
            request_schema={
                "authentication": {
                    "credential": "Production",
                },
            }
        )

        request.return_value = self._response()

        self.gateway.execute(
            operation=operation,
            parameters={
                "username": "admin",
                "password": "secret",
            },
        )

        request.assert_called_once_with(
            method="GET",
            url="https://api.example.com/protected",
            timeout=10,
            params={},
            headers={},
            auth=(
                "admin",
                "secret",
            ),
        )

    @patch("apps.integrations.gateway.requests.request")
    def test_none_authentication_does_not_add_credentials(
        self,
        request,
    ):
        request.return_value = self._response()

        self.gateway.execute(
            operation=self.operation,
            parameters={
                "resource_id": "123",
                "page": "1",
                "limit": "10",
                "test_header": "abc",
            },
        )

        call_kwargs = request.call_args.kwargs

        self.assertNotIn("auth", call_kwargs)
        self.assertNotIn("_manifold_jwt", call_kwargs)

    @patch("apps.integrations.gateway.JwtTokenService.issue")
    @patch("apps.integrations.gateway.requests.request")
    def test_manifold_jwt_is_issued_and_sent_to_requests(
        self,
        request,
        issue_token,
    ):
        self.integration.authentication_type = (
            AuthenticationType.MANIFOLD_JWT
        )
        self.integration.save(
            update_fields=["authentication_type"]
        )

        operation = IntegrationOperation.objects.create(
            integration=self.integration,
            name="JWT Operation",
            http_method=HttpMethod.GET,
            path="/protected",
            request_schema={
                "authentication": {
                    "audience": "composition-engine",
                    "scopes": [
                        "composition:calculate",
                    ],
                },
            },
        )

        issue_token.return_value = "signed-jwt-token"
        request.return_value = self._response()

        self.gateway.execute(
            operation=operation,
            subject="user:123",
        )

        issue_token.assert_called_once_with(
            subject="user:123",
            audience="composition-engine",
            scopes=[
                "composition:calculate",
            ],
        )

        call_kwargs = request.call_args.kwargs

        self.assertEqual(
            call_kwargs["headers"]["Authorization"],
            "Bearer signed-jwt-token",
        )

        self.assertNotIn(
            "_manifold_jwt",
            call_kwargs,
        )

    @patch("apps.integrations.gateway.requests.request")
    def test_manifold_jwt_is_a_valid_signed_token(
        self,
        request,
    ):
        signing_key = JwtSigningKeyService.generate()

        self.integration.authentication_type = (
            AuthenticationType.MANIFOLD_JWT
        )
        self.integration.save(
            update_fields=["authentication_type"]
        )

        operation = IntegrationOperation.objects.create(
            integration=self.integration,
            name="JWT Validation Operation",
            http_method=HttpMethod.GET,
            path="/protected",
            request_schema={
                "authentication": {
                    "audience": "composition-engine",
                    "scopes": [
                        "composition:calculate",
                    ],
                },
            },
        )

        request.return_value = self._response()

        self.gateway.execute(
            operation=operation,
            subject="user:123",
        )

        call_kwargs = request.call_args.kwargs

        authorization = call_kwargs["headers"]["Authorization"]

        self.assertTrue(
            authorization.startswith("Bearer ")
        )

        token = authorization.removeprefix("Bearer ")

        payload = jwt.decode(
            token,
            signing_key.public_key,
            algorithms=["EdDSA"],
            audience="composition-engine",
            issuer="manifold-api",
        )

        self.assertEqual(
            payload["sub"],
            "user:123",
        )

        self.assertEqual(
            payload["aud"],
            "composition-engine",
        )

        self.assertEqual(
            payload["scope"],
            ["composition:calculate"],
        )

        self.assertIn("jti", payload)
        self.assertIn("iat", payload)
        self.assertIn("exp", payload)

    @patch("apps.integrations.gateway.requests.request")
    def test_manifold_jwt_is_validated_using_manifold_jwks(
        self,
        request,
    ):
        self.integration.authentication_type = (
            AuthenticationType.MANIFOLD_JWT
        )
        self.integration.save(
            update_fields=["authentication_type"]
        )

        operation = IntegrationOperation.objects.create(
            integration=self.integration,
            name="JWT JWKS Operation",
            http_method=HttpMethod.GET,
            path="/protected",
            request_schema={
                "authentication": {
                    "audience": "composition-engine",
                    "scopes": [
                        "composition:calculate",
                    ],
                },
            },
        )

        request.return_value = self._response()

        self.gateway.execute(
            operation=operation,
            subject="user:123",
        )

        call_kwargs = request.call_args.kwargs

        authorization = call_kwargs["headers"]["Authorization"]

        self.assertTrue(
            authorization.startswith("Bearer ")
        )

        token = authorization.removeprefix("Bearer ")

        public_key = JwksClient.get_public_key_for_token(
            token
        )

        payload = jwt.decode(
            token,
            public_key,
            algorithms=["EdDSA"],
            audience="composition-engine",
            issuer="manifold-api",
        )

        self.assertEqual(
            payload["sub"],
            "user:123",
        )

        self.assertEqual(
            payload["aud"],
            "composition-engine",
        )

        self.assertEqual(
            payload["scope"],
            ["composition:calculate"],
        )

        self.assertIn("jti", payload)
        self.assertIn("iat", payload)
        self.assertIn("exp", payload)

    @patch("apps.integrations.gateway.requests.request")
    def test_authentication_headers_do_not_replace_operation_headers(
        self,
        request,
    ):
        self.integration.authentication_type = AuthenticationType.API_KEY
        IntegrationCredentialService.create(
            integration=self.integration,
            name="Production",
            credential_type=CredentialType.API_KEY,
            secret="secret",
        )
        self.integration.save(
            update_fields=["authentication_type"]
        )

        operation = IntegrationOperation.objects.create(
            integration=self.integration,
            name="Combined Headers",
            http_method=HttpMethod.GET,
            path="/protected",
            request_schema={
                "authentication": {
                    "credential": "Production",
                    "header": "X-API-Key",
                },
                "headers": {
                    "X-Custom": "custom_header",
                },
            }
        )

        request.return_value = self._response()

        self.gateway.execute(
            operation=operation,
            parameters={
                "custom_header": "custom-value",
            }
        )

        headers = request.call_args.kwargs["headers"]

        self.assertEqual(
            headers["X-Custom"],
            "custom-value",
        )

        self.assertEqual(
            headers["X-API-Key"],
            "secret",
        )