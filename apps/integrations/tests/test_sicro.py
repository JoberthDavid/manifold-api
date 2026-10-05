from unittest.mock import Mock, patch

import requests
from cryptography.fernet import Fernet
from django.test import TestCase, override_settings

from apps.integrations.exceptions import (
    IntegrationCredentialError,
    IntegrationNotConfiguredError,
)
from apps.integrations.models import (
    CredentialType,
    Integration,
)
from apps.integrations.services.integration_credentials import (
    IntegrationCredentialService,
)
from apps.integrations.clients.sicro import SicroClient


@override_settings(
    MANIFOLD_CREDENTIAL_ENCRYPTION_KEY=Fernet.generate_key().decode()
)
class SicroClientTests(TestCase):

    def setUp(self):
        self.integration = Integration.objects.create(
            code="SICRO",
            name="SICRO",
            base_url="https://sicro.example.com",
            enabled=True,
            timeout=15,
        )

    def create_api_key(self, secret="teste-sicro-123456"):
        return IntegrationCredentialService.create(
            integration=self.integration,
            name="API principal",
            credential_type=CredentialType.API_KEY,
            secret=secret,
        )

    def mock_response(
        self,
        *,
        status_code=200,
        payload=None,
    ):
        response = Mock()
        response.status_code = status_code
        response.json.return_value = payload or {}
        response.raise_for_status.return_value = None

        if status_code >= 400:
            response.raise_for_status.side_effect = (
                requests.HTTPError(
                    f"HTTP {status_code}"
                )
            )

        return response

    def test_search_items_without_credential(self):
        payload = {
            "count": 1,
            "next": None,
            "previous": None,
            "results": [],
        }

        response = self.mock_response(payload=payload)

        with patch(
            "apps.integrations.clients.sicro.requests.request",
            return_value=response,
        ) as request:
            result = SicroClient(
                self.integration
            ).search_items(
                descriptions="pavimento",
            )

        self.assertEqual(result, payload)

        request.assert_called_once_with(
            method="GET",
            url="https://sicro.example.com/itens/",
            params={
                "code": "",
                "descriptions": "pavimento",
                "descriptions__group": "CO",
                "source_files": "",
                "limit": 20,
                "offset": 0,
            },
            headers={
                "Accept": "application/json",
            },
            timeout=15,
        )

    def test_search_items_sends_api_key(self):
        self.create_api_key()

        response = self.mock_response(
            payload={"results": []}
        )

        with patch(
            "apps.integrations.clients.sicro.requests.request",
            return_value=response,
        ) as request:
            SicroClient(
                self.integration
            ).search_items(
                code="0307084",
                limit=10,
                offset=20,
            )

        request.assert_called_once()

        call = request.call_args

        self.assertEqual(
            call.kwargs["headers"],
            {
                "Accept": "application/json",
                "X-API-Key": "teste-sicro-123456",
            },
        )

        self.assertEqual(
            call.kwargs["params"],
            {
                "code": "0307084",
                "descriptions": "",
                "descriptions__group": "CO",
                "source_files": "",
                "limit": 10,
                "offset": 20,
            },
        )

    def test_disabled_integration_is_rejected(self):
        self.integration.enabled = False
        self.integration.save(update_fields=["enabled"])

        with self.assertRaises(IntegrationNotConfiguredError):
            SicroClient(self.integration)

    def test_invalid_integration_is_rejected(self):
        with self.assertRaises(IntegrationNotConfiguredError):
            SicroClient(None)

    def test_missing_base_url_is_rejected(self):
        self.integration.base_url = ""
        self.integration.save(update_fields=["base_url"])

        with self.assertRaises(IntegrationNotConfiguredError):
            SicroClient(self.integration)

    def test_http_401_raises_credential_error(self):
        response = self.mock_response(
            status_code=401,
            payload={"detail": "Unauthorized"},
        )

        with patch(
            "apps.integrations.clients.sicro.requests.request",
            return_value=response,
        ):
            with self.assertRaises(
                IntegrationCredentialError
            ):
                SicroClient(
                    self.integration
                ).search_items()

    def test_http_403_raises_credential_error(self):
        response = self.mock_response(
            status_code=403,
            payload={"detail": "Forbidden"},
        )

        with patch(
            "apps.integrations.clients.sicro.requests.request",
            return_value=response,
        ):
            with self.assertRaises(
                IntegrationCredentialError
            ):
                SicroClient(
                    self.integration
                ).search_items()

    def test_other_http_error_raises_integration_error(self):
        response = self.mock_response(
            status_code=500,
            payload={"detail": "Internal Server Error"},
        )

        with patch(
            "apps.integrations.clients.sicro.requests.request",
            return_value=response,
        ):
            with self.assertRaises(
                IntegrationNotConfiguredError
            ):
                SicroClient(
                    self.integration
                ).search_items()

    def test_timeout_raises_integration_error(self):
        with patch(
            "apps.integrations.clients.sicro.requests.request",
            side_effect=requests.Timeout,
        ):
            with self.assertRaises(
                IntegrationNotConfiguredError
            ):
                SicroClient(
                    self.integration
                ).search_items()

    def test_connection_error_raises_integration_error(self):
        with patch(
            "apps.integrations.clients.sicro.requests.request",
            side_effect=requests.ConnectionError,
        ):
            with self.assertRaises(
                IntegrationNotConfiguredError
            ):
                SicroClient(
                    self.integration
                ).search_items()

    def test_invalid_json_raises_integration_error(self):
        response = Mock()
        response.status_code = 200
        response.raise_for_status.return_value = None
        response.json.side_effect = ValueError

        with patch(
            "apps.integrations.clients.sicro.requests.request",
            return_value=response,
        ):
            with self.assertRaises(
                IntegrationNotConfiguredError
            ):
                SicroClient(
                    self.integration
                ).search_items()

    def test_non_object_json_raises_integration_error(self):
        response = Mock()
        response.status_code = 200
        response.raise_for_status.return_value = None
        response.json.return_value = []

        with patch(
            "apps.integrations.clients.sicro.requests.request",
            return_value=response,
        ):
            with self.assertRaises(
                IntegrationNotConfiguredError
            ):
                SicroClient(
                    self.integration
                ).search_items()