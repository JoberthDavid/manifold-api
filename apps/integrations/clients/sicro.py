from __future__ import annotations

from typing import Any

import requests

from apps.integrations.exceptions import (
    IntegrationCredentialError,
    IntegrationNotConfiguredError,
)
from apps.integrations.models import CredentialType, Integration
from apps.integrations.services.integration_credentials import (
    IntegrationCredentialService,
)


class SicroClient:
    """
    Cliente HTTP da API SICRO.

    Este cliente é responsável somente pela comunicação com a API externa.
    Regras de composição, cálculo, preços e consolidação pertencem a outros
    domínios da plataforma.
    """

    def __init__(self, integration: Integration):
        if not isinstance(integration, Integration):
            raise IntegrationNotConfiguredError(
                "A integração SICRO é inválida."
            )

        if not integration.enabled:
            raise IntegrationNotConfiguredError(
                "A integração SICRO está desativada."
            )

        if not integration.base_url:
            raise IntegrationNotConfiguredError(
                "A URL base da integração SICRO não está configurada."
            )

        self.integration = integration

    def _get_credential(self):
        return (
            self.integration.credentials
            .filter(
                credential_type=CredentialType.API_KEY,
                enabled=True,
            )
            .order_by("created_at")
            .first()
        )

    def _build_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
        }

        credential = self._get_credential()

        if credential is None:
            return headers

        secret = IntegrationCredentialService.get_secret(
            credential
        )

        headers["X-API-Key"] = secret

        return headers

    def _request(
        self,
        *,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:

        url = (
            f"{self.integration.base_url.rstrip('/')}/"
            f"{path.lstrip('/')}"
        )

        try:
            response = requests.request(
                method=method,
                url=url,
                params=params,
                headers=self._build_headers(),
                timeout=self.integration.timeout,
            )
        except requests.Timeout as exc:
            raise IntegrationNotConfiguredError(
                "A requisição para a API SICRO excedeu o tempo limite."
            ) from exc
        except requests.RequestException as exc:
            raise IntegrationNotConfiguredError(
                "Não foi possível comunicar com a API SICRO."
            ) from exc

        if response.status_code in (401, 403):
            raise IntegrationCredentialError(
                "A API SICRO rejeitou as credenciais da integração."
            )

        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise IntegrationNotConfiguredError(
                f"A API SICRO retornou HTTP {response.status_code}."
            ) from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise IntegrationNotConfiguredError(
                "A API SICRO retornou uma resposta JSON inválida."
            ) from exc

        if not isinstance(payload, dict):
            raise IntegrationNotConfiguredError(
                "A API SICRO retornou um JSON em formato inválido."
            )

        return payload

    def search_items(
        self,
        *,
        code: str = "",
        descriptions: str = "",
        descriptions_group: str = "CO",
        source_files: str = "",
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        """
        Pesquisa itens do catálogo SICRO.

        Endpoint:
            GET /itens/
        """

        params = {
            "code": code,
            "descriptions": descriptions,
            "descriptions__group": descriptions_group,
            "source_files": source_files,
            "limit": limit,
            "offset": offset,
        }

        return self._request(
            method="GET",
            path="/itens/",
            params=params,
        )