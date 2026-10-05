from __future__ import annotations

from typing import Any

import requests

from apps.integrations.exceptions import (
    IntegrationCredentialError,
    IntegrationNotConfiguredError,
)
from apps.integrations.models import (
    CredentialType,
    Integration,
    IntegrationCredential,
)
from apps.integrations.providers.railway import RailwayProvider
from apps.integrations.services.api_key_fingerprint import ApiKeyFingerprintService
from apps.integrations.services.api_key_generator import ApiKeyGenerator
from apps.integrations.services.credential_rotation import CredentialRotationResult
from apps.integrations.services.integration_credentials import (
    IntegrationCredentialService,
)


class CompositionEngineClient:

    def __init__(
        self,
        integration: Integration,
    ):
        if not isinstance(integration, Integration):
            raise IntegrationNotConfiguredError(
                "A integração do Composition Engine é inválida."
            )

        if not integration.enabled:
            raise IntegrationNotConfiguredError(
                "A integração do Composition Engine "
                "está desativada."
            )

        if not integration.base_url:
            raise IntegrationNotConfiguredError(
                "A URL base do Composition Engine "
                "não está configurada."
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

    def _build_headers(
        self,
        secret: str | None = None,
    ) -> dict[str, str]:

        if secret is None:
            credential = self._get_credential()

            if credential is None:
                raise IntegrationCredentialError(
                    "Nenhuma credencial do "
                    "Composition Engine está configurada."
                )

            secret = (
                IntegrationCredentialService.get_secret(
                    credential
                )
            )

        return {
            "Accept": "application/json",
            "X-API-Key": secret,
        }

    def health(self) -> bool:
        url = (
            f"{self.integration.base_url.rstrip('/')}"
            "/health"
        )

        try:
            response = requests.get(
                url,
                headers={
                    "Accept": "application/json",
                },
                timeout=self.integration.timeout,
            )
        except requests.RequestException:
            return False

        return response.status_code == 200

    def explosion(
        self,
        *,
        composition_code: str,
        source_file_uf: str,
        type_system: str,
        methodology: str,
        monetary_base_date: str,
        reference_base_date: str,
        secret: str | None = None,
    ) -> dict[str, Any]:

        url = (
            f"{self.integration.base_url.rstrip('/')}"
            f"/compositions/{composition_code}/explosion"
        )

        params = {
            "source_file_uf": source_file_uf,
            "type_system": type_system,
            "methodology": methodology,
            "monetary_base_date": monetary_base_date,
            "reference_base_date": reference_base_date,
        }

        try:
            response = requests.get(
                url,
                params=params,
                headers=self._build_headers(secret),
                timeout=self.integration.timeout,
            )
        except requests.Timeout as exc:
            raise IntegrationNotConfiguredError(
                "A requisição ao Composition Engine "
                "excedeu o tempo limite."
            ) from exc
        except requests.RequestException as exc:
            raise IntegrationNotConfiguredError(
                "Não foi possível comunicar com o "
                "Composition Engine."
            ) from exc

        if response.status_code in (401, 403):
            raise IntegrationCredentialError(
                "O Composition Engine rejeitou "
                "a credencial."
            )

        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise IntegrationNotConfiguredError(
                "O Composition Engine retornou "
                f"HTTP {response.status_code}."
            ) from exc

        try:
            payload = response.json()
        except ValueError as exc:
            raise IntegrationNotConfiguredError(
                "O Composition Engine retornou "
                "JSON inválido."
            ) from exc

        if not isinstance(payload, dict):
            raise IntegrationNotConfiguredError(
                "O Composition Engine retornou "
                "JSON em formato inválido."
            )

        return payload

    @classmethod
    def rotate_composition_engine(
        cls,
        *,
        integration: Integration,
        credential: IntegrationCredential,
    ) -> CredentialRotationResult:

        old_secret = (
            IntegrationCredentialService.get_secret(
                credential
            )
        )

        new_secret = ApiKeyGenerator.generate()

        fingerprint = (
            ApiKeyFingerprintService.generate(
                new_secret
            )
        )

        provider = RailwayProvider.from_settings()

        client = CompositionEngineClient(integration)

        try:
            # Publica nova chave.
            provider.set_secret(
                name="COMPOSITION_ENGINE_API_KEY",
                value=new_secret,
            )

            # Reinicia com a nova configuração.
            provider.redeploy()

            # Aqui precisamos aguardar o novo deployment
            # ficar saudável.
            cls._wait_until_healthy(client)

            # Testa autenticação usando explicitamente
            # a nova chave.
            cls._test_authentication(
                client=client,
                secret=new_secret,
            )

        except Exception:
            # Rollback externo.
            provider.set_secret(
                name="COMPOSITION_ENGINE_API_KEY",
                value=old_secret,
            )
            provider.redeploy()

            raise

        IntegrationCredentialService.update_secret(
            credential,
            new_secret,
        )

        return CredentialRotationResult(
            credential_id=str(credential.id),
            fingerprint=fingerprint,
        )