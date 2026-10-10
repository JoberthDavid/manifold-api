from __future__ import annotations

import json
from typing import Any

from apps.integrations.exceptions import (
    IntegrationCredentialError,
    IntegrationNotConfiguredError,
)
from apps.integrations.models import (
    AuthenticationType,
    CredentialType,
    Integration,
    IntegrationCredential,
)
from apps.integrations.services.integration_credentials import (
    IntegrationCredentialService,
)


class IntegrationAuthenticationResolver:
    """
    Resolve a autenticação de uma integração de forma declarativa.

    Credenciais persistidas nunca são recebidas pelos parâmetros da
    operação. O resolver localiza a IntegrationCredential associada à
    Integration e delega a leitura do segredo ao
    IntegrationCredentialService.

    A identidade do usuário autenticado é recebida separadamente
    através de ``subject`` e nunca faz parte dos parâmetros da
    operação externa.
    """

    def __init__(self, integration: Integration):
        if not isinstance(integration, Integration):
            raise IntegrationNotConfiguredError(
                "A integração informada é inválida."
            )

        self.integration = integration

    def resolve(
        self,
        *,
        authentication_config: dict[str, Any] | None = None,
        subject: str | None = None,
    ) -> dict[str, Any]:
        authentication_config = authentication_config or {}

        authentication_type = self.integration.authentication_type

        if authentication_type == AuthenticationType.NONE:
            return {
                "headers": {},
                "auth": None,
            }

        if authentication_type == AuthenticationType.API_KEY:
            return self._resolve_api_key(
                authentication_config=authentication_config,
            )

        if authentication_type == AuthenticationType.BEARER_TOKEN:
            return self._resolve_bearer_token(
                authentication_config=authentication_config,
            )

        if authentication_type == AuthenticationType.BASIC_AUTH:
            return self._resolve_basic_auth(
                authentication_config=authentication_config,
            )

        if authentication_type == AuthenticationType.OAUTH2:
            return self._resolve_oauth2(
                authentication_config=authentication_config,
            )

        if authentication_type == AuthenticationType.MANIFOLD_JWT:
            return self._resolve_manifold_jwt(
                authentication_config=authentication_config,
                subject=subject,
            )

        raise IntegrationNotConfiguredError(
            "Tipo de autenticação não suportado: "
            f"{authentication_type}."
        )

    def _get_credential(
        self,
        *,
        authentication_config: dict[str, Any],
    ) -> IntegrationCredential:
        credential_name = authentication_config.get("credential")

        if not isinstance(credential_name, str) or not credential_name.strip():
            raise IntegrationNotConfiguredError(
                "A credencial da integração não está configurada."
            )

        try:
            credential = self.integration.credentials.get(
                name=credential_name.strip(),
            )
        except IntegrationCredential.DoesNotExist as exc:
            raise IntegrationCredentialError(
                "A credencial configurada não foi encontrada."
            ) from exc

        return credential

    def _get_secret(
        self,
        *,
        authentication_config: dict[str, Any],
        expected_type: str,
    ) -> str:
        credential = self._get_credential(
            authentication_config=authentication_config,
        )

        if credential.credential_type != expected_type:
            raise IntegrationCredentialError(
                "O tipo da credencial não corresponde ao tipo "
                "de autenticação da integração."
            )

        return IntegrationCredentialService.get_secret(
            credential
        )

    def _resolve_api_key(
        self,
        *,
        authentication_config: dict[str, Any],
    ) -> dict[str, Any]:
        header_name = authentication_config.get(
            "header",
            "X-API-Key",
        )

        if not isinstance(header_name, str) or not header_name:
            raise IntegrationNotConfiguredError(
                "O nome do header da API Key não está configurado."
            )

        secret = self._get_secret(
            authentication_config=authentication_config,
            expected_type=CredentialType.API_KEY,
        )

        return {
            "headers": {
                header_name: secret,
            },
            "auth": None,
        }

    def _resolve_bearer_token(
        self,
        *,
        authentication_config: dict[str, Any],
    ) -> dict[str, Any]:
        secret = self._get_secret(
            authentication_config=authentication_config,
            expected_type=CredentialType.BEARER_TOKEN,
        )

        return {
            "headers": {
                "Authorization": f"Bearer {secret}",
            },
            "auth": None,
        }

    def _resolve_basic_auth(
        self,
        *,
        authentication_config: dict[str, Any],
    ) -> dict[str, Any]:
        secret = self._get_secret(
            authentication_config=authentication_config,
            expected_type=CredentialType.BASIC_AUTH,
        )

        try:
            credentials = json.loads(secret)
        except (TypeError, json.JSONDecodeError) as exc:
            raise IntegrationCredentialError(
                "A credencial Basic Auth não contém um JSON válido."
            ) from exc

        if not isinstance(credentials, dict):
            raise IntegrationCredentialError(
                "A credencial Basic Auth deve conter um objeto JSON."
            )

        username = credentials.get("username")
        password = credentials.get("password")

        if not isinstance(username, str) or not username:
            raise IntegrationCredentialError(
                "O usuário do Basic Auth não está configurado."
            )

        if not isinstance(password, str) or not password:
            raise IntegrationCredentialError(
                "A senha do Basic Auth não está configurada."
            )

        return {
            "headers": {},
            "auth": (
                username,
                password,
            ),
        }

    def _resolve_oauth2(
        self,
        *,
        authentication_config: dict[str, Any],
    ) -> dict[str, Any]:
        raise IntegrationNotConfiguredError(
            "A autenticação OAuth 2.0 ainda não está implementada."
        )

    def _resolve_manifold_jwt(
        self,
        *,
        authentication_config: dict[str, Any],
        subject: str | None,
    ) -> dict[str, Any]:
        audience = authentication_config.get("audience")
        scopes = authentication_config.get("scopes")

        if not isinstance(audience, str) or not audience:
            raise IntegrationNotConfiguredError(
                "A audiência do MANIFOLD_JWT não está configurada."
            )

        if not isinstance(scopes, list) or not scopes:
            raise IntegrationNotConfiguredError(
                "Os escopos do MANIFOLD_JWT não estão configurados."
            )

        if not all(
            isinstance(scope, str) and scope
            for scope in scopes
        ):
            raise IntegrationNotConfiguredError(
                "Os escopos do MANIFOLD_JWT devem ser strings "
                "não vazias."
            )

        if not isinstance(subject, str) or not subject:
            raise IntegrationCredentialError(
                "O sujeito do MANIFOLD_JWT não foi fornecido."
            )

        return {
            "headers": {},
            "auth": None,
            "jwt": {
                "subject": subject,
                "audience": audience,
                "scopes": scopes,
            },
        }