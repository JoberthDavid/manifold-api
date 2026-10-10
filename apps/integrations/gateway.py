from __future__ import annotations

from typing import Any

import requests

from apps.integrations.authentication import IntegrationAuthenticationResolver
from apps.integrations.exceptions import (
    IntegrationCredentialError,
    IntegrationNotConfiguredError,
)
from apps.integrations.models import Integration, IntegrationOperation
from apps.security.services.jwt_tokens import JwtTokenService


class IntegrationGateway:
    def __init__(self, integration: Integration):
        if not isinstance(integration, Integration):
            raise IntegrationNotConfiguredError(
                "A integração informada é inválida."
            )

        if not integration.enabled:
            raise IntegrationNotConfiguredError(
                "A integração está desativada."
            )

        if not integration.base_url:
            raise IntegrationNotConfiguredError(
                "A URL base da integração não está configurada."
            )

        self.integration = integration
        self.authentication_resolver = IntegrationAuthenticationResolver(
            integration
        )

    def execute(
        self,
        *,
        operation,
        parameters=None,
        subject=None,
    ):
        self._validate_operation(operation)

        parameters = parameters or {}
        schema = operation.request_schema or {}

        url = self._build_url(
            path=operation.path,
            parameters=parameters,
        )

        request_kwargs = self._build_request_kwargs(
            schema=schema,
            parameters=parameters,
        )

        authentication_config = schema.get(
            "authentication",
            {},
        )

        authentication = self.authentication_resolver.resolve(
            authentication_config=authentication_config,
            subject=subject,
        )

        self._apply_authentication(
            request_kwargs=request_kwargs,
            authentication=authentication,
        )

        try:
            response = requests.request(
                method=operation.http_method,
                url=url,
                timeout=self.integration.timeout,
                **request_kwargs,
            )

        except requests.Timeout as exc:
            raise IntegrationNotConfiguredError(
                "A requisição da integração excedeu o tempo limite."
            ) from exc

        except requests.RequestException as exc:
            raise IntegrationNotConfiguredError(
                "Não foi possível comunicar com a integração."
            ) from exc

        if response.status_code in (401, 403):
            raise IntegrationCredentialError(
                "A integração rejeitou as credenciais."
            )

        try:
            response.raise_for_status()

        except requests.HTTPError as exc:
            raise IntegrationNotConfiguredError(
                f"A integração retornou HTTP {response.status_code}."
            ) from exc

        return self._parse_response(response)

    def _validate_operation(self, operation):
        if not isinstance(operation, IntegrationOperation):
            raise IntegrationNotConfiguredError(
                "A operação informada é inválida."
            )

        if operation.integration_id != self.integration.id:
            raise IntegrationNotConfiguredError(
                "A operação não pertence à integração informada."
            )

        if not operation.enabled:
            raise IntegrationNotConfiguredError(
                "A operação está desativada."
            )

        if not operation.path:
            raise IntegrationNotConfiguredError(
                "O caminho da operação não está configurado."
            )

    def _build_url(
        self,
        *,
        path,
        parameters,
    ):
        try:
            resolved_path = path.format(**parameters)

        except KeyError as exc:
            raise IntegrationNotConfiguredError(
                f"Parâmetro do caminho não informado: {exc.args[0]}."
            ) from exc

        base_url = self.integration.base_url.rstrip("/")
        resolved_path = resolved_path.lstrip("/")

        return f"{base_url}/{resolved_path}"

    def _build_request_kwargs(
        self,
        *,
        schema,
        parameters,
    ):
        request_kwargs = {
            "headers": {},
        }

        query_mapping = schema.get("query", {})
        headers_mapping = schema.get("headers", {})
        body_mapping = schema.get("body", {})

        query = self._resolve_mapping(
            mapping=query_mapping,
            parameters=parameters,
        )

        headers = self._resolve_mapping(
            mapping=headers_mapping,
            parameters=parameters,
        )

        body = self._resolve_mapping(
            mapping=body_mapping,
            parameters=parameters,
        )

        request_kwargs["params"] = query
        request_kwargs["headers"].update(headers)

        if body:
            request_kwargs["json"] = body

        return request_kwargs

    @staticmethod
    def _resolve_mapping(
        *,
        mapping,
        parameters,
    ):
        if not mapping:
            return {}

        if not isinstance(mapping, dict):
            raise IntegrationNotConfiguredError(
                "O mapeamento da requisição deve ser um objeto JSON."
            )

        resolved = {}

        for target_name, parameter_name in mapping.items():
            if parameter_name not in parameters:
                # Parâmetros declarados no schema são opcionais por padrão.
                # Se o cliente não os informar, simplesmente não os enviaremos.
                continue

            value = parameters[parameter_name]

            if value is None:
                continue

            resolved[target_name] = value

        return resolved

    @staticmethod
    def _apply_authentication(
        *,
        request_kwargs,
        authentication,
    ):
        if not authentication:
            return

        headers = authentication.get("headers") or {}

        request_kwargs["headers"].update(headers)

        auth = authentication.get("auth")

        if auth is not None:
            request_kwargs["auth"] = auth

        jwt_configuration = authentication.get("jwt")

        if jwt_configuration:
            token = JwtTokenService.issue(
                subject=jwt_configuration["subject"],
                audience=jwt_configuration["audience"],
                scopes=jwt_configuration["scopes"],
            )

            request_kwargs["headers"]["Authorization"] = (
                f"Bearer {token}"
            )

    @staticmethod
    def _parse_response(response):
        if not response.content:
            return None

        content_type = response.headers.get(
            "Content-Type",
            "",
        ).lower()

        if "application/json" in content_type:
            return response.json()

        return response.text