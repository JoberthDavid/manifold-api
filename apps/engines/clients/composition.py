from __future__ import annotations

from datetime import date
from typing import Any

import requests

from apps.engines.contracts import EngineRequestContext
from apps.engines.clients.base import HttpEngineClient
from apps.engines.exceptions import (
    EngineAuthenticationError,
    EngineRequestError,
    EngineResponseError,
)
from apps.security.services.jwt_tokens import JwtTokenService


class CompositionEngineClient(HttpEngineClient):
    """
    Client responsável pela comunicação entre o Manifold
    e o composition-engine.
    """

    ENGINE_NAME = "composition-engine"
    AUDIENCE = "composition-engine"

    @property
    def engine_name(self) -> str:
        return self.ENGINE_NAME

    def calculate(
        self,
        *,
        composition_code: str,
        context: EngineRequestContext,
        source_file_uf: str,
        type_system: str,
        methodology: str,
        monetary_base_date: date,
        reference_base_date: date,
    ) -> dict[str, Any]:
        """
        Calcula uma composição utilizando o composition-engine.
        """

        token = self._issue_token(
            context=context,
            scopes=["composition:calculate"],
        )

        url = (
            f"{self.base_url}/compositions/"
            f"{composition_code}/calculate"
        )

        params = {
            "source_file_uf": source_file_uf,
            "type_system": type_system,
            "methodology": methodology,
            "monetary_base_date": monetary_base_date.isoformat(),
            "reference_base_date": reference_base_date.isoformat(),
        }

        response = self._request(
            method="POST",
            url=url,
            token=token,
            params=params,
        )

        return self._parse_response(response)

    def explode(
        self,
        *,
        composition_code: str,
        context: EngineRequestContext,
        source_file_uf: str,
        type_system: str,
        methodology: str,
        monetary_base_date: date,
        reference_base_date: date,
    ) -> dict[str, Any]:
        """
        Realiza a explosão de uma composição utilizando
        o composition-engine.
        """

        token = self._issue_token(
            context=context,
            scopes=["composition:explosion"],
        )

        url = (
            f"{self.base_url}/compositions/"
            f"{composition_code}/explosion"
        )

        params = {
            "source_file_uf": source_file_uf,
            "type_system": type_system,
            "methodology": methodology,
            "monetary_base_date": monetary_base_date.isoformat(),
            "reference_base_date": reference_base_date.isoformat(),
        }

        response = self._request(
            method="GET",
            url=url,
            token=token,
            params=params,
        )

        return self._parse_response(response)

    def call(
        self,
        *,
        operation: str,
        context: EngineRequestContext,
        **kwargs: Any,
    ) -> Any:
        """
        Executa uma operação da engine através do contrato genérico.
        """

        if operation == "calculate":
            return self.calculate(
                context=context,
                **kwargs,
            )

        if operation == "explosion":
            return self.explode(
                context=context,
                **kwargs,
            )

        raise ValueError(
            f"Operação não suportada pelo {self.ENGINE_NAME}: "
            f"{operation}"
        )

    def _issue_token(
        self,
        *,
        context: EngineRequestContext,
        scopes: list[str],
    ) -> str:
        """
        Emite um JWT interno do Manifold para a engine.
        """

        try:
            return JwtTokenService.issue(
                subject=f"user:{context.user_id}",
                audience=self.AUDIENCE,
                scopes=scopes,
            )
        except Exception as exc:
            raise EngineAuthenticationError(
                "Não foi possível emitir o token interno "
                "para o composition-engine."
            ) from exc

    def _request(
        self,
        *,
        method: str,
        url: str,
        token: str,
        params: dict[str, Any],
    ) -> requests.Response:
        """
        Executa uma requisição HTTP autenticada contra a engine.
        """

        try:
            response = requests.request(
                method=method,
                url=url,
                params=params,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/json",
                },
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise EngineRequestError(
                f"Falha de comunicação com o {self.ENGINE_NAME}."
            ) from exc

        if response.status_code in (401, 403):
            raise EngineAuthenticationError(
                f"O {self.ENGINE_NAME} rejeitou a autenticação."
            )

        if not response.ok:
            raise EngineRequestError(
                f"O {self.ENGINE_NAME} retornou HTTP "
                f"{response.status_code}: {response.text}"
            )

        return response

    @staticmethod
    def _parse_response(
        response: requests.Response,
    ) -> dict[str, Any]:
        """
        Converte a resposta HTTP para um dicionário JSON.
        """

        try:
            payload = response.json()
        except ValueError as exc:
            raise EngineResponseError(
                "A resposta do composition-engine não contém "
                "JSON válido."
            ) from exc

        if not isinstance(payload, dict):
            raise EngineResponseError(
                "A resposta do composition-engine possui um "
                "formato inesperado."
            )

        return payload
