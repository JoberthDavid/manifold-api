from __future__ import annotations

from dataclasses import dataclass

import requests
from django.conf import settings

from apps.integrations.exceptions import (
    IntegrationNotConfiguredError,
)


class RailwayProviderError(RuntimeError):
    """Erro de comunicação com a API do Railway."""


@dataclass(frozen=True)
class RailwayProvider:
    api_url: str
    api_token: str
    project_id: str
    environment_id: str
    service_id: str
    timeout: int = 15

    @classmethod
    def from_settings(cls) -> "RailwayProvider":
        values = {
            "api_url": getattr(
                settings,
                "RAILWAY_API_URL",
                "",
            ),
            "api_token": getattr(
                settings,
                "RAILWAY_API_TOKEN",
                "",
            ),
            "project_id": getattr(
                settings,
                "RAILWAY_PROJECT_ID",
                "",
            ),
            "environment_id": getattr(
                settings,
                "RAILWAY_ENVIRONMENT_ID",
                "",
            ),
            "service_id": getattr(
                settings,
                "RAILWAY_SERVICE_ID",
                "",
            ),
        }

        missing = [
            name
            for name, value in values.items()
            if not value
        ]

        if missing:
            raise IntegrationNotConfiguredError(
                "Configuração do Railway incompleta: "
                + ", ".join(missing)
            )

        return cls(**values)

    def _request(
        self,
        *,
        query: str,
        variables: dict,
    ) -> dict:
        try:
            response = requests.post(
                self.api_url,
                json={
                    "query": query,
                    "variables": variables,
                },
                headers={
                    "Authorization": (
                        f"Bearer {self.api_token}"
                    ),
                    "Content-Type": "application/json",
                },
                timeout=self.timeout,
            )
        except requests.RequestException as exc:
            raise RailwayProviderError(
                "Não foi possível comunicar com o Railway."
            ) from exc

        if response.status_code >= 400:
            raise RailwayProviderError(
                "O Railway retornou HTTP "
                f"{response.status_code}."
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise RailwayProviderError(
                "O Railway retornou JSON inválido."
            ) from exc

        if payload.get("errors"):
            raise RailwayProviderError(
                "A API do Railway retornou erro GraphQL."
            )

        return payload.get("data", {})

    def set_secret(
        self,
        *,
        name: str,
        value: str,
    ) -> None:
        mutation = """
        mutation variableUpsert(
            $input: VariableUpsertInput!
        ) {
            variableUpsert(input: $input)
        }
        """

        self._request(
            query=mutation,
            variables={
                "input": {
                    "projectId": self.project_id,
                    "environmentId": self.environment_id,
                    "serviceId": self.service_id,
                    "name": name,
                    "value": value,
                }
            },
        )

    def redeploy(self) -> None:
        mutation = """
        mutation serviceInstanceRedeploy(
            $serviceId: String!,
            $environmentId: String!
        ) {
            serviceInstanceRedeploy(
                serviceId: $serviceId,
                environmentId: $environmentId
            )
        }
        """

        self._request(
            query=mutation,
            variables={
                "serviceId": self.service_id,
                "environmentId": self.environment_id,
            },
        )
        