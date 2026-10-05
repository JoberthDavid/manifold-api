from __future__ import annotations

from dataclasses import dataclass

from django.db import transaction

from apps.integrations.models import (
    CredentialType,
    Integration,
    IntegrationCredential,
)
from apps.integrations.providers.railway import (
    RailwayProvider,
)
from apps.integrations.services.api_key_fingerprint import (
    ApiKeyFingerprintService,
)
from apps.integrations.services.api_key_generator import (
    ApiKeyGenerator,
)
from apps.integrations.services.integration_credentials import (
    IntegrationCredentialService,
)


@dataclass(frozen=True)
class CredentialRotationResult:
    credential_id: str
    fingerprint: str


class CredentialRotationService:
    """
    Gera, publica e armazena credenciais de integração.

    A chave original nunca é retornada pelo serviço.
    """

    @classmethod
    @transaction.atomic
    def rotate_composition_engine(
        cls,
        *,
        integration: Integration,
        credential: IntegrationCredential | None = None,
    ) -> CredentialRotationResult:

        new_secret = ApiKeyGenerator.generate()

        fingerprint = (
            ApiKeyFingerprintService.generate(
                new_secret
            )
        )

        provider = RailwayProvider.from_settings()

        # 1. Atualiza primeiro o ambiente externo.
        provider.set_secret(
            name="COMPOSITION_ENGINE_API_KEY",
            value=new_secret,
        )

        # 2. Aplica a nova variável no serviço.
        provider.redeploy()

        # 3. Persiste a credencial no Manifold.
        if credential is None:
            credential = (
                IntegrationCredentialService.create(
                    integration=integration,
                    name="composition-engine",
                    credential_type=CredentialType.API_KEY,
                    secret=new_secret,
                )
            )
        else:
            IntegrationCredentialService.update_secret(
                credential,
                new_secret,
            )

        return CredentialRotationResult(
            credential_id=str(credential.id),
            fingerprint=fingerprint,
        )
    