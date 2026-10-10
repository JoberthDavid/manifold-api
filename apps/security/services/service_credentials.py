from __future__ import annotations

import hashlib
import secrets

from django.utils import timezone

from apps.security.models import Service, ServiceCredential


class ServiceCredentialError(Exception):
    """Erro relacionado a credenciais técnicas de serviço."""


class ServiceCredentialService:
    TOKEN_BYTES = 32

    @classmethod
    def create(
        cls,
        *,
        name: str,
        service: Service,
        expires_at=None,
    ) -> tuple[ServiceCredential, str]:
        name = name.strip()

        if not name:
            raise ServiceCredentialError(
                "O nome da credencial é obrigatório."
            )

        if not isinstance(service, Service):
            raise ServiceCredentialError(
                "O serviço informado é inválido."
            )

        if not service.enabled:
            raise ServiceCredentialError(
                "O serviço está desativado."
            )

        if expires_at is not None and expires_at <= timezone.now():
            raise ServiceCredentialError(
                "A data de expiração deve estar no futuro."
            )

        token = secrets.token_urlsafe(cls.TOKEN_BYTES)
        token_hash = cls._hash_token(token)

        credential = ServiceCredential.objects.create(
            name=name,
            service=service,
            token_hash=token_hash,
            expires_at=expires_at,
        )

        return credential, token

    @classmethod
    def authenticate(
        cls,
        *,
        token: str,
    ) -> ServiceCredential | None:
        if not token:
            return None

        token_hash = cls._hash_token(token)

        try:
            credential = ServiceCredential.objects.select_related(
                "service",
            ).get(
                token_hash=token_hash,
            )
        except ServiceCredential.DoesNotExist:
            return None

        if not credential.enabled:
            return None

        if (
            credential.expires_at is not None
            and credential.expires_at <= timezone.now()
        ):
            return None

        credential.last_used_at = timezone.now()
        credential.save(
            update_fields=("last_used_at",),
        )

        return credential

    @classmethod
    def enable(
        cls,
        credential: ServiceCredential,
    ) -> ServiceCredential:
        credential.enabled = True
        credential.save(update_fields=("enabled",))
        return credential

    @classmethod
    def disable(
        cls,
        credential: ServiceCredential,
    ) -> ServiceCredential:
        credential.enabled = False
        credential.save(update_fields=("enabled",))
        return credential

    @classmethod
    def _hash_token(cls, token: str) -> str:
        return hashlib.sha256(
            token.encode("utf-8"),
        ).hexdigest()