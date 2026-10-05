from django.utils import timezone

from apps.integrations.exceptions import IntegrationCredentialError
from apps.integrations.models import (
    CredentialType,
    Integration,
    IntegrationCredential,
)
from apps.integrations.services.credentials import (
    CredentialEncryptionService,
)


class IntegrationCredentialService:
    """Manages persisted integration credentials."""

    @classmethod
    def create(
        cls,
        *,
        integration: Integration,
        name: str,
        credential_type: str,
        secret: str,
        expires_at=None,
    ) -> IntegrationCredential:
        if not isinstance(integration, Integration):
            raise IntegrationCredentialError(
                "A integração informada é inválida."
            )

        if not name or not name.strip():
            raise IntegrationCredentialError(
                "O nome da credencial não pode ser vazio."
            )

        valid_credential_types = {
            choice
            for choice, _ in CredentialType.choices
        }

        if credential_type not in valid_credential_types:
            raise IntegrationCredentialError(
                "O tipo da credencial é inválido."
            )

        encrypted_value = CredentialEncryptionService.encrypt(secret)

        return IntegrationCredential.objects.create(
            integration=integration,
            name=name.strip(),
            credential_type=credential_type,
            encrypted_value=encrypted_value,
            expires_at=expires_at,
        )

    @classmethod
    def get_secret(
        cls,
        credential: IntegrationCredential,
    ) -> str:
        if not isinstance(credential, IntegrationCredential):
            raise IntegrationCredentialError(
                "A credencial informada é inválida."
            )

        if not credential.enabled:
            raise IntegrationCredentialError(
                "A credencial está desativada."
            )

        if (
            credential.expires_at is not None
            and credential.expires_at <= timezone.now()
        ):
            raise IntegrationCredentialError(
                "A credencial está expirada."
            )

        return CredentialEncryptionService.decrypt(
            credential.encrypted_value
        )

    @classmethod
    def update_secret(
        cls,
        credential: IntegrationCredential,
        secret: str,
        *,
        expires_at=None,
    ) -> IntegrationCredential:
        if not isinstance(credential, IntegrationCredential):
            raise IntegrationCredentialError(
                "A credencial informada é inválida."
            )

        credential.encrypted_value = (
            CredentialEncryptionService.encrypt(secret)
        )
        credential.expires_at = expires_at
        credential.save(
            update_fields=(
                "encrypted_value",
                "expires_at",
                "updated_at",
            )
        )

        return credential

    @classmethod
    def enable(
        cls,
        credential: IntegrationCredential,
    ) -> IntegrationCredential:
        if not isinstance(credential, IntegrationCredential):
            raise IntegrationCredentialError(
                "A credencial informada é inválida."
            )

        credential.enabled = True
        credential.save(update_fields=("enabled", "updated_at"))

        return credential

    @classmethod
    def disable(
        cls,
        credential: IntegrationCredential,
    ) -> IntegrationCredential:
        if not isinstance(credential, IntegrationCredential):
            raise IntegrationCredentialError(
                "A credencial informada é inválida."
            )

        credential.enabled = False
        credential.save(update_fields=("enabled", "updated_at"))

        return credential