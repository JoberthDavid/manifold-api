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
from apps.integrations.services.api_key_fingerprint import (
    ApiKeyFingerprintService,
)


class IntegrationCredentialService:
    """Manages persisted integration credentials."""

    @classmethod
    def create(
        cls,
        *,
        integration,
        name,
        credential_type,
        secret,
        expires_at=None,
    ):
        if not isinstance(integration, Integration):
            raise IntegrationCredentialError(
                "A integração informada é inválida."
            )

        if not name or not name.strip():
            raise IntegrationCredentialError(
                "O nome da credencial é obrigatório."
            )

        valid_credential_types = {
            choice for choice, _ in CredentialType.choices
        }

        if credential_type not in valid_credential_types:
            raise IntegrationCredentialError(
                "O tipo de credencial informado é inválido."
            )

        encrypted_value = CredentialEncryptionService.encrypt(secret)
        fingerprint = ApiKeyFingerprintService.generate(secret)

        return IntegrationCredential.objects.create(
            integration=integration,
            name=name.strip(),
            credential_type=credential_type,
            encrypted_value=encrypted_value,
            fingerprint=fingerprint,
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
        credential,
        secret,
        *,
        expires_at=None,
    ):
        if not isinstance(credential, IntegrationCredential):
            raise IntegrationCredentialError(
                "A credencial informada é inválida."
            )

        if not secret:
            raise IntegrationCredentialError(
                "O segredo da credencial não pode ser vazio."
            )

        encrypted_value = CredentialEncryptionService.encrypt(secret)
        fingerprint = ApiKeyFingerprintService.generate(secret)

        credential.encrypted_value = encrypted_value
        credential.fingerprint = fingerprint
        credential.expires_at = expires_at

        credential.save(
            update_fields=[
                "encrypted_value",
                "fingerprint",
                "expires_at",
                "updated_at",
            ]
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