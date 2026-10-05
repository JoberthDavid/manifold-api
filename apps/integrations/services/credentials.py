from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings

from apps.integrations.exceptions import IntegrationCredentialError


class CredentialEncryptionService:
    """Encrypts and decrypts integration credentials."""

    @classmethod
    def _get_fernet(cls) -> Fernet:
        key = settings.MANIFOLD_CREDENTIAL_ENCRYPTION_KEY

        if not key:
            raise IntegrationCredentialError(
                "A chave de criptografia das credenciais não está configurada."
            )

        try:
            return Fernet(key.encode())
        except (TypeError, ValueError) as exc:
            raise IntegrationCredentialError(
                "A chave de criptografia das credenciais é inválida."
            ) from exc

    @classmethod
    def encrypt(cls, value: str) -> str:
        if not isinstance(value, str):
            raise IntegrationCredentialError(
                "O valor da credencial deve ser uma string."
            )

        if not value:
            raise IntegrationCredentialError(
                "O valor da credencial não pode ser vazio."
            )

        encrypted = cls._get_fernet().encrypt(value.encode())
        return encrypted.decode()

    @classmethod
    def decrypt(cls, encrypted_value: str) -> str:
        if not isinstance(encrypted_value, str):
            raise IntegrationCredentialError(
                "O valor criptografado deve ser uma string."
            )

        if not encrypted_value:
            raise IntegrationCredentialError(
                "O valor criptografado não pode ser vazio."
            )

        try:
            decrypted = cls._get_fernet().decrypt(
                encrypted_value.encode()
            )
        except InvalidToken as exc:
            raise IntegrationCredentialError(
                "Não foi possível descriptografar a credencial."
            ) from exc

        try:
            return decrypted.decode()
        except UnicodeDecodeError as exc:
            raise IntegrationCredentialError(
                "A credencial descriptografada possui conteúdo inválido."
            ) from exc
        