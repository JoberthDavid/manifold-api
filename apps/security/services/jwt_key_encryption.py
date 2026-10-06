from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


class JwtKeyEncryptionError(Exception):
    """Erro relacionado à proteção das chaves JWT."""


class JwtKeyEncryptionService:
    """Criptografa e descriptografa chaves privadas de assinatura JWT."""

    @classmethod
    def _get_fernet(cls) -> Fernet:
        key = getattr(
            settings,
            "MANIFOLD_JWT_KEY_ENCRYPTION_KEY",
            "",
        )

        if not key:
            raise JwtKeyEncryptionError(
                "A chave de criptografia das chaves JWT não está configurada."
            )

        try:
            return Fernet(key.encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise JwtKeyEncryptionError(
                "A chave de criptografia das chaves JWT é inválida."
            ) from exc

    @classmethod
    def encrypt(cls, value: str) -> str:
        if not isinstance(value, str):
            raise JwtKeyEncryptionError(
                "A chave privada deve ser uma string."
            )

        if not value:
            raise JwtKeyEncryptionError(
                "A chave privada não pode ser vazia."
            )

        encrypted = cls._get_fernet().encrypt(
            value.encode("utf-8")
        )

        return encrypted.decode("utf-8")

    @classmethod
    def decrypt(cls, encrypted_value: str) -> str:
        if not isinstance(encrypted_value, str):
            raise JwtKeyEncryptionError(
                "O valor criptografado deve ser uma string."
            )

        if not encrypted_value:
            raise JwtKeyEncryptionError(
                "O valor criptografado não pode ser vazio."
            )

        try:
            decrypted = cls._get_fernet().decrypt(
                encrypted_value.encode("utf-8")
            )
        except InvalidToken as exc:
            raise JwtKeyEncryptionError(
                "Não foi possível descriptografar a chave privada JWT."
            ) from exc

        try:
            return decrypted.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise JwtKeyEncryptionError(
                "A chave privada descriptografada possui conteúdo inválido."
            ) from exc