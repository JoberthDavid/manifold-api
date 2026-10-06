from __future__ import annotations

import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from apps.security.models import JwtSigningKey
from apps.security.services.jwt_key_encryption import (
    JwtKeyEncryptionService,
)


class JwtSigningKeyService:
    """Gerencia as chaves Ed25519 utilizadas para assinatura de JWT."""

    ALGORITHM = "EdDSA"

    @classmethod
    def generate(cls) -> JwtSigningKey:
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_key_value = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        public_key_value = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        encrypted_private_key = JwtKeyEncryptionService.encrypt(
            private_key_value
        )

        return JwtSigningKey.objects.create(
            kid=f"manifold-{uuid.uuid4()}",
            algorithm=cls.ALGORITHM,
            private_key=encrypted_private_key,
            public_key=public_key_value,
        )

    @classmethod
    def get_active_key(cls) -> JwtSigningKey:
        key = (
            JwtSigningKey.objects
            .filter(enabled=True, retired_at__isnull=True)
            .order_by("-created_at")
            .first()
        )

        if key is None:
            raise RuntimeError(
                "Nenhuma chave de assinatura JWT ativa está configurada."
            )

        return key

    @classmethod
    def get_private_key(cls, key: JwtSigningKey) -> Ed25519PrivateKey:
        private_key_value = JwtKeyEncryptionService.decrypt(
            key.private_key
        )

        try:
            private_key = serialization.load_pem_private_key(
                private_key_value.encode("utf-8"),
                password=None,
            )
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                "A chave privada JWT armazenada é inválida."
            ) from exc

        if not isinstance(private_key, Ed25519PrivateKey):
            raise RuntimeError(
                "A chave privada armazenada não é Ed25519."
            )

        return private_key