from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization

from apps.security.models import JwtSigningKey


class JwtJwksService:
    """Constrói o JWKS público das chaves de assinatura JWT."""

    @classmethod
    def build(cls) -> dict:
        keys = (
            JwtSigningKey.objects
            .filter(
                enabled=True,
                retired_at__isnull=True,
            )
            .order_by("-created_at")
        )

        return {
            "keys": [
                cls._build_jwk(key)
                for key in keys
            ]
        }

    @classmethod
    def _build_jwk(cls, key: JwtSigningKey) -> dict:
        public_key = serialization.load_pem_public_key(
            key.public_key.encode("utf-8")
        )

        raw_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": key.algorithm,
            "kid": key.kid,
            "x": cls._base64url_encode(raw_public_key),
        }

    @staticmethod
    def _base64url_encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")