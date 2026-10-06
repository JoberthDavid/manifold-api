from __future__ import annotations

import base64

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from apps.security.services.jwt_jwks import JwtJwksService


class JwtVerificationError(Exception):
    """Erro relacionado à validação de JWT."""


class JwtVerificationService:
    """Valida JWTs emitidos pelo Manifold usando o JWKS público."""

    @classmethod
    def verify(
        cls,
        token: str,
        *,
        audience: str,
    ) -> dict:
        if not token:
            raise JwtVerificationError(
                "O token JWT não pode ser vazio."
            )

        if not audience:
            raise JwtVerificationError(
                "O audience não pode ser vazio."
            )

        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise JwtVerificationError(
                "O header do JWT é inválido."
            ) from exc

        kid = header.get("kid")

        if not kid:
            raise JwtVerificationError(
                "O JWT não possui kid."
            )

        jwks = JwtJwksService.build()

        jwk = next(
            (
                item
                for item in jwks["keys"]
                if item["kid"] == kid
            ),
            None,
        )

        if jwk is None:
            raise JwtVerificationError(
                "A chave pública do JWT não foi encontrada no JWKS."
            )

        if jwk.get("alg") != "EdDSA":
            raise JwtVerificationError(
                "O algoritmo do JWT não é suportado."
            )

        if jwk.get("crv") != "Ed25519":
            raise JwtVerificationError(
                "A curva da chave JWT não é suportada."
            )

        try:
            public_key = cls._public_key_from_jwk(jwk)

            return jwt.decode(
                token,
                public_key,
                algorithms=["EdDSA"],
                audience=audience,
                issuer="manifold-api",
            )

        except jwt.InvalidTokenError as exc:
            raise JwtVerificationError(
                "O JWT não pôde ser validado."
            ) from exc

    @staticmethod
    def _public_key_from_jwk(jwk: dict) -> Ed25519PublicKey:
        try:
            encoded_key = jwk["x"]

            padding = "=" * (-len(encoded_key) % 4)

            raw_key = base64.urlsafe_b64decode(
                encoded_key + padding
            )

            return Ed25519PublicKey.from_public_bytes(
                raw_key
            )

        except (
            KeyError,
            ValueError,
            TypeError,
        ) as exc:
            raise JwtVerificationError(
                "A chave pública JWK é inválida."
            ) from exc