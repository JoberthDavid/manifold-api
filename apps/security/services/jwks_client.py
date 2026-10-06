from __future__ import annotations

import jwt
from django.conf import settings


class JwksClientError(Exception):
    """Erro relacionado ao consumo do JWKS."""


class JwksClient:
    """Cliente para consumo do endpoint JWKS do Manifold."""

    DEFAULT_URL = "http://127.0.0.1:8000/.well-known/jwks.json"

    @classmethod
    def get_jwks(cls) -> dict:
        import requests

        url = getattr(
            settings,
            "MANIFOLD_JWKS_URL",
            cls.DEFAULT_URL,
        )

        try:
            response = requests.get(
                url,
                timeout=5,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise JwksClientError(
                "Não foi possível consultar o JWKS do Manifold."
            ) from exc

        try:
            data = response.json()
        except ValueError as exc:
            raise JwksClientError(
                "A resposta do JWKS não contém JSON válido."
            ) from exc

        if not isinstance(data, dict):
            raise JwksClientError(
                "A resposta do JWKS possui formato inválido."
            )

        keys = data.get("keys")

        if not isinstance(keys, list):
            raise JwksClientError(
                "A resposta do JWKS não contém uma lista de chaves."
            )

        return data

    @classmethod
    def get_public_key_for_token(cls, token: str):
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError as exc:
            raise JwksClientError(
                "O header do JWT é inválido."
            ) from exc

        kid = header.get("kid")

        if not kid:
            raise JwksClientError(
                "O JWT não possui kid."
            )

        jwks = cls.get_jwks()

        jwk = next(
            (
                key
                for key in jwks["keys"]
                if key.get("kid") == kid
            ),
            None,
        )

        if jwk is None:
            raise JwksClientError(
                "A chave pública do JWT não foi encontrada no JWKS."
            )

        if jwk.get("kty") != "OKP":
            raise JwksClientError(
                "O tipo da chave pública não é suportado."
            )

        if jwk.get("crv") != "Ed25519":
            raise JwksClientError(
                "A curva da chave pública não é suportada."
            )

        if jwk.get("alg") != "EdDSA":
            raise JwksClientError(
                "O algoritmo da chave pública não é suportado."
            )

        try:
            return jwt.algorithms.OKPAlgorithm.from_jwk(
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": jwk["x"],
                }
            )
        except (
            KeyError,
            ValueError,
            TypeError,
        ) as exc:
            raise JwksClientError(
                "A chave pública JWK é inválida."
            ) from exc