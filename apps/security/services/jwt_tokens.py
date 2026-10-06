from __future__ import annotations

import time
import uuid
from typing import Sequence

import jwt

from apps.security.services.jwt_keys import JwtSigningKeyService


class JwtTokenService:
    """Emite JWTs internos assinados pelo Manifold."""

    ISSUER = "manifold-api"
    DEFAULT_TTL_SECONDS = 300

    @classmethod
    def issue(
        cls,
        *,
        subject: str,
        audience: str,
        scopes: Sequence[str],
        ttl_seconds: int | None = None,
    ) -> str:
        if not subject:
            raise ValueError("O subject do JWT não pode ser vazio.")

        if not audience:
            raise ValueError("O audience do JWT não pode ser vazio.")

        if not scopes:
            raise ValueError("O JWT deve possuir pelo menos um scope.")

        if any(not isinstance(scope, str) or not scope for scope in scopes):
            raise ValueError("Todos os scopes do JWT devem ser strings não vazias.")

        ttl = (
            cls.DEFAULT_TTL_SECONDS
            if ttl_seconds is None
            else ttl_seconds
        )

        if ttl <= 0:
            raise ValueError("O TTL do JWT deve ser maior que zero.")

        signing_key = JwtSigningKeyService.get_active_key()
        private_key = JwtSigningKeyService.get_private_key(signing_key)

        now = int(time.time())
        expires_at = now + ttl

        payload = {
            "iss": cls.ISSUER,
            "sub": subject,
            "aud": audience,
            "scope": list(scopes),
            "iat": now,
            "exp": expires_at,
            "jti": str(uuid.uuid4()),
        }

        return jwt.encode(
            payload,
            private_key,
            algorithm=signing_key.algorithm,
            headers={
                "kid": signing_key.kid,
                "typ": "JWT",
            },
        )