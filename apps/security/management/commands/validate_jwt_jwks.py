from __future__ import annotations

import jwt

from django.core.management.base import BaseCommand, CommandError

from apps.security.services.jwks_client import (
    JwksClient,
    JwksClientError,
)
from apps.security.services.jwt_keys import (
    JwtSigningKeyService,
)
from apps.security.services.jwt_tokens import (
    JwtTokenService,
)


class Command(BaseCommand):
    help = "Valida um JWT usando a chave pública obtida pelo endpoint JWKS."

    def handle(self, *args, **options):
        try:
            signing_key = JwtSigningKeyService.get_active_key()

            token = JwtTokenService.issue(
                subject="user:integration-test",
                audience="composition-engine",
                scopes=["composition:calculate"],
            )

            self.stdout.write(
                f"JWT emitido com kid: {signing_key.kid}"
            )

            public_key = JwksClient.get_public_key_for_token(
                token
            )

            payload = jwt.decode(
                token,
                public_key,
                algorithms=["EdDSA"],
                audience="composition-engine",
                issuer="manifold-api",
            )

        except (
            RuntimeError,
            JwksClientError,
            jwt.InvalidTokenError,
        ) as exc:
            raise CommandError(
                f"Falha na validação JWT via JWKS: {exc}"
            ) from exc

        self.stdout.write(
            self.style.SUCCESS(
                "JWT validado com sucesso através do endpoint JWKS."
            )
        )

        self.stdout.write(
            f"subject: {payload['sub']}"
        )

        self.stdout.write(
            f"audience: {payload['aud']}"
        )

        self.stdout.write(
            f"scope: {', '.join(payload['scope'])}"
        )

        self.stdout.write(
            f"jti: {payload['jti']}"
        )