from __future__ import annotations

from django.core.management.base import BaseCommand

from apps.security.services.jwt_keys import JwtSigningKeyService


class Command(BaseCommand):
    help = "Gera uma nova chave Ed25519 para assinatura de JWT."

    def handle(self, *args, **options):
        key = JwtSigningKeyService.generate()

        self.stdout.write(
            self.style.SUCCESS(
                "Chave de assinatura JWT criada com sucesso."
            )
        )
        self.stdout.write(f"kid: {key.kid}")
        self.stdout.write(f"algorithm: {key.algorithm}")
        self.stdout.write(f"created_at: {key.created_at.isoformat()}")