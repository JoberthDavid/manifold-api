from __future__ import annotations

import hashlib


class ApiKeyFingerprintService:
    """Gera identificadores não reversíveis para API keys."""

    @staticmethod
    def generate(secret: str) -> str:
        if not isinstance(secret, str):
            raise TypeError("A API key deve ser uma string.")

        if not secret:
            raise ValueError("A API key não pode ser vazia.")

        return hashlib.sha256(
            secret.encode("utf-8")
        ).hexdigest()
    