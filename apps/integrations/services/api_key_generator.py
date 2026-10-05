from __future__ import annotations

import secrets


class ApiKeyGenerator:
    """Gera chaves de autenticação criptograficamente seguras."""

    KEY_BYTES = 32

    @classmethod
    def generate(cls) -> str:
        """
        Gera uma API key com 256 bits de entropia.

        32 bytes são representados por 64 caracteres hexadecimais.
        """
        return secrets.token_hex(cls.KEY_BYTES)
    