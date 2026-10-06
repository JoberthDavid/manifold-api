from __future__ import annotations

import uuid

from django.db import models


class JwtSigningKey(models.Model):
    """
    Chave utilizada pelo Manifold para assinatura de JWTs.

    A chave privada deve permanecer armazenada de forma criptografada.
    A chave pública pode ser disponibilizada através do JWKS.
    """

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )

    kid = models.CharField(
        max_length=100,
        unique=True,
        verbose_name="identificador da chave",
    )

    algorithm = models.CharField(
        max_length=20,
        default="EdDSA",
        verbose_name="algoritmo",
    )

    private_key = models.TextField(
        verbose_name="chave privada criptografada",
    )

    public_key = models.TextField(
        verbose_name="chave pública",
    )

    enabled = models.BooleanField(
        default=True,
        verbose_name="ativa",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="criada em",
    )

    retired_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="aposentada em",
    )

    class Meta:
        ordering = ("-created_at",)
        verbose_name = "chave de assinatura JWT"
        verbose_name_plural = "chaves de assinatura JWT"

    def __str__(self) -> str:
        return f"{self.kid} ({self.algorithm})"