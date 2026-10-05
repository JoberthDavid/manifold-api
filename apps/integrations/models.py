import uuid

from django.db import models


class IntegrationType(models.TextChoices):
    REST_API = "REST_API", "API REST"


class CredentialType(models.TextChoices):
    API_KEY = "API_KEY", "API Key"
    BEARER_TOKEN = "BEARER_TOKEN", "Bearer Token"
    BASIC_AUTH = "BASIC_AUTH", "Basic Auth"
    OAUTH2 = "OAUTH2", "OAuth 2.0"


class Integration(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    code = models.CharField(
        max_length=100,
        unique=True,
        verbose_name="código",
    )
    name = models.CharField(
        max_length=200,
        verbose_name="nome",
    )
    integration_type = models.CharField(
        max_length=30,
        choices=IntegrationType.choices,
        default=IntegrationType.REST_API,
        verbose_name="tipo",
    )
    base_url = models.URLField(
        max_length=500,
        verbose_name="URL base",
    )
    enabled = models.BooleanField(
        default=True,
        verbose_name="ativa",
    )
    timeout = models.PositiveIntegerField(
        default=10,
        verbose_name="timeout",
        help_text="Tempo máximo da requisição em segundos.",
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="criada em",
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name="atualizada em",
    )

    class Meta:
        ordering = ("code",)
        verbose_name = "integração"
        verbose_name_plural = "integrações"

    def __str__(self):
        return f"{self.name} ({self.code})"


class IntegrationCredential(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    integration = models.ForeignKey(
        Integration,
        on_delete=models.CASCADE,
        related_name="credentials",
        verbose_name="integração",
    )
    name = models.CharField(
        max_length=200,
        verbose_name="nome",
    )
    credential_type = models.CharField(
        max_length=30,
        choices=CredentialType.choices,
        verbose_name="tipo",
    )
    encrypted_value = models.TextField(
        verbose_name="valor criptografado",
    )
    enabled = models.BooleanField(
        default=True,
        verbose_name="ativa",
    )
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="expira em",
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="criada em",
    )
    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name="atualizada em",
    )

    class Meta:
        ordering = ("integration", "name")
        verbose_name = "credencial de integração"
        verbose_name_plural = "credenciais de integração"

    def __str__(self):
        return f"{self.integration.code} — {self.name}"