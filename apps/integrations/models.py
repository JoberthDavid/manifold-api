import uuid

from django.db import models
from django.utils.text import slugify


class IntegrationType(models.TextChoices):
    REST_API = "REST_API", "API REST"


class AuthenticationType(models.TextChoices):
    NONE = "NONE", "Sem autenticação"
    API_KEY = "API_KEY", "API Key"
    BEARER_TOKEN = "BEARER_TOKEN", "Bearer Token"
    BASIC_AUTH = "BASIC_AUTH", "Basic Auth"
    OAUTH2 = "OAUTH2", "OAuth 2.0"
    MANIFOLD_JWT = "MANIFOLD_JWT", "JWT interno do Manifold"


class CredentialType(models.TextChoices):
    API_KEY = "API_KEY", "API Key"
    BEARER_TOKEN = "BEARER_TOKEN", "Bearer Token"
    BASIC_AUTH = "BASIC_AUTH", "Basic Auth"
    OAUTH2 = "OAUTH2", "OAuth 2.0"


class HttpMethod(models.TextChoices):
    GET = "GET", "GET"
    POST = "POST", "POST"
    PUT = "PUT", "PUT"
    PATCH = "PATCH", "PATCH"
    DELETE = "DELETE", "DELETE"


class Integration(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    name = models.CharField(
        max_length=200,
        verbose_name="nome",
    )
    slug = models.SlugField(
        max_length=200,
        unique=True,
        editable=False,
        verbose_name="slug",
    )
    integration_type = models.CharField(
        max_length=30,
        choices=IntegrationType.choices,
        default=IntegrationType.REST_API,
        verbose_name="tipo",
    )
    authentication_type = models.CharField(
        max_length=30,
        choices=AuthenticationType.choices,
        default=AuthenticationType.NONE,
        verbose_name="autenticação",
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
        ordering = ("name",)
        verbose_name = "integração"
        verbose_name_plural = "integrações"

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = self._generate_unique_slug()

        super().save(*args, **kwargs)

    def _generate_unique_slug(self):
        base_slug = slugify(self.name)

        if not base_slug:
            base_slug = "integration"

        slug = base_slug
        counter = 2

        while (
            Integration.objects
            .filter(slug=slug)
            .exclude(pk=self.pk)
            .exists()
        ):
            slug = f"{base_slug}-{counter}"
            counter += 1

        return slug

    def __str__(self):
        return self.name


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
    fingerprint = models.CharField(
        max_length=64,
        unique=True,
        verbose_name="fingerprint",
        help_text="Identificador SHA-256 da credencial.",
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
        return f"{self.integration.name} — {self.name}"


class IntegrationOperation(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    integration = models.ForeignKey(
        Integration,
        on_delete=models.CASCADE,
        related_name="operations",
        verbose_name="integração",
    )
    name = models.CharField(
        max_length=200,
        verbose_name="nome",
    )
    slug = models.SlugField(
        max_length=200,
        verbose_name="slug",
    )
    http_method = models.CharField(
        max_length=10,
        choices=HttpMethod.choices,
        verbose_name="método HTTP",
    )
    path = models.CharField(
        max_length=500,
        verbose_name="caminho",
        help_text=(
            "Caminho relativo à URL base. "
            "Pode conter variáveis entre chaves."
        ),
    )
    request_schema = models.JSONField(
        default=dict,
        blank=True,
        verbose_name="schema da requisição",
        help_text=(
            "Configuração declarativa da requisição em JSON. "
            "Utilize as chaves 'authentication', 'path', 'query', "
            "'headers' e 'body'. Os valores devem indicar os nomes "
            "dos parâmetros fornecidos ao Gateway. Para autenticação "
            "MANIFOLD_JWT, informe 'authentication.audience' e "
            "'authentication.scopes'. Exemplo: "
            '{"authentication":{"audience":"composition-engine",'
            '"scopes":["composition:explosion"]},'
            '"path":{"composition_code":"composition_code"},'
            '"query":{"source_file_uf":"source_file_uf",'
            '"type_system":"type_system",'
            '"methodology":"methodology",'
            '"monetary_base_date":"monetary_base_date",'
            '"reference_base_date":"reference_base_date"}}'
        ),
    )
    enabled = models.BooleanField(
        default=True,
        verbose_name="ativa",
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
        constraints = (
            models.UniqueConstraint(
                fields=("integration", "slug"),
                name="uq_integration_operation_slug",
            ),
        )
        verbose_name = "operação de integração"
        verbose_name_plural = "operações de integração"

    def save(self, *args, **kwargs):
        if not self.slug:
            self.slug = self._generate_unique_slug()

        super().save(*args, **kwargs)

    def _generate_unique_slug(self):
        base_slug = slugify(self.name)

        if not base_slug:
            base_slug = "operation"

        slug = base_slug
        counter = 2

        while (
            IntegrationOperation.objects
            .filter(
                integration=self.integration,
                slug=slug,
            )
            .exclude(pk=self.pk)
            .exists()
        ):
            slug = f"{base_slug}-{counter}"
            counter += 1

        return slug

    def __str__(self):
        return f"{self.integration.name} — {self.name}"