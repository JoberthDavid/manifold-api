import uuid

from django.db import models
from django.utils.text import slugify

from apps.security.services.jwt_key_encryption import JwtKeyEncryptionService


class JwtSigningKey(models.Model):
    class Algorithm(models.TextChoices):
        EDDSA = "EdDSA", "EdDSA"

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    kid = models.CharField(max_length=200, unique=True)
    algorithm = models.CharField(
        max_length=20,
        choices=Algorithm.choices,
        default=Algorithm.EDDSA,
    )
    private_key = models.TextField()
    public_key = models.TextField()
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    retired_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def set_private_key(self, value: str) -> None:
        self.private_key = JwtKeyEncryptionService.encrypt(value)

    def get_private_key(self) -> str:
        return JwtKeyEncryptionService.decrypt(self.private_key)

    def __str__(self) -> str:
        return self.kid


class Service(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    name = models.CharField(max_length=200)
    slug = models.SlugField(
        max_length=200,
        unique=True,
        editable=False,
    )
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(self.name) or "service"
            candidate = base_slug
            counter = 2

            while Service.objects.filter(slug=candidate).exclude(pk=self.pk).exists():
                candidate = f"{base_slug}-{counter}"
                counter += 1

            self.slug = candidate

        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return self.name


class ServiceCredential(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    service = models.ForeignKey(
        Service,
        on_delete=models.CASCADE,
        related_name="credentials",
    )
    name = models.CharField(max_length=200)
    token_hash = models.CharField(
        max_length=64,
        unique=True,
    )
    enabled = models.BooleanField(default=True)
    expires_at = models.DateTimeField(
        null=True,
        blank=True,
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(
        null=True,
        blank=True,
    )

    class Meta:
        ordering = ["service", "name"]
        constraints = [
            models.UniqueConstraint(
                fields=["service", "name"],
                name="uq_service_credential_service_name",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.service.name} — {self.name}"


class TechnicalEndpoint(models.Model):
    class HttpMethod(models.TextChoices):
        GET = "GET", "GET"
        POST = "POST", "POST"
        PUT = "PUT", "PUT"
        PATCH = "PATCH", "PATCH"
        DELETE = "DELETE", "DELETE"

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    name = models.CharField(max_length=200)
    slug = models.SlugField(
        max_length=200,
        unique=True,
        editable=False,
    )
    http_method = models.CharField(
        max_length=10,
        choices=HttpMethod.choices,
    )
    path = models.CharField(max_length=500)
    description = models.TextField(
        blank=True,
        default="",
    )
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["path", "http_method"]
        constraints = [
            models.UniqueConstraint(
                fields=["http_method", "path"],
                name="uq_technical_endpoint_method_path",
            ),
        ]

    def save(self, *args, **kwargs):
        if not self.slug:
            base_slug = slugify(self.name) or "technical-endpoint"
            candidate = base_slug
            counter = 2

            while (
                TechnicalEndpoint.objects
                .filter(slug=candidate)
                .exclude(pk=self.pk)
                .exists()
            ):
                candidate = f"{base_slug}-{counter}"
                counter += 1

            self.slug = candidate

        if self.path and not self.path.startswith("/"):
            self.path = f"/{self.path}"

        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.http_method} {self.path}"


class ServiceTechnicalEndpoint(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
    )
    service = models.ForeignKey(
        Service,
        on_delete=models.CASCADE,
        related_name="technical_endpoints",
    )
    endpoint = models.ForeignKey(
        TechnicalEndpoint,
        on_delete=models.CASCADE,
        related_name="authorized_services",
    )
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["service", "endpoint"]
        constraints = [
            models.UniqueConstraint(
                fields=["service", "endpoint"],
                name="uq_service_technical_endpoint",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.service.name} → {self.endpoint}"