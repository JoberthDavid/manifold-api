from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.db import models
from django.conf import settings
import uuid


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("O usuário deve possuir um e-mail.")

        email = self.normalize_email(email)

        user = self.model(
            email=email,
            **extra_fields,
        )

        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()

        user.save(using=self._db)

        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superusuário deve possuir is_staff=True.")

        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superusuário deve possuir is_superuser=True.")

        return self.create_user(
            email=email,
            password=password,
            **extra_fields,
        )


class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(
        unique=True,
        verbose_name="e-mail",
    )

    first_name = models.CharField(
        max_length=150,
        blank=True,
        verbose_name="nome",
    )

    last_name = models.CharField(
        max_length=150,
        blank=True,
        verbose_name="sobrenome",
    )

    is_staff = models.BooleanField(
        default=False,
        verbose_name="acesso administrativo",
    )

    is_active = models.BooleanField(
        default=True,
        verbose_name="ativo",
    )

    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="data de criação",
    )

    updated_at = models.DateTimeField(
        auto_now=True,
        verbose_name="data de atualização",
    )

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.email

import uuid

from django.conf import settings
from django.db import models


class Session(models.Model):
    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        verbose_name="identificador",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="sessions",
        verbose_name="usuário",
    )
    token_hash = models.CharField(
        max_length=64,
        unique=True,
        verbose_name="hash do token",
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="data de criação",
    )
    expires_at = models.DateTimeField(
        verbose_name="data de expiração",
    )
    last_seen_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="último acesso",
    )
    revoked_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="data de revogação",
    )
    ip_address = models.GenericIPAddressField(
        null=True,
        blank=True,
        verbose_name="endereço IP",
    )
    user_agent = models.TextField(
        blank=True,
        verbose_name="user agent",
    )

    class Meta:
        ordering = ("-created_at",)
        verbose_name = "sessão"
        verbose_name_plural = "sessões"
        indexes = [
            models.Index(
                fields=("user", "revoked_at"),
                name="session_user_active_idx",
            ),
            models.Index(
                fields=("expires_at",),
                name="accounts_session_expires_idx",
            ),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=("user",),
                condition=models.Q(revoked_at__isnull=True),
                name="session_one_active_per_user",
            ),
        ]

    def __str__(self):
        return f"{self.user.email} — {self.created_at:%d/%m/%Y %H:%M}"


class AuthenticationChallenge(models.Model):
    class ChallengeType(models.TextChoices):
        EMAIL_OTP = "EMAIL_OTP", "Código por e-mail"

    id = models.UUIDField(
        primary_key=True,
        default=uuid.uuid4,
        editable=False,
        verbose_name="identificador",
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="authentication_challenges",
        verbose_name="usuário",
    )
    challenge_type = models.CharField(
        max_length=32,
        choices=ChallengeType.choices,
        verbose_name="tipo",
    )
    token_hash = models.CharField(
        max_length=64,
        verbose_name="hash do código",
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        verbose_name="data de criação",
    )
    expires_at = models.DateTimeField(
        verbose_name="data de expiração",
    )
    verified_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="data de validação",
    )
    revoked_at = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="data de revogação",
    )
    attempts = models.PositiveSmallIntegerField(
        default=0,
        verbose_name="tentativas",
    )
    max_attempts = models.PositiveSmallIntegerField(
        default=5,
        verbose_name="máximo de tentativas",
    )

    class Meta:
        ordering = ("-created_at",)
        verbose_name = "desafio de autenticação"
        verbose_name_plural = "desafios de autenticação"
        indexes = [
            models.Index(
                fields=("user", "revoked_at"),
                name="challenge_user_active_idx",
            ),
            models.Index(
                fields=("expires_at",),
                name="challenge_expires_idx",
            ),
        ]

    def __str__(self):
        return (
            f"{self.user.email} — "
            f"{self.get_challenge_type_display()} — "
            f"{self.created_at:%d/%m/%Y %H:%M}"
        )