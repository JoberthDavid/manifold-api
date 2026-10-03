import hashlib
import secrets
from datetime import timedelta

from django.utils import timezone

from .models import Session, User

from django.db import transaction


class SessionService:
    """Regras de criação, validação e revogação de sessões."""

    DEFAULT_DURATION = timedelta(hours=24)

    @classmethod
    def _hash_token(cls, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @classmethod
    @transaction.atomic
    def create_session(
        cls,
        user,
        *,
        ip_address=None,
        user_agent="",
        duration=None,
    ):
        """
        Cria uma nova sessão para o usuário.

        A sessão ativa anterior é revogada antes da criação
        da nova sessão.

        O usuário é bloqueado durante a operação para impedir
        concorrência na criação de sessões.
        """

        locked_user = (
            User.objects
            .select_for_update()
            .get(pk=user.pk)
        )

        now = timezone.now()
        duration = duration or cls.DEFAULT_DURATION

        cls.revoke_active_sessions(
            locked_user,
            revoked_at=now,
        )

        token = secrets.token_urlsafe(32)
        token_hash = cls._hash_token(token)

        session = Session.objects.create(
            user=locked_user,
            token_hash=token_hash,
            expires_at=now + duration,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        return session, token

    @classmethod
    def authenticate_session(cls, token: str):
        """
        Valida um token de sessão.

        Retorna o usuário autenticado ou None.
        """

        if not token:
            return None

        token_hash = cls._hash_token(token)

        session = (
            Session.objects
            .select_related("user")
            .filter(
                token_hash=token_hash,
                revoked_at__isnull=True,
            )
            .first()
        )

        if session is None:
            return None

        now = timezone.now()

        if session.expires_at <= now:
            session.revoked_at = now
            session.save(update_fields=["revoked_at"])
            return None

        if not session.user.is_active:
            return None

        session.last_seen_at = now
        session.save(update_fields=["last_seen_at"])

        return session.user

    @classmethod
    def revoke_session(cls, token: str) -> bool:
        """Revoga uma sessão específica."""

        if not token:
            return False

        token_hash = cls._hash_token(token)

        updated = (
            Session.objects
            .filter(
                token_hash=token_hash,
                revoked_at__isnull=True,
            )
            .update(
                revoked_at=timezone.now(),
            )
        )

        return updated > 0

    @classmethod
    def revoke_active_sessions(cls, user, *, revoked_at=None) -> int:
        """Revoga todas as sessões ativas do usuário."""

        revoked_at = revoked_at or timezone.now()

        return (
            Session.objects
            .filter(
                user=user,
                revoked_at__isnull=True,
            )
            .update(
                revoked_at=revoked_at,
            )
        )