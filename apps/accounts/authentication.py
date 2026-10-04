from dataclasses import dataclass
from enum import Enum

from django.db import transaction
from django.utils import timezone

from apps.communications.services import EmailServiceFactory

from .challenge import (
    AuthenticationChallengeService,
    AuthenticationChallengeStatus,
)
from .models import Session, User
from .notifications import AuthenticationNotificationService
from .services import SessionService


class CredentialAuthenticationStatus(str, Enum):
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    INACTIVE_USER = "INACTIVE_USER"
    VALID = "VALID"


@dataclass(frozen=True)
class CredentialAuthenticationResult:
    status: CredentialAuthenticationStatus
    user: User | None = None

    @property
    def is_valid(self) -> bool:
        return self.status == CredentialAuthenticationStatus.VALID


class AuthenticationStatus(str, Enum):
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    INACTIVE_USER = "INACTIVE_USER"

    TWO_FACTOR_REQUIRED = "TWO_FACTOR_REQUIRED"
    TWO_FACTOR_INVALID_CODE = "TWO_FACTOR_INVALID_CODE"
    TWO_FACTOR_EXPIRED = "TWO_FACTOR_EXPIRED"
    TWO_FACTOR_EXHAUSTED = "TWO_FACTOR_EXHAUSTED"
    TWO_FACTOR_REVOKED = "TWO_FACTOR_REVOKED"

    EMAIL_DELIVERY_FAILED = "EMAIL_DELIVERY_FAILED"

    AUTHENTICATED = "AUTHENTICATED"


@dataclass(frozen=True)
class AuthenticationResult:
    status: AuthenticationStatus
    user: User | None = None
    session: Session | None = None
    token: str | None = None
    challenge_id: str | None = None
    attempts_remaining: int | None = None

    @property
    def is_authenticated(self) -> bool:
        return self.status == AuthenticationStatus.AUTHENTICATED

    @property
    def requires_two_factor(self) -> bool:
        return self.status == AuthenticationStatus.TWO_FACTOR_REQUIRED

    @property
    def email_delivery_failed(self) -> bool:
        return self.status == AuthenticationStatus.EMAIL_DELIVERY_FAILED


class AuthenticationService:
    @classmethod
    def authenticate_credentials(
        cls,
        email: str,
        password: str,
    ) -> CredentialAuthenticationResult:
        if not email or not password:
            return CredentialAuthenticationResult(
                status=CredentialAuthenticationStatus.INVALID_CREDENTIALS,
            )

        normalized_email = email.strip()

        try:
            user = User.objects.get(email__iexact=normalized_email)
        except User.DoesNotExist:
            return CredentialAuthenticationResult(
                status=CredentialAuthenticationStatus.INVALID_CREDENTIALS,
            )

        if not user.is_active:
            return CredentialAuthenticationResult(
                status=CredentialAuthenticationStatus.INACTIVE_USER,
                user=user,
            )

        if not user.check_password(password):
            return CredentialAuthenticationResult(
                status=CredentialAuthenticationStatus.INVALID_CREDENTIALS,
            )

        return CredentialAuthenticationResult(
            status=CredentialAuthenticationStatus.VALID,
            user=user,
        )

    @classmethod
    def requires_two_factor(cls, user: User) -> bool:
        return False

    @classmethod
    def login(
        cls,
        email: str,
        password: str,
        *,
        ip_address=None,
        user_agent="",
        duration=None,
    ) -> AuthenticationResult:
        credentials = cls.authenticate_credentials(
            email=email,
            password=password,
        )

        if credentials.status == CredentialAuthenticationStatus.INVALID_CREDENTIALS:
            return AuthenticationResult(
                status=AuthenticationStatus.INVALID_CREDENTIALS,
            )

        if credentials.status == CredentialAuthenticationStatus.INACTIVE_USER:
            return AuthenticationResult(
                status=AuthenticationStatus.INACTIVE_USER,
                user=credentials.user,
            )

        user = credentials.user

        if user is None:
            return AuthenticationResult(
                status=AuthenticationStatus.INVALID_CREDENTIALS,
            )

        if cls.requires_two_factor(user):
            challenge_creation = (
                AuthenticationChallengeService.create_email_challenge(user)
            )

            email_service = EmailServiceFactory.create()

            notification_service = AuthenticationNotificationService(
                email_service=email_service,
            )

            delivery_result = notification_service.send_authentication_code(
                recipient=user.email,
                verification_code=challenge_creation.verification_code,
            )

            if not delivery_result.is_sent:
                AuthenticationChallengeService.revoke(
                    challenge_creation.challenge,
                )

                return AuthenticationResult(
                    status=AuthenticationStatus.EMAIL_DELIVERY_FAILED,
                    user=user,
                    challenge_id=str(challenge_creation.challenge.id),
                )

            return AuthenticationResult(
                status=AuthenticationStatus.TWO_FACTOR_REQUIRED,
                user=user,
                challenge_id=str(challenge_creation.challenge.id),
            )

        session, token = SessionService.create_session(
            user,
            ip_address=ip_address,
            user_agent=user_agent,
            duration=duration,
        )

        return AuthenticationResult(
            status=AuthenticationStatus.AUTHENTICATED,
            user=user,
            session=session,
            token=token,
        )

    @classmethod
    @transaction.atomic
    def verify_two_factor(
        cls,
        challenge_id,
        code: str,
        *,
        ip_address=None,
        user_agent="",
        duration=None,
    ) -> AuthenticationResult:
        challenge_result = AuthenticationChallengeService.verify(
            challenge_id,
            code,
        )

        status = challenge_result.status
        challenge = challenge_result.challenge

        if status == AuthenticationChallengeStatus.ACTIVE:
            attempts_remaining = None

            if challenge is not None:
                attempts_remaining = max(
                    challenge.max_attempts - challenge.attempts,
                    0,
                )

            return AuthenticationResult(
                status=AuthenticationStatus.TWO_FACTOR_INVALID_CODE,
                user=challenge.user if challenge else None,
                challenge_id=str(challenge_id),
                attempts_remaining=attempts_remaining,
            )

        if status == AuthenticationChallengeStatus.EXPIRED:
            return AuthenticationResult(
                status=AuthenticationStatus.TWO_FACTOR_EXPIRED,
                user=challenge.user if challenge else None,
                challenge_id=str(challenge_id),
            )

        if status == AuthenticationChallengeStatus.EXHAUSTED:
            return AuthenticationResult(
                status=AuthenticationStatus.TWO_FACTOR_EXHAUSTED,
                user=challenge.user if challenge else None,
                challenge_id=str(challenge_id),
                attempts_remaining=0,
            )

        if status == AuthenticationChallengeStatus.REVOKED:
            return AuthenticationResult(
                status=AuthenticationStatus.TWO_FACTOR_REVOKED,
                user=challenge.user if challenge else None,
                challenge_id=str(challenge_id),
            )

        if status != AuthenticationChallengeStatus.VERIFIED:
            return AuthenticationResult(
                status=AuthenticationStatus.TWO_FACTOR_REVOKED,
                user=challenge.user if challenge else None,
                challenge_id=str(challenge_id),
            )

        if challenge is None:
            return AuthenticationResult(
                status=AuthenticationStatus.TWO_FACTOR_REVOKED,
                challenge_id=str(challenge_id),
            )

        if challenge.consumed_at is not None:
            return AuthenticationResult(
                status=AuthenticationStatus.TWO_FACTOR_REVOKED,
                user=challenge.user,
                challenge_id=str(challenge_id),
            )

        user = challenge.user

        if not user.is_active:
            return AuthenticationResult(
                status=AuthenticationStatus.INACTIVE_USER,
                user=user,
                challenge_id=str(challenge_id),
            )

        challenge.consumed_at = timezone.now()
        challenge.save(
            update_fields=("consumed_at",)
        )

        session, token = SessionService.create_session(
            user,
            ip_address=ip_address,
            user_agent=user_agent,
            duration=duration,
        )

        return AuthenticationResult(
            status=AuthenticationStatus.AUTHENTICATED,
            user=user,
            session=session,
            token=token,
            challenge_id=str(challenge_id),
        )

    @classmethod
    def logout(cls, token: str) -> bool:
        return SessionService.revoke_session(token)