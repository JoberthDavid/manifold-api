from dataclasses import dataclass
from enum import Enum

from .challenge import AuthenticationChallengeService
from .models import Session, User
from .services import SessionService
from .challenge import (
    AuthenticationChallengeService,
    AuthenticationChallengeStatus,
)

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
    AUTHENTICATED = "AUTHENTICATED"


@dataclass(frozen=True)
class AuthenticationResult:
    status: AuthenticationStatus
    user: User | None = None
    session: Session | None = None
    token: str | None = None
    challenge_id: str | None = None

    @property
    def is_authenticated(self) -> bool:
        return self.status == AuthenticationStatus.AUTHENTICATED

    @property
    def requires_two_factor(self) -> bool:
        return self.status == AuthenticationStatus.TWO_FACTOR_REQUIRED


class AuthenticationService:
    @classmethod
    def authenticate_credentials(
        cls,
        email: str,
        password: str,
    ) -> CredentialAuthenticationResult:
        if not email or not password:
            return CredentialAuthenticationResult(
                status=CredentialAuthenticationStatus.INVALID_CREDENTIALS
            )

        normalized_email = email.strip()

        try:
            user = User.objects.get(
                email__iexact=normalized_email
            )
        except User.DoesNotExist:
            return CredentialAuthenticationResult(
                status=CredentialAuthenticationStatus.INVALID_CREDENTIALS
            )

        if not user.is_active:
            return CredentialAuthenticationResult(
                status=CredentialAuthenticationStatus.INACTIVE_USER,
                user=user,
            )

        if not user.check_password(password):
            return CredentialAuthenticationResult(
                status=CredentialAuthenticationStatus.INVALID_CREDENTIALS
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

        if (
            credentials.status
            == CredentialAuthenticationStatus.INVALID_CREDENTIALS
        ):
            return AuthenticationResult(
                status=AuthenticationStatus.INVALID_CREDENTIALS
            )

        if (
            credentials.status
            == CredentialAuthenticationStatus.INACTIVE_USER
        ):
            return AuthenticationResult(
                status=AuthenticationStatus.INACTIVE_USER,
                user=credentials.user,
            )

        user = credentials.user

        if user is None:
            return AuthenticationResult(
                status=AuthenticationStatus.INVALID_CREDENTIALS
            )

        if cls.requires_two_factor(user):
            challenge = (
                AuthenticationChallengeService
                .create_email_challenge(user)
            )

            return AuthenticationResult(
                status=AuthenticationStatus.TWO_FACTOR_REQUIRED,
                user=user,
                challenge_id=str(challenge.challenge.id),
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
    def verify_two_factor(
        cls,
        challenge_id,
        code: str,
        *,
        ip_address=None,
        user_agent="",
        duration=None,
    ) -> AuthenticationResult:
        challenge_result = (
            AuthenticationChallengeService.verify(
                challenge_id,
                code,
            )
        )

        if (
            challenge_result.status
            != AuthenticationChallengeStatus.VERIFIED
        ):
            return AuthenticationResult(
                status=AuthenticationStatus.TWO_FACTOR_REQUIRED,
                user=(
                    challenge_result.challenge.user
                    if challenge_result.challenge
                    else None
                ),
                challenge_id=str(challenge_id),
            )

        challenge = challenge_result.challenge

        if challenge is None:
            return AuthenticationResult(
                status=AuthenticationStatus.INVALID_CREDENTIALS
            )

        user = challenge.user

        if not user.is_active:
            return AuthenticationResult(
                status=AuthenticationStatus.INACTIVE_USER,
                user=user,
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
    def logout(cls, token: str) -> bool:
        return SessionService.revoke_session(token)