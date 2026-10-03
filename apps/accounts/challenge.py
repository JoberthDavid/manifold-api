import hashlib
import secrets
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum

from django.db import transaction
from django.utils import timezone

from .models import AuthenticationChallenge, User


class AuthenticationChallengeType(str, Enum):
    EMAIL_OTP = "EMAIL_OTP"


class AuthenticationChallengeStatus(str, Enum):
    ACTIVE = "ACTIVE"
    VERIFIED = "VERIFIED"
    EXPIRED = "EXPIRED"
    EXHAUSTED = "EXHAUSTED"
    REVOKED = "REVOKED"


@dataclass(frozen=True)
class AuthenticationChallengeResult:
    status: AuthenticationChallengeStatus
    challenge: AuthenticationChallenge | None = None


@dataclass(frozen=True)
class AuthenticationChallengeCreationResult:
    challenge: AuthenticationChallenge
    verification_code: str


class AuthenticationChallengeService:
    DEFAULT_DURATION = timedelta(minutes=10)
    DEFAULT_MAX_ATTEMPTS = 5
    CODE_DIGITS = 6

    @classmethod
    def _hash_code(cls, code: str) -> str:
        return hashlib.sha256(
            code.encode("utf-8")
        ).hexdigest()

    @classmethod
    def _generate_code(cls) -> str:
        maximum = 10 ** cls.CODE_DIGITS

        return f"{secrets.randbelow(maximum):0{cls.CODE_DIGITS}d}"

    @classmethod
    @transaction.atomic
    def create_email_challenge(
        cls,
        user: User,
        *,
        duration=None,
        max_attempts=None,
    ) -> AuthenticationChallengeCreationResult:
        now = timezone.now()

        duration = duration or cls.DEFAULT_DURATION
        max_attempts = (
            max_attempts
            if max_attempts is not None
            else cls.DEFAULT_MAX_ATTEMPTS
        )

        cls.revoke_active_challenges(user, revoked_at=now)

        verification_code = cls._generate_code()
        token_hash = cls._hash_code(verification_code)

        challenge = AuthenticationChallenge.objects.create(
            user=user,
            challenge_type=AuthenticationChallenge.ChallengeType.EMAIL_OTP,
            token_hash=token_hash,
            expires_at=now + duration,
            max_attempts=max_attempts,
        )

        return AuthenticationChallengeCreationResult(
            challenge=challenge,
            verification_code=verification_code,
        )

    @classmethod
    def get_status(
        cls,
        challenge: AuthenticationChallenge,
    ) -> AuthenticationChallengeStatus:
        if challenge.revoked_at is not None:
            return AuthenticationChallengeStatus.REVOKED

        if challenge.verified_at is not None:
            return AuthenticationChallengeStatus.VERIFIED

        if challenge.expires_at <= timezone.now():
            return AuthenticationChallengeStatus.EXPIRED

        if challenge.attempts >= challenge.max_attempts:
            return AuthenticationChallengeStatus.EXHAUSTED

        return AuthenticationChallengeStatus.ACTIVE

    @classmethod
    @transaction.atomic
    def verify(
        cls,
        challenge_id,
        code: str,
    ) -> AuthenticationChallengeResult:
        try:
            challenge = (
                AuthenticationChallenge.objects
                .select_for_update()
                .select_related("user")
                .get(pk=challenge_id)
            )
        except AuthenticationChallenge.DoesNotExist:
            return AuthenticationChallengeResult(
                status=AuthenticationChallengeStatus.REVOKED,
            )

        status = cls.get_status(challenge)

        if status != AuthenticationChallengeStatus.ACTIVE:
            return AuthenticationChallengeResult(
                status=status,
                challenge=challenge,
            )

        challenge.attempts += 1

        token_hash = cls._hash_code(code.strip())

        if secrets.compare_digest(
            challenge.token_hash,
            token_hash,
        ):
            challenge.verified_at = timezone.now()

            challenge.save(
                update_fields=(
                    "attempts",
                    "verified_at",
                )
            )

            return AuthenticationChallengeResult(
                status=AuthenticationChallengeStatus.VERIFIED,
                challenge=challenge,
            )

        if challenge.attempts >= challenge.max_attempts:
            challenge.revoked_at = timezone.now()

            challenge.save(
                update_fields=(
                    "attempts",
                    "revoked_at",
                )
            )

            return AuthenticationChallengeResult(
                status=AuthenticationChallengeStatus.EXHAUSTED,
                challenge=challenge,
            )

        challenge.save(
            update_fields=("attempts",)
        )

        return AuthenticationChallengeResult(
            status=AuthenticationChallengeStatus.ACTIVE,
            challenge=challenge,
        )

    @classmethod
    @transaction.atomic
    def revoke(
        cls,
        challenge: AuthenticationChallenge,
    ) -> bool:
        if challenge.revoked_at is not None:
            return False

        if challenge.verified_at is not None:
            return False

        challenge.revoked_at = timezone.now()

        challenge.save(
            update_fields=("revoked_at",)
        )

        return True

    @classmethod
    def revoke_active_challenges(
        cls,
        user: User,
        *,
        revoked_at=None,
    ) -> int:
        revoked_at = revoked_at or timezone.now()

        return (
            AuthenticationChallenge.objects
            .filter(
                user=user,
                revoked_at__isnull=True,
                verified_at__isnull=True,
            )
            .update(revoked_at=revoked_at)
        )