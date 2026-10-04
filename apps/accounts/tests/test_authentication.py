from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from ..authentication import (
    AuthenticationService,
    AuthenticationStatus,

)
from ..challenge import (
    AuthenticationChallengeService,
)
from ..models import User


class AuthenticationTwoFactorStateTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="two-factor@example.com",
            password="StrongPassword123!",
        )

    def create_challenge(self):
        return AuthenticationChallengeService.create_email_challenge(
            self.user,
        )

    def test_wrong_code_returns_invalid_code(self):
        challenge_creation = self.create_challenge()

        result = AuthenticationService.verify_two_factor(
            challenge_creation.challenge.id,
            "000000",
        )

        self.assertEqual(
            result.status,
            AuthenticationStatus.TWO_FACTOR_INVALID_CODE,
        )
        self.assertEqual(result.attempts_remaining, 4)
        self.assertIsNone(result.session)
        self.assertIsNone(result.token)

    def test_expired_challenge_returns_expired(self):
        challenge_creation = self.create_challenge()

        challenge = challenge_creation.challenge
        challenge.expires_at = timezone.now() - timedelta(minutes=1)
        challenge.save(update_fields=("expires_at",))

        result = AuthenticationService.verify_two_factor(
            challenge.id,
            challenge_creation.verification_code,
        )

        self.assertEqual(
            result.status,
            AuthenticationStatus.TWO_FACTOR_EXPIRED,
        )
        self.assertIsNone(result.session)
        self.assertIsNone(result.token)

    def test_exhausted_challenge_returns_exhausted(self):
        challenge_creation = self.create_challenge()

        challenge = challenge_creation.challenge

        for _ in range(challenge.max_attempts):
            result = AuthenticationService.verify_two_factor(
                challenge.id,
                "000000",
            )

        self.assertEqual(
            result.status,
            AuthenticationStatus.TWO_FACTOR_EXHAUSTED,
        )
        self.assertEqual(result.attempts_remaining, 0)
        self.assertIsNone(result.session)
        self.assertIsNone(result.token)

    def test_revoked_challenge_returns_revoked(self):
        challenge_creation = self.create_challenge()

        challenge = challenge_creation.challenge

        AuthenticationChallengeService.revoke(challenge)

        result = AuthenticationService.verify_two_factor(
            challenge.id,
            challenge_creation.verification_code,
        )

        self.assertEqual(
            result.status,
            AuthenticationStatus.TWO_FACTOR_REVOKED,
        )
        self.assertIsNone(result.session)
        self.assertIsNone(result.token)

    def test_verified_code_authenticates_and_creates_session(self):
        challenge_creation = self.create_challenge()

        result = AuthenticationService.verify_two_factor(
            challenge_creation.challenge.id,
            challenge_creation.verification_code,
        )

        self.assertEqual(
            result.status,
            AuthenticationStatus.AUTHENTICATED,
        )
        self.assertTrue(result.is_authenticated)
        self.assertIsNotNone(result.session)
        self.assertIsNotNone(result.token)

        self.assertEqual(
            result.session.user,
            self.user,
        )

    def test_verified_challenge_cannot_be_used_again(self):
        challenge_creation = self.create_challenge()

        first_result = AuthenticationService.verify_two_factor(
            challenge_creation.challenge.id,
            challenge_creation.verification_code,
        )

        self.assertEqual(
            first_result.status,
            AuthenticationStatus.AUTHENTICATED,
        )

        second_result = AuthenticationService.verify_two_factor(
            challenge_creation.challenge.id,
            challenge_creation.verification_code,
        )

        self.assertEqual(
            second_result.status,
            AuthenticationStatus.TWO_FACTOR_REVOKED,
        )

        self.assertIsNone(second_result.session)
        self.assertIsNone(second_result.token)