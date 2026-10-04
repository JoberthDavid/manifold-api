import re
from datetime import timedelta
from unittest.mock import patch

from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from apps.communications.email import (
    EmailDeliveryResult,
    EmailDeliveryStatus,
)

from ..authentication import (
    AuthenticationResult,
    AuthenticationService,
    AuthenticationStatus,
    CredentialAuthenticationResult,
    CredentialAuthenticationStatus,
)
from ..challenge import (
    AuthenticationChallengeService,
    AuthenticationChallengeStatus,
)
from ..models import AuthenticationChallenge, Session, User
from ..services import SessionService


class SessionServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="usuario@example.com",
            password="SenhaSegura123!",
        )

    def test_create_session_creates_session_and_returns_token(self):
        session, token = SessionService.create_session(self.user)

        self.assertIsInstance(session, Session)
        self.assertIsInstance(token, str)
        self.assertTrue(token)

        self.assertEqual(session.user, self.user)
        self.assertEqual(len(session.token_hash), 64)
        self.assertNotEqual(session.token_hash, token)

        self.assertIsNone(session.revoked_at)
        self.assertIsNone(session.last_seen_at)

    def test_create_session_stores_only_token_hash(self):
        session, token = SessionService.create_session(self.user)

        self.assertNotEqual(session.token_hash, token)
        self.assertEqual(
            session.token_hash,
            SessionService._hash_token(token),
        )

        self.assertFalse(
            Session.objects.filter(token_hash=token).exists()
        )

    def test_create_session_sets_default_expiration(self):
        before = timezone.now()

        session, _ = SessionService.create_session(self.user)

        after = timezone.now()

        expected_min = before + SessionService.DEFAULT_DURATION
        expected_max = after + SessionService.DEFAULT_DURATION

        self.assertGreaterEqual(session.expires_at, expected_min)
        self.assertLessEqual(session.expires_at, expected_max)

    def test_create_session_accepts_custom_duration(self):
        duration = timedelta(hours=8)

        before = timezone.now()

        session, _ = SessionService.create_session(
            self.user,
            duration=duration,
        )

        after = timezone.now()

        expected_min = before + duration
        expected_max = after + duration

        self.assertGreaterEqual(session.expires_at, expected_min)
        self.assertLessEqual(session.expires_at, expected_max)

    def test_authenticate_session_returns_user_for_valid_token(self):
        _, token = SessionService.create_session(self.user)

        authenticated_user = SessionService.authenticate_session(token)

        self.assertEqual(authenticated_user, self.user)

    def test_authenticate_session_updates_last_seen_at(self):
        session, token = SessionService.create_session(self.user)

        self.assertIsNone(session.last_seen_at)

        authenticated_user = SessionService.authenticate_session(token)

        self.assertEqual(authenticated_user, self.user)

        session.refresh_from_db()

        self.assertIsNotNone(session.last_seen_at)

    def test_authenticate_session_returns_none_for_invalid_token(self):
        authenticated_user = SessionService.authenticate_session(
            "token-invalido"
        )

        self.assertIsNone(authenticated_user)

    def test_authenticate_session_returns_none_for_empty_token(self):
        self.assertIsNone(
            SessionService.authenticate_session("")
        )

        self.assertIsNone(
            SessionService.authenticate_session(None)
        )

    def test_revoked_session_cannot_be_authenticated(self):
        _, token = SessionService.create_session(self.user)

        revoked = SessionService.revoke_session(token)

        self.assertTrue(revoked)

        authenticated_user = SessionService.authenticate_session(token)

        self.assertIsNone(authenticated_user)

    def test_expired_session_cannot_be_authenticated(self):
        session, token = SessionService.create_session(
            self.user,
            duration=timedelta(seconds=-1),
        )

        authenticated_user = SessionService.authenticate_session(token)

        self.assertIsNone(authenticated_user)

        session.refresh_from_db()

        self.assertIsNotNone(session.revoked_at)

    def test_inactive_user_cannot_authenticate_session(self):
        _, token = SessionService.create_session(self.user)

        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        authenticated_user = SessionService.authenticate_session(token)

        self.assertIsNone(authenticated_user)

    def test_new_session_revokes_previous_active_session(self):
        first_session, first_token = SessionService.create_session(
            self.user
        )

        second_session, second_token = SessionService.create_session(
            self.user
        )

        first_session.refresh_from_db()

        self.assertIsNotNone(first_session.revoked_at)
        self.assertIsNone(second_session.revoked_at)

        self.assertIsNone(
            SessionService.authenticate_session(first_token)
        )

        self.assertEqual(
            SessionService.authenticate_session(second_token),
            self.user,
        )

    def test_user_can_have_multiple_historical_sessions(self):
        first_session, _ = SessionService.create_session(self.user)

        second_session, _ = SessionService.create_session(self.user)

        self.assertNotEqual(first_session.id, second_session.id)

        self.assertEqual(
            Session.objects.filter(user=self.user).count(),
            2,
        )

    def test_revoke_session_returns_true_when_session_is_active(self):
        _, token = SessionService.create_session(self.user)

        result = SessionService.revoke_session(token)

        self.assertTrue(result)

    def test_revoke_session_returns_false_for_invalid_token(self):
        result = SessionService.revoke_session(
            "token-invalido"
        )

        self.assertFalse(result)

    def test_revoke_session_returns_false_when_already_revoked(self):
        _, token = SessionService.create_session(self.user)

        first_result = SessionService.revoke_session(token)
        second_result = SessionService.revoke_session(token)

        self.assertTrue(first_result)
        self.assertFalse(second_result)

    def test_database_rejects_two_active_sessions_for_same_user(self):
        Session.objects.create(
            user=self.user,
            token_hash=SessionService._hash_token(
                "primeiro-token"
            ),
            expires_at=timezone.now() + timedelta(hours=24),
        )

        with self.assertRaises(IntegrityError):
            Session.objects.create(
                user=self.user,
                token_hash=SessionService._hash_token(
                    "segundo-token"
                ),
                expires_at=timezone.now() + timedelta(hours=24),
            )

    def test_database_allows_historical_revoked_sessions(self):
        revoked_session = Session.objects.create(
            user=self.user,
            token_hash=SessionService._hash_token(
                "token-revogado"
            ),
            expires_at=timezone.now() + timedelta(hours=24),
            revoked_at=timezone.now(),
        )

        active_session = Session.objects.create(
            user=self.user,
            token_hash=SessionService._hash_token(
                "token-ativo"
            ),
            expires_at=timezone.now() + timedelta(hours=24),
        )

        self.assertIsNotNone(revoked_session.revoked_at)
        self.assertIsNone(active_session.revoked_at)

    def test_revoke_active_sessions_revokes_active_session(self):
        session, _ = SessionService.create_session(
            self.user
        )

        self.assertIsNone(session.revoked_at)

        revoked_count = SessionService.revoke_active_sessions(
            self.user
        )

        self.assertEqual(revoked_count, 1)

        session.refresh_from_db()

        self.assertIsNotNone(session.revoked_at)

    def test_revoke_active_sessions_returns_zero_when_no_active_session_exists(
        self,
    ):
        revoked_count = SessionService.revoke_active_sessions(
            self.user
        )

        self.assertEqual(revoked_count, 0)

class AuthenticationServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="user@example.com",
            password="correct-password",
            is_active=True,
        )

    def test_authenticate_credentials_with_valid_credentials(self):
        result = AuthenticationService.authenticate_credentials(
            "user@example.com",
            "correct-password",
        )

        self.assertIsInstance(
            result,
            CredentialAuthenticationResult,
        )
        self.assertEqual(
            result.status,
            CredentialAuthenticationStatus.VALID,
        )
        self.assertEqual(result.user, self.user)

    def test_authenticate_credentials_is_case_insensitive(self):
        result = AuthenticationService.authenticate_credentials(
            "USER@EXAMPLE.COM",
            "correct-password",
        )

        self.assertEqual(
            result.status,
            CredentialAuthenticationStatus.VALID,
        )
        self.assertEqual(result.user, self.user)

    def test_authenticate_credentials_strips_email(self):
        result = AuthenticationService.authenticate_credentials(
            "  user@example.com  ",
            "correct-password",
        )

        self.assertEqual(
            result.status,
            CredentialAuthenticationStatus.VALID,
        )
        self.assertEqual(result.user, self.user)

    def test_authenticate_credentials_with_wrong_password(self):
        result = AuthenticationService.authenticate_credentials(
            "user@example.com",
            "wrong-password",
        )

        self.assertEqual(
            result.status,
            CredentialAuthenticationStatus.INVALID_CREDENTIALS,
        )
        self.assertIsNone(result.user)

    def test_authenticate_credentials_with_unknown_email(self):
        result = AuthenticationService.authenticate_credentials(
            "unknown@example.com",
            "correct-password",
        )

        self.assertEqual(
            result.status,
            CredentialAuthenticationStatus.INVALID_CREDENTIALS,
        )
        self.assertIsNone(result.user)

    def test_authenticate_credentials_with_empty_email(self):
        result = AuthenticationService.authenticate_credentials(
            "",
            "correct-password",
        )

        self.assertEqual(
            result.status,
            CredentialAuthenticationStatus.INVALID_CREDENTIALS,
        )
        self.assertIsNone(result.user)

    def test_authenticate_credentials_with_empty_password(self):
        result = AuthenticationService.authenticate_credentials(
            "user@example.com",
            "",
        )

        self.assertEqual(
            result.status,
            CredentialAuthenticationStatus.INVALID_CREDENTIALS,
        )
        self.assertIsNone(result.user)

    def test_authenticate_credentials_with_inactive_user(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        result = AuthenticationService.authenticate_credentials(
            "user@example.com",
            "correct-password",
        )

        self.assertEqual(
            result.status,
            CredentialAuthenticationStatus.INACTIVE_USER,
        )
        self.assertEqual(result.user, self.user)

    def test_login_with_invalid_credentials(self):
        result = AuthenticationService.login(
            "user@example.com",
            "wrong-password",
        )

        self.assertIsInstance(result, AuthenticationResult)
        self.assertEqual(
            result.status,
            AuthenticationStatus.INVALID_CREDENTIALS,
        )
        self.assertIsNone(result.user)
        self.assertIsNone(result.session)
        self.assertIsNone(result.token)
        self.assertIsNone(result.challenge_id)

    def test_login_with_invalid_credentials(self):
        result = AuthenticationService.login(
            "user@example.com",
            "wrong-password",
        )

        self.assertIsInstance(result, AuthenticationResult)
        self.assertEqual(
            result.status,
            AuthenticationStatus.INVALID_CREDENTIALS,
        )
        self.assertIsNone(result.user)
        self.assertIsNone(result.session)
        self.assertIsNone(result.token)
        self.assertIsNone(result.challenge_id)

    def test_login_with_inactive_user(self):
        self.user.is_active = False
        self.user.save(update_fields=["is_active"])

        result = AuthenticationService.login(
            "user@example.com",
            "correct-password",
        )

        self.assertEqual(
            result.status,
            AuthenticationStatus.INACTIVE_USER,
        )
        self.assertEqual(result.user, self.user)
        self.assertIsNone(result.session)
        self.assertIsNone(result.token)
        self.assertIsNone(result.challenge_id)

    def test_login_with_valid_credentials_authenticates_user(self):
        result = AuthenticationService.login(
            "user@example.com",
            "correct-password",
        )

        self.assertEqual(
            result.status,
            AuthenticationStatus.AUTHENTICATED,
        )
        self.assertTrue(result.is_authenticated)
        self.assertFalse(result.requires_two_factor)
        self.assertEqual(result.user, self.user)
        self.assertIsNotNone(result.session)
        self.assertIsNotNone(result.token)
        self.assertIsNone(result.challenge_id)

    @patch(
        "apps.accounts.authentication.AuthenticationService.requires_two_factor",
        return_value=True,
    )
    def test_login_requires_two_factor_without_creating_session(
        self,
        requires_two_factor,
    ):
        result = AuthenticationService.login(
            "user@example.com",
            "correct-password",
        )

        self.assertEqual(
            result.status,
            AuthenticationStatus.TWO_FACTOR_REQUIRED,
        )

        self.assertIsNone(result.session)
        self.assertIsNone(result.token)
        self.assertIsNotNone(result.challenge_id)

        self.assertEqual(
            AuthenticationChallenge.objects.count(),
            1,
        )

        self.assertEqual(
            Session.objects.count(),
            0,
        )

    def test_authenticate_credentials_does_not_create_session(self):
        result = AuthenticationService.authenticate_credentials(
            "user@example.com",
            "correct-password",
        )

        self.assertEqual(
            result.status,
            CredentialAuthenticationStatus.VALID,
        )

        self.assertEqual(
            Session.objects.filter(user=self.user).count(),
            0,
        )

class AuthenticationChallengeServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            email="challenge@example.com",
            password="StrongPassword123!",
        )

    def test_create_email_challenge(self):
        result = (
            AuthenticationChallengeService
            .create_email_challenge(self.user)
        )

        challenge = result.challenge

        self.assertIsNotNone(challenge)
        self.assertEqual(
            challenge.user,
            self.user,
        )
        self.assertEqual(
            challenge.challenge_type,
            AuthenticationChallenge.ChallengeType.EMAIL_OTP,
        )
        self.assertEqual(
            len(result.verification_code),
            6,
        )
        self.assertTrue(
            result.verification_code.isdigit()
        )
        self.assertEqual(
            challenge.attempts,
            0,
        )
        self.assertIsNotNone(
            challenge.expires_at
        )

    def test_verify_valid_code(self):
        result = (
            AuthenticationChallengeService
            .create_email_challenge(self.user)
        )

        verification = (
            AuthenticationChallengeService
            .verify(
                result.challenge.id,
                result.verification_code,
            )
        )

        self.assertEqual(
            verification.status,
            AuthenticationChallengeStatus.VERIFIED,
        )
        self.assertIsNotNone(
            verification.challenge.verified_at
        )

    def test_verify_invalid_code(self):
        result = (
            AuthenticationChallengeService
            .create_email_challenge(self.user)
        )

        verification = (
            AuthenticationChallengeService
            .verify(
                result.challenge.id,
                "000000",
            )
        )

        self.assertEqual(
            verification.status,
            AuthenticationChallengeStatus.ACTIVE,
        )
        self.assertEqual(
            verification.challenge.attempts,
            1,
        )
        self.assertIsNone(
            verification.challenge.verified_at
        )

    def test_challenge_exhausts_after_max_attempts(self):
        result = (
            AuthenticationChallengeService
            .create_email_challenge(
                self.user,
                max_attempts=2,
            )
        )

        first = AuthenticationChallengeService.verify(
            result.challenge.id,
            "000000",
        )

        self.assertEqual(
            first.status,
            AuthenticationChallengeStatus.ACTIVE,
        )

        second = AuthenticationChallengeService.verify(
            result.challenge.id,
            "000000",
        )

        self.assertEqual(
            second.status,
            AuthenticationChallengeStatus.EXHAUSTED,
        )

        self.assertIsNotNone(
            second.challenge.revoked_at
        )

    def test_expired_challenge(self):
        result = (
            AuthenticationChallengeService
            .create_email_challenge(
                self.user,
                duration=timedelta(seconds=-1),
            )
        )

        verification = AuthenticationChallengeService.verify(
            result.challenge.id,
            result.verification_code,
        )

        self.assertEqual(
            verification.status,
            AuthenticationChallengeStatus.EXPIRED,
        )

    def test_revoke_active_challenge(self):
        result = (
            AuthenticationChallengeService
            .create_email_challenge(self.user)
        )

        revoked = AuthenticationChallengeService.revoke(
            result.challenge
        )

        self.assertTrue(revoked)

        result.challenge.refresh_from_db()

        self.assertIsNotNone(
            result.challenge.revoked_at
        )

    def test_new_challenge_revokes_previous_one(self):
        first = (
            AuthenticationChallengeService
            .create_email_challenge(self.user)
        )

        second = (
            AuthenticationChallengeService
            .create_email_challenge(self.user)
        )

        first.challenge.refresh_from_db()

        self.assertIsNotNone(
            first.challenge.revoked_at
        )

        self.assertIsNone(
            second.challenge.revoked_at
        )

    def test_verified_challenge_cannot_be_reused(self):
        result = (
            AuthenticationChallengeService
            .create_email_challenge(self.user)
        )

        first = AuthenticationChallengeService.verify(
            result.challenge.id,
            result.verification_code,
        )

        second = AuthenticationChallengeService.verify(
            result.challenge.id,
            result.verification_code,
        )

        self.assertEqual(
            first.status,
            AuthenticationChallengeStatus.VERIFIED,
        )

        self.assertEqual(
            second.status,
            AuthenticationChallengeStatus.VERIFIED,
        )

    @patch(
        "apps.accounts.authentication.AuthenticationService.requires_two_factor",
        return_value=True,
    )
    def test_login_with_two_factor_creates_challenge_and_sends_code(
        self,
        requires_two_factor,
    ):
        with patch(
            "apps.accounts.authentication.EmailServiceFactory.create",
        ) as create_email_service:
            email_service = create_email_service.return_value

            email_service.send.return_value = EmailDeliveryResult(
                status=EmailDeliveryStatus.SENT,
                message=None,
            )

            result = AuthenticationService.login(
                "challenge@example.com",
                "StrongPassword123!",
            )

        self.assertEqual(
            result.status,
            AuthenticationStatus.TWO_FACTOR_REQUIRED,
        )

        self.assertIsNotNone(result.challenge_id)
        self.assertIsNone(result.session)
        self.assertIsNone(result.token)

        challenge = AuthenticationChallenge.objects.get(
            pk=result.challenge_id,
        )

        self.assertEqual(challenge.attempts, 0)
        self.assertIsNone(challenge.verified_at)
        self.assertIsNone(challenge.revoked_at)

        email_service.send.assert_called_once()

        sent_message = email_service.send.call_args.args[0]

        self.assertEqual(
            sent_message.recipient,
            self.user.email,
        )

        self.assertIn(
            "Código de autenticação",
            sent_message.subject,
        )

        self.assertNotEqual(
            sent_message.body,
            challenge.token_hash,
        )

    @patch(
        "apps.accounts.authentication.AuthenticationService.requires_two_factor",
        return_value=True,
    )
    def test_login_does_not_authenticate_when_email_delivery_fails(
        self,
        requires_two_factor,
    ):
        with patch(
            "apps.accounts.authentication.EmailServiceFactory.create",
        ) as create_email_service:
            email_service = create_email_service.return_value

            email_service.send.return_value = EmailDeliveryResult(
                status=EmailDeliveryStatus.FAILED,
                message=None,
                error="SMTP connection failed",
            )

            result = AuthenticationService.login(
                "challenge@example.com",
                "StrongPassword123!",
            )

        self.assertEqual(
            result.status,
            AuthenticationStatus.EMAIL_DELIVERY_FAILED,
        )

        self.assertFalse(result.is_authenticated)
        self.assertIsNone(result.session)
        self.assertIsNone(result.token)

        challenge = AuthenticationChallenge.objects.get(
            pk=result.challenge_id,
        )

        self.assertIsNotNone(challenge.revoked_at)

        self.assertEqual(
            Session.objects.count(),
            0,
        )

    @patch(
        "apps.accounts.authentication.AuthenticationService.requires_two_factor",
        return_value=True,
    )
    def test_correct_two_factor_code_creates_session(
        self,
        requires_two_factor,
    ):
        with patch(
            "apps.accounts.authentication.EmailServiceFactory.create",
        ) as create_email_service:
            email_service = create_email_service.return_value

            email_service.send.return_value = EmailDeliveryResult(
                status=EmailDeliveryStatus.SENT,
                message=None,
            )

            login_result = AuthenticationService.login(
                "challenge@example.com",
                "StrongPassword123!",
            )

        self.assertEqual(
            login_result.status,
            AuthenticationStatus.TWO_FACTOR_REQUIRED,
        )

        sent_message = email_service.send.call_args.args[0]

        code_match = re.search(
            r"\b\d{6}\b",
            sent_message.body,
        )

        self.assertIsNotNone(code_match)

        code = code_match.group()

        self.assertEqual(
            Session.objects.count(),
            0,
        )

        verify_result = AuthenticationService.verify_two_factor(
            login_result.challenge_id,
            code,
        )

        self.assertEqual(
            verify_result.status,
            AuthenticationStatus.AUTHENTICATED,
        )

        self.assertTrue(
            verify_result.is_authenticated,
        )

        self.assertIsNotNone(
            verify_result.session,
        )

        self.assertIsNotNone(
            verify_result.token,
        )

        self.assertEqual(
            Session.objects.count(),
            1,
        )

    @patch(
        "apps.accounts.authentication.AuthenticationService.requires_two_factor",
        return_value=True,
    )
    def test_incorrect_two_factor_code_respects_attempt_limit(
        self,
        requires_two_factor,
    ):
        with patch(
            "apps.accounts.authentication.EmailServiceFactory.create",
        ) as create_email_service:
            email_service = create_email_service.return_value

            email_service.send.return_value = EmailDeliveryResult(
                status=EmailDeliveryStatus.SENT,
                message=None,
            )

            login_result = AuthenticationService.login(
                "challenge@example.com",
                "StrongPassword123!",
            )

        challenge_id = login_result.challenge_id

        self.assertIsNotNone(challenge_id)

        for attempt in range(4):
            result = AuthenticationService.verify_two_factor(
                challenge_id,
                "000000",
            )

            self.assertEqual(
                result.status,
                AuthenticationStatus.TWO_FACTOR_INVALID_CODE,
            )

            self.assertIsNone(
                result.session,
            )

        result = AuthenticationService.verify_two_factor(
            challenge_id,
            "000000",
        )

        self.assertEqual(
            result.status,
            AuthenticationStatus.TWO_FACTOR_EXHAUSTED,
        )

        self.assertEqual(
            result.attempts_remaining,
            0,
        )

        self.assertIsNone(
            result.session,
        )

        self.assertIsNone(
            result.token,
        )

        challenge = AuthenticationChallenge.objects.get(
            pk=challenge_id,
        )

        self.assertEqual(
            challenge.attempts,
            challenge.max_attempts,
        )

        self.assertIsNotNone(
            challenge.revoked_at,
        )

        self.assertEqual(
            Session.objects.count(),
            0,
        )

