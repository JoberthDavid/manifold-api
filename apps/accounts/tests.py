from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from .models import Session, User
from .services import SessionService
from django.db import IntegrityError
from .authentication import (
    AuthenticationResult,
    AuthenticationService,
    AuthenticationStatus,
    CredentialAuthenticationResult,
    CredentialAuthenticationStatus,
)
from unittest.mock import patch


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

    def test_login_requires_two_factor_without_creating_session(self):
        with patch.object(
            AuthenticationService,
            "requires_two_factor",
            return_value=True,
        ):
            result = AuthenticationService.login(
                "user@example.com",
                "correct-password",
            )

        self.assertEqual(
            result.status,
            AuthenticationStatus.TWO_FACTOR_REQUIRED,
        )
        self.assertTrue(result.requires_two_factor)
        self.assertFalse(result.is_authenticated)
        self.assertEqual(result.user, self.user)
        self.assertIsNone(result.session)
        self.assertIsNone(result.token)
        self.assertIsNone(result.challenge_id)

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