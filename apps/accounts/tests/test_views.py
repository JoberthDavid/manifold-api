from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIRequestFactory, force_authenticate

from apps.accounts.api.views import (
    LoginView,
    LogoutView,
    MeView,
    TwoFactorVerifyView,
)
from apps.accounts.authentication import (
    AuthenticationResult,
    AuthenticationStatus,
)
from apps.accounts.models import User


class LoginViewTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    @patch("apps.accounts.api.views.AuthenticationService.login")
    def test_authenticated_login(self, mock_login):
        mock_login.return_value = AuthenticationResult(
            status=AuthenticationStatus.AUTHENTICATED,
            token="session-token",
        )

        request = self.factory.post(
            "/api/auth/login/",
            {
                "email": "usuario@example.com",
                "password": "senha-segura",
            },
            format="json",
        )

        response = LoginView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["status"], "AUTHENTICATED")
        self.assertEqual(response.data["token"], "session-token")

        mock_login.assert_called_once()

    @patch("apps.accounts.api.views.AuthenticationService.login")
    def test_two_factor_required_login(self, mock_login):
        mock_login.return_value = AuthenticationResult(
            status=AuthenticationStatus.TWO_FACTOR_REQUIRED,
            challenge_id="challenge-123",
        )

        request = self.factory.post(
            "/api/auth/login/",
            {
                "email": "usuario@example.com",
                "password": "senha-segura",
            },
            format="json",
        )

        response = LoginView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["status"], "TWO_FACTOR_REQUIRED")
        self.assertEqual(
            response.data["challenge_id"],
            "challenge-123",
        )

    @patch("apps.accounts.api.views.AuthenticationService.login")
    def test_invalid_credentials(self, mock_login):
        mock_login.return_value = AuthenticationResult(
            status=AuthenticationStatus.INVALID_CREDENTIALS,
        )

        request = self.factory.post(
            "/api/auth/login/",
            {
                "email": "usuario@example.com",
                "password": "senha-incorreta",
            },
            format="json",
        )

        response = LoginView.as_view()(request)

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data["status"], "INVALID_CREDENTIALS")

    def test_invalid_login_payload(self):
        request = self.factory.post(
            "/api/auth/login/",
            {
                "email": "email-invalido",
            },
            format="json",
        )

        response = LoginView.as_view()(request)

        self.assertEqual(response.status_code, 400)


class TwoFactorVerifyViewTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    @patch("apps.accounts.api.views.AuthenticationService.verify_two_factor")
    def test_authenticated_two_factor(self, mock_verify):
        mock_verify.return_value = AuthenticationResult(
            status=AuthenticationStatus.AUTHENTICATED,
            token="session-token",
            challenge_id="challenge-123",
        )

        request = self.factory.post(
            "/api/auth/2fa/verify/",
            {
                "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
                "code": "123456",
            },
            format="json",
        )

        response = TwoFactorVerifyView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["status"], "AUTHENTICATED")
        self.assertEqual(response.data["token"], "session-token")

    @patch("apps.accounts.api.views.AuthenticationService.verify_two_factor")
    def test_invalid_two_factor_code(self, mock_verify):
        mock_verify.return_value = AuthenticationResult(
            status=AuthenticationStatus.TWO_FACTOR_INVALID_CODE,
            challenge_id="550e8400-e29b-41d4-a716-446655440000",
            attempts_remaining=4,
        )

        request = self.factory.post(
            "/api/auth/2fa/verify/",
            {
                "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
                "code": "123456",
            },
            format="json",
        )

        response = TwoFactorVerifyView.as_view()(request)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data["status"],
            "TWO_FACTOR_INVALID_CODE",
        )
        self.assertEqual(
            response.data["attempts_remaining"],
            4,
        )

    @patch("apps.accounts.api.views.AuthenticationService.verify_two_factor")
    def test_two_factor_exhausted(self, mock_verify):
        mock_verify.return_value = AuthenticationResult(
            status=AuthenticationStatus.TWO_FACTOR_EXHAUSTED,
            challenge_id="550e8400-e29b-41d4-a716-446655440000",
            attempts_remaining=0,
        )

        request = self.factory.post(
            "/api/auth/2fa/verify/",
            {
                "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
                "code": "123456",
            },
            format="json",
        )

        response = TwoFactorVerifyView.as_view()(request)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data["status"],
            "TWO_FACTOR_EXHAUSTED",
        )


class LogoutViewTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    @patch("apps.accounts.api.views.AuthenticationService.logout")
    def test_logout(self, mock_logout):
        mock_logout.return_value = True

        user = User.objects.create_user(
            email="usuario@example.com",
            password="senha-segura",
        )

        request = self.factory.post("/api/auth/logout/")

        force_authenticate(
            request,
            user=user,
            token="session-token",
        )

        response = LogoutView.as_view()(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["status"], "LOGGED_OUT")

        mock_logout.assert_called_once_with("session-token")

    def test_logout_requires_authentication(self):
        request = self.factory.post("/api/auth/logout/")

        response = LogoutView.as_view()(request)

        self.assertEqual(response.status_code, 401)


class MeViewTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()

    def test_me_requires_authentication(self):
        request = self.factory.get("/api/auth/me/")

        response = MeView.as_view()(request)

        self.assertEqual(response.status_code, 401)

    def test_me_returns_authenticated_user(self):
        user = User.objects.create_user(
            email="usuario@example.com",
            password="senha-segura",
        )

        request = self.factory.get("/api/auth/me/")
        force_authenticate(
            request,
            user=user,
            token="session-token",
        )

        response = MeView.as_view()(request)

        self.assertEqual(response.data["id"], str(user.id))
        self.assertEqual(
            response.data["email"],
            "usuario@example.com",
        )
        self.assertTrue(response.data["is_active"])
