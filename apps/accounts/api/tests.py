from unittest.mock import patch

from django.test import TestCase
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.test import APIRequestFactory

from apps.accounts.api.authentication import SessionAuthentication


class SessionAuthenticationTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.authentication = SessionAuthentication()

    @patch("apps.accounts.api.authentication.SessionService.authenticate_session")
    def test_authenticate_with_valid_bearer_token(self, mock_authenticate_session):
        user = object()

        mock_authenticate_session.return_value = user

        request = self.factory.get(
            "/api/test/",
            HTTP_AUTHORIZATION="Bearer valid-session-token",
        )

        result = self.authentication.authenticate(request)

        self.assertIsNotNone(result)

        authenticated_user, authenticated_token = result

        self.assertIs(authenticated_user, user)
        self.assertEqual(
            authenticated_token,
            "valid-session-token",
        )

        mock_authenticate_session.assert_called_once_with(
            "valid-session-token"
        )

    @patch("apps.accounts.api.authentication.SessionService.authenticate_session")
    def test_authenticate_with_invalid_bearer_token(
        self,
        mock_authenticate_session,
    ):
        mock_authenticate_session.return_value = None

        request = self.factory.get(
            "/api/test/",
            HTTP_AUTHORIZATION="Bearer invalid-session-token",
        )

        with self.assertRaises(AuthenticationFailed):
            self.authentication.authenticate(request)

        mock_authenticate_session.assert_called_once_with(
            "invalid-session-token"
        )

    def test_authenticate_without_authorization_header(self):
        request = self.factory.get("/api/test/")

        result = self.authentication.authenticate(request)

        self.assertIsNone(result)

    def test_authenticate_with_invalid_authorization_scheme(self):
        request = self.factory.get(
            "/api/test/",
            HTTP_AUTHORIZATION="Basic some-credentials",
        )

        with self.assertRaises(AuthenticationFailed):
            self.authentication.authenticate(request)

    def test_authenticate_with_malformed_authorization_header(self):
        request = self.factory.get(
            "/api/test/",
            HTTP_AUTHORIZATION="Bearer",
        )

        with self.assertRaises(AuthenticationFailed):
            self.authentication.authenticate(request)

    def test_authenticate_with_empty_bearer_token(self):
        request = self.factory.get(
            "/api/test/",
            HTTP_AUTHORIZATION="Bearer ",
        )

        with self.assertRaises(AuthenticationFailed):
            self.authentication.authenticate(request)
