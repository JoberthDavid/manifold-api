from unittest.mock import patch

from django.test import TestCase
from rest_framework.test import APIClient

from apps.accounts.models import User


class TwoFactorAuthenticationFlowTests(TestCase):
    def setUp(self):
        self.client = APIClient()

        self.user = User.objects.create_user(
            email="usuario@example.com",
            password="senha-segura",
        )

    @patch("apps.accounts.authentication.AuthenticationService.requires_two_factor")
    @patch(
        "apps.accounts.authentication.AuthenticationNotificationService"
    )
    def test_login_requires_two_factor_and_verify_creates_session(
        self,
        mock_notification_service,
        mock_requires_two_factor,
    ):
        mock_requires_two_factor.return_value = True

        notification_service = mock_notification_service.return_value
        notification_service.send_authentication_code.return_value.is_sent = True

        login_response = self.client.post(
            "/api/auth/login/",
            {
                "email": "usuario@example.com",
                "password": "senha-segura",
            },
            format="json",
        )

        self.assertEqual(login_response.status_code, 200)
        self.assertEqual(
            login_response.data["status"],
            "TWO_FACTOR_REQUIRED",
        )

        challenge_id = login_response.data["challenge_id"]

        self.assertIsNotNone(challenge_id)

        challenge = self.user.authentication_challenges.get(
            id=challenge_id,
        )

        verification_code = (
            notification_service.send_authentication_code.call_args.kwargs[
                "verification_code"
            ]
        )

        verify_response = self.client.post(
            "/api/auth/2fa/verify/",
            {
                "challenge_id": challenge_id,
                "code": verification_code,
            },
            format="json",
        )

        self.assertEqual(verify_response.status_code, 200)
        self.assertEqual(
            verify_response.data["status"],
            "AUTHENTICATED",
        )

        token = verify_response.data["token"]

        self.assertIsNotNone(token)

        challenge.refresh_from_db()

        self.assertIsNotNone(challenge.consumed_at)

        self.client.credentials(
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

        me_response = self.client.get("/api/auth/me/")

        self.assertEqual(me_response.status_code, 200)
        self.assertEqual(
            me_response.data["id"],
            str(self.user.id),
        )
        self.assertEqual(
            me_response.data["email"],
            self.user.email,
        )
