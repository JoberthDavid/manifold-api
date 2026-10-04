from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient

from apps.accounts.authentication import AuthenticationStatus
from apps.accounts.challenge import AuthenticationChallengeService
from apps.accounts.models import User


class TwoFactorErrorFlowTests(TestCase):
    def setUp(self):
        self.client = APIClient()

        self.user = User.objects.create_user(
            email="usuario@example.com",
            password="senha-segura",
        )

    def create_challenge(self):
        result = AuthenticationChallengeService.create_email_challenge(
            self.user,
        )

        return result

    def test_invalid_code_returns_api_error(self):
        challenge_result = self.create_challenge()

        response = self.client.post(
            "/api/auth/2fa/verify/",
            {
                "challenge_id": str(challenge_result.challenge.id),
                "code": "000000",
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data["status"],
            AuthenticationStatus.TWO_FACTOR_INVALID_CODE.value,
        )
        self.assertEqual(
            response.data["attempts_remaining"],
            challenge_result.challenge.max_attempts - 1,
        )

    def test_expired_challenge_returns_api_error(self):
        challenge_result = self.create_challenge()

        challenge = challenge_result.challenge
        challenge.expires_at = timezone.now() - timedelta(minutes=1)
        challenge.save(update_fields=["expires_at"])

        response = self.client.post(
            "/api/auth/2fa/verify/",
            {
                "challenge_id": str(challenge.id),
                "code": challenge_result.verification_code,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data["status"],
            AuthenticationStatus.TWO_FACTOR_EXPIRED.value,
        )

    def test_exhausted_challenge_returns_api_error(self):
        challenge_result = self.create_challenge()

        challenge = challenge_result.challenge

        challenge.attempts = challenge.max_attempts
        challenge.save(update_fields=["attempts"])

        response = self.client.post(
            "/api/auth/2fa/verify/",
            {
                "challenge_id": str(challenge.id),
                "code": challenge_result.verification_code,
            },
            format="json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(
            response.data["status"],
            AuthenticationStatus.TWO_FACTOR_EXHAUSTED.value,
        )
        self.assertEqual(
            response.data["attempts_remaining"],
            0,
        )

    @patch(
        "apps.accounts.authentication.AuthenticationService.requires_two_factor"
    )
    @patch(
        "apps.accounts.authentication.AuthenticationNotificationService"
    )
    def test_consumed_challenge_cannot_be_reused(
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
            AuthenticationStatus.TWO_FACTOR_REQUIRED.value,
        )

        challenge_id = login_response.data["challenge_id"]

        verification_code = (
            notification_service
            .send_authentication_code
            .call_args
            .kwargs["verification_code"]
        )

        first_response = self.client.post(
            "/api/auth/2fa/verify/",
            {
                "challenge_id": challenge_id,
                "code": verification_code,
            },
            format="json",
        )

        self.assertEqual(first_response.status_code, 200)
        self.assertEqual(
            first_response.data["status"],
            AuthenticationStatus.AUTHENTICATED.value,
        )

        second_response = self.client.post(
            "/api/auth/2fa/verify/",
            {
                "challenge_id": challenge_id,
                "code": verification_code,
            },
            format="json",
        )

        self.assertEqual(second_response.status_code, 400)
        self.assertEqual(
            second_response.data["status"],
            AuthenticationStatus.TWO_FACTOR_REVOKED.value,
        )
