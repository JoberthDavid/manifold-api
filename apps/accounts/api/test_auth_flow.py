from django.test import TestCase
from rest_framework.test import APIClient

from apps.accounts.models import User


class AuthenticationFlowTests(TestCase):
    def setUp(self):
        self.client = APIClient()

        self.user = User.objects.create_user(
            email="usuario@example.com",
            password="senha-segura",
        )

    def test_login_me_logout_and_revoked_session(self):
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
            "AUTHENTICATED",
        )

        token = login_response.data["token"]

        self.assertIsNotNone(token)

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

        logout_response = self.client.post(
            "/api/auth/logout/",
        )

        self.assertEqual(logout_response.status_code, 200)
        self.assertEqual(
            logout_response.data["status"],
            "LOGGED_OUT",
        )

        me_after_logout_response = self.client.get(
            "/api/auth/me/",
        )

        self.assertEqual(
            me_after_logout_response.status_code,
            401,
        )
