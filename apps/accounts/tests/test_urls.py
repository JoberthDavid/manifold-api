from django.test import SimpleTestCase
from django.urls import resolve, reverse


class AuthenticationUrlsTests(SimpleTestCase):
    def test_login_url(self):
        self.assertEqual(
            reverse("accounts-api:login"),
            "/api/auth/login/",
        )

        match = resolve("/api/auth/login/")
        self.assertEqual(match.url_name, "login")

    def test_two_factor_verify_url(self):
        self.assertEqual(
            reverse("accounts-api:two-factor-verify"),
            "/api/auth/2fa/verify/",
        )

        match = resolve("/api/auth/2fa/verify/")
        self.assertEqual(
            match.url_name,
            "two-factor-verify",
        )

    def test_logout_url(self):
        self.assertEqual(
            reverse("accounts-api:logout"),
            "/api/auth/logout/",
        )

        match = resolve("/api/auth/logout/")
        self.assertEqual(match.url_name, "logout")

    def test_me_url(self):
        self.assertEqual(
            reverse("accounts-api:me"),
            "/api/auth/me/",
        )

        match = resolve("/api/auth/me/")
        self.assertEqual(match.url_name, "me")
