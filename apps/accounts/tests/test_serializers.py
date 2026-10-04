from uuid import uuid4

from django.test import SimpleTestCase

from apps.accounts.api.serializers import (
    AuthenticationResponseSerializer,
    LoginSerializer,
    TwoFactorVerifySerializer,
)


class LoginSerializerTests(SimpleTestCase):
    def test_valid_login_payload(self):
        serializer = LoginSerializer(
            data={
                "email": "usuario@example.com",
                "password": "senha-segura",
            }
        )

        self.assertTrue(serializer.is_valid())
        self.assertEqual(
            serializer.validated_data["email"],
            "usuario@example.com",
        )
        self.assertEqual(
            serializer.validated_data["password"],
            "senha-segura",
        )

    def test_invalid_email(self):
        serializer = LoginSerializer(
            data={
                "email": "email-invalido",
                "password": "senha-segura",
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertIn("email", serializer.errors)

    def test_missing_password(self):
        serializer = LoginSerializer(
            data={
                "email": "usuario@example.com",
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertIn("password", serializer.errors)


class TwoFactorVerifySerializerTests(SimpleTestCase):
    def test_valid_two_factor_payload(self):
        challenge_id = uuid4()

        serializer = TwoFactorVerifySerializer(
            data={
                "challenge_id": str(challenge_id),
                "code": "123456",
            }
        )

        self.assertTrue(serializer.is_valid())
        self.assertEqual(
            serializer.validated_data["challenge_id"],
            challenge_id,
        )
        self.assertEqual(
            serializer.validated_data["code"],
            "123456",
        )

    def test_invalid_challenge_id(self):
        serializer = TwoFactorVerifySerializer(
            data={
                "challenge_id": "challenge-invalido",
                "code": "123456",
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertIn("challenge_id", serializer.errors)

    def test_invalid_code_length(self):
        serializer = TwoFactorVerifySerializer(
            data={
                "challenge_id": str(uuid4()),
                "code": "12345",
            }
        )

        self.assertFalse(serializer.is_valid())
        self.assertIn("code", serializer.errors)

    def test_code_is_write_only(self):
        serializer = TwoFactorVerifySerializer(
            data={
                "challenge_id": str(uuid4()),
                "code": "123456",
            }
        )

        self.assertTrue(serializer.is_valid())
        self.assertNotIn("code", serializer.data)


class AuthenticationResponseSerializerTests(SimpleTestCase):
    def test_authenticated_response(self):
        serializer = AuthenticationResponseSerializer(
            data={
                "status": "AUTHENTICATED",
                "token": "session-token",
                "challenge_id": None,
                "attempts_remaining": None,
            }
        )

        self.assertTrue(serializer.is_valid())

    def test_two_factor_required_response(self):
        serializer = AuthenticationResponseSerializer(
            data={
                "status": "TWO_FACTOR_REQUIRED",
                "token": None,
                "challenge_id": str(uuid4()),
                "attempts_remaining": None,
            }
        )

        self.assertTrue(serializer.is_valid())
