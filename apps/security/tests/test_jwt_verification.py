from __future__ import annotations

import jwt
from django.test import TestCase

from apps.security.services.jwt_keys import JwtSigningKeyService
from apps.security.services.jwt_tokens import JwtTokenService
from apps.security.services.jwt_verification import (
    JwtVerificationError,
    JwtVerificationService,
)


class JwtVerificationServiceTests(TestCase):
    def setUp(self):
        self.signing_key = JwtSigningKeyService.generate()

    def test_verifies_token_using_jwks_public_key(self):
        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        payload = JwtVerificationService.verify(
            token,
            audience="composition-engine",
        )

        self.assertEqual(
            payload["iss"],
            "manifold-api",
        )
        self.assertEqual(
            payload["sub"],
            "user:123",
        )
        self.assertEqual(
            payload["aud"],
            "composition-engine",
        )
        self.assertEqual(
            payload["scope"],
            ["composition:calculate"],
        )

    def test_verifies_multiple_scopes(self):
        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=[
                "composition:read",
                "composition:calculate",
            ],
        )

        payload = JwtVerificationService.verify(
            token,
            audience="composition-engine",
        )

        self.assertEqual(
            payload["scope"],
            [
                "composition:read",
                "composition:calculate",
            ],
        )

    def test_rejects_empty_token(self):
        with self.assertRaises(JwtVerificationError):
            JwtVerificationService.verify(
                "",
                audience="composition-engine",
            )

    def test_rejects_empty_audience(self):
        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        with self.assertRaises(JwtVerificationError):
            JwtVerificationService.verify(
                token,
                audience="",
            )

    def test_rejects_wrong_audience(self):
        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        with self.assertRaises(JwtVerificationError):
            JwtVerificationService.verify(
                token,
                audience="budget-engine",
            )

    def test_rejects_token_with_unknown_kid(self):
        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        parts = token.split(".")
        header = jwt.get_unverified_header(token)

        header["kid"] = "unknown-key"

        import json
        import base64

        encoded_header = base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

        tampered_token = ".".join(
            [
                encoded_header,
                parts[1],
                parts[2],
            ]
        )

        with self.assertRaises(JwtVerificationError):
            JwtVerificationService.verify(
                tampered_token,
                audience="composition-engine",
            )

    def test_rejects_tampered_payload(self):
        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        parts = token.split(".")

        payload = jwt.decode(
            token,
            options={
                "verify_signature": False,
            },
        )

        payload["sub"] = "user:999"

        import json
        import base64

        encoded_payload = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

        tampered_token = ".".join(
            [
                parts[0],
                encoded_payload,
                parts[2],
            ]
        )

        with self.assertRaises(JwtVerificationError):
            JwtVerificationService.verify(
                tampered_token,
                audience="composition-engine",
            )

    def test_rejects_invalid_signature(self):
        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        parts = token.split(".")

        modified_signature = (
            parts[2][:-1]
            + ("A" if parts[2][-1] != "A" else "B")
        )

        tampered_token = ".".join(
            [
                parts[0],
                parts[1],
                modified_signature,
            ]
        )

        with self.assertRaises(JwtVerificationError):
            JwtVerificationService.verify(
                tampered_token,
                audience="composition-engine",
            )

    def test_rejects_invalid_token_header(self):
        with self.assertRaises(JwtVerificationError):
            JwtVerificationService.verify(
                "invalid-token",
                audience="composition-engine",
            )