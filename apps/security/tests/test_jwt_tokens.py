from __future__ import annotations

import time

import jwt
from django.test import TestCase

from apps.security.models import JwtSigningKey
from apps.security.services.jwt_keys import JwtSigningKeyService
from apps.security.services.jwt_tokens import JwtTokenService


class JwtTokenServiceTests(TestCase):
    def setUp(self):
        self.signing_key = JwtSigningKeyService.generate()

    def test_issue_creates_signed_jwt(self):
        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 100)

    def test_token_header_contains_kid_and_algorithm(self):
        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        header = jwt.get_unverified_header(token)

        self.assertEqual(header["alg"], "EdDSA")
        self.assertEqual(header["kid"], self.signing_key.kid)
        self.assertEqual(header["typ"], "JWT")

    def test_token_contains_expected_claims(self):
        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        payload = jwt.decode(
            token,
            self.signing_key.public_key,
            algorithms=["EdDSA"],
            audience="composition-engine",
            issuer="manifold-api",
        )

        self.assertEqual(payload["iss"], "manifold-api")
        self.assertEqual(payload["sub"], "user:123")
        self.assertEqual(payload["aud"], "composition-engine")
        self.assertEqual(
            payload["scope"],
            ["composition:calculate"],
        )
        self.assertIn("iat", payload)
        self.assertIn("exp", payload)
        self.assertIn("jti", payload)

    def test_token_expires_after_configured_ttl(self):
        before = int(time.time())

        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
            ttl_seconds=120,
        )

        after = int(time.time())

        payload = jwt.decode(
            token,
            self.signing_key.public_key,
            algorithms=["EdDSA"],
            audience="composition-engine",
            issuer="manifold-api",
        )

        self.assertGreaterEqual(payload["iat"], before)
        self.assertLessEqual(payload["iat"], after)
        self.assertGreaterEqual(
            payload["exp"],
            payload["iat"] + 120,
        )

    def test_default_ttl_is_five_minutes(self):
        before = int(time.time())

        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        payload = jwt.decode(
            token,
            self.signing_key.public_key,
            algorithms=["EdDSA"],
            audience="composition-engine",
            issuer="manifold-api",
        )

        self.assertGreaterEqual(
            payload["exp"],
            before + 300,
        )

    def test_each_token_gets_unique_jti(self):
        token_one = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        token_two = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        payload_one = jwt.decode(
            token_one,
            self.signing_key.public_key,
            algorithms=["EdDSA"],
            audience="composition-engine",
            issuer="manifold-api",
        )

        payload_two = jwt.decode(
            token_two,
            self.signing_key.public_key,
            algorithms=["EdDSA"],
            audience="composition-engine",
            issuer="manifold-api",
        )

        self.assertNotEqual(
            payload_one["jti"],
            payload_two["jti"],
        )

    def test_rejects_empty_subject(self):
        with self.assertRaises(ValueError):
            JwtTokenService.issue(
                subject="",
                audience="composition-engine",
                scopes=["composition:calculate"],
            )

    def test_rejects_empty_audience(self):
        with self.assertRaises(ValueError):
            JwtTokenService.issue(
                subject="user:123",
                audience="",
                scopes=["composition:calculate"],
            )

    def test_rejects_empty_scopes(self):
        with self.assertRaises(ValueError):
            JwtTokenService.issue(
                subject="user:123",
                audience="composition-engine",
                scopes=[],
            )

    def test_rejects_invalid_scope(self):
        with self.assertRaises(ValueError):
            JwtTokenService.issue(
                subject="user:123",
                audience="composition-engine",
                scopes=[""],
            )

    def test_rejects_invalid_ttl(self):
        with self.assertRaises(ValueError):
            JwtTokenService.issue(
                subject="user:123",
                audience="composition-engine",
                scopes=["composition:calculate"],
                ttl_seconds=0,
            )

    def test_issued_token_is_rejected_for_wrong_audience(self):
        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        with self.assertRaises(jwt.InvalidAudienceError):
            jwt.decode(
                token,
                self.signing_key.public_key,
                algorithms=["EdDSA"],
                audience="budget-engine",
                issuer="manifold-api",
            )

    def test_issued_token_is_rejected_for_wrong_issuer(self):
        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        with self.assertRaises(jwt.InvalidIssuerError):
            jwt.decode(
                token,
                self.signing_key.public_key,
                algorithms=["EdDSA"],
                audience="composition-engine",
                issuer="other-service",
            )

    def test_issued_token_is_rejected_when_signature_is_modified(self):
        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        parts = token.split(".")
        parts[1] = parts[1][:-1] + (
            "A" if parts[1][-1] != "A" else "B"
        )
        tampered_token = ".".join(parts)

        with self.assertRaises(jwt.InvalidSignatureError):
            jwt.decode(
                tampered_token,
                self.signing_key.public_key,
                algorithms=["EdDSA"],
                audience="composition-engine",
                issuer="manifold-api",
            )