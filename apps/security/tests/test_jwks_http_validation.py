from __future__ import annotations

import jwt

from django.test import LiveServerTestCase
from django.test.utils import override_settings

from apps.security.services.jwks_client import JwksClient
from apps.security.services.jwt_keys import JwtSigningKeyService
from apps.security.services.jwt_tokens import JwtTokenService


class JwksHttpValidationTests(LiveServerTestCase):
    def setUp(self):
        self.signing_key = JwtSigningKeyService.generate()

        self.jwks_url = (
            f"{self.live_server_url}"
            "/.well-known/jwks.json"
        )

        self.override_jwks_url = override_settings(
            MANIFOLD_JWKS_URL=self.jwks_url
        )
        self.override_jwks_url.enable()
        self.addCleanup(self.override_jwks_url.disable)

    def test_get_jwks_from_http_endpoint(self):
        jwks = JwksClient.get_jwks()

        self.assertIn("keys", jwks)
        self.assertEqual(len(jwks["keys"]), 1)

        self.assertEqual(
            jwks["keys"][0]["kid"],
            self.signing_key.kid,
        )

    def test_get_public_key_from_http_jwks(self):
        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        public_key = JwksClient.get_public_key_for_token(
            token
        )

        self.assertIsNotNone(public_key)

    def test_validate_token_using_public_key_from_http_jwks(self):
        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        public_key = JwksClient.get_public_key_for_token(
            token
        )

        payload = jwt.decode(
            token,
            public_key,
            algorithms=["EdDSA"],
            audience="composition-engine",
            issuer="manifold-api",
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

    def test_wrong_audience_is_rejected(self):
        token = JwtTokenService.issue(
            subject="user:123",
            audience="composition-engine",
            scopes=["composition:calculate"],
        )

        public_key = JwksClient.get_public_key_for_token(
            token
        )

        with self.assertRaises(jwt.InvalidAudienceError):
            jwt.decode(
                token,
                public_key,
                algorithms=["EdDSA"],
                audience="budget-engine",
                issuer="manifold-api",
            )