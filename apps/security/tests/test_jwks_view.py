from __future__ import annotations

import base64

from django.test import TestCase
from django.urls import reverse

from apps.security.services.jwt_keys import JwtSigningKeyService


class JwksViewTests(TestCase):
    def test_jwks_endpoint_returns_200(self):
        JwtSigningKeyService.generate()

        response = self.client.get(
            reverse("jwks")
        )

        self.assertEqual(response.status_code, 200)

    def test_jwks_endpoint_returns_json(self):
        JwtSigningKeyService.generate()

        response = self.client.get(
            reverse("jwks")
        )

        self.assertEqual(
            response["Content-Type"],
            "application/json",
        )

    def test_jwks_endpoint_returns_keys(self):
        key = JwtSigningKeyService.generate()

        response = self.client.get(
            reverse("jwks")
        )

        data = response.json()

        self.assertIn("keys", data)
        self.assertEqual(len(data["keys"]), 1)

        jwk = data["keys"][0]

        self.assertEqual(jwk["kty"], "OKP")
        self.assertEqual(jwk["crv"], "Ed25519")
        self.assertEqual(jwk["use"], "sig")
        self.assertEqual(jwk["alg"], "EdDSA")
        self.assertEqual(jwk["kid"], key.kid)
        self.assertIn("x", jwk)

    def test_jwks_endpoint_is_public(self):
        JwtSigningKeyService.generate()

        response = self.client.get(
            reverse("jwks")
        )

        self.assertEqual(response.status_code, 200)

    def test_jwks_endpoint_does_not_expose_private_key(self):
        key = JwtSigningKeyService.generate()

        response = self.client.get(
            reverse("jwks")
        )

        content = response.content.decode("utf-8")

        self.assertNotIn(key.private_key, content)
        self.assertNotIn("PRIVATE KEY", content)

    def test_jwks_endpoint_exposes_only_public_jwk_fields(self):
        JwtSigningKeyService.generate()

        response = self.client.get(
            reverse("jwks")
        )

        jwk = response.json()["keys"][0]

        self.assertEqual(
            set(jwk.keys()),
            {
                "kty",
                "crv",
                "use",
                "alg",
                "kid",
                "x",
            },
        )

    def test_jwks_endpoint_rejects_post(self):
        JwtSigningKeyService.generate()

        response = self.client.post(
            reverse("jwks")
        )

        self.assertEqual(response.status_code, 405)

    def test_jwks_endpoint_returns_empty_keys_when_no_key_exists(self):
        response = self.client.get(
            reverse("jwks")
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json(),
            {"keys": []},
        )

    def test_jwks_endpoint_returns_valid_ed25519_public_key(self):
        JwtSigningKeyService.generate()

        response = self.client.get(
            reverse("jwks")
        )

        jwk = response.json()["keys"][0]

        encoded_key = jwk["x"]
        padding = "=" * (-len(encoded_key) % 4)

        raw_key = base64.urlsafe_b64decode(
            encoded_key + padding
        )

        self.assertEqual(len(raw_key), 32)