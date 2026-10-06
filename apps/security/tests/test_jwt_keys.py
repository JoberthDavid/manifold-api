from django.test import TestCase

from apps.security.models import JwtSigningKey
from apps.security.services.jwt_key_encryption import (
    JwtKeyEncryptionService,
)
from apps.security.services.jwt_keys import JwtSigningKeyService


class JwtSigningKeyServiceTests(TestCase):

    def test_generate_creates_ed25519_key_pair(self):
        key = JwtSigningKeyService.generate()

        self.assertIsInstance(key, JwtSigningKey)
        self.assertEqual(key.algorithm, "EdDSA")
        self.assertTrue(key.kid.startswith("manifold-"))
        self.assertTrue(key.enabled)
        self.assertIsNone(key.retired_at)

    def test_private_key_is_stored_encrypted(self):
        key = JwtSigningKeyService.generate()

        decrypted = JwtKeyEncryptionService.decrypt(
            key.private_key
        )

        self.assertNotEqual(
            key.private_key,
            decrypted,
        )

        self.assertIn(
            "BEGIN PRIVATE KEY",
            decrypted,
        )

    def test_public_key_is_stored_as_pem(self):
        key = JwtSigningKeyService.generate()

        self.assertIn(
            "BEGIN PUBLIC KEY",
            key.public_key,
        )

    def test_get_active_key_returns_latest_active_key(self):
        first = JwtSigningKeyService.generate()
        second = JwtSigningKeyService.generate()

        active = JwtSigningKeyService.get_active_key()

        self.assertEqual(active.id, second.id)
        self.assertNotEqual(active.id, first.id)

    def test_get_private_key_returns_ed25519_private_key(self):
        key = JwtSigningKeyService.generate()

        private_key = JwtSigningKeyService.get_private_key(key)

        self.assertEqual(
            private_key.__class__.__name__,
            "Ed25519PrivateKey",
        )