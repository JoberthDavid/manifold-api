from django.test import SimpleTestCase

from apps.security.services.jwt_key_encryption import (
    JwtKeyEncryptionError,
    JwtKeyEncryptionService,
)


class JwtKeyEncryptionServiceTests(SimpleTestCase):

    def test_encrypt_and_decrypt_round_trip(self):
        value = "private-key-content"

        encrypted = JwtKeyEncryptionService.encrypt(value)
        decrypted = JwtKeyEncryptionService.decrypt(encrypted)

        self.assertNotEqual(encrypted, value)
        self.assertEqual(decrypted, value)

    def test_encrypt_rejects_empty_value(self):
        with self.assertRaises(JwtKeyEncryptionError):
            JwtKeyEncryptionService.encrypt("")

    def test_decrypt_rejects_empty_value(self):
        with self.assertRaises(JwtKeyEncryptionError):
            JwtKeyEncryptionService.decrypt("")

    def test_decrypt_rejects_invalid_token(self):
        with self.assertRaises(JwtKeyEncryptionError):
            JwtKeyEncryptionService.decrypt("invalid-token")