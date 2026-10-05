from cryptography.fernet import Fernet
from django.test import TestCase, override_settings

from apps.integrations.exceptions import IntegrationCredentialError
from apps.integrations.services.credentials import (
    CredentialEncryptionService,
)


TEST_ENCRYPTION_KEY = Fernet.generate_key().decode()


class CredentialEncryptionServiceTests(TestCase):
    @override_settings(
        MANIFOLD_CREDENTIAL_ENCRYPTION_KEY=TEST_ENCRYPTION_KEY
    )
    def test_encrypt_and_decrypt(self):
        value = "sicro-secret-api-key"

        encrypted = CredentialEncryptionService.encrypt(value)
        decrypted = CredentialEncryptionService.decrypt(encrypted)

        self.assertNotEqual(encrypted, value)
        self.assertEqual(decrypted, value)

    @override_settings(
        MANIFOLD_CREDENTIAL_ENCRYPTION_KEY=TEST_ENCRYPTION_KEY
    )
    def test_encryption_produces_different_ciphertext(self):
        value = "sicro-secret-api-key"

        first = CredentialEncryptionService.encrypt(value)
        second = CredentialEncryptionService.encrypt(value)

        self.assertNotEqual(first, second)

    @override_settings(
        MANIFOLD_CREDENTIAL_ENCRYPTION_KEY=""
    )
    def test_missing_encryption_key_raises_error(self):
        with self.assertRaises(IntegrationCredentialError):
            CredentialEncryptionService.encrypt("secret")

    @override_settings(
        MANIFOLD_CREDENTIAL_ENCRYPTION_KEY=TEST_ENCRYPTION_KEY
    )
    def test_invalid_encrypted_value_raises_error(self):
        with self.assertRaises(IntegrationCredentialError):
            CredentialEncryptionService.decrypt("invalid-ciphertext")

    @override_settings(
        MANIFOLD_CREDENTIAL_ENCRYPTION_KEY=TEST_ENCRYPTION_KEY
    )
    def test_empty_value_raises_error(self):
        with self.assertRaises(IntegrationCredentialError):
            CredentialEncryptionService.encrypt("")

    @override_settings(
        MANIFOLD_CREDENTIAL_ENCRYPTION_KEY=TEST_ENCRYPTION_KEY
    )
    def test_non_string_value_raises_error(self):
        with self.assertRaises(IntegrationCredentialError):
            CredentialEncryptionService.encrypt(123)

    @override_settings(
        MANIFOLD_CREDENTIAL_ENCRYPTION_KEY=TEST_ENCRYPTION_KEY
    )
    def test_non_string_encrypted_value_raises_error(self):
        with self.assertRaises(IntegrationCredentialError):
            CredentialEncryptionService.decrypt(123)
            