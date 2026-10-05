from django.test import SimpleTestCase

from apps.integrations.services.api_key_fingerprint import (
    ApiKeyFingerprintService,
)


class ApiKeyFingerprintServiceTests(SimpleTestCase):

    def test_generates_sha256_hexadecimal_fingerprint(self):
        fingerprint = (
            ApiKeyFingerprintService.generate("a" * 64)
        )

        self.assertEqual(
            len(fingerprint),
            64,
        )

        self.assertRegex(
            fingerprint,
            r"^[0-9a-f]{64}$",
        )

    def test_same_secret_has_same_fingerprint(self):
        secret = "secret"

        first = ApiKeyFingerprintService.generate(secret)
        second = ApiKeyFingerprintService.generate(secret)

        self.assertEqual(first, second)

    def test_different_secrets_have_different_fingerprints(self):
        first = ApiKeyFingerprintService.generate("secret-a")
        second = ApiKeyFingerprintService.generate("secret-b")

        self.assertNotEqual(first, second)

    def test_empty_secret_is_rejected(self):
        with self.assertRaises(ValueError):
            ApiKeyFingerprintService.generate("")

    def test_non_string_secret_is_rejected(self):
        with self.assertRaises(TypeError):
            ApiKeyFingerprintService.generate(None)