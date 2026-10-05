from django.test import SimpleTestCase

from apps.integrations.services.api_key_generator import (
    ApiKeyGenerator,
)


class ApiKeyGeneratorTests(SimpleTestCase):

    def test_generates_64_hexadecimal_characters(self):
        key = ApiKeyGenerator.generate()

        self.assertEqual(len(key), 64)

        self.assertRegex(
            key,
            r"^[0-9a-f]{64}$",
        )

    def test_generates_different_keys(self):
        first = ApiKeyGenerator.generate()
        second = ApiKeyGenerator.generate()

        self.assertNotEqual(first, second)