import asyncio
import re
import unittest
from unittest.mock import AsyncMock

from config import REGEX_PATTERNS
from validator import AsyncValidator, KeyStatus


class OpenCodeZenValidatorTests(unittest.TestCase):
    def test_models_response_is_valid_and_uses_browser_ua(self):
        async def run():
            validator = AsyncValidator.__new__(AsyncValidator)
            validator._check_circuit_breaker = AsyncMock(return_value=None)
            calls = []

            async def fetch(method, url, headers=None, json_body=None, **kwargs):
                calls.append((method, url, headers, json_body))
                return 200, {"data": [{"id": "deepseek-v4-flash-free"}]}, 0, {}

            validator._fetch_with_retry = fetch
            result = await validator.validate_opencode_zen(
                "test-key", "https://opencode.ai/zen/v1"
            )
            return result, calls

        result, calls = asyncio.run(run())
        self.assertEqual(result.status, KeyStatus.VALID)
        self.assertEqual(result.models, ["deepseek-v4-flash-free"])
        self.assertIn("Chrome/", calls[0][2]["User-Agent"])
        self.assertEqual(calls[0][1], "https://opencode.ai/zen/v1/models")

    def test_cloudflare_1010_is_connection_error_not_invalid(self):
        async def run():
            validator = AsyncValidator.__new__(AsyncValidator)
            validator._check_circuit_breaker = AsyncMock(return_value=None)
            calls = 0

            async def fetch(method, url, **kwargs):
                nonlocal calls
                calls += 1
                return 403, {"error": "error code: 1010"}, 0, {}

            validator._fetch_with_retry = fetch
            return await validator.validate_opencode_zen(
                "test-key", "https://opencode.ai/zen/v1"
            )

        result = asyncio.run(run())
        self.assertEqual(result.status, KeyStatus.CONNECTION_ERROR)
        self.assertIn("1010", result.info)


class AwsSecretPatternTests(unittest.TestCase):
    def test_aws_secret_pattern_requires_standalone_40_chars(self):
        pattern = re.compile(REGEX_PATTERNS["aws_secret_key"])
        self.assertIsNone(pattern.search("prefix" + "A" * 40 + "suffix"))
        self.assertIsNotNone(pattern.search(" " + "A1/" * 13 + "A"))
        self.assertIsNone(pattern.search("your-secret-key-placeholder"))

class GeminiValidationTests(unittest.TestCase):
    def test_api_key_invalid_reason_is_invalid_and_header_is_used(self):
        async def run():
            validator = AsyncValidator.__new__(AsyncValidator)
            validator._check_circuit_breaker = AsyncMock(return_value=None)
            calls = []

            async def fetch(method, url, headers=None, **kwargs):
                calls.append((method, url, headers))
                return 400, {"error": {"status": "INVALID_ARGUMENT",
                                        "details": [{"reason": "API_KEY_INVALID"}]}}, 0, {}

            validator._fetch_with_retry = fetch
            result = await validator.validate_gemini("test-key", "")
            return result, calls

        result, calls = asyncio.run(run())
        self.assertEqual(result.status, KeyStatus.INVALID)
        self.assertIn("API_KEY_INVALID", result.info)
        self.assertEqual(calls[0][2]["x-goog-api-key"], "test-key")


if __name__ == "__main__":
    unittest.main()
