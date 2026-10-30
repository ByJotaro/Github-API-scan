import re
import unittest

from config import COMPILED_BASE_URL_PATTERNS
from database import normalize_base_url
from key_extractor import _choose_base_url, _match_context
from scanner import GitHubScanner


class DetectionPipelineTests(unittest.TestCase):
    def test_line_context_reaches_nearby_base_url(self):
        content = (
            "OPENAI_API_KEY=sk-test-placeholder\n"
            "OPENAI_BASE_URL=https://custom.example/v1/chat/completions\n"
        )
        start = content.index("sk-test")
        context = _match_context(content, start, start + 20)
        self.assertIn("custom.example", context)
        self.assertEqual(
            _choose_base_url(re.findall(r"https?://[^\s\"']+", context), context),
            "https://custom.example/v1/chat/completions",
        )

    def test_unknown_endpoint_normalizes_api_path(self):
        self.assertEqual(
            normalize_base_url("https://unknown.example/api/v1/chat/completions"),
            "https://unknown.example/api/v1",
        )
        self.assertEqual(
            normalize_base_url("https://unknown.example/v1/models"),
            "https://unknown.example/v1",
        )

    def test_scanner_prefers_api_url_over_documentation_url(self):
        scanner = GitHubScanner.__new__(GitHubScanner)
        scanner._base_url_patterns = COMPILED_BASE_URL_PATTERNS
        url, is_relay = scanner._extract_base_url(
            "OPENAI_API_KEY=sk-test-placeholder\n"
            "docs=https://example.com/docs\n"
            "OPENAI_BASE_URL=https://custom.example/api/v1/chat/completions\n",
            "openai",
        )
        self.assertEqual(url, "https://custom.example/api/v1")
        self.assertTrue(is_relay)


if __name__ == "__main__":
    unittest.main()
