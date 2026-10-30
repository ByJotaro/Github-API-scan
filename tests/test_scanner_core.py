# -*- coding: utf-8 -*-
"""Юнит-тесты ядра scanner.py и key_extractor.py — без сети и без реальной БД.

Покрыто:
  * детекторы config.COMPILED_REGEX_PATTERNS (все платформы конфига);
  * calculate_entropy / score_secret_candidate и ENTROPY_THRESHOLD;
  * is_test_key / is_blacklisted_url / mask_key;
  * ScanResult и извлечение окна контекста;
  * _extract_base_url: родной домен, relay, чёрные списки, fallback;
  * _should_skip_key: test_key / low_score / sequential_chars;
  * _extract_keys_from_content: dedup по БД, relay/opencode_zen, AWS-гард;
  * key_extractor: AWS context-guard, разбор gist-контента, base_url.

Никаких HTTP-вызовов: aiohttp-сессия подменяется фейком, БД — заглушкой.
"""

import asyncio
import queue
import threading

import pytest

import config as app_config
import key_extractor
import scanner
from config import (
    COMPILED_AZURE_URL_PATTERN,
    COMPILED_BASE_URL_PATTERNS,
    COMPILED_REGEX_PATTERNS,
)
from scanner import ScanResult


# ============================================================================
#                              Вспомогательные данные
# ============================================================================

_ALNUM = "Ab3dEf9hIj2kLm5nOp8qRs1tUv4wXy7zA6bC9dE0fG3k"
_HEX_LOWER = "0123456789abcdef"
_HEX_UPPER = "0123456789ABCDEF"


def fill(base: str, length: int) -> str:
    """Детерминированная строка нужной длины из заданного алфавита."""
    return (base * (length // len(base) + 2))[:length]


_OPENAI_KEY = "sk-proj-" + fill(_ALNUM, 48)
_OPENAI_KEY_2 = "sk-proj-" + fill("Zz9yY8xX7wW6vV5uU4tT3sS2rR1qQ0pP", 48)
_ANTHROPIC_KEY = "sk-ant-" + fill(_ALNUM, 40)
_SK40 = "sk-" + fill(_ALNUM, 40)
_AWS_ACCESS_KEY = "AKIA" + fill(_HEX_UPPER, 16)
# 40 символов base64-алфавита, без слов-заглушек из TEST_KEY_PATTERNS.
_AWS_SECRET_40 = fill("wJalrXUtnFEMIK7MDENGbPxRfiCYzAbC9dE0", 40)
# Матчится детектором openai, но содержит 'test' → is_test_key.
_TEST_KEY = "sk-" + fill(_ALNUM, 20) + "test" + fill(_ALNUM, 20)


# (позитив, похожий-но-невалидный мусор).
# Для контекст-зависимых детекторов (cohere, zhipu, steam …) позитив содержит
# ключевое слово-контекст через пробел; ожидаемый токен — часть до пробела.
DETECTOR_SAMPLES = {
    # --- Основные AI-платформы ---
    "openai": (_OPENAI_KEY, "sk-test" + fill(_ALNUM, 24)),
    "gemini": ("AIza" + fill(_ALNUM, 35), "AIza" + fill(_ALNUM, 34)),
    "anthropic": (_ANTHROPIC_KEY, "sk-ant-" + "x" * 40),
    "azure": ("0123456789abcdef0123456789abcdef", "0" * 32),
    # --- AI-платформы среднего приоритета ---
    "huggingface": ("hf_" + fill(_ALNUM, 34), "hf_" + fill(_ALNUM, 20)),
    "groq": ("gsk_" + fill(_ALNUM, 52), "gsk_" + fill(_ALNUM, 51)),
    "deepseek": ("sk-" + fill(_ALNUM, 48), "sk-" + fill(_ALNUM, 20)),
    "cohere": (fill(_ALNUM, 40) + " cohere", fill(_ALNUM, 40)),
    "mistral": (fill(_ALNUM, 32) + " mistral", fill(_ALNUM, 32)),
    "together": (fill(_HEX_LOWER, 64) + " together", fill(_HEX_LOWER, 64)),
    "replicate": ("r8_" + fill(_ALNUM, 37), "r8_" + fill(_ALNUM, 20)),
    "perplexity": ("pplx-" + fill(_ALNUM, 48), "pplx-" + fill(_ALNUM, 47)),
    "fireworks": ("fw_" + fill(_ALNUM, 40), "fw_" + fill(_ALNUM, 30)),
    "anyscale": ("esecret_" + fill(_ALNUM, 40), "esecret_" + fill(_ALNUM, 30)),
    "xai": ("xai-" + fill(_ALNUM, 40), "xai-" + fill(_ALNUM, 20)),
    "openrouter": ("sk-or-v1-" + fill(_ALNUM, 40), "sk-or-v1-" + fill(_ALNUM, 20)),
    "cerebras": ("csk-" + fill(_ALNUM, 40), "csk-" + fill(_ALNUM, 20)),
    "voyage": ("va-" + fill(_ALNUM, 40), "va-" + fill(_ALNUM, 20)),
    "jina": ("jina_" + fill(_ALNUM, 40), "jina_" + fill(_ALNUM, 20)),
    "lepton": ("lep-" + fill(_ALNUM, 40), "lep-" + fill(_ALNUM, 20)),
    "modal": ("ak-" + fill(_ALNUM, 40), "ak-" + fill(_ALNUM, 20)),
    # --- GitHub ---
    "github": ("ghp_" + fill(_ALNUM, 36), "ghp_" + fill(_ALNUM, 10)),
    # --- Облачные провайдеры ---
    "aws_access_key": (_AWS_ACCESS_KEY, "AKIA" + fill(_HEX_LOWER, 16)),
    "aws_secret_key": (_AWS_SECRET_40, fill(_ALNUM, 39)),
    "steam": (fill(_HEX_UPPER, 32) + " steam", fill(_HEX_UPPER, 32)),
    # --- Китайские AI-провайдеры (sk- + контекст) ---
    "zhipu": (_SK40 + " zhipu", _SK40),
    "yi": (_SK40 + " lingyiwanwu", _SK40),
    "baichuan": (_SK40 + " baichuan", _SK40),
    "moonshot": (_SK40 + " moonshot", _SK40),
    "stepfun": (_SK40 + " stepfun", _SK40),
    "minimax": ("eyJ" + fill(_ALNUM, 40) + " minimax", "eyJ" + fill(_ALNUM, 40)),
    "siliconflow": (_SK40 + " siliconflow", _SK40),
    "dashscope": (_SK40 + " aliyun", _SK40),
    "volcengine": (_SK40 + " volces", _SK40),
    "internlm": (_SK40 + " internlm", _SK40),
    # --- VPS / облака ---
    "digitalocean": ("dop_v1_" + fill(_ALNUM, 64), "dop_v1_" + fill(_ALNUM, 40)),
    "linode": (fill(_HEX_LOWER, 64) + " linode", fill(_HEX_LOWER, 64)),
    "vultr": (fill(_HEX_LOWER, 36) + " vultr", fill(_HEX_LOWER, 36)),
    "hetzner": (fill(_ALNUM, 64) + " hetzner", fill(_ALNUM, 64)),
    "scaleway": ("SCW" + fill(_ALNUM, 40), "SCW" + fill(_ALNUM, 20)),
    # --- GPU cloud ---
    "runpod": ("RPv2:" + fill(_ALNUM, 40), "RPv2:" + fill(_ALNUM, 20)),
    "lambdalabs": ("sk_live_" + fill(_ALNUM, 40), "sk_live_" + fill(_ALNUM, 30)),
    "coreweave": (fill(_ALNUM, 64) + " coreweave", fill(_ALNUM, 64)),
    "shadeform": ("sf_" + fill(_ALNUM, 40), "sf_" + fill(_ALNUM, 20)),
    # --- Расширенный каталог ---
    "elevenlabs": ("sk_" + fill(_ALNUM, 32), "sk_" + fill(_ALNUM, 20)),
    "tavily": ("tvly-" + fill(_ALNUM, 30), "tvly-" + fill(_ALNUM, 20)),
    "firecrawl": ("fc-" + fill(_ALNUM, 30), "fc-" + fill(_ALNUM, 20)),
    "apify": ("apify_api_" + fill(_ALNUM, 20), "apify_api_" + fill(_ALNUM, 10)),
    "langfuse": ("sk-lf-" + fill(_ALNUM, 30), "sk-lf-" + fill(_ALNUM, 20)),
    "astra": ("AstraCS:" + fill(_ALNUM, 30), "AstraCS:" + fill(_ALNUM, 20)),
    "sourcegraph": ("sgp_" + fill(_ALNUM, 30), "sgp_" + fill(_ALNUM, 20)),
    "wordware": ("ww_" + fill(_ALNUM, 30), "ww_" + fill(_ALNUM, 20)),
    "llamacloud": ("llc-" + fill(_ALNUM, 30), "llc-" + fill(_ALNUM, 20)),
}


def _expected_token(positive_sample: str) -> str:
    return positive_sample.split(" ")[0]


# ============================================================================
#                        Заглушки БД / сети / i18n
# ============================================================================

class FakeDB:
    """Минимум Database, нужный GitHubScanner: key_exists() и _blob_cache."""

    def __init__(self, existing=()):
        self.existing = set(existing)
        self._blob_cache = set()
        self.key_exists_calls = []

    def key_exists(self, api_key):
        self.key_exists_calls.append(api_key)
        return api_key in self.existing


def make_scanner(db=None):
    """Сканер без сетевой инициализации (Github-клиенты не нужны чистым методам)."""
    s = scanner.GitHubScanner.__new__(scanner.GitHubScanner)
    s.result_queue = queue.Queue()
    s.db = db if db is not None else FakeDB()
    s.stop_event = threading.Event()
    s.dashboard = None
    s._processed_keys = set()
    s._processed_lock = threading.Lock()
    s._processed_shas = set()
    s._sha_lock = threading.Lock()
    s._sha_batch_buffer = []
    s._key_patterns = COMPILED_REGEX_PATTERNS
    s._base_url_patterns = COMPILED_BASE_URL_PATTERNS
    s._azure_url_pattern = COMPILED_AZURE_URL_PATTERN
    s.stats = {
        "total_found": 0,
        "files_scanned": 0,
        "skipped_entropy": 0,
        "skipped_blacklist": 0,
        "skipped_sha": 0,
        "skipped_file_filter": 0,
    }
    return s


class _FakeResponse:
    def __init__(self, text, status=200):
        self._text = text
        self.status = status

    async def text(self, errors="replace"):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False


class _FakeSession:
    """aiohttp.ClientSession-совместимый фейк: только GET + async context."""

    def __init__(self, text, status=200):
        self._text = text
        self._status = status
        self.closed = False
        self.requests = []

    def get(self, url, **kwargs):
        self.requests.append(url)
        return _FakeResponse(self._text, self._status)

    async def close(self):
        self.closed = True


_GIST_URL = "https://gist.githubusercontent.com/u/1/raw/abc/file.env"


def extract_from_gist(content, url=_GIST_URL, status=200):
    """key_extractor.fetch_and_extract на фейковой сессии (без сети)."""
    extractor = key_extractor.KeyExtractor()
    extractor.session = _FakeSession(content, status)
    return asyncio.run(extractor.fetch_and_extract(url))


@pytest.fixture
def db():
    return FakeDB()


@pytest.fixture
def scanner_core(db):
    return make_scanner(db)


# ============================================================================
#                         1. Детекторы из конфига
# ============================================================================

def test_every_configured_detector_has_samples():
    assert set(DETECTOR_SAMPLES) == set(COMPILED_REGEX_PATTERNS)
    assert len(DETECTOR_SAMPLES) == len(COMPILED_REGEX_PATTERNS)


@pytest.mark.parametrize("platform", sorted(DETECTOR_SAMPLES))
def test_detector_matches_positive_sample(platform):
    positive, _ = DETECTOR_SAMPLES[platform]
    match = COMPILED_REGEX_PATTERNS[platform].search(positive)
    assert match is not None, f"{platform}: позитив не распознан"
    assert match.group(0) == _expected_token(positive), (
        f"{platform}: детектор вернул не тот токен"
    )


@pytest.mark.parametrize("platform", sorted(DETECTOR_SAMPLES))
def test_detector_rejects_lookalike(platform):
    _, lookalike = DETECTOR_SAMPLES[platform]
    assert COMPILED_REGEX_PATTERNS[platform].search(lookalike) is None, (
        f"{platform}: похожий мусор ошибочно распознан"
    )


@pytest.mark.parametrize("platform,garbage", [
    ("openai", "sk-test1234567890abcdefghijklmn"),  # secret-fixture: fake, not a key
    ("openai", "sk-your_api_key_1234567890abcdef"),
    ("anthropic", "sk-ant-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
    ("gemini", "AIzaTooShort"),
    ("huggingface", "hf_" + fill(_ALNUM, 20)),
    ("github", "ghp_short123"),
    ("aws_access_key", "AKIA" + fill(_HEX_LOWER, 16)),
    ("aws_secret_key", fill(_ALNUM, 39)),
])
def test_detector_rejects_placeholder_shapes(platform, garbage):
    assert COMPILED_REGEX_PATTERNS[platform].search(garbage) is None


def test_openai_detector_matches_key_inside_code_line():
    line = 'OPENAI_API_KEY="%s"' % _OPENAI_KEY
    match = COMPILED_REGEX_PATTERNS["openai"].search(line)
    assert match is not None
    assert match.group(0) == _OPENAI_KEY


def test_context_anchored_detector_requires_keyword_on_same_line():
    # (?=.*cohere) не переходит через перевод строки (нет re.DOTALL).
    key = fill(_ALNUM, 40)
    assert COMPILED_REGEX_PATTERNS["cohere"].search(key + "\nprovider: cohere") is None
    assert COMPILED_REGEX_PATTERNS["cohere"].search(key + " cohere") is not None


# ============================================================================
#                          2. Энтропия и пороги
# ============================================================================

def test_entropy_empty_string_is_zero():
    assert scanner.calculate_entropy("") == 0.0


def test_entropy_single_repeated_symbol_is_zero():
    assert scanner.calculate_entropy("a" * 64) == 0.0


def test_entropy_two_equiprobable_symbols_is_one_bit():
    assert scanner.calculate_entropy("ab" * 8) == pytest.approx(1.0)


def test_entropy_four_equiprobable_symbols_is_two_bits():
    assert scanner.calculate_entropy("abcd" * 8) == pytest.approx(2.0)


def test_entropy_random_base64_is_above_threshold():
    assert scanner.calculate_entropy(fill(_ALNUM, 64)) > scanner.ENTROPY_THRESHOLD
    assert scanner.calculate_entropy(_OPENAI_KEY) > scanner.ENTROPY_THRESHOLD


def test_entropy_numeric_placeholder_is_below_threshold():
    assert scanner.calculate_entropy("1234567890") < scanner.ENTROPY_THRESHOLD


def test_entropy_is_cached_per_string():
    scanner.calculate_entropy.cache_clear()
    first = scanner.calculate_entropy(_OPENAI_KEY)
    hits_before = scanner.calculate_entropy.cache_info().hits
    second = scanner.calculate_entropy(_OPENAI_KEY)
    assert first == second
    assert scanner.calculate_entropy.cache_info().hits == hits_before + 1


def test_score_secret_candidate_short_strings_score_zero():
    assert scanner.score_secret_candidate("") == 0.0
    assert scanner.score_secret_candidate("short") == 0.0


def test_score_secret_candidate_random_key_passes_default_threshold():
    score = scanner.score_secret_candidate(_OPENAI_KEY)
    assert score > scanner.ENTROPY_THRESHOLDS["default"]


def test_score_secret_candidate_penalizes_english_words():
    assert scanner.score_secret_candidate("mysecretkeyexample") < 3.8


# ============================================================================
#                       3. is_test_key / чёрный список
# ============================================================================

@pytest.mark.parametrize("placeholder", [
    "your_api_key",
    "sk-" + "x" * 20,
    "example",
    "test",
    "sample_key_123",
    "demo",
    "<your_key>",
    "placeholder_value",
    "insert_key_here",
    "replace_me",
    "CHANGEME",
    "my-secret-token",
])
def test_is_test_key_true_for_placeholders(placeholder):
    assert scanner.is_test_key(placeholder) is True


@pytest.mark.parametrize("real_key", [
    _OPENAI_KEY,
    _SK40,
    _AWS_ACCESS_KEY,
    "1234567890",
])
def test_is_test_key_false_for_realistic_keys(real_key):
    assert scanner.is_test_key(real_key) is False


def test_numeric_placeholder_is_rejected_by_score_not_by_name_list(scanner_core):
    # '1234567890' не содержит слов-заглушек, поэтому режется оценкой секрета.
    assert scanner.is_test_key("1234567890") is False
    should_skip, reason = scanner_core._should_skip_key("1234567890")
    assert should_skip is True
    assert reason.startswith("low_score:")


@pytest.mark.parametrize("url,expected", [
    ("http://localhost:8080/v1", True),
    ("https://example.com/v1", True),
    ("https://api.openai.com/v1", False),
    ("", False),
])
def test_is_blacklisted_url(url, expected):
    assert scanner.is_blacklisted_url(url) is expected


# ============================================================================
#                              4. mask_key
# ============================================================================

@pytest.mark.parametrize("raw,expected", [
    ("", "..."),
    ("abc", "abc...abc"),
    ("abcdefghijkl", "abcd...ijkl"),
    ("sk-proj-ABCDEFGHIJKLMNOP", "sk-proj-...MNOP"),
    (_OPENAI_KEY, "sk-proj-...Ab3d"),
])
def test_mask_key(raw, expected):
    assert scanner.mask_key(raw) == expected


def test_mask_key_preserves_prefix_and_suffix_lengths():
    masked = scanner.mask_key(_OPENAI_KEY)
    assert masked.startswith(_OPENAI_KEY[:8])
    assert masked.endswith(_OPENAI_KEY[-4:])
    assert len(masked) == 8 + len("...") + 4


def test_mask_key_hides_middle_of_long_key():
    masked = scanner.mask_key(_OPENAI_KEY)
    assert _OPENAI_KEY[8:-4] not in masked


# ============================================================================
#                    5. ScanResult и окно контекста
# ============================================================================

def test_scan_result_defaults():
    result = ScanResult(
        platform="openai",
        api_key=_OPENAI_KEY,
        base_url="https://api.openai.com/v1",
        source_url="https://github.com/a/b/blob/main/.env",
    )
    assert result.platform == "openai"
    assert result.api_key == _OPENAI_KEY
    assert result.base_url == "https://api.openai.com/v1"
    assert result.source_url == "https://github.com/a/b/blob/main/.env"
    assert result.is_azure is False
    assert result.is_relay is False
    assert result.context == ""


def test_scan_result_keeps_explicit_flags():
    result = ScanResult(
        platform="relay",
        api_key=_OPENAI_KEY,
        base_url="https://api.relay.dev/v1",
        source_url="u",
        is_azure=True,
        is_relay=True,
        context="ctx",
    )
    assert result.is_azure is True
    assert result.is_relay is True
    assert result.context == "ctx"


def _content_with_key_at(line_index, total_lines=30, key="KEY_HERE"):
    lines = ["line %d" % i for i in range(total_lines)]
    lines[line_index] = key
    return "\n".join(lines), lines


@pytest.mark.parametrize("line_index", [0, 15, 29])
def test_extract_context_uses_configured_window(scanner_core, line_index):
    window = app_config.config.context_window
    content, lines = _content_with_key_at(line_index)
    context = scanner_core._extract_context(content, content.index("KEY_HERE"))
    expected = lines[max(0, line_index - window):min(len(lines), line_index + window + 1)]
    assert context.split("\n") == expected


def test_extract_context_window_size_for_middle_line(scanner_core):
    window = app_config.config.context_window
    content, _ = _content_with_key_at(15)
    context = scanner_core._extract_context(content, content.index("KEY_HERE"))
    assert len(context.split("\n")) == 2 * window + 1


def test_extract_context_truncates_at_file_edges(scanner_core):
    window = app_config.config.context_window
    first_content, _ = _content_with_key_at(0)
    last_content, _ = _content_with_key_at(29)
    first_ctx = scanner_core._extract_context(first_content, first_content.index("KEY_HERE"))
    last_ctx = scanner_core._extract_context(last_content, last_content.index("KEY_HERE"))
    assert len(first_ctx.split("\n")) == window + 1
    assert len(last_ctx.split("\n")) == window + 1
    assert first_ctx.split("\n")[0] == "KEY_HERE"
    assert last_ctx.split("\n")[-1] == "KEY_HERE"


# ============================================================================
#             5.1 _extract_base_url / _should_skip_url / Azure
# ============================================================================

@pytest.mark.parametrize("platform,context,expected_url,expected_relay", [
    ("openai", 'base_url = "https://api.openai.com/v1"',
     "https://api.openai.com/v1", False),
    ("openai", "OPENAI_API_BASE=https://api.openai.com/v1",
     "https://api.openai.com/v1", False),
    ("openai", 'base_url = "https://api.my-relay-proxy.dev/v1"',
     "https://api.my-relay-proxy.dev/v1", True),
    ("anthropic", "https://api.anthropic.com/v1/messages",
     "https://api.anthropic.com/v1", False),
    ("anthropic", "https://myclaudehehe.cc/v1",
     "https://myclaudehehe.cc/v1", True),
    ("gemini", "https://generativelanguage.googleapis.com/v1beta",
     "https://generativelanguage.googleapis.com/v1beta", False),
    # Чёрные списки документации/чужих API → fallback на дефолт платформы.
    ("openai", "https://stackoverflow.com/questions/123",
     "https://api.openai.com", False),
    ("openai", "https://docs.djangoproject.com/en/5.0/",
     "https://api.openai.com", False),
    ("gemini", "https://maps.googleapis.com/maps/api/place/textsearch/json",
     "https://generativelanguage.googleapis.com/v1beta", False),
    # Для не-OpenAI платформ URL без родного домена и API-признаков отбрасывается.
    ("anthropic", "https://example-shop.com/products",
     "https://api.anthropic.com", False),
    ("openai", "no urls in this context", "https://api.openai.com", False),
    ("aws_secret_key", "no urls in this context", "", False),
])
def test_extract_base_url(scanner_core, platform, context, expected_url, expected_relay):
    assert scanner_core._extract_base_url(context, platform) == (expected_url, expected_relay)


def test_extract_base_url_normalizes_endpoint_tail(scanner_core):
    url, is_relay = scanner_core._extract_base_url(
        "https://api.openai.com/v1/chat/completions", "openai"
    )
    assert url == "https://api.openai.com/v1"
    assert is_relay is False


@pytest.mark.parametrize("url,expected", [
    ("http://localhost:8080/v1", (True, "blacklisted")),
    ("https://example.com/v1", (True, "blacklisted")),
    ("https://api.openai.com/v1", (False, "")),
])
def test_should_skip_url(scanner_core, url, expected):
    assert scanner_core._should_skip_url(url) == expected


@pytest.mark.parametrize("url,expected", [
    ("https://api.relay.dev/v1", True),
    ("https://api.openai.com/v1", True),
    ("https://docs.djangoproject.com/en/5.0/", False),
])
def test_is_valid_relay_url(scanner_core, url, expected):
    assert scanner_core._is_valid_relay_url(url) is expected


def test_azure_context_detection(scanner_core):
    assert scanner_core._is_azure_context("AZURE_OPENAI_ENDPOINT = ...") is True
    assert scanner_core._is_azure_context("azure_endpoint: https://x.openai.azure.com") is True
    assert scanner_core._is_azure_context("plain openai key") is False


def test_azure_endpoint_extraction(scanner_core):
    endpoint = scanner_core._extract_azure_endpoint(
        "https://my-res.openai.azure.com/openai/deployments/chat"
    )
    assert endpoint == "https://my-res.openai.azure.com"
    assert scanner_core._extract_azure_endpoint("no endpoint here") is None


# ============================================================================
#        5.2 _should_skip_key: test_key / low_score / sequential_chars
# ============================================================================

@pytest.mark.parametrize("key,reason_prefix", [
    ("your_api_key", "test_key"),
    ("sk-" + "x" * 30, "test_key"),
    (_TEST_KEY, "test_key"),
    ("1234567890", "low_score:"),
    ("a" * 40, "low_score:"),
    ("AKIA0123456789ABCDEF", "sequential_chars"),
    ("sk-abcdefghijklmnopqrstuvwxyz0123456789a", "sequential_chars"),  # secret-fixture
])
def test_should_skip_key_rejects(key, reason_prefix):
    should_skip, reason = make_scanner()._should_skip_key(key)
    assert should_skip is True
    assert reason.startswith(reason_prefix)


@pytest.mark.parametrize("key", [
    _OPENAI_KEY,
    _SK40,
    fill(_ALNUM, 45),
    _AWS_SECRET_40,
])
def test_should_skip_key_accepts_high_entropy_keys(key):
    should_skip, reason = make_scanner()._should_skip_key(key)
    assert should_skip is False
    assert reason == ""


# ============================================================================
#     5.3 _extract_keys_from_content: результаты, dedup, relay, AWS-гард
# ============================================================================

def _openai_content(key=_OPENAI_KEY, base_url="https://api.openai.com/v1"):
    return 'OPENAI_API_BASE="%s"\nOPENAI_API_KEY="%s"\n' % (base_url, key)


def test_extract_keys_from_content_returns_scanresult(scanner_core):
    source = "https://github.com/a/b/blob/main/.env"
    results = scanner_core._extract_keys_from_content(_openai_content(), source)
    assert len(results) == 1
    result = results[0]
    assert result.platform == "openai"
    assert result.api_key == _OPENAI_KEY
    assert result.base_url == "https://api.openai.com/v1"
    assert result.is_relay is False
    assert result.is_azure is False
    assert result.source_url == source
    assert "OPENAI_API_KEY" in result.context


def test_extract_keys_from_content_skips_duplicate_in_same_content(scanner_core):
    content = _openai_content() + 'SECOND="%s"\n' % _OPENAI_KEY
    assert len(scanner_core._extract_keys_from_content(content, "u")) == 1
    # Повторный проход: ключ уже в кэше обработанных.
    assert scanner_core._extract_keys_from_content(content, "u") == []


def test_extract_keys_from_content_skips_key_already_in_database():
    database = FakeDB(existing=[_OPENAI_KEY])
    s = make_scanner(database)
    assert s._extract_keys_from_content(_openai_content(), "u") == []
    assert database.key_exists_calls == [_OPENAI_KEY]


def test_is_key_processed_uses_memory_cache_after_first_db_lookup(db):
    s = make_scanner(db)
    assert s._is_key_processed(_OPENAI_KEY) is False
    s._mark_key_processed(_OPENAI_KEY)
    assert s._is_key_processed(_OPENAI_KEY) is True
    # В БД сходили один раз — дальше отвечает кэш памяти.
    assert db.key_exists_calls == [_OPENAI_KEY]


def test_is_key_processed_true_when_database_has_key():
    s = make_scanner(FakeDB(existing=[_OPENAI_KEY]))
    assert s._is_key_processed(_OPENAI_KEY) is True


def test_extract_keys_from_content_maps_relay_platform(scanner_core):
    content = _openai_content(base_url="https://api.my-relay-proxy.dev/v1")
    results = scanner_core._extract_keys_from_content(content, "u")
    assert len(results) == 1
    assert results[0].platform == "relay"
    assert results[0].base_url == "https://api.my-relay-proxy.dev/v1"
    assert results[0].is_relay is True


def test_extract_keys_from_content_maps_opencode_zen(scanner_core):
    content = _openai_content(base_url="https://api.opencode.ai/zen/v1")
    results = scanner_core._extract_keys_from_content(content, "u")
    assert len(results) == 1
    assert results[0].platform == "opencode_zen"
    assert results[0].base_url == "https://api.opencode.ai/zen/v1"


def test_extract_keys_from_content_skips_test_key_and_counts():
    s = make_scanner()
    results = s._extract_keys_from_content('key = "%s"\n' % _TEST_KEY, "u")
    assert results == []
    assert s.stats["skipped_entropy"] == 1


def test_extract_keys_from_content_filters_low_entropy_key():
    s = make_scanner()
    results = s._extract_keys_from_content('TOKEN = "%s"\n' % ("a" * 40), "u")
    assert results == []
    assert s.stats["skipped_entropy"] == 1


def test_extract_keys_from_content_skips_blacklisted_base_url():
    s = make_scanner()
    content = 'base_url="http://localhost:8080/v1"\nkey="%s"\n' % _OPENAI_KEY
    assert s._extract_keys_from_content(content, "u") == []
    assert s.stats["skipped_blacklist"] == 1


def test_extract_keys_from_content_requires_aws_context_for_secret():
    bare = make_scanner()
    assert bare._extract_keys_from_content('token = "%s"\n' % _AWS_SECRET_40, "u") == []

    with_context = make_scanner()
    results = with_context._extract_keys_from_content(
        'aws_secret_access_key = "%s"\n' % _AWS_SECRET_40, "u"
    )
    assert [r.platform for r in results] == ["aws_secret_key"]
    assert results[0].api_key == _AWS_SECRET_40
    assert results[0].base_url == ""
    assert results[0].is_relay is False


def test_extract_keys_from_content_never_reports_bare_azure_hex(scanner_core):
    # Платформа 'azure' пропускается в цикле: 32 hex без Azure-контекста — мусор.
    content = 'key = "0123456789abcdef0123456789abcdef"\n'
    assert scanner_core._extract_keys_from_content(content, "u") == []


def test_extract_keys_from_content_uses_azure_endpoint_from_context(scanner_core):
    content = (
        "AZURE_OPENAI_ENDPOINT=https://my-res.openai.azure.com\n"
        'OPENAI_API_KEY="%s"\n' % _OPENAI_KEY
    )
    results = scanner_core._extract_keys_from_content(content, "u")
    assert len(results) == 1
    result = results[0]
    assert result.platform == "azure"
    assert result.base_url == "https://my-res.openai.azure.com"
    assert result.is_azure is True
    assert result.is_relay is False


def test_extract_keys_from_content_azure_context_without_endpoint(scanner_core):
    content = 'AZURE_OPENAI_KEY="%s"\n' % _OPENAI_KEY
    results = scanner_core._extract_keys_from_content(content, "u")
    assert len(results) == 1
    assert results[0].platform == "azure"
    assert results[0].base_url == ""
    assert results[0].is_azure is True


# ============================================================================
#        6. key_extractor: AWS context-guard, парсинг, base_url
# ============================================================================

def test_key_extractor_extracts_openai_key_with_base_url():
    content = "OPENAI_API_KEY=%s\nbase_url=https://api.openai.com/v1\n" % _OPENAI_KEY
    results = extract_from_gist(content)
    assert results == [{
        "platform": "openai",
        "api_key": _OPENAI_KEY,
        "base_url": "https://api.openai.com/v1",
        "source_url": _GIST_URL,
    }]


def test_key_extractor_aws_secret_without_context_is_dropped():
    assert extract_from_gist('token = "%s"\n' % _AWS_SECRET_40) == []


def test_key_extractor_aws_secret_with_context_is_accepted():
    results = extract_from_gist('aws_secret_access_key = "%s"\n' % _AWS_SECRET_40)
    assert [r["platform"] for r in results] == ["aws_secret_key"]
    assert results[0]["api_key"] == _AWS_SECRET_40
    assert results[0]["source_url"] == _GIST_URL


def test_key_extractor_aws_secret_accepts_secret_key_phrase():
    results = extract_from_gist('# secret key\nfoo = "%s"\n' % _AWS_SECRET_40)
    assert [r["platform"] for r in results] == ["aws_secret_key"]


def test_key_extractor_aws_secret_requires_guard_word_for_bare_assignment():
    # 'AK=<secret>' не даёт ни одного слова-гарда → ключ отбрасывается.
    assert extract_from_gist('AK=%s\n' % _AWS_SECRET_40) == []


def test_key_extractor_maps_opencode_zen():
    content = 'base_url="https://api.opencode.ai/zen/v1"\nkey=%s\n' % _OPENAI_KEY
    results = extract_from_gist(content)
    assert len(results) == 1
    assert results[0]["platform"] == "opencode_zen"
    assert results[0]["base_url"] == "https://api.opencode.ai/zen/v1"


def test_key_extractor_returns_every_key_in_multi_key_env():
    content = "A=%s\nB=%s\n" % (_OPENAI_KEY, _OPENAI_KEY_2)
    results = extract_from_gist(content)
    assert [r["api_key"] for r in results] == [_OPENAI_KEY, _OPENAI_KEY_2]


def test_key_extractor_returns_nothing_for_non_200():
    content = "OPENAI_API_KEY=%s\n" % _OPENAI_KEY
    assert extract_from_gist(content, status=404) == []


def test_key_extractor_returns_nothing_for_too_short_content():
    assert extract_from_gist("abc") == []


def test_key_extractor_returns_nothing_for_oversized_content():
    assert extract_from_gist("x" * 500_001) == []


def test_key_extractor_skips_blocked_file_extension():
    content = 'aws_secret_access_key = "%s"\n' % _AWS_SECRET_40
    assert extract_from_gist(content, url="https://raw.example.org/assets/logo.png") == []


def test_match_context_uses_line_radius():
    lines = ["line %d" % i for i in range(40)]
    lines[20] = "KEY=" + _OPENAI_KEY
    content = "\n".join(lines)
    start = content.index("KEY=")
    context = key_extractor._match_context(content, start, start + len("KEY=" + _OPENAI_KEY))
    parts = context.split("\n")
    assert parts[0] == "line 8"
    assert parts[-1] == "line 32"
    assert len(parts) == 25


def test_choose_base_url_prefers_api_endpoint_and_skips_code_hosts():
    urls = [
        "https://github.com/a/b",
        "https://shop.dev/about",
        "https://api.relay.dev/v1",
    ]
    assert key_extractor._choose_base_url(urls, "") == "https://api.relay.dev/v1"
    assert key_extractor._choose_base_url(["https://github.com/a/b"], "") == ""


def test_should_skip_file_filters_binaries_and_large_files():
    assert key_extractor._should_skip_file("assets/logo.png") is True
    assert key_extractor._should_skip_file("src/main.py") is False
    assert key_extractor._should_skip_file(".env", 600 * 1024) is True
    assert key_extractor._should_skip_file("node_modules/pkg/index.js") is True


# ============================================================================
#       Регрессия: skip-логи не должны падать на kwarg key= (баг 2026-10-29)
# ============================================================================

def test_slog_i18n_accepts_key_placeholder_kwarg():
    """`_slog_i18n("log_skip_key", key=...)` раньше падал с TypeError:
    got multiple values for argument 'key' — и любой пропуск ключа валил
    весь _extract_keys_from_content. Шаблон "Skip {key} ({reason})" требует
    подстановку именно с именем key.
    """
    msg = scanner._slog_i18n("log_skip_key", key="sk-***", reason="low_score")
    assert "sk-***" in msg
    assert "low_score" in msg
    assert "{key}" not in msg

    url_msg = scanner._slog_i18n("log_skip_url", key="sk-***", reason="localhost")
    assert "localhost" in url_msg
    assert "{key}" not in url_msg


def test_tf_formats_key_placeholder():
    from tui_i18n import tf

    assert tf("log_skip_key", "en", key="sk-***", reason="low_score") == (
        "Skip sk-*** (low_score)"
    )
    assert "Пропуск sk-***" in tf("log_skip_key", "ru", key="sk-***", reason="low_score")


def test_aws_secret_env_assignment_is_detected():
    """`.env`-форма AWS_SECRET_ACCESS_KEY=<40> раньше не матчилась:
    lookbehind включал '=' и стоял ровно перед значением."""
    content = "AWS_SECRET_ACCESS_KEY=%s\n" % _AWS_SECRET_40
    results = make_scanner()._extract_keys_from_content(content, "u")
    assert [r.platform for r in results] == ["aws_secret_key"]
