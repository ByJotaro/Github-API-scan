"""Тесты ядра validator.py без сети.

Покрытие:
  * константы (MAX_CONCURRENCY, RPM_*, HIGH_VALUE_MODELS, REQUEST_TIMEOUT);
  * mask_key, ValidationResult, _math_challenge / _content_has_answer;
  * CircuitBreaker: порог открытия, игнор бизнес-ошибок, таймер полуоткрытия,
    лимит пробных запросов, закрытие по успеху, изоляция по домену;
  * классификация статусов (_classify_status) и транзитных ошибок;
  * ретраи и экспоненциальный backoff (_retry_cfg, _fetch_with_retry) через
    фейковую aiohttp-сессию;
  * выбор эндпоинта (_normalize_base_url, _try_url_variants,
    _is_likely_valid_relay) и анти-SSRF;
  * построение payload/headers и разбор ответов OpenAI-совместимого API
    (validate_openai, validate_anthropic, validate_gemini, _validate_simple_account);
  * подтверждение ключа (confirm_key) и диспетчеризация платформ
    (validate_single) — реальные сетевые запросы всегда подменены.

Сеть не используется: любой HTTP идёт через monkeypatch/mock.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
from types import SimpleNamespace
from unittest.mock import MagicMock

import aiohttp
import pytest

import validator as vmod
from config import EXTRA_PROVIDERS
from database import KeyStatus
from scanner import ScanResult
from validator import (
    HIGH_VALUE_MODELS,
    MAX_CONCURRENCY,
    RPM_ENTERPRISE_THRESHOLD,
    RPM_FREE_TRIAL_THRESHOLD,
    AsyncValidator,
    CircuitBreaker,
    CircuitState,
    ValidationResult,
    mask_key,
)

DEFAULT_URLS = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
    "gemini": "https://generativelanguage.googleapis.com/v1beta",
    "opencode_zen": "https://opencode.ai/zen/v1",
}


@pytest.fixture(autouse=True)
def isolated_config(monkeypatch):
    """Изолирует module-level config от реального config_local.py.

    Реальный config_local может содержать токены/прокси и другие значения —
    тесты не должны на них опираться.
    """
    shim = SimpleNamespace(
        circuit_breaker_enabled=True,
        default_base_urls=dict(DEFAULT_URLS),
        proxy_url=None,
        validator_max_retries=3,
        validator_retry_backoff=1.5,
        request_timeout=15,
    )
    monkeypatch.setattr(vmod, "config", shim)
    return shim


class _PlanExhausted(BaseException):
    """Наследуем BaseException, чтобы не быть проглоченным `except Exception`."""


class FetchCall:
    def __init__(self, method, url, headers, json_body, parse_json):
        self.method = method
        self.url = url
        self.headers = headers or {}
        self.json_body = json_body
        self.parse_json = parse_json


class Harness:
    """Экземпляр AsyncValidator с полностью подменённым HTTP-слоем."""

    def __init__(self, responses=()):
        self.validator = AsyncValidator.__new__(AsyncValidator)
        self.validator.db = MagicMock()
        self.validator.dashboard = None
        self.validator._session = None
        self.validator._circuit_breaker = CircuitBreaker()
        self.validator._last_headers = {}
        self.responses = list(responses)
        self.calls: list[FetchCall] = []

        async def fetch(method, url, headers=None, json_body=None,
                        parse_json=True):
            self.calls.append(FetchCall(method, url, headers, json_body,
                                        parse_json))
            if not self.responses:
                raise _PlanExhausted(f"unexpected request {method} {url}")
            return self.responses.pop(0)

        self.validator._fetch_with_retry = fetch

    # --- удобные выборки ---
    def get_urls(self):
        return [c.url for c in self.calls if c.method == "GET"]

    def posted_bodies(self):
        return [c.json_body for c in self.calls if c.method == "POST"]

    def posted_models(self):
        return [b.get("model") for b in self.posted_bodies() if b]


# ---------------------------------------------------------------------------
# Константы и модульные значения
# ---------------------------------------------------------------------------

def test_module_constants():
    assert MAX_CONCURRENCY == 100
    assert RPM_ENTERPRISE_THRESHOLD == 3000
    assert RPM_FREE_TRIAL_THRESHOLD == 20
    assert HIGH_VALUE_MODELS == ["gpt-4", "gpt-4-turbo", "gpt-4o",
                                 "gpt-4-32k", "claude-3-opus"]


def test_request_timeout_is_aiohttp_timeout_with_connect_limit():
    assert isinstance(vmod.REQUEST_TIMEOUT, aiohttp.ClientTimeout)
    assert vmod.REQUEST_TIMEOUT.connect == 10
    # total берётся из config.request_timeout либо дефолта 15
    assert vmod.REQUEST_TIMEOUT.total == vmod._req_timeout_total
    assert vmod.REQUEST_TIMEOUT.total > 0


# ---------------------------------------------------------------------------
# Жизненный цикл AsyncValidator (без реальной сессии)
# ---------------------------------------------------------------------------

def test_init_wires_global_breaker_and_semaphore():
    validator = AsyncValidator(MagicMock())
    assert validator.semaphore._value == MAX_CONCURRENCY
    assert validator._circuit_breaker is vmod.circuit_breaker
    assert validator._session is None
    asyncio.run(validator.close())


def test_close_closes_open_session_only_once():
    class ClosingSession:
        def __init__(self):
            self.closed = False
            self.close_calls = 0

        async def close(self):
            self.close_calls += 1
            self.closed = True

    validator = AsyncValidator.__new__(AsyncValidator)
    session = ClosingSession()
    validator._session = session

    async def scenario():
        await validator.close()
        await validator.close()  # уже закрытая сессия не закрывается повторно

    asyncio.run(scenario())
    assert session.closed is True
    assert session.close_calls == 1


# ---------------------------------------------------------------------------
# mask_key
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "key, expected",
    [
        ("", "..."),
        ("short", "shor...hort"),
        ("123456789012", "1234...9012"),            # ровно 12 → короткая ветка
        ("1234567890123", "12345678...0123"),       # 13 → длинная ветка
        ("sk-abcdefghijklmnopqrstuvwxyz", "sk-abcde...wxyz"),  # secret-fixture
    ],
)
def test_mask_key(key, expected):
    assert mask_key(key) == expected


def test_mask_key_hides_middle_of_real_key():
    key = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"
    masked = mask_key(key)
    assert key not in masked
    assert masked.startswith("sk-proj-")
    assert masked.endswith("6789")


# ---------------------------------------------------------------------------
# ValidationResult
# ---------------------------------------------------------------------------

def test_validation_result_defaults_are_per_instance():
    first = ValidationResult(KeyStatus.VALID, "ok")
    second = ValidationResult(KeyStatus.VALID, "ok")
    first.models.append("m1")
    assert second.models == []
    assert first.model_tier == ""
    assert first.rpm == 0
    assert first.balance_usd == 0.0
    assert first.is_high_value is False


def test_validation_result_keeps_explicit_models():
    result = ValidationResult(KeyStatus.VALID, "ok", models=["a", "b"])
    assert result.models == ["a", "b"]


# ---------------------------------------------------------------------------
# Арифметическая проверка
# ---------------------------------------------------------------------------

def test_math_challenge_format_and_answer():
    pattern = re.compile(r"Calculate (\d{5})\+(\d{5}), and reply")
    for _ in range(50):
        prompt, answer = vmod._math_challenge()
        match = pattern.search(prompt)
        assert match, prompt
        assert int(match.group(1)) + int(match.group(2)) == int(answer)


@pytest.mark.parametrize(
    "content, answer, expected",
    [
        ("42", "42", True),
        (" 4 2 ", "42", True),
        ("1,234", "1234", True),
        ("The answer is 1234.", "1234", True),
        ("420", "42", False),
        ("142", "42", False),
        ("180245", "80245", False),   # подстрока длинного числа
        ("", "42", False),
        ("余额不足", "42", False),
    ],
)
def test_content_has_answer(content, answer, expected):
    assert vmod._content_has_answer(content, answer) is expected


# ---------------------------------------------------------------------------
# CircuitBreaker
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url, domain",
    [
        ("https://API.Example.COM:8443/v1/models", "api.example.com"),
        ("https://sub.openai.azure.com/x", "sub.openai.azure.com"),
        ("garbage", ""),
        ("", ""),
    ],
)
def test_circuit_extract_domain(url, domain):
    assert CircuitBreaker._extract_domain(url) == domain


@pytest.mark.parametrize(
    "domain, protected",
    [
        ("", True),
        ("api.openai.com", True),
        ("api.anthropic.com", True),
        ("generativelanguage.googleapis.com", True),
        ("github.com", True),
        ("raw.githubusercontent.com", True),
        # суффиксное сопоставление для динамических Azure-инстансов
        ("my-resource.openai.azure.com", True),
        ("example.com", False),
        ("api.siliconflow.cn", False),
    ],
)
def test_circuit_protected_domains(domain, protected):
    assert CircuitBreaker._is_protected_domain(domain) is protected


@pytest.mark.parametrize(
    "status, network",
    [
        (502, True), (503, True), (504, True),
        (400, False), (401, False), (403, False), (404, False), (429, False),
        (418, False),  # не входит ни в один список
    ],
)
def test_circuit_network_error_by_status(status, network):
    assert CircuitBreaker._is_network_error(None, status) is network


def test_circuit_network_error_by_exception():
    assert CircuitBreaker._is_network_error(asyncio.TimeoutError(), None)
    assert CircuitBreaker._is_network_error(
        aiohttp.ServerDisconnectedError(), None)
    assert not CircuitBreaker._is_network_error(ValueError("x"), None)
    assert not CircuitBreaker._is_network_error(None, None)


def test_circuit_opens_only_at_failure_threshold():
    breaker = CircuitBreaker()
    url = "https://api.example.com/v1/models"
    domain = "api.example.com"

    async def scenario():
        for _ in range(49):
            await breaker.record_failure(url, http_status=503)
        assert await breaker.get_state(url) is CircuitState.CLOSED
        assert await breaker.is_allowed(url)
        assert breaker._domain_states[domain]["failure_count"] == 49

        await breaker.record_failure(url, http_status=503)
        assert await breaker.get_state(url) is CircuitState.OPEN
        assert not await breaker.is_allowed(url)

    asyncio.run(scenario())


def test_circuit_ignores_business_errors():
    """401/403/404/429/400 — сервер отвечает, значит связь жива."""
    breaker = CircuitBreaker()
    url = "https://api.example.com/v1/models"

    async def scenario():
        for _ in range(200):
            await breaker.record_failure(url, http_status=401)
            await breaker.record_failure(url, http_status=429)
            await breaker.record_failure(url, http_status=404)
            await breaker.record_failure(url, error=ValueError("bad"))
        assert await breaker.get_stats() == {}
        assert await breaker.get_state(url) is CircuitState.CLOSED

    asyncio.run(scenario())


def test_circuit_is_isolated_per_domain():
    breaker = CircuitBreaker()

    async def scenario():
        for _ in range(60):
            await breaker.record_failure("https://a.example.com/x",
                                         http_status=503)
        assert not await breaker.is_allowed("https://a.example.com/x")
        assert await breaker.is_allowed("https://b.example.com/x")
        assert await breaker.is_allowed("https://api.openai.com/v1/models")

    asyncio.run(scenario())


def test_circuit_half_open_after_recovery_timeout_and_probe_limit():
    breaker = CircuitBreaker()
    url = "https://api.example.com/v1"
    clock = [1000.0]
    original_time = vmod.time.time
    vmod.time.time = lambda: clock[0]
    try:
        async def scenario():
            for _ in range(50):
                await breaker.record_failure(url, http_status=503)
            assert await breaker.get_state(url) is CircuitState.OPEN

            clock[0] += 10  # меньше recovery timeout
            assert await breaker.get_state(url) is CircuitState.OPEN

            clock[0] += vmod.CIRCUIT_BREAKER_RECOVERY_TIMEOUT
            assert await breaker.get_state(url) is CircuitState.HALF_OPEN

            allowed = [await breaker.is_allowed(url)
                       for _ in range(vmod.CIRCUIT_BREAKER_HALF_OPEN_REQUESTS + 2)]
            assert allowed.count(True) == vmod.CIRCUIT_BREAKER_HALF_OPEN_REQUESTS
            assert allowed.count(False) == 2

        asyncio.run(scenario())
    finally:
        vmod.time.time = original_time


def test_circuit_half_open_failure_restarts_timer():
    breaker = CircuitBreaker()
    url = "https://api.example.com/v1"
    clock = [2000.0]
    original_time = vmod.time.time
    vmod.time.time = lambda: clock[0]
    try:
        async def scenario():
            for _ in range(50):
                await breaker.record_failure(url, http_status=503)

            clock[0] += vmod.CIRCUIT_BREAKER_RECOVERY_TIMEOUT + 1
            assert await breaker.get_state(url) is CircuitState.HALF_OPEN

            await breaker.record_failure(url, http_status=503)
            assert await breaker.get_state(url) is CircuitState.OPEN

            # Таймер перезапущен: до истечения нового окна не полуоткрывается
            clock[0] += 1
            assert await breaker.get_state(url) is CircuitState.OPEN

        asyncio.run(scenario())
    finally:
        vmod.time.time = original_time


def test_circuit_success_closes_and_resets_counter():
    breaker = CircuitBreaker()
    url = "https://api.example.com/v1"

    async def scenario():
        for _ in range(60):
            await breaker.record_failure(url, http_status=503)
        assert await breaker.get_state(url) is CircuitState.OPEN
        await breaker.record_success(url)
        stats = await breaker.get_stats()
        assert stats["api.example.com"] == {"state": "closed", "failure_count": 0}
        assert await breaker.is_allowed(url)

    asyncio.run(scenario())


def test_circuit_success_for_unknown_domain_creates_no_state():
    breaker = CircuitBreaker()

    async def scenario():
        await breaker.record_success("https://never-seen.example.com/x")
        assert await breaker.get_stats() == {}

    asyncio.run(scenario())


def test_circuit_never_records_protected_domain_failures():
    breaker = CircuitBreaker()

    async def scenario():
        for _ in range(100):
            await breaker.record_failure("https://api.openai.com/v1/models",
                                         http_status=503)
        assert await breaker.get_stats() == {}
        assert await breaker.is_allowed("https://api.openai.com/v1/models")

    asyncio.run(scenario())


def test_circuit_stats_and_reset():
    breaker = CircuitBreaker()

    async def scenario():
        await breaker.record_failure("https://a.example.com/x", http_status=502)
        await breaker.record_failure("https://a.example.com/x", http_status=502)
        stats = await breaker.get_stats()
        assert stats == {"a.example.com": {"state": "closed",
                                          "failure_count": 2}}
        breaker.reset()
        assert await breaker.get_stats() == {}

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Классификация статусов / транзитность
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "status, expected",
    [
        (200, KeyStatus.VALID),
        (201, KeyStatus.VALID),
        (204, KeyStatus.VALID),
        (300, KeyStatus.CONNECTION_ERROR),
        (302, KeyStatus.CONNECTION_ERROR),
        (400, KeyStatus.INVALID),
        (401, KeyStatus.INVALID),
        (403, KeyStatus.INVALID),
        (404, KeyStatus.INVALID),
        (422, KeyStatus.INVALID),
        (402, KeyStatus.QUOTA_EXCEEDED),
        (429, KeyStatus.QUOTA_EXCEEDED),
        (405, KeyStatus.UNVERIFIED),
        (410, KeyStatus.UNVERIFIED),
        (418, KeyStatus.UNVERIFIED),
        (451, KeyStatus.UNVERIFIED),
        (500, KeyStatus.CONNECTION_ERROR),
        (503, KeyStatus.CONNECTION_ERROR),
    ],
)
def test_classify_status(status, expected):
    assert AsyncValidator._classify_status(status) is expected


@pytest.mark.parametrize(
    "exc, status, transient",
    [
        (None, None, False),
        (None, 502, True),
        (None, 503, True),
        (None, 504, True),
        (None, 500, False),   # 500 не ретраится, хотя и CONNECTION_ERROR
        (None, 401, False),
        (None, 404, False),
        (asyncio.TimeoutError(), None, True),
        (aiohttp.ServerDisconnectedError(), None, True),
        (aiohttp.ClientPayloadError("x"), None, True),
        (ValueError("x"), None, False),
    ],
)
def test_is_transient_error(exc, status, transient):
    assert AsyncValidator._is_transient_error(exc, status) is transient


# ---------------------------------------------------------------------------
# _retry_cfg
# ---------------------------------------------------------------------------

def test_retry_cfg_reads_config(isolated_config):
    harness = Harness()
    assert harness.validator._retry_cfg() == (3, 1.5)

    isolated_config.validator_max_retries = 7
    isolated_config.validator_retry_backoff = 2.5
    assert harness.validator._retry_cfg() == (7, 2.5)


@pytest.mark.parametrize(
    "retries, backoff, expected",
    [
        (0, 0.0, (2, 0.8)),
        (None, None, (2, 0.8)),
        (5, 0.0, (5, 0.8)),
        (0, 3.0, (2, 3.0)),
    ],
)
def test_retry_cfg_fallbacks(isolated_config, retries, backoff, expected):
    isolated_config.validator_max_retries = retries
    isolated_config.validator_retry_backoff = backoff
    assert Harness().validator._retry_cfg() == expected


# ---------------------------------------------------------------------------
# _normalize_base_url / _cache / _try_url_variants
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "raw, normalized",
    [
        ("https://api.siliconflow.cn/v1/chat/completions",
         "https://api.siliconflow.cn/v1"),
        ("https://relay.com/openai/v1/models", "https://relay.com/openai/v1"),
        ("https://api.openai.com", "https://api.openai.com"),
        ("https://api.openai.com/", "https://api.openai.com"),
        ("  https://api.openai.com/v1beta  ", "https://api.openai.com/v1beta"),
        ("https://host/v2/models/embeddings", "https://host/v2"),
        ("not a url", "not a url"),
        ("ftp://x/y", "ftp://x/y"),
        ("", ""),
    ],
)
def test_normalize_base_url(raw, normalized):
    harness = Harness()
    assert harness.validator._normalize_base_url(raw) == normalized


def test_normalize_base_url_uses_cache():
    harness = Harness()
    source = "https://cached.example.com/v1/models"
    assert harness.validator._normalize_base_url(source) == \
        "https://cached.example.com/v1"
    assert vmod._NORMALIZE_CACHE[source] == "https://cached.example.com/v1"
    # повторный вызов отдаёт то же значение (кеш не ломает результат)
    assert harness.validator._normalize_base_url(source) == \
        "https://cached.example.com/v1"


def test_normalize_cache_is_lru_bounded():
    for i in range(vmod._NORMALIZE_CACHE_MAX + 5):
        vmod._cache_put(f"unit-test-{i}", f"v{i}")
    assert len(vmod._NORMALIZE_CACHE) == vmod._NORMALIZE_CACHE_MAX
    # самые старые вытеснены, свежие на месте
    assert vmod._cache_get("unit-test-0") is None
    assert vmod._cache_get(f"unit-test-{vmod._NORMALIZE_CACHE_MAX + 4}") is not None


@pytest.mark.parametrize(
    "base, path, expected",
    [
        ("https://api.openai.com/v1", "models",
         ["https://api.openai.com/v1/models",
          "https://api.openai.com/models"]),
        ("https://relay.example.com", "chat/completions",
         ["https://relay.example.com/chat/completions",
          "https://relay.example.com/v1/chat/completions"]),
        ("https://relay.example.com/v1/chat/completions", "/models",
         ["https://relay.example.com/v1/models",
          "https://relay.example.com/models"]),
    ],
)
def test_try_url_variants(base, path, expected):
    assert Harness().validator._try_url_variants(base, path) == expected


# ---------------------------------------------------------------------------
# _is_likely_valid_relay (анти-SSRF)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "url, valid",
    [
        ("not_url", False),
        ("ftp://x", False),
        ("https://api.example.com/v1", True),
        ("https://docs.python.org/3/", False),
        ("https://stackoverflow.com/q/1", False),
        ("https://pris.ly/x", False),
        ("http://127.0.0.1:8080", False),
        ("http://10.0.0.5/v1", False),
        ("http://[::1]/v1", False),
        ("http://router.local/v1", False),
        ("https://x.com/" + "a/" * 30, False),
    ],
)
def test_is_likely_valid_relay(url, valid):
    assert Harness().validator._is_likely_valid_relay(url) is valid


# ---------------------------------------------------------------------------
# Разбор rate-limit заголовков и баланса
# ---------------------------------------------------------------------------

def test_extract_rate_limits_full():
    harness = Harness()
    headers = {
        "X-RateLimit-Limit-Requests": "1000",
        "X-RateLimit-Limit-Tokens": "200000",
        "X-Concurrent-Limit": "5",
        "X-OpenAI-Tier": "tier-3",
        "X-Request-Id": "abc",
    }
    result = harness.validator._extract_rate_limits(headers)
    assert result["rpm"] == 1000
    assert result["tpd"] == 200000
    assert result["concurrency_limit"] == 5
    assert result["rate_tier"] == "tier-3"

    saved = json.loads(result["rate_headers"])
    assert saved["x-ratelimit-limit-requests"] == "1000"
    assert saved["x-openai-tier"] == "tier-3"
    assert "x-request-id" not in saved


def test_extract_rate_limits_falls_back_to_remaining():
    harness = Harness()
    result = harness.validator._extract_rate_limits({
        "X-RateLimit-Limit-Requests": "abc",
        "X-RateLimit-Remaining-Requests": "7",
    })
    assert result["rpm"] == 7
    assert result["tpd"] == 0


def test_extract_rate_limits_empty_headers():
    harness = Harness()
    result = harness.validator._extract_rate_limits(None)
    assert result == {
        "rpm": 0, "tpd": 0, "concurrency_limit": 0,
        "rate_tier": "", "rate_headers": "",
    }


@pytest.mark.parametrize(
    "data, fields, expected",
    [
        ({"data": {"quota": 500000}}, ["data.quota"], 5.0),   # one-api units
        ({"quota": 10000}, ["quota"], 10000.0),               # ровно граница
        ({"quota": 10001}, ["quota"], pytest.approx(0.10001)),
        ({"a": 0, "b": 12}, ["a", "b"], 12.0),                # 0 пропускается
        ({"a": "xx"}, ["a", "b"], 0.0),
        ({}, ["x"], 0.0),
        ({"nested": {"deep": {"v": 3}}}, ["nested.deep.v"], 3.0),
    ],
)
def test_extract_balance_from_response(data, fields, expected):
    harness = Harness()
    assert harness.validator._extract_balance_from_response(data, fields) == expected


# ---------------------------------------------------------------------------
# _check_circuit_breaker / _record_circuit_result
# ---------------------------------------------------------------------------

def test_check_circuit_breaker_disabled(isolated_config):
    isolated_config.circuit_breaker_enabled = False
    harness = Harness()

    async def scenario():
        for _ in range(60):
            await harness.validator._circuit_breaker.record_failure(
                "https://api.example.com/x", http_status=503)
        assert await harness.validator._check_circuit_breaker(
            "https://api.example.com/x") is None

    asyncio.run(scenario())


def test_check_circuit_breaker_returns_connection_error_when_open():
    harness = Harness()

    async def scenario():
        for _ in range(60):
            await harness.validator._circuit_breaker.record_failure(
                "https://api.example.com/x", http_status=503)
        result = await harness.validator._check_circuit_breaker(
            "https://api.example.com/x")
        assert result is not None
        assert result.status is KeyStatus.CONNECTION_ERROR
        assert "прерван" in result.info.lower()

    asyncio.run(scenario())


def test_check_circuit_breaker_allows_closed_domain():
    harness = Harness()

    async def scenario():
        assert await harness.validator._check_circuit_breaker(
            "https://api.example.com/x") is None
        assert await harness.validator._check_circuit_breaker(
            "https://api.openai.com/v1") is None

    asyncio.run(scenario())


def test_record_circuit_result_respects_disabled_flag(isolated_config):
    isolated_config.circuit_breaker_enabled = False
    harness = Harness()

    async def scenario():
        for _ in range(60):
            await harness.validator._record_circuit_result(
                "https://api.example.com/x", http_status=503)
        assert await harness.validator._circuit_breaker.get_stats() == {}

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# _fetch_with_retry (фейковая aiohttp-сессия)
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, status=200, headers=None, payload=None,
                 json_error=None):
        self.status = status
        self.headers = dict(headers or {})
        self._payload = payload
        self._json_error = json_error
        self.json_calls = 0

    async def json(self, content_type=None):
        self.json_calls += 1
        if self._json_error is not None:
            raise self._json_error
        return self._payload


class FakeCtx:
    def __init__(self, response=None, error=None):
        self._response = response
        self._error = error

    async def __aenter__(self):
        if self._error is not None:
            raise self._error
        return self._response

    async def __aexit__(self, *exc_info):
        return False


class FakeSession:
    def __init__(self, outcomes=()):
        self.outcomes = list(outcomes)
        self.calls = []
        self.closed = False

    def _next(self, method, url, kwargs):
        self.calls.append((method, url, kwargs))
        if not self.outcomes:
            raise _PlanExhausted(f"unexpected {method} {url}")
        item = self.outcomes.pop(0)
        if isinstance(item, BaseException):
            return FakeCtx(error=item)
        return FakeCtx(response=item)

    def get(self, url, **kwargs):
        return self._next("GET", url, kwargs)

    def post(self, url, **kwargs):
        return self._next("POST", url, kwargs)


@pytest.fixture
def sleep_log(monkeypatch):
    delays = []

    async def fake_sleep(delay):
        delays.append(delay)

    monkeypatch.setattr(asyncio, "sleep", fake_sleep)
    return delays


def make_fetch_validator(outcomes=()):
    validator = AsyncValidator.__new__(AsyncValidator)
    validator.db = MagicMock()
    validator.dashboard = None
    validator._circuit_breaker = CircuitBreaker()
    validator._session = FakeSession(outcomes)
    return validator


def test_fetch_success_returns_status_payload_rpm_headers():
    response = FakeResponse(200, {"x-ratelimit-limit-requests": "42"},
                            {"ok": True})
    validator = make_fetch_validator([response])

    result = asyncio.run(validator._fetch_with_retry(
        "GET", "https://api.example.com/v1/models", headers={"A": "b"}))

    assert result == (200, {"ok": True}, 42,
                      {"x-ratelimit-limit-requests": "42"})
    assert response.json_calls == 1
    assert len(validator._session.calls) == 1
    method, url, kwargs = validator._session.calls[0]
    assert (method, url) == ("GET", "https://api.example.com/v1/models")
    assert kwargs["headers"] == {"A": "b"}
    assert kwargs["proxy"] is None


def test_fetch_invalid_rpm_header_yields_zero():
    validator = make_fetch_validator([
        FakeResponse(200, {"x-ratelimit-limit-requests": "abc"}, {})])
    status, data, rpm, _ = asyncio.run(validator._fetch_with_retry(
        "GET", "https://api.example.com/v1/models"))
    assert (status, rpm) == (200, 0)


def test_fetch_post_sends_json_body():
    validator = make_fetch_validator([FakeResponse(200, {}, {"ok": 1})])
    body = {"model": "m", "messages": []}
    asyncio.run(validator._fetch_with_retry(
        "POST", "https://api.example.com/v1/chat/completions",
        headers={"H": "v"}, json_body=body))
    _, _, kwargs = validator._session.calls[0]
    assert kwargs["json"] == body
    assert kwargs["headers"] == {"H": "v"}


def test_fetch_retries_503_then_success(isolated_config, sleep_log):
    isolated_config.validator_retry_backoff = 1.0
    validator = make_fetch_validator([
        FakeResponse(503),
        FakeResponse(200, {}, {"ok": True}),
    ])
    status, data, _, _ = asyncio.run(validator._fetch_with_retry(
        "GET", "https://api.example.com/v1/models"))

    assert (status, data) == (200, {"ok": True})
    assert len(validator._session.calls) == 2
    assert len(sleep_log) == 1
    assert 1.0 <= sleep_log[0] < 1.5  # backoff + jitter(0..0.5*backoff)


def test_fetch_all_503_returns_last_status_and_grows_backoff(
        isolated_config, sleep_log):
    isolated_config.validator_retry_backoff = 1.0
    validator = make_fetch_validator([FakeResponse(503) for _ in range(3)])

    result = asyncio.run(validator._fetch_with_retry(
        "GET", "https://api.example.com/v1/models"))

    assert result == (503, None, 0, {})
    assert len(validator._session.calls) == 3
    assert len(sleep_log) == 2
    assert 1.0 <= sleep_log[0] < 1.5
    assert 2.0 <= sleep_log[1] < 3.0


def test_fetch_retries_after_timeout(sleep_log):
    validator = make_fetch_validator([
        asyncio.TimeoutError(),
        FakeResponse(200, {}, {"ok": 1}),
    ])
    status, data, _, _ = asyncio.run(validator._fetch_with_retry(
        "GET", "https://api.example.com/v1/models"))
    assert (status, data) == (200, {"ok": 1})
    assert len(validator._session.calls) == 2
    assert len(sleep_log) == 1


def test_fetch_retries_after_transient_client_error(sleep_log):
    validator = make_fetch_validator([
        aiohttp.ClientPayloadError("cut"),
        FakeResponse(201, {}, {}),
    ])
    status, _, _, _ = asyncio.run(validator._fetch_with_retry(
        "POST", "https://api.example.com/v1/x", json_body={"a": 1}))
    assert status == 201
    assert len(validator._session.calls) == 2


def test_fetch_non_transient_client_error_stops_immediately(sleep_log):
    class _FatalClientError(aiohttp.ClientError):
        pass

    validator = make_fetch_validator([_FatalClientError("fatal")])
    result = asyncio.run(validator._fetch_with_retry(
        "GET", "https://api.example.com/v1/models"))

    assert result == (None, None, 0, {})
    assert len(validator._session.calls) == 1
    assert sleep_log == []


def test_fetch_unexpected_exception_stops(sleep_log):
    validator = make_fetch_validator([ValueError("boom")])
    result = asyncio.run(validator._fetch_with_retry(
        "GET", "https://api.example.com/v1/models"))
    assert result == (None, None, 0, {})
    assert len(validator._session.calls) == 1
    assert sleep_log == []


def test_fetch_timeouts_exhaust_retries(isolated_config, sleep_log):
    isolated_config.validator_max_retries = 2
    isolated_config.validator_retry_backoff = 1.0
    validator = make_fetch_validator([
        asyncio.TimeoutError(), asyncio.TimeoutError()])

    result = asyncio.run(validator._fetch_with_retry(
        "GET", "https://api.example.com/v1/models"))

    assert result == (None, None, 0, {})
    assert len(validator._session.calls) == 2
    assert len(sleep_log) == 1


def test_fetch_bad_json_yields_none_payload():
    validator = make_fetch_validator([
        FakeResponse(200, {}, json_error=ValueError("bad json"))])
    status, data, _, _ = asyncio.run(validator._fetch_with_retry(
        "GET", "https://api.example.com/v1/models"))
    assert status == 200
    assert data is None


def test_fetch_parse_json_false_does_not_parse():
    response = FakeResponse(200, {}, {"ignored": True})
    validator = make_fetch_validator([response])
    status, data, _, _ = asyncio.run(validator._fetch_with_retry(
        "GET", "https://api.example.com/v1/models", parse_json=False))
    assert (status, data) == (200, None)
    assert response.json_calls == 0


def test_fetch_uses_proxy_from_config(isolated_config):
    isolated_config.proxy_url = "http://proxy.local:8080"
    validator = make_fetch_validator([FakeResponse(200, {}, {})])
    asyncio.run(validator._fetch_with_retry(
        "GET", "https://api.example.com/v1/models"))
    _, _, kwargs = validator._session.calls[0]
    assert kwargs["proxy"] == "http://proxy.local:8080"


def test_fetch_records_failures_in_circuit_breaker():
    validator = make_fetch_validator([FakeResponse(503) for _ in range(3)])

    async def scenario():
        await validator._fetch_with_retry(
            "GET", "https://api.example.com/v1/models")
        stats = await validator._circuit_breaker.get_stats()
        assert stats["api.example.com"] == {"state": "closed",
                                           "failure_count": 3}

    asyncio.run(scenario())


def test_fetch_success_closes_seeded_breaker_state():
    validator = make_fetch_validator([FakeResponse(200, {}, {})])

    async def scenario():
        for _ in range(2):
            await validator._circuit_breaker.record_failure(
                "https://api.example.com/v1/models", http_status=503)
        await validator._fetch_with_retry(
            "GET", "https://api.example.com/v1/models")
        stats = await validator._circuit_breaker.get_stats()
        assert stats["api.example.com"] == {"state": "closed",
                                           "failure_count": 0}

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# validate_openai
# ---------------------------------------------------------------------------

def test_validate_openai_rejects_private_base_url():
    harness = Harness()
    result = asyncio.run(harness.validator.validate_openai(
        "k", "http://127.0.0.1:1234/v1"))
    assert result.status is KeyStatus.INVALID
    assert "base_url" in result.info
    assert harness.calls == []


def test_validate_openai_models_success_gpt4():
    harness = Harness([(200, {"data": [{"id": "gpt-4o"},
                                       {"id": "gpt-3.5-turbo"}]}, 1000, {})])
    result = asyncio.run(harness.validator.validate_openai(
        "sk-test", "https://api.openai.com/v1"))

    assert result.status is KeyStatus.VALID
    assert result.models == ["gpt-4o", "gpt-3.5-turbo"]
    assert result.model_tier == "GPT-4"
    assert result.rpm == 1000
    assert result.is_high_value is True
    assert result.info.startswith("2 моделей")


def test_validate_openai_free_trial_tier_annotation():
    harness = Harness([(200, {"data": [{"id": "some-model"}]}, 20, {})])
    result = asyncio.run(harness.validator.validate_openai(
        "k", "https://api.openai.com/v1"))
    assert "[Free Trial]" in result.info
    assert result.model_tier == "GPT-3.5"
    assert result.is_high_value is False


def test_validate_openai_enterprise_tier_annotation():
    harness = Harness([(200, {"data": [{"id": "some-model"}]}, 3000, {})])
    result = asyncio.run(harness.validator.validate_openai(
        "k", "https://api.openai.com/v1"))
    assert "[Enterprise]" in result.info
    assert result.is_high_value is True


def test_validate_openai_models_auth_rejected():
    harness = Harness([(401, {}, 0, {})])
    result = asyncio.run(harness.validator.validate_openai(
        "k", "https://api.openai.com/v1"))
    assert result.status is KeyStatus.INVALID
    assert "auth" in result.info.lower()


def test_validate_openai_models_429_quota():
    harness = Harness([(429, {}, 0, {})])
    result = asyncio.run(harness.validator.validate_openai(
        "k", "https://api.openai.com/v1"))
    assert result.status is KeyStatus.QUOTA_EXCEEDED


def test_validate_openai_falls_back_to_chat_when_models_closed():
    harness = Harness([
        (404, {}, 0, {}), (404, {}, 0, {}),
        (200, {"choices": []}, 0, {}),
    ])
    result = asyncio.run(harness.validator.validate_openai(
        "k", "https://relay.example.com"))

    assert result.status is KeyStatus.VALID
    assert "chat" in result.info.lower()
    body = harness.posted_bodies()[0]
    assert body == {"model": "gpt-3.5-turbo",
                    "messages": [{"role": "user", "content": "Hi"}],
                    "max_tokens": 1}


def test_validate_openai_chat_401_after_models_404_keeps_valid():
    harness = Harness([
        (404, {}, 0, {}), (404, {}, 0, {}),
        (401, {}, 0, {}),
    ])
    result = asyncio.run(harness.validator.validate_openai(
        "k", "https://relay.example.com"))
    assert result.status is KeyStatus.VALID
    assert "auth ok" in result.info


def test_validate_openai_chat_400_model_error_is_valid():
    harness = Harness([
        (404, {}, 0, {}), (404, {}, 0, {}),
        (400, {"error": {"code": "model_not_found"}}, 0, {}),
    ])
    result = asyncio.run(harness.validator.validate_openai(
        "k", "https://relay.example.com"))
    assert result.status is KeyStatus.VALID
    assert "модель недоступна" in result.info


def test_validate_openai_chat_400_invalid_api_key_is_invalid():
    harness = Harness([
        (404, {}, 0, {}), (404, {}, 0, {}),
        (400, {"error": {"message": "invalid_api_key"}}, 0, {}),
    ])
    result = asyncio.run(harness.validator.validate_openai(
        "k", "https://relay.example.com"))
    assert result.status is KeyStatus.INVALID


def test_validate_openai_all_transient_is_connection_error():
    harness = Harness([(None, None, 0, {}) for _ in range(4)])
    result = asyncio.run(harness.validator.validate_openai(
        "k", "https://relay.example.com"))
    assert result.status is KeyStatus.CONNECTION_ERROR
    assert "повторных попыток" in result.info


def test_validate_openai_all_404_is_unverified():
    harness = Harness([(404, {}, 0, {}) for _ in range(4)])
    result = asyncio.run(harness.validator.validate_openai(
        "k", "https://relay.example.com"))
    assert result.status is KeyStatus.UNVERIFIED
    assert "404" in result.info


def test_validate_openai_500_is_connection_error():
    harness = Harness([(500, {}, 0, {}) for _ in range(4)])
    result = asyncio.run(harness.validator.validate_openai(
        "k", "https://relay.example.com"))
    assert result.status is KeyStatus.CONNECTION_ERROR
    assert "500" in result.info


def test_validate_openai_uses_default_base_url_when_empty():
    harness = Harness([(200, {"data": []}, 0, {})])
    result = asyncio.run(harness.validator.validate_openai("k", ""))
    assert result.status is KeyStatus.VALID
    assert harness.calls[0].url == "https://api.openai.com/v1/models"


def test_validate_openai_headers_have_bearer_and_browser_ua():
    harness = Harness([(200, {"data": []}, 0, {})])
    asyncio.run(harness.validator.validate_openai(
        "secret-key", "https://api.openai.com/v1"))
    headers = harness.calls[0].headers
    assert headers["Authorization"] == "Bearer secret-key"
    assert "Mozilla/5.0" in headers["User-Agent"]
    assert headers["Content-Type"] == "application/json"


def test_validate_openai_parses_bare_string_models():
    harness = Harness([(200, {"data": ["bare-model"]}, 0, {})])
    result = asyncio.run(harness.validator.validate_openai(
        "k", "https://api.openai.com/v1"))
    assert result.models == ["bare-model"]


def test_validate_openai_malformed_models_payload_is_empty_list():
    harness = Harness([(200, {"data": "notalist"}, 0, {})])
    result = asyncio.run(harness.validator.validate_openai(
        "k", "https://api.openai.com/v1"))
    assert result.status is KeyStatus.VALID
    assert result.models == []


def test_validate_openai_respects_open_breaker():
    harness = Harness([])

    async def scenario():
        for _ in range(60):
            await harness.validator._circuit_breaker.record_failure(
                "https://relay.example.com/v1", http_status=503)
        result = await harness.validator.validate_openai(
            "k", "https://relay.example.com/v1")
        assert result.status is KeyStatus.CONNECTION_ERROR
        assert "прерван" in result.info.lower()
        assert harness.calls == []

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# validate_anthropic
# ---------------------------------------------------------------------------

def test_validate_anthropic_success_opus():
    harness = Harness([(200, {"model": "claude-3-opus-20240229"}, 0, {})])
    result = asyncio.run(harness.validator.validate_anthropic("k", ""))

    assert result.status is KeyStatus.VALID
    assert result.model_tier == "Claude-3-Opus"
    assert result.is_high_value is True

    call = harness.calls[0]
    assert call.url == "https://api.anthropic.com/v1/messages"
    assert call.headers["x-api-key"] == "k"
    assert call.headers["anthropic-version"] == "2023-06-01"
    assert call.headers["content-type"] == "application/json"
    assert call.json_body == {
        "model": "claude-3-haiku-20240307",
        "max_tokens": 1,
        "messages": [{"role": "user", "content": "Hi"}],
    }


def test_validate_anthropic_success_haiku_is_not_high_value():
    harness = Harness([(200, {"model": "claude-3-haiku"}, 0, {})])
    result = asyncio.run(harness.validator.validate_anthropic(
        "k", "https://api.anthropic.com"))
    assert result.model_tier == "Claude-3"
    assert result.is_high_value is False


def test_validate_anthropic_200_without_model_field():
    harness = Harness([(200, {}, 0, {})])
    result = asyncio.run(harness.validator.validate_anthropic(
        "k", "https://api.anthropic.com"))
    assert result.status is KeyStatus.VALID
    assert result.model_tier == "Claude-3"


@pytest.mark.parametrize(
    "message, status, info_fragment",
    [
        ("Your credit balance is too low", KeyStatus.QUOTA_EXCEEDED, "средств"),
        ("billing issue", KeyStatus.QUOTA_EXCEEDED, "биллинг"),
        ("bad request", KeyStatus.VALID, "ошибка запроса"),
    ],
)
def test_validate_anthropic_400_variants(message, status, info_fragment):
    harness = Harness([(400, {"error": {"message": message}}, 0, {})])
    result = asyncio.run(harness.validator.validate_anthropic(
        "k", "https://api.anthropic.com"))
    assert result.status is status
    assert info_fragment in result.info


def test_validate_anthropic_401_invalid():
    harness = Harness([(401, {}, 0, {})])
    result = asyncio.run(harness.validator.validate_anthropic(
        "k", "https://api.anthropic.com"))
    assert result.status is KeyStatus.INVALID


def test_validate_anthropic_403_disabled_key_is_invalid():
    harness = Harness([(403, {"error": {"message": "key disabled"}}, 0, {})])
    result = asyncio.run(harness.validator.validate_anthropic(
        "k", "https://api.anthropic.com"))
    assert result.status is KeyStatus.INVALID
    assert "заблокирован" in result.info


def test_validate_anthropic_403_other_is_quota():
    harness = Harness([(403, {"error": {"message": "restricted"}}, 0, {})])
    result = asyncio.run(harness.validator.validate_anthropic(
        "k", "https://api.anthropic.com"))
    assert result.status is KeyStatus.QUOTA_EXCEEDED


def test_validate_anthropic_429_quota():
    harness = Harness([(429, {}, 0, {})])
    result = asyncio.run(harness.validator.validate_anthropic(
        "k", "https://api.anthropic.com"))
    assert result.status is KeyStatus.QUOTA_EXCEEDED


def test_validate_anthropic_transient_is_connection_error():
    harness = Harness([(None, None, 0, {})])
    result = asyncio.run(harness.validator.validate_anthropic(
        "k", "https://api.anthropic.com"))
    assert result.status is KeyStatus.CONNECTION_ERROR


def test_validate_anthropic_500_is_connection_error():
    harness = Harness([(500, {}, 0, {})])
    result = asyncio.run(harness.validator.validate_anthropic(
        "k", "https://api.anthropic.com"))
    assert result.status is KeyStatus.CONNECTION_ERROR
    assert "500" in result.info


# ---------------------------------------------------------------------------
# validate_gemini
# ---------------------------------------------------------------------------

def test_validate_gemini_success_with_pro():
    harness = Harness([(200, {"models": [
        {"name": "models/gemini-1.5-pro-002"},
        {"name": "models/gemini-1.5-flash"},
    ]}, 0, {})])
    result = asyncio.run(harness.validator.validate_gemini("k", ""))

    assert result.status is KeyStatus.VALID
    assert result.model_tier == "Gemini-Pro"
    assert result.is_high_value is True
    assert result.models == ["gemini-1.5-pro-002", "gemini-1.5-flash"]
    call = harness.calls[0]
    assert call.url == "https://generativelanguage.googleapis.com/v1beta/models"
    assert call.headers["x-goog-api-key"] == "k"


def test_validate_gemini_without_pro_has_low_tier():
    harness = Harness([(200, {"models": [
        {"name": "models/gemini-1.5-flash"}]}, 0, {})])
    result = asyncio.run(harness.validator.validate_gemini("k", ""))
    assert result.model_tier == "Gemini"
    assert result.is_high_value is False


def test_validate_gemini_api_key_invalid_is_invalid():
    harness = Harness([(400, {"error": {
        "message": "API key not valid. Please pass a valid API key.",
        "status": "INVALID_ARGUMENT",
        "details": [{"reason": "API_KEY_INVALID"}],
    }}, 0, {})])
    result = asyncio.run(harness.validator.validate_gemini("k", ""))
    assert result.status is KeyStatus.INVALID


def test_validate_gemini_leaked_key_is_invalid():
    harness = Harness([(400, {"error": {
        "message": "API key was reported as leaked.",
        "status": "PERMISSION_DENIED"}}, 0, {})])
    result = asyncio.run(harness.validator.validate_gemini("k", ""))
    assert result.status is KeyStatus.INVALID


def test_validate_gemini_other_400_is_unverified():
    harness = Harness([(400, {"error": {
        "message": "malformed request", "status": "INVALID_ARGUMENT"}}, 0, {})])
    result = asyncio.run(harness.validator.validate_gemini("k", ""))
    assert result.status is KeyStatus.UNVERIFIED
    assert "INVALID_ARGUMENT" in result.info


@pytest.mark.parametrize(
    "status, expected",
    [
        (401, KeyStatus.INVALID),
        (404, KeyStatus.UNVERIFIED),
        (429, KeyStatus.QUOTA_EXCEEDED),
        (500, KeyStatus.CONNECTION_ERROR),
        (503, KeyStatus.CONNECTION_ERROR),
        (418, KeyStatus.UNVERIFIED),
    ],
)
def test_validate_gemini_status_mapping(status, expected):
    harness = Harness([(status, {}, 0, {})])
    result = asyncio.run(harness.validator.validate_gemini("k", ""))
    assert result.status is expected


def test_validate_gemini_transient_is_connection_error():
    harness = Harness([(None, None, 0, {})])
    result = asyncio.run(harness.validator.validate_gemini("k", ""))
    assert result.status is KeyStatus.CONNECTION_ERROR


def test_validate_gemini_relay_base_gets_version_suffix():
    harness = Harness([(200, {"models": []}, 0, {})])
    asyncio.run(harness.validator.validate_gemini(
        "k", "https://relay.example.com"))
    assert harness.calls[0].url == "https://relay.example.com/v1beta/models"


def test_validate_gemini_keeps_existing_version_in_relay_base():
    harness = Harness([(200, {"models": []}, 0, {})])
    asyncio.run(harness.validator.validate_gemini(
        "k", "https://relay.example.com/v1beta/"))
    assert harness.calls[0].url == "https://relay.example.com/v1beta/models"


# ---------------------------------------------------------------------------
# _validate_simple_account (каталог EXTRA_PROVIDERS)
# ---------------------------------------------------------------------------

def test_simple_account_uses_catalog_apikey_header_for_elevenlabs():
    harness = Harness([(200, {}, 0, {})])
    result = asyncio.run(harness.validator._validate_simple_account(
        "secret", "", "elevenlabs"))

    assert result.status is KeyStatus.VALID
    assert result.info == "Elevenlabs действителен"
    call = harness.calls[0]
    assert call.url == "https://api.elevenlabs.io/v1/user"
    assert call.headers == {"xi-api-key": "secret"}


def test_simple_account_uses_basic_auth_for_langfuse():
    harness = Harness([(200, {}, 0, {})])
    asyncio.run(harness.validator._validate_simple_account(
        "secret", "", "langfuse"))
    call = harness.calls[0]
    expected = base64.b64encode(b"secret").decode()
    assert call.headers == {"Authorization": f"Basic {expected}"}
    assert call.url.endswith("/projects")


def test_simple_account_uses_token_auth_for_sourcegraph():
    harness = Harness([(200, {}, 0, {})])
    asyncio.run(harness.validator._validate_simple_account(
        "secret", "", "sourcegraph"))
    assert harness.calls[0].headers == {"Authorization": "Token secret"}


def test_simple_account_uses_custom_header_for_heygen():
    harness = Harness([(200, {}, 0, {})])
    asyncio.run(harness.validator._validate_simple_account(
        "secret", "", "heygen"))
    assert harness.calls[0].headers == {"X-Api-Key": "secret"}


def test_simple_account_firecrawl_uses_credit_usage_endpoint():
    harness = Harness([(200, {"success": True, "data": {}}, 0, {})])
    result = asyncio.run(harness.validator._validate_simple_account(
        "fc-secret", "", "firecrawl"))

    assert result.status is KeyStatus.VALID
    call = harness.calls[0]
    assert call.url == "https://api.firecrawl.dev/v1/team/credit-usage"
    assert call.headers == {"Authorization": "Bearer fc-secret"}


@pytest.mark.parametrize("platform", ["astra", "wordware"])
def test_simple_account_without_probe_path_is_unverified(platform):
    harness = Harness()
    result = asyncio.run(harness.validator._validate_simple_account(
        "secret", "", platform))
    assert result.status is KeyStatus.UNVERIFIED
    assert "нет проверочного эндпоинта" in result.info
    assert harness.calls == []


def test_simple_account_without_any_base_url_is_unverified():
    harness = Harness()
    result = asyncio.run(harness.validator._validate_simple_account(
        "secret", "", "unknown-platform"))
    assert result.status is KeyStatus.UNVERIFIED
    assert result.info == "Нет base_url"
    assert harness.calls == []


@pytest.mark.parametrize(
    "status, payload, expected",
    [
        (401, {}, KeyStatus.INVALID),
        (403, {}, KeyStatus.UNVERIFIED),
        (404, {}, KeyStatus.UNVERIFIED),
        (429, {}, KeyStatus.QUOTA_EXCEEDED),
        (418, {}, KeyStatus.UNVERIFIED),
        (500, {}, KeyStatus.CONNECTION_ERROR),
        (None, None, KeyStatus.CONNECTION_ERROR),
    ],
)
def test_simple_account_status_mapping(status, payload, expected):
    harness = Harness([(status, payload, 0, {})])
    result = asyncio.run(harness.validator._validate_simple_account(
        "secret", "https://api.example.com", "myplat"))
    assert result.status is expected


def test_simple_account_basic_auth_401_is_unverified():
    harness = Harness([(401, {}, 0, {})])
    result = asyncio.run(harness.validator._validate_simple_account(
        "secret", "https://api.example.com", "myplat", auth="basic"))
    assert result.status is KeyStatus.UNVERIFIED
    assert "auth неполон" in result.info


def test_simple_account_explicit_path_and_custom_header():
    harness = Harness([(200, {}, 0, {})])
    asyncio.run(harness.validator._validate_simple_account(
        "secret", "https://api.example.com", "myplat",
        auth="custom", header="X-Key", path="/me"))
    call = harness.calls[0]
    assert call.url == "https://api.example.com/me"
    assert call.headers == {"X-Key": "secret"}


# ---------------------------------------------------------------------------
# confirm_key
# ---------------------------------------------------------------------------

def _stub_math_challenge(monkeypatch, answer="42"):
    monkeypatch.setattr(vmod, "_math_challenge",
                        lambda: ("Calculate 2+40, and reply with the result only.",
                                 answer))


def test_confirm_key_without_base_url_returns_valid():
    harness = Harness()
    result = asyncio.run(harness.validator.confirm_key("k", ""))
    assert result.status is KeyStatus.VALID
    assert "нет base_url" in result.info
    assert harness.calls == []


def test_confirm_key_delegates_to_gemini(monkeypatch):
    harness = Harness()

    async def fake_confirm(api_key, base_url, models=None):
        return ValidationResult(KeyStatus.VALID, "gemini-confirm")

    harness.validator._confirm_gemini = fake_confirm
    result = asyncio.run(harness.validator.confirm_key(
        "k", "https://x.example.com", [], "gemini"))
    assert result.info == "gemini-confirm"

    # делегирование и по base_url, при пустом platform
    result = asyncio.run(harness.validator.confirm_key(
        "k", "https://generativelanguage.googleapis.com/v1beta", []))
    assert result.info == "gemini-confirm"


def test_confirm_key_delegates_to_anthropic():
    harness = Harness()

    async def fake_confirm(api_key, base_url, models=None):
        return ValidationResult(KeyStatus.VALID, "anthropic-confirm")

    harness.validator._confirm_anthropic = fake_confirm
    assert asyncio.run(harness.validator.confirm_key(
        "k", "https://api.anthropic.com", [], "anthropic")).info == \
        "anthropic-confirm"
    assert asyncio.run(harness.validator.confirm_key(
        "k", "https://api.anthropic.com/v1", [], "relay")).info == \
        "anthropic-confirm"


def test_confirm_key_confirms_model_with_correct_answer(monkeypatch):
    _stub_math_challenge(monkeypatch)
    harness = Harness([
        (200, {"data": [{"id": "gpt-4o-mini"}]}, 0, {}),
        (200, {"choices": [{"message": {"content": "42"}}]}, 0, {}),
    ])

    result = asyncio.run(harness.validator.confirm_key(
        "k", "https://relay.example.com/v1"))

    assert result.status is KeyStatus.VALID
    assert "Подтверждён" in result.info
    assert "1/1" in result.info
    assert result.models == ["gpt-4o-mini"]
    harness.validator.db.mark_models_confirmed_batch.assert_called_once_with(
        "k", ["gpt-4o-mini"])

    body = harness.posted_bodies()[0]
    assert body["model"] == "gpt-4o-mini"
    assert body["max_tokens"] == 50
    assert body["temperature"] == 0
    assert body["messages"][0]["role"] == "user"
    assert "2+40" in body["messages"][0]["content"]


def test_confirm_key_rejects_garbage_200(monkeypatch):
    _stub_math_challenge(monkeypatch)
    harness = Harness([
        (200, {"data": [{"id": "m1"}]}, 0, {}),
        (200, {"choices": [{"message": {"content": "余额不足"}}]}, 0, {}),
    ])
    result = asyncio.run(harness.validator.confirm_key(
        "k", "https://relay.example.com/v1"))

    assert result.status is KeyStatus.VALID
    assert "чат не отвечает" in result.info
    harness.validator.db.mark_models_confirmed_batch.assert_not_called()


def test_confirm_key_masked_quota_in_200_body(monkeypatch):
    _stub_math_challenge(monkeypatch)
    harness = Harness([
        (200, {"data": [{"id": "m1"}]}, 0, {}),
        (200, {"error": "quota exceeded"}, 0, {}),
    ])
    result = asyncio.run(harness.validator.confirm_key(
        "k", "https://relay.example.com/v1"))
    assert result.status is KeyStatus.QUOTA_EXCEEDED
    assert "429/402" in result.info


def test_confirm_key_all_auth_failures_invalid(monkeypatch):
    _stub_math_challenge(monkeypatch)
    harness = Harness([
        (200, {"data": [{"id": "a"}, {"id": "b"}, {"id": "c"}]}, 0, {}),
        (401, {}, 0, {}), (401, {}, 0, {}), (401, {}, 0, {}),
    ])
    result = asyncio.run(harness.validator.confirm_key(
        "k", "https://relay.example.com/v1"))
    assert result.status is KeyStatus.INVALID
    assert len(harness.posted_bodies()) == 3


def test_confirm_key_rate_limit_counts_as_quota(monkeypatch):
    _stub_math_challenge(monkeypatch)
    harness = Harness([
        (200, {"data": [{"id": "m1"}]}, 0, {}),
        (429, {}, 0, {}),
    ])
    result = asyncio.run(harness.validator.confirm_key(
        "k", "https://relay.example.com/v1"))
    assert result.status is KeyStatus.QUOTA_EXCEEDED


def test_confirm_key_ranks_models_by_priority(monkeypatch):
    _stub_math_challenge(monkeypatch, answer="42")
    harness = Harness([
        (200, {"data": [{"id": "zzz-last"}, {"id": "gpt-4o"},
                        {"id": "claude-3-5-sonnet"}]}, 0, {}),
        (200, {"choices": [{"message": {"content": "no"}}]}, 0, {}),
        (200, {"choices": [{"message": {"content": "no"}}]}, 0, {}),
        (200, {"choices": [{"message": {"content": "no"}}]}, 0, {}),
    ])
    result = asyncio.run(harness.validator.confirm_key(
        "k", "https://relay.example.com/v1"))

    assert harness.posted_models() == [
        "claude-3-5-sonnet", "gpt-4o", "zzz-last"]
    assert result.status is KeyStatus.VALID
    assert "3 моделей" in result.info


def test_confirm_key_tries_url_variants_on_404(monkeypatch):
    _stub_math_challenge(monkeypatch)
    harness = Harness([
        (404, {}, 0, {}), (404, {}, 0, {}),
        (404, {}, 0, {}),
        (200, {"choices": [{"message": {"content": "42"}}]}, 0, {}),
    ])
    result = asyncio.run(harness.validator.confirm_key(
        "k", "https://relay.example.com/v1", models=["gpt-4o"]))

    assert result.status is KeyStatus.VALID
    assert "Подтверждён" in result.info
    chat_urls = [c.url for c in harness.calls if c.method == "POST"]
    assert chat_urls == [
        "https://relay.example.com/v1/chat/completions",
        "https://relay.example.com/chat/completions",
    ]


def test_confirm_key_uses_default_model_list_when_all_sources_empty(monkeypatch):
    _stub_math_challenge(monkeypatch)
    responses = [(404, {}, 0, {}), (404, {}, 0, {})]
    responses += [(200, {"choices": [{"message": {"content": "no"}}]}, 0, {})
                  for _ in range(13)]
    harness = Harness(responses)

    result = asyncio.run(harness.validator.confirm_key(
        "k", "https://relay.example.com/v1"))

    models_used = harness.posted_models()
    assert len(models_used) == 13
    assert models_used[0] == "claude-3-5-sonnet"  # приоритет выше gpt-4o
    assert result.status is KeyStatus.VALID
    assert "13 моделей" in result.info


def test_confirm_key_models_endpoint_auth_rejected(monkeypatch):
    _stub_math_challenge(monkeypatch)
    harness = Harness([(401, {}, 0, {})])
    result = asyncio.run(harness.validator.confirm_key(
        "k", "https://relay.example.com/v1"))
    assert result.status is KeyStatus.INVALID
    assert harness.posted_bodies() == []


def test_confirm_key_models_endpoint_quota(monkeypatch):
    _stub_math_challenge(monkeypatch)
    harness = Harness([(429, {}, 0, {})])
    result = asyncio.run(harness.validator.confirm_key(
        "k", "https://relay.example.com/v1"))
    assert result.status is KeyStatus.QUOTA_EXCEEDED
    assert harness.posted_bodies() == []


# ---------------------------------------------------------------------------
# validate_single: диспетчеризация платформ
# ---------------------------------------------------------------------------

SPECIFIC_HANDLERS = [
    "validate_azure",
    "validate_gemini",
    "validate_anthropic",
    "validate_huggingface",
    "validate_groq",
    "validate_deepseek",
    "validate_cohere",
    "validate_mistral",
    "validate_together",
    "validate_replicate",
    "validate_jina",
    "validate_perplexity",
    "validate_fireworks",
    "validate_aws_access_key",
    "validate_aws_secret_key",
    "validate_steam",
    "validate_github",
    "validate_opencode_zen",
    "validate_openai",
    "validate_unverified",
]


def _stub_specific_handlers(validator):
    called = []

    def make(name):
        async def handler(api_key, base_url):
            called.append((name, api_key, base_url))
            return ValidationResult(KeyStatus.VALID, name)
        return handler

    for name in SPECIFIC_HANDLERS:
        setattr(validator, name, make(name))
    return called


def _scan_result(platform, base_url="", is_azure=False):
    return ScanResult(
        platform=platform,
        api_key="key",
        base_url=base_url,
        source_url="https://example.com/file",
        is_azure=is_azure,
    )


@pytest.mark.parametrize(
    "platform, base_url, is_azure, handler",
    [
        ("azure", "https://x.openai.azure.com", False, "validate_azure"),
        ("AZURE", "", False, "validate_azure"),
        ("relay", "https://x.openai.azure.com", True, "validate_azure"),
        ("GEMINI", "", False, "validate_gemini"),
        ("anthropic", "", False, "validate_anthropic"),
        ("huggingface", "", False, "validate_huggingface"),
        ("groq", "", False, "validate_groq"),
        ("deepseek", "", False, "validate_deepseek"),
        ("cohere", "", False, "validate_cohere"),
        ("mistral", "", False, "validate_mistral"),
        ("together", "", False, "validate_together"),
        ("replicate", "", False, "validate_replicate"),
        ("jina", "", False, "validate_jina"),
        ("perplexity", "", False, "validate_perplexity"),
        ("fireworks", "", False, "validate_fireworks"),
        ("aws_access_key", "", False, "validate_aws_access_key"),
        ("aws_secret_key", "", False, "validate_aws_secret_key"),
        ("steam", "", False, "validate_steam"),
        ("github", "", False, "validate_github"),
        ("openai", "", False, "validate_openai"),
        ("xai", "", False, "validate_openai"),
        ("openrouter", "", False, "validate_openai"),
        ("digitalocean", "", False, "validate_unverified"),
        ("figma_token", "", False, "validate_unverified"),
        ("unknown-platform", "https://relay.example.com", False,
         "validate_openai"),
        ("unknown-platform", "", False, "validate_unverified"),
        ("relay", "https://opencode.ai/zen/v1", False,
         "validate_opencode_zen"),
        ("opencode_zen", "", False, "validate_opencode_zen"),
    ],
)
def test_validate_single_dispatch(platform, base_url, is_azure, handler):
    harness = Harness()
    called = _stub_specific_handlers(harness.validator)

    result = asyncio.run(harness.validator.validate_single(
        _scan_result(platform, base_url, is_azure)))

    assert [c[0] for c in called] == [handler]
    assert called[0][1:] == ("key", base_url)
    assert result.info == handler


def test_validate_single_routes_extra_providers_through_catalog():
    harness = Harness()
    calls = []

    async def fake_simple(api_key, base_url, platform, auth="bearer",
                          header="", path="/user"):
        calls.append((api_key, base_url, platform, auth, header, path))
        return ValidationResult(KeyStatus.VALID, "extra")

    harness.validator._validate_simple_account = fake_simple

    result = asyncio.run(harness.validator.validate_single(
        _scan_result("elevenlabs")))

    assert result.info == "extra"
    meta = EXTRA_PROVIDERS["elevenlabs"]
    assert calls == [("key", "", "elevenlabs", meta["auth"], meta["header"],
                      meta["path"])]


def test_validate_single_unknown_extra_provider_falls_back_to_unverified():
    harness = Harness()
    harness.validator.validate_unverified = _make_unverified()

    result = asyncio.run(harness.validator.validate_single(
        _scan_result("not-in-catalog")))
    assert result.status is KeyStatus.UNVERIFIED


def _make_unverified():
    async def handler(api_key, base_url):
        return ValidationResult(KeyStatus.UNVERIFIED, "unverified")
    return handler


def test_validate_single_confirmed_end_to_end_without_network(monkeypatch):
    """Полный путь unknown-platform → validate_openai → сети нет."""
    isolated = Harness([(200, {"data": [{"id": "gpt-4o"}]}, 0, {})])
    result = asyncio.run(isolated.validator.validate_single(
        _scan_result("custom-relay", "https://relay.example.com/v1")))

    assert result.status is KeyStatus.VALID
    assert result.models == ["gpt-4o"]
    assert isolated.calls[0].url == "https://relay.example.com/v1/models"


# ---------------------------------------------------------------------------
# Регрессия: _last_headers (org/tier для _probe_openai_billing)
# ---------------------------------------------------------------------------

def test_async_validator_initializes_last_headers():
    """`_last_headers` читался в _probe_openai_billing, но не инициализировался:
    AttributeError глотался в _save_key_metadata, и метаданные ключа
    (tpd / concurrency_limit / balance_usd / org_plan) молча не сохранялись."""
    v = AsyncValidator(db=MagicMock())
    assert v._last_headers == {}


def test_validate_openai_records_response_headers():
    """Заголовки успешного /models должны попадать в _last_headers."""
    harness = Harness([(200, {"data": [{"id": "gpt-4o"}]}, 0,
                         {"x-openai-organization": "org-abc", "x-ratelimit-limit-requests": "500"})])
    asyncio.run(harness.validator.validate_openai("sk-valid", "https://api.openai.com/v1"))
    assert harness.validator._last_headers.get("x-openai-organization") == "org-abc"


def test_validate_openai_records_chat_fallback_headers():
    """Fallback на chat/completions тоже должен обновлять _last_headers."""
    harness = Harness([
        (404, {"error": "not found"}, 0, {"x-last": "models"}),
        (200, {"choices": [{"message": {"content": "hi"}}]}, 0,
         {"x-openai-tier": "tier-3"}),
    ])
    asyncio.run(harness.validator.validate_openai("sk-valid", "https://relay.example/v1"))
    assert harness.validator._last_headers.get("x-openai-tier") == "tier-3"
