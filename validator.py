"""
Модуль валидатора - Асинхронная проверка API Key + глубокая оценка стоимости

Основные функции:
1. AsyncIO + aiohttp высокопроизводительная проверка (100 одновременных запросов)
2. Глубокая оценка стоимости (определение GPT-4, проверка баланса, анализ RPM)
3. Детализация состояний (valid, invalid, quota_exceeded, connection_error)
4. Интеграция с UI-панелью

Оптимизация v2.1:
- Экспорт OptimizedAsyncValidator (использование пула соединений и интеллектуальных повторных попыток)
- Сохранение обратной совместимости с исходным AsyncValidator
"""

import asyncio
import json
import ssl
import re
from typing import Tuple, Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass

import aiohttp
from aiohttp import ClientTimeout, TCPConnector
from loguru import logger

from config import (
    config,
    PROTECTED_DOMAINS,
    SAFE_HTTP_STATUS_CODES,
    CIRCUIT_BREAKER_HTTP_CODES,
    CIRCUIT_BREAKER_FAILURE_THRESHOLD,
    CIRCUIT_BREAKER_RECOVERY_TIMEOUT,
    CIRCUIT_BREAKER_HALF_OPEN_REQUESTS
)
# Модуль config целиком — для доступа к EXTRA_PROVIDERS / REGEX_PATTERNS
# (config-экземпляр dataclass выше перекрывает имя, поэтому отдельный алиас).
from config import EXTRA_PROVIDERS as _EXTRA_PROVIDERS
from database import Database, LeakedKey, KeyStatus


# ============================================================================
#                              Константы и конфигурация
# ============================================================================

# Максимальное количество одновременных запросов
MAX_CONCURRENCY = 100

# Тайм-аут запроса (config.request_timeout может переопределить)
_req_timeout_total = getattr(config, 'request_timeout', 15) or 15
REQUEST_TIMEOUT = ClientTimeout(total=_req_timeout_total, connect=10)

# Список высокостоимостных моделей
HIGH_VALUE_MODELS = ['gpt-4', 'gpt-4-turbo', 'gpt-4o', 'gpt-4-32k', 'claude-3-opus']

# Пороговые значения RPM
RPM_ENTERPRISE_THRESHOLD = 3000   # >= 3000 - корпоративный уровень
RPM_FREE_TRIAL_THRESHOLD = 20     # <= 20 - бесплатный пробный период


# ============================================================================
#                     Прерыватель цепи (Circuit Breaker) - защита от ложных срабатываний
# ============================================================================

from enum import Enum
from urllib.parse import urlparse
import time
import threading
import random
from collections import OrderedDict


def _math_challenge() -> tuple:
    """Генерирует арифметическую задачу и ожидаемый ответ.

    Случайные большие числа → провайдер не может захардкодить ответ, и мусорные
    ответы (китайские «余额不足»/квота, заглушки) не совпадут с результатом.
    Возвращает (prompt_text, answer_str).
    """
    a = random.randint(10000, 99999)
    b = random.randint(10000, 99999)
    answer = str(a + b)
    prompt = (f"Calculate {a}+{b}, and reply with the result only.")
    return prompt, answer


def _content_has_answer(content: str, answer: str) -> bool:
    """Проверить, что ответ содержит правильную сумму (строго).

    Отсекает мусор: китайские сообщения о квоте, заглушки, ошибки — они не
    содержат правильное число. Учитывает форматирование (пробелы/запятые).
    """
    if not content:
        return False
    # Очистка: убрать пробелы/неразрывные/разделители тысяч
    cleaned = re.sub(r"[\s  ,']", "", str(content))
    # Матч с границами числа: ответ-сумма не должен быть подстрокой
    # более длинного числа (180245 содержит 80245 → ложный CONFIRMED).
    return bool(re.search(r'(?<!\d)' + re.escape(answer) + r'(?!\d)', cleaned))


# Модульный кеш нормализации base_url (чистая функция, потокобезопасен через GIL
# для dict-операций). Ограничен LRU-политикой (4096), чтобы на длинных прогонах
# по произвольным URL не расти без памяти.
_NORMALIZE_CACHE_MAX = 4096
_NORMALIZE_CACHE: "OrderedDict[str, str]" = OrderedDict()


def _cache_get(key: str):
    val = _NORMALIZE_CACHE.get(key)
    if val is not None:
        _NORMALIZE_CACHE.move_to_end(key)
    return val


def _cache_put(key: str, val: str) -> None:
    _NORMALIZE_CACHE[key] = val
    _NORMALIZE_CACHE.move_to_end(key)
    while len(_NORMALIZE_CACHE) > _NORMALIZE_CACHE_MAX:
        _NORMALIZE_CACHE.popitem(last=False)


class CircuitState(Enum):
    """Состояние прерывателя цепи"""
    CLOSED = "closed"        # Нормальный режим, запросы разрешены
    OPEN = "open"            # Прерывание, запросы отклоняются
    HALF_OPEN = "half_open"  # Полуоткрытый режим, разрешены тестовые запросы


class CircuitBreaker:
    """
    Прерыватель цепи для доменов - с защитой от ложных срабатываний
    
    Основная логика безопасности:
    1. Белый список защищенных доменов - никогда не прерывать
    2. Строгая классификация ошибок - только ошибки уровня соединения активируют прерыватель
    """
    
    def __init__(self):
        # Домен -> информация о состоянии
        self._domain_states: Dict[str, dict] = {}
        self._lock = threading.Lock()  # Потокобезопасность
    
    @staticmethod
    def _extract_domain(url: str) -> str:
        """Извлечь домен из URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower().split(':')[0]  # Удалить номер порта
        except Exception:
            return ""
    
    @staticmethod
    def _is_protected_domain(domain: str) -> bool:
        """
        Проверить, защищен ли домен
        
        Поддерживает суффиксное сопоставление, например my-resource.openai.azure.com совпадет с openai.azure.com
        """
        if not domain:
            return True  # Пустой домен по умолчанию защищен
        
        # Точное совпадение
        if domain in PROTECTED_DOMAINS:
            return True
        
        # Суффиксное сопоставление (для динамических поддоменов Azure и т.д.)
        for protected in PROTECTED_DOMAINS:
            if domain.endswith('.' + protected) or domain.endswith(protected):
                return True
        
        return False
    
    @staticmethod
    def _is_network_error(error: Exception = None, http_status: int = None) -> bool:
        """
        Определить, является ли ошибкой уровня сети (должна активировать прерыватель)
        
        Ошибки уровня сети:
        - Отказ в соединении / ошибка DNS (ClientConnectorError)
        - Тайм-аут (TimeoutError)
        - Ошибка шлюза 502/503/504
        
        Ошибки уровня приложения (не активируют прерыватель):
        - 401/403/429 и другие бизнес-ошибки
        """
        # Проверить тип исключения
        if error is not None:
            if isinstance(error, (aiohttp.ClientConnectorError, asyncio.TimeoutError)):
                return True
            # ServerDisconnectedError и другие также считаются ошибками сети
            if isinstance(error, aiohttp.ServerDisconnectedError):
                return True
        
        # Проверить HTTP-статус код
        if http_status is not None:
            if http_status in CIRCUIT_BREAKER_HTTP_CODES:
                return True
            # Ошибки уровня приложения не активируют прерыватель
            if http_status in SAFE_HTTP_STATUS_CODES:
                return False
        
        return False
    
    async def get_state(self, url: str) -> CircuitState:
        """Получить состояние прерывателя цепи для домена"""
        domain = self._extract_domain(url)
        
        # Защищенные домены всегда возвращают CLOSED
        if self._is_protected_domain(domain):
            return CircuitState.CLOSED
        
        with self._lock:
            if domain not in self._domain_states:
                return CircuitState.CLOSED
            
            state_info = self._domain_states[domain]
            current_state = state_info.get('state', CircuitState.CLOSED)
            
            # Проверить, следует ли перейти из OPEN в HALF_OPEN
            if current_state == CircuitState.OPEN:
                open_time = state_info.get('open_time', 0)
                if time.time() - open_time >= CIRCUIT_BREAKER_RECOVERY_TIMEOUT:
                    state_info['state'] = CircuitState.HALF_OPEN
                    state_info['half_open_requests'] = 0
                    return CircuitState.HALF_OPEN
            
            return current_state
    
    async def is_allowed(self, url: str) -> bool:
        """Проверить, разрешен ли запрос"""
        state = await self.get_state(url)
        
        if state == CircuitState.CLOSED:
            return True
        elif state == CircuitState.OPEN:
            return False
        else:  # HALF_OPEN
            domain = self._extract_domain(url)
            with self._lock:
                state_info = self._domain_states.get(domain, {})
                half_open_requests = state_info.get('half_open_requests', 0)
                if half_open_requests < CIRCUIT_BREAKER_HALF_OPEN_REQUESTS:
                    state_info['half_open_requests'] = half_open_requests + 1
                    return True
                return False
    
    async def record_success(self, url: str):
        """Записать успешный запрос"""
        domain = self._extract_domain(url)
        
        if self._is_protected_domain(domain):
            return
        
        with self._lock:
            if domain in self._domain_states:
                # Сбросить состояние после успеха
                self._domain_states[domain] = {
                    'state': CircuitState.CLOSED,
                    'failure_count': 0
                }
    
    async def record_failure(
        self, 
        url: str, 
        error: Exception = None, 
        http_status: int = None
    ):
        """
        Записать неудачный запрос - с защитой от ложных срабатываний
        
        Args:
            url: URL запроса
            error: Объект исключения
            http_status: HTTP статус код
        """
        domain = self._extract_domain(url)
        
        # ========== Проверка безопасности 1: Защищенные домены ==========
        if self._is_protected_domain(domain):
            return  # Игнорировать, не записывать неудачу
        
        # ========== Проверка безопасности 2: Ошибки уровня приложения ==========
        if not self._is_network_error(error, http_status):
            return  # Бизнес-ошибки не активируют прерыватель
        
        # ========== Запись ошибок уровня сети ==========
        with self._lock:
            if domain not in self._domain_states:
                self._domain_states[domain] = {
                    'state': CircuitState.CLOSED,
                    'failure_count': 0
                }
            
            state_info = self._domain_states[domain]
            state_info['failure_count'] = state_info.get('failure_count', 0) + 1
            
            # Проверить, активировался ли прерыватель
            if state_info['failure_count'] >= CIRCUIT_BREAKER_FAILURE_THRESHOLD:
                state_info['state'] = CircuitState.OPEN
                state_info['open_time'] = time.time()
    
    async def get_stats(self) -> Dict[str, Any]:
        """Получить статистику прерывателя цепи"""
        with self._lock:
            stats = {}
            for domain, info in self._domain_states.items():
                stats[domain] = {
                    'state': info.get('state', CircuitState.CLOSED).value,
                    'failure_count': info.get('failure_count', 0)
                }
            return stats

    def reset(self):
        """Сбросить все состояния доменов (для повторной валидации)"""
        with self._lock:
            self._domain_states.clear()


# Глобальный экземпляр прерывателя цепи
circuit_breaker = CircuitBreaker()


def mask_key(key: str) -> str:
    """Маскировать среднюю часть API Key"""
    if len(key) <= 12:
        return key[:4] + "..." + key[-4:]
    return key[:8] + "..." + key[-4:]


@dataclass
class ValidationResult:
    """Класс данных результата валидации"""
    status: KeyStatus
    info: str
    model_tier: str = ""
    rpm: int = 0
    balance_usd: float = 0.0
    is_high_value: bool = False
    models: list = None  # список идентификаторов моделей из /models

    def __post_init__(self):
        if self.models is None:
            self.models = []


class AsyncValidator:
    """Асинхронный валидатор API Key - с интеграцией прерывателя цепи"""
    
    def __init__(self, db: Database, dashboard=None):
        self.db = db
        self.dashboard = dashboard
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
        self._session: Optional[aiohttp.ClientSession] = None
        self._circuit_breaker = circuit_breaker  # Использовать глобальный прерыватель
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Получить или создать aiohttp сессию"""
        if self._session is None or self._session.closed:
            # Настроить прокси
            # ThreadedResolver — использует системный DNS резолвер в потоке,
            # исправляет ClientConnectorDNSError на Windows
            connector = TCPConnector(
                limit=MAX_CONCURRENCY,
                limit_per_host=50,
                ssl=ssl.create_default_context(),
                force_close=False,
                use_dns_cache=True,
                ttl_dns_cache=600,
                keepalive_timeout=60,
                enable_cleanup_closed=True,
                resolver=aiohttp.resolver.ThreadedResolver(),
            )
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=REQUEST_TIMEOUT,
                trust_env=True  # Поддержка прокси из переменных окружения
            )
        return self._session
    
    async def close(self):
        """Закрыть сессию"""
        if self._session and not self._session.closed:
            await self._session.close()
    
    def _get_proxy(self) -> Optional[str]:
        """Получить URL прокси"""
        return config.proxy_url if config.proxy_url else None
    
    def _log(self, message: str, level: str = "INFO"):
        """Вывести лог"""
        if self.dashboard:
            self.dashboard.add_log(message, level)
    
    def _normalize_base_url(self, base_url: str) -> str:
        """
        Привести base_url к API-корню, отбросив хвостовые сегменты эндпоинтов.

        Функция чистая от входной строки — результат кешируется в модульный
        dict _NORMALIZE_CACHE: на горячем gemini-дрейне один и тот же base_url
        (generativelanguage.googleapis.com/v1beta) нормализуется тысячи раз.
        См. _normalize_base_url_uncached для фактических правил/примеров.
        """
        if not base_url:
            return base_url
        cached = _cache_get(base_url)
        if cached is not None:
            return cached
        result = self._normalize_base_url_uncached(base_url)
        _cache_put(base_url, result)
        return result

    def _normalize_base_url_uncached(self, base_url: str) -> str:
        """
        Привести base_url к API-корню, отбросив хвостовые сегменты эндпоинтов.

        Сканер извлекает URL «по соседству с ключом», поэтому base_url часто
        содержит полный путь вызова, например:
            https://api.siliconflow.cn/v1/chat/completions
        Если такой URL напрямую склеить с /models, получится мусорный адрес
        …/v1/chat/completions/models, и валидация заведомо провалится.

        Правила:
          1. Оставить scheme://host[:port].
          2. Из пути удалить известные суффиксы эндпоинтов
             (chat/completions, completions, embeddings, models, messages…).
          3. Сохранить префикс версии (v1, v1beta, openai/v1 и т.п.),
             отбросив всё после него.
        Примеры:
          https://api.siliconflow.cn/v1/chat/completions
            -> https://api.siliconflow.cn/v1
          https://relay.com/openai/v1/models -> https://relay.com/openai/v1
          https://api.openai.com             -> https://api.openai.com
        """
        if not base_url:
            return base_url
        from urllib.parse import urlparse

        try:
            parsed = urlparse(base_url.strip())
        except ValueError:
            return base_url
        if not parsed.scheme or not parsed.netloc:
            return base_url

        host = f"{parsed.scheme}://{parsed.netloc}"
        segments = [s for s in parsed.path.split('/') if s]

        # Известные имена сегментов эндпоинтов (OpenAI-совместимые + Gemini)
        ENDPOINT_SEGMENTS = {
            'chat', 'completions', 'embeddings', 'models', 'messages',
            'audio', 'transcriptions', 'translations', 'images',
            'generations', 'files', 'fine_tunes', 'fine-tunes',
            'moderations', 'responses', 'edits', 'invitations',
        }
        # 1. Удалить хвостовые сегменты-эндпоинты
        while segments and segments[-1] in ENDPOINT_SEGMENTS:
            segments.pop()

        # 2. Найти сегмент-версию (v1, v1beta, v2, v1openai …) и обрезать после него
        import re as _re
        cut = None
        for idx, seg in enumerate(segments):
            if _re.fullmatch(r'v\d\w*', seg, _re.IGNORECASE):
                cut = idx + 1
                break
        if cut is not None:
            segments = segments[:cut]

        if segments:
            return host + '/' + '/'.join(segments)
        return host

    def _is_likely_valid_relay(self, url: str) -> bool:
        """Проверить, что URL может быть API-эндпоинтом + защита от SSRF.

        Проверки:
        1. Исключить documentation/settings/guide pages
        2. Заблокировать частные IP (RFC1918, loopback, link-local)
        3. Заблокировать опасные суффиксы (.local/.internal/.corp)
        4. Черный список documentation доменов
        """
        if not url or not url.startswith('http'):
            return False
        url_lower = url.lower()
        # Документация/settings
        doc_indicators = ['docs', 'settings', 'guide', 'tutorial', 'help',
                          '/ref/', '/docs/', '/guide']
        if any(ind in url_lower for ind in doc_indicators):
            return False
        # Черный список documentation доменов
        invalid_domains = [
            'docs.djangoproject.com', 'docs.python.org',
            'developer.mozilla.org', 'stackoverflow.com',
            'themoviedb.org', 'prisma.io', 'pris.ly',
            'every.to', 'makersuite.google.com',
        ]
        for inv in invalid_domains:
            if inv in url_lower:
                return False
        # SSRF: блокировка частных IP и локальных суффиксов
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ''
            import ipaddress
            try:
                ip = ipaddress.ip_address(host)
                if (ip.is_private or ip.is_loopback
                        or ip.is_link_local or ip.is_reserved):
                    return False
            except ValueError:
                pass
            for suffix in ('.local', '.internal', '.corp', '.lan', '.home'):
                if host.endswith(suffix):
                    return False
            path = parsed.path.strip('/')
            if path and '/' in path and len(path) > 40:
                return False
        except Exception:
            pass
        return True

    def _try_url_variants(self, base_url: str, path: str) -> list:
        """
        Сгенерировать варианты URL для эндпоинта.

        Сначала base_url нормализуется к API-корню (см. _normalize_base_url),
        затем перебираются варианты с/без префикса /v1, чтобы попасть в
        правильный эндпоинт независимо от того, как именно был записан URL
        в исходном коде.
        """
        base = self._normalize_base_url(base_url).rstrip('/')
        path = path.lstrip('/')

        variants = [f"{base}/{path}"]

        # Если в нормализованном URL нет /v1 — попробовать с /v1
        if '/v1' not in base:
            variants.append(f"{base}/v1/{path}")

        # Если /v1 есть — попробовать и без него (некоторые реле держат модели
        # прямо в корне), но аккуратно: вырезаем только суффикс /v1 из пути
        if base.endswith('/v1'):
            variants.append(f"{base[:-3].rstrip('/')}/{path}")

        # Дедупликация с сохранением порядка
        seen = set()
        uniq = []
        for v in variants:
            if v not in seen:
                seen.add(v)
                uniq.append(v)
        return uniq
    
    # ========================================================================
    #                           Методы интеграции прерывателя цепи
    # ========================================================================
    
    async def _check_circuit_breaker(self, base_url: str) -> Optional[ValidationResult]:
        """
        Проверить состояние прерывателя цепи
        
        Returns:
            Если прерыватель активен, возвращает результат CONNECTION_ERROR; иначе None
        """
        if not config.circuit_breaker_enabled:
            return None
        
        if not await self._circuit_breaker.is_allowed(base_url):
            self._log(f"Прерывание: {base_url[:30]}...", "WARN")
            return ValidationResult(KeyStatus.CONNECTION_ERROR, "Домен прерван")
        
        return None
    
    async def _record_circuit_result(
        self, 
        url: str, 
        success: bool = False, 
        error: Exception = None,
        http_status: int = None
    ):
        """Записать результат запроса в прерыватель"""
        if not config.circuit_breaker_enabled:
            return
        
        if success:
            await self._circuit_breaker.record_success(url)
        else:
            await self._circuit_breaker.record_failure(url, error, http_status)

    # ========================================================================
    #           Универсальный HTTP-запрос с повторными попытками (retry)
    # ========================================================================
    # Ранее один тайм-аут/ошибка соединения навсегда помечали ключ как
    # connection_error. Теперь транзитные ошибки (тайм-аут, обрыв соединения,
    # 502/503/504) повторяются с экспоненциальным backoff, и лишь после
    # исчерпания попыток ключ считается connection_error.

    def _retry_cfg(self) -> Tuple[int, float]:
        # Config-driven: validator_max_retries (default 3), validator_retry_backoff (default 1.5)
        # Hardcoded fallback (2, 0.8) если config не задан
        retries = getattr(config, 'validator_max_retries', None) or 2
        backoff = getattr(config, 'validator_retry_backoff', None) or 0.8
        return (retries, backoff)

    @staticmethod
    def _is_transient_error(exc: Optional[Exception],
                            status: Optional[int]) -> bool:
        """Транзитная ошибка = стоит повторить (сеть/тайм-аут/шлюз)."""
        if status is not None:
            if status in (502, 503, 504):
                return True
            return False
        if exc is None:
            return False
        # Тайм-ауты и обрывы соединения — транзитные
        if isinstance(exc, (asyncio.TimeoutError,)):
            return True
        name = type(exc).__name__
        transient = ("Timeout", "ConnectorError", "ClientConnectorError",
                     "ClientOSError", "ClientPayloadError", "ServerDisconnectedError",
                     "ConnectionError", "OSError")
        return any(t in name for t in transient)

    @staticmethod
    def _classify_status(status: int) -> KeyStatus:
        """Сопоставить HTTP-код со статусом ключа.

        200 → VALID, 401/403 → INVALID (отказ auth — ключ отвергнут),
        429/402 → QUOTA/оплата, 5xx/3xx → CONNECTION_ERROR (транзитная),
        405/410 → UNVERIFIED (endpoint ответил, но метод/ресурс недоступен),
        400/404/422 → INVALID (бизнес-ошибка по умолчанию; валидаторы
        могут переопределить на UNVERIFIED, если контекст не подтверждает
        невалидность ключа), прочие → UNVERIFIED (безопаснее, чем INVALID).
        """
        if 200 <= status < 300:
            return KeyStatus.VALID
        if status in (401, 403):
            return KeyStatus.INVALID
        if status in (429, 402):
            return KeyStatus.QUOTA_EXCEEDED
        if status >= 500 or 300 <= status < 400:
            return KeyStatus.CONNECTION_ERROR
        if status in (405, 410):
            return KeyStatus.UNVERIFIED
        if status in (400, 404, 422):
            return KeyStatus.INVALID
        return KeyStatus.UNVERIFIED

    async def _fetch_with_retry(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        parse_json: bool = True,
    ) -> Tuple[Optional[int], Any, int, Dict]:
        """
        Выполнить HTTP-запрос с повторными попытками.

        Returns:
            (status_code, json_data, rpm, headers) — при успехе.
            (None, None, 0, {}) — если все попытки провалились транзитной ошибкой.
        """
        retries, backoff = self._retry_cfg()
        proxy = self._get_proxy()
        session = await self._get_session()
        last_exc: Optional[Exception] = None

        for attempt in range(retries):
            try:
                if method.upper() == "GET":
                    ctx = session.get(url, headers=headers, proxy=proxy)
                else:
                    ctx = session.post(url, headers=headers,
                                       json=json_body, proxy=proxy)
                async with ctx as resp:
                    status = resp.status
                    rpm = 0
                    try:
                        rpm = int(resp.headers.get('x-ratelimit-limit-requests', 0))
                    except (ValueError, TypeError):
                        rpm = 0
                    # Транзитный статус шлюза → повторить
                    if status in (502, 503, 504) and attempt < retries - 1:
                        await self._record_circuit_result(url, http_status=status)
                        delay = backoff * (2 ** attempt) + random.uniform(0, backoff * 0.5)
                        await asyncio.sleep(delay)
                        continue
                    data = None
                    if parse_json:
                        try:
                            data = await resp.json(content_type=None)
                        except Exception:
                            data = None
                    # Записать результат в прерыватель цепи
                    if status < 500:
                        await self._record_circuit_result(
                            url, success=(200 <= status < 400), http_status=status)
                    else:
                        await self._record_circuit_result(url, http_status=status)
                    return status, data, rpm, dict(resp.headers)
            except asyncio.TimeoutError as e:
                last_exc = e
                await self._record_circuit_result(url, error=e)
                if attempt < retries - 1:
                    delay = backoff * (2 ** attempt) + random.uniform(0, backoff * 0.5)
                    await asyncio.sleep(delay)
                    continue
            except aiohttp.ClientConnectorError as e:
                last_exc = e
                await self._record_circuit_result(url, error=e)
                if attempt < retries - 1:
                    delay = backoff * (2 ** attempt) + random.uniform(0, backoff * 0.5)
                    await asyncio.sleep(delay)
                    continue
            except aiohttp.ClientError as e:
                last_exc = e
                # Прочие клиентские ошибки — транзитные, повторить
                if self._is_transient_error(e, None) and attempt < retries - 1:
                    await self._record_circuit_result(url, error=e)
                    delay = backoff * (2 ** attempt) + random.uniform(0, backoff * 0.5)
                    await asyncio.sleep(delay)
                    continue
                logger.debug(f"HTTP ошибка ({type(e).__name__}): {e}")
                break
            except Exception as e:
                last_exc = e
                logger.debug(f"Неожиданная ошибка запроса: {type(e).__name__}: {e}")
                break

        # Все попытки исчерпаны транзитной ошибкой
        if last_exc:
            await self._record_circuit_result(url, error=last_exc)
        return None, None, 0, {}

    # ---------- rate-limit / billing / org metadata ----------

    def _extract_rate_limits(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Извлечь rate-limit данные из HTTP headers."""
        result: Dict[str, Any] = {
            "rpm": 0, "tpd": 0, "concurrency_limit": 0,
            "rate_tier": "", "rate_headers": "",
        }
        # Нормализуем ключи headers в lowercase
        hl = {k.lower(): v for k, v in headers.items()} if headers else {}

        # RPM (requests per minute) — ищем по множеству вариантов
        rpm_keys = [
            "x-ratelimit-limit-requests", "x-ratelimit-limit",
            "x-ratelimit-limit-minute", "ratelimit-limit-requests",
            "ratelimit-limit", "x-ratelimit-requests-limit",
            "x-rl-limit-requests", "x-quota-limit",
        ]
        for key in rpm_keys:
            if key in hl:
                try:
                    result["rpm"] = int(hl[key])
                except (ValueError, TypeError):
                    pass
                break

        # TPD (tokens per day) / TPM (tokens per minute)
        tpd_keys = [
            "x-ratelimit-limit-tokens", "x-ratelimit-limit-tokens-day",
            "x-ratelimit-limit-token", "ratelimit-limit-tokens",
            "ratelimit-limit-token", "x-ratelimit-tokens-limit",
            "x-rl-limit-tokens", "x-quota-tokens",
        ]
        for key in tpd_keys:
            if key in hl:
                try:
                    result["tpd"] = int(hl[key])
                except (ValueError, TypeError):
                    pass
                break

        # Concurrency / parallel requests
        conc_keys = [
            "x-ratelimit-limit-concurrent", "x-concurrent-limit",
            "x-ratelimit-limit-parallel", "x-parallel-limit",
            "x-ratelimit-concurrent", "x-concurrency-limit",
        ]
        for key in conc_keys:
            if key in hl:
                try:
                    result["concurrency_limit"] = int(hl[key])
                except (ValueError, TypeError):
                    pass
                break

        # Rate tier
        tier_keys = [
            "x-openai-tier", "x-rate-tier", "x-ratelimit-tier",
            "x-openai-ratelist-tier", "x-tier", "x-plan-tier",
        ]
        for key in tier_keys:
            if key in hl:
                result["rate_tier"] = str(hl[key])
                break

        # Сохранить все rate-limit headers как JSON
        rate_headers = {k: v for k, v in hl.items()
                        if "ratelimit" in k or "rate-limit" in k
                        or "tier" in k or "limit" in k or "quota" in k
                        or "remaining" in k or "reset" in k}
        if rate_headers:
            result["rate_headers"] = json.dumps(rate_headers, ensure_ascii=False)

        # Если нет limit, но есть remaining — используем remaining как оценку
        if not result["rpm"]:
            for key in ("x-ratelimit-remaining-requests", "ratelimit-remaining",
                         "x-ratelimit-remaining"):
                if key in hl:
                    try:
                        result["rpm"] = int(hl[key])
                    except (ValueError, TypeError):
                        pass
                    break

        return result

    async def _probe_openai_billing(self, api_key: str, base_url: str) -> Dict[str, Any]:
        """Получить баланс и org plan для OpenAI ключа.

        Returns:
            {"balance_usd": float, "org_plan": str}
        """
        result: Dict[str, Any] = {"balance_usd": -1, "org_plan": ""}
        headers = {"Authorization": f"Bearer {api_key}"}
        session = await self._get_session()
        proxy = self._get_proxy()

        # 0) Проверить org info из headers последнего ответа (chat completion)
        if self._last_headers:
            hl = {k.lower(): v for k, v in self._last_headers.items()}
            for key in ("x-openai-organization", "openai-organization",
                         "x-openai-org", "x-org-id"):
                if key in hl:
                    result["org_plan"] = f"org:{hl[key]}"
                    break
            for key in ("x-openai-tier", "x-rate-tier", "x-openai-ratelist-tier"):
                if key in hl:
                    if not result.get("rate_tier"):
                        result["rate_tier"] = str(hl[key])

        # 1) Billing balance — пробуем несколько endpoint'ов
        billing_urls = [
            "https://api.openai.com/v1/organization/costs?start_time=0&limit=1",
            "https://api.openai.com/dashboard/billing/credit_grants",
            "https://api.openai.com/v1/organization/usage",
            "https://api.openai.com/dashboard/billing/subscription",
        ]
        for burl in billing_urls:
            try:
                async with session.get(burl, headers=headers, proxy=proxy) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        if isinstance(data, dict):
                            for field in ("total_granted_amount", "total_available",
                                          "balance", "hard_limit_usd",
                                          "soft_limit_usd", "account_balance"):
                                val = data.get(field)
                                if val is not None:
                                    try:
                                        result["balance_usd"] = float(val)
                                        break
                                    except (ValueError, TypeError):
                                        pass
                            total = data.get("total_granted_amount")
                            used = data.get("total_used_amount")
                            if total is not None and used is not None:
                                try:
                                    result["balance_usd"] = float(total) - float(used)
                                except (ValueError, TypeError):
                                    pass
                        break
            except Exception:
                continue

        # 2) Org plan из /organization endpoint
        if not result["org_plan"]:
            try:
                org_url = "https://api.openai.com/v1/organization"
                async with session.get(org_url, headers=headers, proxy=proxy) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        if isinstance(data, dict):
                            _plan = data.get("plan", {})
                            plan = _plan.get("title") if isinstance(_plan, dict) else str(_plan)
                            if not plan:
                                plan = data.get("plan")
                            if plan:
                                result["org_plan"] = str(plan)
            except Exception:
                pass

        return result

    async def _save_key_metadata(self, api_key: str, platform: str,
                                 base_url: str,
                                 headers: Optional[Dict] = None) -> None:
        """Собрать и сохранить расширенные метаданные ключа."""
        try:
            rate = self._extract_rate_limits(headers or {})
            billing = {"balance_usd": -1, "org_plan": ""}
            if platform in ("openai", "relay"):
                billing = await self._probe_openai_billing(api_key, base_url)
            self.db.update_key_meta(
                api_key,
                tpd=rate.get("tpd", 0),
                concurrency_limit=rate.get("concurrency_limit", 0),
                balance_usd=billing.get("balance_usd", -1),
                org_plan=billing.get("org_plan", ""),
                rate_tier=rate.get("rate_tier", ""),
                rate_headers=rate.get("rate_headers", ""),
            )
        except Exception as e:
            logger.debug(f"Ошибка сохранения метаданных ключа: {e}")

    async def _validate_models_endpoint(
        self,
        platform_name: str,
        api_key: str,
        base_url: str,
        default_url: str,
    ) -> ValidationResult:
        """
        Универсальная проверка OpenAI-совместимых провайдеров через GET /models.

        Используется для groq/deepseek/cohere/mistral/together/perplexity/
        fireworks/xai/openrouter/cerebras и т.п. — все они принимают
        Authorization: Bearer <key> и отдают список моделей на /models.
        """
        if not base_url:
            base_url = default_url
        if not self._is_likely_valid_relay(base_url):
            return ValidationResult(KeyStatus.INVALID, "base_url недействителен")

        circuit_result = await self._check_circuit_breaker(base_url)
        if circuit_result:
            return circuit_result

        headers = {"Authorization": f"Bearer {api_key}"}
        # Пробуем /models и варианты с/без /v1
        urls = self._try_url_variants(base_url, "models")
        last_status: Optional[int] = None
        # Отслеживаем, был ли явный отказ аутентификации (401/403)
        auth_rejected = False

        for url in urls:
            status, data, _, _ = await self._fetch_with_retry("GET", url, headers=headers)
            if status is None:
                # Транзитная ошибка на этом URL — пробуем следующий вариант
                continue
            last_status = status
            if status == 200:
                models_count = 0
                models_list: List[str] = []
                if isinstance(data, dict):
                    models = data.get("data") or data.get("models") or []
                    if isinstance(models, list):
                        models_count = len(models)
                        for m in models:
                            mid = m.get("id") if isinstance(m, dict) else str(m)
                            if mid:
                                models_list.append(mid)
                return ValidationResult(
                    KeyStatus.VALID,
                    f"{platform_name} действителен ({models_count} моделей)",
                    models=models_list)
            if status == 429:
                return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Квота исчерпана")
            if status in (401, 403):
                # Явный отказ аутентификации — ключ невалиден
                auth_rejected = True
                break
            # 404/400/422 — endpoint может отсутствовать на этом relay;
            # пробуем следующий вариант URL, не делаем вывод о невалидности ключа

        # Если был явный отказ auth — ключ невалиден
        if auth_rejected:
            return ValidationResult(KeyStatus.INVALID, "Недействителен")

        # Fallback: POST /chat/completions (некоторые relay не отдают /models)
        chat_body = {"model": "gpt-3.5-turbo",
                     "messages": [{"role": "user", "content": "Hi"}],
                     "max_tokens": 1}
        for url in self._try_url_variants(base_url, "chat/completions"):
            status, data, _, _ = await self._fetch_with_retry(
                "POST", url, headers=headers, json_body=chat_body)
            if status is None:
                continue
            last_status = status
            if status == 200:
                return ValidationResult(KeyStatus.VALID,
                                        f"{platform_name} действителен (chat)")
            if status == 429:
                return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Квота исчерпана")
            if status in (401, 403):
                return ValidationResult(KeyStatus.INVALID, "Недействителен")
            if status == 400 and isinstance(data, dict):
                _err = data.get("error", {})
                if isinstance(_err, dict):
                    err_msg = str(_err.get("code", "") or _err.get("message", "")).lower()
                else:
                    err_msg = str(_err).lower()
                if any(k in err_msg for k in ("model", "does not exist",
                                              "not found", "deprecated")):
                    return ValidationResult(KeyStatus.VALID,
                                            f"{platform_name}: auth ok, модель недоступна")
            # 404 — не OpenAI-эндпоинт; пробуем следующий вариант

        if last_status is not None:
            # 404/400/422 — auth не был явно отвергнут
            if last_status in (404, 400, 422):
                return ValidationResult(KeyStatus.UNVERIFIED,
                                        f"{platform_name}: HTTP {last_status} (endpoint не подтверждён)")
            return ValidationResult(self._classify_status(last_status),
                                     f"{platform_name}: HTTP {last_status}")
        return ValidationResult(
            KeyStatus.CONNECTION_ERROR,
            f"{platform_name}: ошибка соединения (после повторных попыток)")

    async def validate_openai(self, api_key: str, base_url: str) -> ValidationResult:
        """
        Асинхронная проверка OpenAI / ретранслятора (OpenAI-совместимый API).

        Логика определения валидности (по корректным эндпоинтам):
          1. GET {api_root}/models  — список моделей. 200 => VALID,
             401/403 => INVALID (ключ отвергнут), 429 => QUOTA,
             404 на /models => пробуем вариант без /v1 и chat/completions.
          2. Если /models не дал окончательного ответа (404/модели скрыты),
             POST {api_root}/chat/completions с max_tokens=1:
             200 => VALID, 401/403 => INVALID, 429 => QUOTA,
             400 с model_error => считаем ключ валидным (модель недоступна,
             но аутентификация прошла), 404 => INVALID (не OpenAI-эндпоинт).
          3. Транзитные ошибки (тайм-аут/5xx/обрыв) ретраятся внутри
             _fetch_with_retry; лишь после исчерпания попыток — CONNECTION_ERROR.
        """
        # Подставить дефолтный base_url если пустой
        if not base_url:
            base_url = config.default_base_urls.get("openai", "https://api.openai.com/v1")
        # Предварительная проверка base_url (SSRF / мусорные домены)
        if not self._is_likely_valid_relay(base_url):
            return ValidationResult(KeyStatus.INVALID, "base_url недействителен")

        # Проверка прерывателя
        circuit_result = await self._check_circuit_breaker(self._normalize_base_url(base_url))
        if circuit_result:
            return circuit_result

        headers = {"Authorization": f"Bearer {api_key}",
                   "Content-Type": "application/json",
                   # Браузерный UA: многие OpenAI-совместимые реле за
                   # Cloudflare (opencode.ai, ...) блокируют не-браузеры
                   # (error 1010) — ключ валиден, но запрос получает 403.
                   "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                                  "Chrome/126.0 Safari/537.36")}

        model_tier = "GPT-3.5"
        rpm = 0

        # ====== Шаг 1: GET /models ======
        last_models_status: Optional[int] = None
        for url in self._try_url_variants(base_url, "models"):
            status, data, rpm, _ = await self._fetch_with_retry(
                "GET", url, headers=headers)
            if status is None:
                # Транзитная ошибка на этом варианте URL — пробуем следующий
                continue
            last_models_status = status
            if status == 200 and isinstance(data, dict):
                _raw_models = data.get("data", [])
                if not isinstance(_raw_models, list):
                    _raw_models = []
                models_list = [m.get("id", "") if isinstance(m, dict) else str(m)
                               for m in _raw_models]
                models_list = [m for m in models_list if m]
                for m in models_list:
                    if any(hv in (m or "").lower() for hv in ['gpt-4', 'gpt-4o']):
                        model_tier = "GPT-4"
                        break
                model_names = [m[:15] for m in models_list[:3]]
                info = f"{len(models_list)} моделей: {', '.join(model_names)}"
                rpm_tier = ""
                if rpm >= RPM_ENTERPRISE_THRESHOLD:
                    rpm_tier = "Enterprise"
                elif 0 < rpm <= RPM_FREE_TRIAL_THRESHOLD:
                    rpm_tier = "Free Trial"
                if rpm_tier:
                    info = f"{info} [{rpm_tier}]"
                is_high = model_tier == "GPT-4" or rpm >= RPM_ENTERPRISE_THRESHOLD
                return ValidationResult(KeyStatus.VALID, info, model_tier, rpm, 0.0, is_high,
                                         models=models_list)

            if status == 429:
                return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Квота исчерпана")
            if status in (401, 403):
                # Явный отказ аутентификации — ключ невалиден, дальше не пытаемся
                return ValidationResult(KeyStatus.INVALID, "Недействителен (auth)")
            # 404/400/5xx — попробуем следующий вариант URL или fallback

        # ====== Шаг 2: POST /chat/completions (fallback) ======
        # Некоторые реле закрывают /models, но принимают chat/completions.
        # max_tokens=1 — минимальный расход квоты.
        chat_body = {"model": "gpt-3.5-turbo",
                     "messages": [{"role": "user", "content": "Hi"}],
                     "max_tokens": 1}
        last_chat_status: Optional[int] = None
        last_chat_body: Any = None
        for url in self._try_url_variants(base_url, "chat/completions"):
            status, data, _, _ = await self._fetch_with_retry(
                "POST", url, headers=headers, json_body=chat_body)
            if status is None:
                continue
            last_chat_status = status
            last_chat_body = data
            if status == 200:
                return ValidationResult(KeyStatus.VALID, "Действителен (chat)",
                                        model_tier, rpm, 0.0, False)
            if status == 429:
                return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Квота исчерпана")
            if status in (401, 403):
                # Ключ был VALID через /models, но chat/completions отдаёт 401.
                # Это не делает ключ INVALID — оставляем VALID без подтверждения.
                return ValidationResult(
                    KeyStatus.VALID,
                    f"VALID (auth ok на /models, chat/completions 401)")
            if status == 400 and isinstance(data, dict):
                # 400 часто = неверная модель, но ключ при этом прошёл auth.
                _err = data.get("error", {})
                if isinstance(_err, dict):
                    err_msg = str(_err.get("code", "") or _err.get("message", "")).lower()
                else:
                    err_msg = str(_err).lower()
                if any(k in err_msg for k in ("model", "does not exist",
                                              "not found", "deprecated")):
                    return ValidationResult(KeyStatus.VALID,
                                            "Действителен (auth ok, модель недоступна)",
                                            model_tier, rpm, 0.0, False)
                # Иной 400 (напр. invalid_api_key) — невалиден
                if "api_key" in err_msg or "authentication" in err_msg:
                    return ValidationResult(KeyStatus.INVALID, "Недействителен")
            # 404 — не OpenAI-эндпоинт; пробуем следующий вариант

        # ====== Итоговая классификация ======
        # Если был хоть один «осмысленный» ответ от сервера — используем его.
        # connection_error ставим только если ВСЕ варианты дали транзитный сбой.
        if last_chat_status is not None:
            # 400/404 без явного отказа auth — ключ возможно валиден,
            # endpoint не поддерживает запрошенный формат. Не теряем ключ.
            if last_chat_status in (400, 404):
                return ValidationResult(KeyStatus.UNVERIFIED,
                                        f"OpenAI: HTTP {last_chat_status} (auth не подтверждён, но и не отвергнут)")
            return ValidationResult(self._classify_status(last_chat_status),
                                     f"OpenAI: HTTP {last_chat_status}")
        if last_models_status is not None:
            if last_models_status in (400, 404):
                return ValidationResult(KeyStatus.UNVERIFIED,
                                        f"OpenAI: HTTP {last_models_status} (endpoint не подтверждён)")
            return ValidationResult(self._classify_status(last_models_status),
                                     f"OpenAI: HTTP {last_models_status}")
        # Все варианты URL не ответили даже после ретраев
        return ValidationResult(KeyStatus.CONNECTION_ERROR,
                                 "Ошибка соединения (после повторных попыток)")
    async def validate_opencode_zen(self, api_key: str, base_url: str) -> ValidationResult:
        """Проверка OpenCode Zen (https://opencode.ai/zen/v1).

        OpenAI-совместимый gateway за Cloudflare: без браузерного UA отдаёт
        403 "error code: 1010" — ключ валиден, но запрос блокируется. Поэтому:
          1. GET  /models с браузерным UA -> 200 VALID (список моделей).
          2. POST /chat/completions с фри-моделью (deepseek-v4-flash-free),
             max_tokens=1 -> 200 VALID.
          3. 401/403 (НЕ 1010) -> INVALID; 429 -> QUOTA; 400/404 -> по статусу.
          4. 403 с Cloudflare 1010 -> CONNECTION_ERROR (блок, не отказ ключа).
        """
        if not base_url:
            base_url = config.default_base_urls.get(
                "opencode_zen", "https://opencode.ai/zen/v1")
        else:
            base_url = self._normalize_base_url(base_url).rstrip('/')

        circuit_result = await self._check_circuit_breaker(base_url)
        if circuit_result:
            return circuit_result

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/126.0 Safari/537.36"),
            "Accept": "application/json",
            "Origin": "https://opencode.ai",
            "Referer": "https://opencode.ai/",
        }

        def _is_cf_block(data) -> bool:
            """Cloudflare 1010 (challenge) — не отказ auth, а блок не-браузера."""
            if isinstance(data, dict):
                msg = str(data.get("error") or data.get("message") or "")
            else:
                msg = str(data or "")
            return "1010" in msg

        # ====== Шаг 1: GET /models ======
        status, data, rpm, _ = await self._fetch_with_retry(
            "GET", f"{base_url}/models", headers=headers)
        if status == 200 and isinstance(data, dict):
            models_list = []
            for m in (data.get("data") or []):
                mid = m.get("id", "") if isinstance(m, dict) else str(m)
                if mid:
                    models_list.append(mid)
            info = f"OpenCode Zen: {len(models_list)} моделей"
            is_high = any("free" not in (m or "").lower() for m in models_list)
            return ValidationResult(KeyStatus.VALID, info, "GPT-4", rpm, 0.0,
                                    is_high, models=models_list)
        if status in (401,):
            return ValidationResult(KeyStatus.INVALID, "OpenCode Zen: недействителен (auth)")
        if status in (403,) and not _is_cf_block(data):
            return ValidationResult(KeyStatus.INVALID, "OpenCode Zen: недействителен (auth)")
        if status == 429:
            return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "OpenCode Zen: квота исчерпана")

        # ====== Шаг 2: POST chat/completions с фри-моделью ======
        chat_body = {
            "model": "deepseek-v4-flash-free",
            "messages": [{"role": "user", "content": "Hi"}],
            "max_tokens": 1,
        }
        status, data, _, _ = await self._fetch_with_retry(
            "POST", f"{base_url}/chat/completions", headers=headers,
            json_body=chat_body)
        if status == 200:
            return ValidationResult(KeyStatus.VALID, "OpenCode Zen: действителен (chat)",
                                    "GPT-4", rpm, 0.0, True)
        if status in (401,):
            return ValidationResult(KeyStatus.INVALID, "OpenCode Zen: недействителен (auth)")
        if status in (403,):
            if _is_cf_block(data):
                return ValidationResult(KeyStatus.CONNECTION_ERROR,
                                        "OpenCode Zen: Cloudflare-блок (1010), ключ не проверен")
            return ValidationResult(KeyStatus.INVALID, "OpenCode Zen: недействителен (auth)")
        if status == 429:
            return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "OpenCode Zen: квота исчерпана")
        if status == 400 and isinstance(data, dict):
            err = str(data.get("error", {}))
            if "auth" in err.lower() or "api_key" in err.lower():
                return ValidationResult(KeyStatus.INVALID, "OpenCode Zen: недействителен")
            return ValidationResult(KeyStatus.VALID,
                                    "OpenCode Zen: auth ok (модель недоступна)")
        if status is not None:
            return ValidationResult(self._classify_status(status),
                                    f"OpenCode Zen: HTTP {status}")
        return ValidationResult(KeyStatus.CONNECTION_ERROR,
                                "OpenCode Zen: ошибка соединения")
    
    async def validate_gemini(self, api_key: str, base_url: str) -> ValidationResult:
        """
        Асинхронная проверка Gemini - с интеграцией прерывателя цепи.

        Использует ?key=<api_key> в query string (формат Google AI).
        Учитывает base_url (для relay-Gemini), нормализуя его к /v1beta.
        """
        if not base_url:
            base_url = "https://generativelanguage.googleapis.com/v1beta"
        else:
            base_url = self._normalize_base_url(base_url)
            # Если после нормализации нет версии — добавляем /v1beta
            if not re.search(r'/v\d\w*$', base_url):
                base_url = base_url.rstrip('/') + '/v1beta'

        # Прерыватель по домену
        circuit_result = await self._check_circuit_breaker(base_url)
        if circuit_result:
            return circuit_result

        # Официальный Gemini REST API рекомендует x-goog-api-key; query
        # параметр key оставляем только для legacy relay-совместимости.
        headers = {"x-goog-api-key": api_key,
                   "Accept": "application/json",
                   "User-Agent": "Github-API-scan/1.0"}
        url = f"{base_url.rstrip('/')}/models"
        status, data, _, _ = await self._fetch_with_retry("GET", url, headers=headers)
        if status == 200 and isinstance(data, dict):
            models = data.get("models", [])
            models_list = []
            for m in models:
                name = m.get('name', '') if isinstance(m, dict) else str(m)
                if name:
                    models_list.append(name.replace('models/', ''))
            has_pro = any('gemini-1.5-pro' in (m or '').lower()
                          for m in models_list)
            tier = "Gemini-Pro" if has_pro else "Gemini"
            return ValidationResult(KeyStatus.VALID, f"{len(models_list)} моделей",
                                    tier, 0, 0.0, has_pro,
                                    models=models_list)
        if status == 429:
            return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Gemini: квота исчерпана")
        if status is None:
            return ValidationResult(KeyStatus.CONNECTION_ERROR,
                                    "Gemini: ошибка соединения (после повторных попыток)")
        if status == 401:
            return ValidationResult(KeyStatus.INVALID, f"Gemini: HTTP 401 (ключ отвергнут)")
        if status == 400:
            # Gemini возвращает структурированный error.status/details[].reason.
            # API_KEY_INVALID и leaked-key body = INVALID; прочий malformed
            # request не доказывает, что credential неверный.
            err_msg = ""
            err_status = ""
            reasons = []
            if isinstance(data, dict):
                err = data.get("error", {})
                if isinstance(err, dict):
                    err_msg = str(err.get("message", ""))
                    err_status = str(err.get("status", ""))
                    reasons = [str(d.get("reason", "")) for d in (err.get("details") or [])
                               if isinstance(d, dict)]
                else:
                    err_msg = str(err)
            err_lower = " ".join([err_msg, err_status, *reasons]).lower()
            if ("api_key_invalid" in err_lower or "api key not valid" in err_lower
                    or "reported as leaked" in err_lower
                    or "leaked api key" in err_lower):
                return ValidationResult(KeyStatus.INVALID,
                                        "Gemini: ключ отвергнут (API_KEY_INVALID/leaked)")
            return ValidationResult(KeyStatus.UNVERIFIED,
                                    f"Gemini: HTTP 400 ({err_status or 'invalid request'})")
        if status == 404:
            return ValidationResult(KeyStatus.UNVERIFIED, "Gemini: HTTP 404 (endpoint не найден)")
        if status >= 500:
            return ValidationResult(KeyStatus.CONNECTION_ERROR, f"Gemini: HTTP {status}")
        return ValidationResult(self._classify_status(status), f"Gemini: HTTP {status}")

    async def validate_gemini_deep(
        self, api_key: str, base_url: str,
        candidate_models: List[str] = None
    ) -> ValidationResult:
        """
        Глубокая проверка Gemini: GET /models, и если ответ UNVERIFIED/QUOTA
        (403/400/404 — ключ возможно валиден, но /models не отдал список) —
        попробовать реальную генерацию через _confirm_gemini (generateContent).

        Многие Gemini-ключи отдают 403 на /models, но пропускают generateContent.
        Решает 3954 застрявших UNVERIFIED gemini (вкл. 1525 без base_url).
        """
        if not base_url:
            base_url = config.default_base_urls.get(
                "gemini", "https://generativelanguage.googleapis.com/v1beta")

        vr = await self.validate_gemini(api_key, base_url)
        # VALID через /models — достаточно, ключ работает
        if vr.status == KeyStatus.VALID:
            return vr

        # UNVERIFIED/QUOTA — /models не подтвердил, пробуем генерацию.
        # fallback-кандидаты (т.к. список моделей мы не получили)
        if candidate_models is None:
            candidate_models = [
                "gemini-2.5-flash", "gemini-2.0-flash",
                "gemini-1.5-flash", "gemini-1.5-pro",
                "gemini-flash-latest",
            ]
        deep = await self._confirm_gemini(api_key, base_url, candidate_models)
        # Если генерация дала CONNECTION_ERROR — хуже исходного, отдаём vr
        if deep.status == KeyStatus.CONNECTION_ERROR:
            return vr
        return deep

    async def validate_anthropic(self, api_key: str, base_url: str) -> ValidationResult:
        """
        Асинхронная проверка Anthropic Claude Key - с retry и прерывателем цепи.

        Anthropic использует специальные Headers:
        - x-api-key: API Key
        - anthropic-version: версия API

        POST /v1/messages для проверки (GET /models не поддерживается).
        Особая обработка:
        - 400 + "credit balance is too low" → QUOTA_EXCEEDED (Key действителен)
        - 401 → INVALID (аутентификация не удалась)
        """
        if not base_url:
            base_url = config.default_base_urls["anthropic"]

        circuit_result = await self._check_circuit_breaker(base_url)
        if circuit_result:
            return circuit_result

        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json"
        }
        body = {
            "model": "claude-3-haiku-20240307",
            "max_tokens": 1,
            "messages": [{"role": "user", "content": "Hi"}]
        }
        url = f"{base_url.rstrip('/')}/v1/messages"
        status, data, _, _ = await self._fetch_with_retry(
            "POST", url, headers=headers, json_body=body)

        if status == 200:
            model_used = ""
            if isinstance(data, dict):
                model_used = data.get("model", "claude-3")
            is_high = "opus" in model_used.lower() or "sonnet" in model_used.lower()
            tier = "Claude-3-Opus" if "opus" in model_used.lower() else "Claude-3"
            return ValidationResult(KeyStatus.VALID, "Claude действителен", tier, 0, 0.0, is_high)

        # Извлечь текст ошибки из JSON
        err_msg = ""
        if isinstance(data, dict):
            err = data.get("error", {})
            if isinstance(err, dict):
                err_msg = err.get("message", "")
            elif isinstance(err, str):
                err_msg = err
        err_lower = err_msg.lower()

        if status == 400:
            if "credit" in err_lower and "balance" in err_lower:
                return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Claude: недостаточно средств", "Claude-3", 0, 0.0, False)
            elif "billing" in err_lower:
                return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Claude: проблема с биллингом", "Claude-3", 0, 0.0, False)
            return ValidationResult(KeyStatus.VALID, "Действителен (ошибка запроса)", "Claude", 0, 0.0, False)
        if status == 401:
            return ValidationResult(KeyStatus.INVALID, "Claude: аутентификация не удалась")
        if status == 403:
            if "disabled" in err_lower:
                return ValidationResult(KeyStatus.INVALID, "Claude Key заблокирован")
            return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Claude: доступ ограничен", "Claude", 0, 0.0, False)
        if status == 429:
            return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Claude: ограничение скорости")
        if status is None:
            return ValidationResult(KeyStatus.CONNECTION_ERROR,
                                    "Claude: ошибка соединения (после повторных попыток)")
        return ValidationResult(self._classify_status(status), f"Claude: HTTP {status}")
    
    async def validate_azure(self, api_key: str, base_url: str) -> ValidationResult:
        """Асинхронная проверка Azure - с retry и прерывателем цепи"""
        if not base_url:
            return ValidationResult(KeyStatus.UNVERIFIED, "Отсутствует Endpoint")

        circuit_result = await self._check_circuit_breaker(base_url)
        if circuit_result:
            return circuit_result

        headers = {"api-key": api_key, "Content-Type": "application/json"}
        
        # 1. Попытка GET /openai/deployments
        url = f"{base_url.rstrip('/')}/openai/deployments?api-version=2023-05-15"
        status, data, _, _ = await self._fetch_with_retry("GET", url, headers=headers)
        if status == 200:
            return ValidationResult(KeyStatus.VALID, "Azure действителен", "Azure-GPT", 0, 0.0, True)
        if status == 429:
            return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Azure: квота исчерпана")
        if status == 401:
            return ValidationResult(KeyStatus.INVALID, "Azure: HTTP 401 (ключ отвергнут)")
        
        # 2. Если 403/404/другое — пробуем chat/completions с минимальным запросом
        # Нужен deployment name — пробуем gpt-4o, gpt-35-turbo
        for deployment in ["gpt-4o", "gpt-35-turbo", "gpt-4"]:
            url = f"{base_url.rstrip('/')}/openai/deployments/{deployment}/chat/completions?api-version=2023-05-15"
            body = {
                "messages": [{"role": "user", "content": "hi"}],
                "max_tokens": 1
            }
            status2, data2, _, _ = await self._fetch_with_retry("POST", url, headers=headers, json_body=body)
            if status2 == 200:
                return ValidationResult(KeyStatus.VALID, f"Azure {deployment}", "Azure-GPT", 0, 0.0, True)
            if status2 == 429:
                return ValidationResult(KeyStatus.QUOTA_EXCEEDED, f"Azure {deployment}: квота")
            if status2 == 401:
                return ValidationResult(KeyStatus.INVALID, f"Azure {deployment}: 401")
        
        # Всё не удалось
        if status is None:
            return ValidationResult(KeyStatus.CONNECTION_ERROR, "Azure: ошибка соединения")
        return ValidationResult(KeyStatus.UNVERIFIED, f"Azure: HTTP {status} (deployment не найден)")
    
    async def probe_gpt4(self, api_key: str, base_url: str) -> bool:
        """Определить, поддерживается ли GPT-4"""
        if not base_url:
            base_url = config.default_base_urls["openai"]
        
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        body = {"model": "gpt-4", "messages": [{"role": "user", "content": "1"}], "max_tokens": 1}
        
        session = await self._get_session()
        proxy = self._get_proxy()
        
        for url in self._try_url_variants(base_url, "chat/completions"):
            try:
                async with session.post(url, headers=headers, json=body, proxy=proxy) as resp:
                    return resp.status == 200
            except Exception as e:
                logger.debug(f"Ошибка проверки: {type(e).__name__}: {e}")
                continue
        return False
    
    async def probe_billing(self, api_key: str, base_url: str) -> dict:
        """
        Определить баланс ретранслятора/официального API
        
        Возвращает:
            {
                'balance': float,      # Баланс (USD)
                'used': float,         # Использовано
                'limit': float,        # Общий лимит
                'source': str          # Источник баланса
            }
        """
        result = {'balance': 0.0, 'used': 0.0, 'limit': 0.0, 'source': ''}
        
        headers = {"Authorization": f"Bearer {api_key}"}
        session = await self._get_session()
        proxy = self._get_proxy()
        
        # ========== 1. Проверка официального баланса OpenAI ==========
        if not base_url or "api.openai.com" in base_url:
            # Запрос баланса официального API требует organization header
            # Но большинство утекших Key не имеют этой информации, пропускаем
            return result
        
        # ========== 2. Проверка баланса ретранслятора ==========
        billing_endpoints = [
            # one-api / new-api формат (наиболее распространенный)
            {
                'path': '/api/user/self',
                'fields': ['quota', 'used_quota', 'data.quota', 'data.used_quota']
            },
            {
                'path': '/api/user/info', 
                'fields': ['quota', 'used_quota', 'balance', 'data.quota']
            },
            # Формат совместимый с OpenAI
            {
                'path': '/dashboard/billing/subscription',
                'fields': ['hard_limit_usd', 'soft_limit_usd', 'system_hard_limit_usd']
            },
            {
                'path': '/v1/dashboard/billing/subscription',
                'fields': ['hard_limit_usd', 'soft_limit_usd']
            },
            {
                'path': '/dashboard/billing/credit_grants',
                'fields': ['total_granted', 'total_used', 'total_available']
            },
            # Другие ретрансляторы
            {
                'path': '/user/info',
                'fields': ['balance', 'quota', 'credits', 'remaining']
            },
            {
                'path': '/api/status',
                'fields': ['quota', 'balance', 'credits']
            },
        ]
        
        for endpoint in billing_endpoints:
            try:
                url = f"{base_url.rstrip('/')}{endpoint['path']}"
                async with session.get(url, headers=headers, proxy=proxy) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        balance = self._extract_balance_from_response(data, endpoint['fields'])
                        if balance > 0:
                            result['balance'] = balance
                            result['source'] = endpoint['path']
                            return result
            except Exception as e:
                logger.debug(f"Ошибка проверки: {type(e).__name__}: {e}")
                continue
        
        return result
    
    def _extract_balance_from_response(self, data: dict, fields: list) -> float:
        """
        Извлечь баланс из данных ответа
        
        Поддерживает вложенные поля, такие как 'data.quota'
        """
        for field in fields:
            try:
                value = data
                for key in field.split('.'):
                    if isinstance(value, dict):
                        value = value.get(key)
                    else:
                        value = None
                        break
                
                if value is not None and value != 0:
                    balance = float(value)
                    # Единица quota в one-api - "500000" означает $5
                    # Необходимо разделить на 100000 для перевода в доллары
                    if balance > 10000:
                        balance = balance / 100000
                    return balance
            except (ValueError, TypeError, AttributeError):
                continue
        return 0.0
    
    async def probe_quota_by_request(self, api_key: str, base_url: str) -> dict:
        """
        Проверить квоту путем реального запроса
        
        Это наиболее точный метод: попытка отправить минимальный запрос
        
        Возвращает:
            {
                'has_quota': bool,     # Есть ли квота
                'error_type': str,     # Тип ошибки (quota/rate_limit/auth/other)
                'message': str         # Подробная информация
            }
        """
        if not base_url:
            base_url = config.default_base_urls["openai"]
        
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        session = await self._get_session()
        proxy = self._get_proxy()
        
        # Минимальный запрос: 1 токен
        chat_body = {
            "model": "gpt-3.5-turbo",
            "messages": [{"role": "user", "content": "1"}],
            "max_tokens": 1
        }
        
        for url in self._try_url_variants(base_url, "chat/completions"):
            try:
                async with session.post(url, headers=headers, json=chat_body, proxy=proxy) as resp:
                    response_text = await resp.text()
                    
                    if resp.status == 200:
                        return {'has_quota': True, 'error_type': None, 'message': 'Есть квота'}
                    
                    elif resp.status == 429:
                        # Различать исчерпание квоты и ограничение скорости
                        if 'quota' in response_text.lower() or 'exceeded' in response_text.lower():
                            return {'has_quota': False, 'error_type': 'quota', 'message': 'Квота исчерпана'}
                        elif 'rate' in response_text.lower():
                            # Ограничение скорости означает, что Key действителен, просто запрос слишком быстрый
                            return {'has_quota': True, 'error_type': 'rate_limit', 'message': 'Ограничение скорости (есть квота)'}
                        else:
                            return {'has_quota': False, 'error_type': 'quota', 'message': 'Ошибка 429'}
                    
                    elif resp.status == 401:
                        return {'has_quota': False, 'error_type': 'auth', 'message': 'Ошибка аутентификации'}
                    
                    elif resp.status == 402:
                        # Payment Required - явно указывает на отсутствие средств
                        return {'has_quota': False, 'error_type': 'quota', 'message': 'Требуется оплата'}
                    
                    elif resp.status == 400:
                        # Проверить, недостаточно ли средств
                        if 'insufficient' in response_text.lower() or 'quota' in response_text.lower():
                            return {'has_quota': False, 'error_type': 'quota', 'message': 'Недостаточно средств'}
                        # Другие ошибки 400 могут быть проблемой формата запроса, Key может быть действительным
                        return {'has_quota': True, 'error_type': 'other', 'message': 'Ошибка запроса'}
                    
                    else:
                        return {'has_quota': False, 'error_type': 'other', 'message': f'HTTP {resp.status}'}
                        
            except asyncio.TimeoutError:
                continue
            except aiohttp.ClientConnectorError:
                return {'has_quota': False, 'error_type': 'connection', 'message': 'Ошибка соединения'}
            except Exception as e:
                logger.debug(f"Ошибка проверки: {type(e).__name__}: {e}")
                continue
        
        return {'has_quota': False, 'error_type': 'other', 'message': 'Невозможно проверить'}
    

    # ========================================================================
    #                           Методы проверки новых платформ
    # ========================================================================

    async def validate_huggingface(self, api_key: str, base_url: str) -> ValidationResult:
        """Проверить Hugging Face API Key (Bearer auth, эндпоинт /models/gpt2)"""
        if not base_url:
            base_url = "https://api-inference.huggingface.co"
        base = self._normalize_base_url(base_url)
        circuit_result = await self._check_circuit_breaker(base)
        if circuit_result:
            return circuit_result
        headers = {"Authorization": f"Bearer {api_key}"}
        url = f"{base.rstrip('/')}/models/gpt2"
        status, data, _, _ = await self._fetch_with_retry("GET", url, headers=headers)
        if status == 200:
            return ValidationResult(KeyStatus.VALID, "HuggingFace действителен")
        if status == 429:
            return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Квота исчерпана")
        if status == 401:
            return ValidationResult(KeyStatus.INVALID, "Недействителен")
        if status == 403:
            return ValidationResult(KeyStatus.UNVERIFIED, "HuggingFace: доступ ограничен (ключ возможно валиден)")
        if status == 404:
            return ValidationResult(KeyStatus.UNVERIFIED, "HuggingFace: модель не найдена (ключ возможно валиден)")
        if status is None:
            return ValidationResult(KeyStatus.CONNECTION_ERROR,
                                    "HuggingFace: ошибка соединения (после повторных попыток)")
        return ValidationResult(self._classify_status(status), f"HuggingFace: HTTP {status}")

    async def validate_groq(self, api_key: str, base_url: str) -> ValidationResult:
        return await self._validate_models_endpoint(
            "Groq", api_key, base_url, "https://api.groq.com/openai/v1")

    async def validate_deepseek(self, api_key: str, base_url: str) -> ValidationResult:
        return await self._validate_models_endpoint(
            "DeepSeek", api_key, base_url, "https://api.deepseek.com")

    async def validate_cohere(self, api_key: str, base_url: str) -> ValidationResult:
        return await self._validate_models_endpoint(
            "Cohere", api_key, base_url, "https://api.cohere.ai/v1")

    async def validate_mistral(self, api_key: str, base_url: str) -> ValidationResult:
        return await self._validate_models_endpoint(
            "Mistral", api_key, base_url, "https://api.mistral.ai/v1")

    async def validate_together(self, api_key: str, base_url: str) -> ValidationResult:
        return await self._validate_models_endpoint(
            "Together", api_key, base_url, "https://api.together.xyz/v1")

    async def validate_replicate(self, api_key: str, base_url: str) -> ValidationResult:
        """Проверить Replicate API Key (Token auth, эндпоинт /account)"""
        if not base_url:
            base_url = "https://api.replicate.com/v1"
        base = self._normalize_base_url(base_url)
        circuit_result = await self._check_circuit_breaker(base)
        if circuit_result:
            return circuit_result
        headers = {"Authorization": f"Token {api_key}"}
        url = f"{base.rstrip('/')}/account"
        status, data, _, _ = await self._fetch_with_retry("GET", url, headers=headers)
        if status == 200:
            return ValidationResult(KeyStatus.VALID, "Replicate действителен")
        if status == 429:
            return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Квота исчерпана")
        if status == 401:
            return ValidationResult(KeyStatus.INVALID, "Replicate: ключ отвергнут")
        if status == 403:
            return ValidationResult(KeyStatus.UNVERIFIED, "Replicate: доступ ограничен (ключ возможно валиден)")
        if status == 404:
            return ValidationResult(KeyStatus.UNVERIFIED, "Replicate: HTTP 404 (endpoint не найден, ключ возможно валиден)")
        if status is None:
            return ValidationResult(KeyStatus.CONNECTION_ERROR,
                                    "Replicate: ошибка соединения (после повторных попыток)")
        return ValidationResult(self._classify_status(status), f"Replicate: HTTP {status}")

    async def validate_jina(self, api_key: str, base_url: str) -> ValidationResult:
        """Проверить Jina AI API Key (embeddings endpoint)"""
        if not base_url:
            base_url = "https://api.jina.ai/v1"
        base = self._normalize_base_url(base_url)
        circuit_result = await self._check_circuit_breaker(base)
        if circuit_result:
            return circuit_result
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        url = f"{base.rstrip('/')}/embeddings"
        body = {"input": ["test"], "model": "jina-embeddings-v2-base-en"}
        status, data, _, _ = await self._fetch_with_retry("POST", url, headers=headers, json_body=body)
        if status == 200:
            return ValidationResult(KeyStatus.VALID, "Jina AI действителен")
        if status == 429:
            return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Jina: квота исчерпана")
        if status == 401:
            return ValidationResult(KeyStatus.INVALID, "Jina: ключ отвергнут")
        if status is None:
            return ValidationResult(KeyStatus.CONNECTION_ERROR, "Jina: ошибка соединения")
        return ValidationResult(self._classify_status(status), f"Jina: HTTP {status}")

    async def validate_perplexity(self, api_key: str, base_url: str) -> ValidationResult:
        return await self._validate_models_endpoint(
            "Perplexity", api_key, base_url, "https://api.perplexity.ai")

    async def validate_fireworks(self, api_key: str, base_url: str) -> ValidationResult:
        return await self._validate_models_endpoint(
            "Fireworks", api_key, base_url, "https://api.fireworks.ai/inference/v1")

    async def validate_aws_access_key(self, api_key: str, base_url: str) -> ValidationResult:
        """Проверить AWS Access Key (только проверка формата, без реального вызова)"""
        if api_key.startswith('AKIA') and len(api_key) == 20:
            return ValidationResult(KeyStatus.UNVERIFIED, "AWS Key: формат верный")
        return ValidationResult(KeyStatus.INVALID, "Неверный формат")

    async def validate_aws_secret_key(self, api_key: str, base_url: str) -> ValidationResult:
        """AWS Secret Key — нельзя проверить без Access Key, только формат"""
        return ValidationResult(KeyStatus.UNVERIFIED, "AWS Secret: формат сохранён")

    async def validate_steam(self, api_key: str, base_url: str) -> ValidationResult:
        """Проверить Steam Web API Key"""
        if not base_url:
            base_url = "https://api.steampowered.com"
        base = self._normalize_base_url(base_url)
        circuit_result = await self._check_circuit_breaker(base)
        if circuit_result:
            return circuit_result
        # Пробуем GetNewsForApp (публичный эндпоинт, требует только key)
        url = f"{base.rstrip('/')}/ISteamNews/GetNewsForApp/v0002/?appid=440&count=1&key={api_key}"
        status, data, _, _ = await self._fetch_with_retry("GET", url, headers={})
        if status == 200:
            return ValidationResult(KeyStatus.VALID, "Steam действителен")
        if status == 403:
            return ValidationResult(KeyStatus.INVALID, "Steam: ключ отвергнут")
        if status is None:
            return ValidationResult(KeyStatus.CONNECTION_ERROR, "Steam: ошибка соединения")
        return ValidationResult(self._classify_status(status), f"Steam: HTTP {status}")
    
    async def validate_github(self, api_key: str, base_url: str) -> ValidationResult:
        """Проверить GitHub API токен (ghp_, github_pat_, gho_, ghu_, ghs_, ghr_)"""
        if not base_url:
            base_url = "https://api.github.com"
        base = self._normalize_base_url(base_url)
        circuit_result = await self._check_circuit_breaker(base)
        if circuit_result:
            return circuit_result
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }
        url = f"{base.rstrip('/')}/user"
        status, data, _, _ = await self._fetch_with_retry("GET", url, headers=headers)
        if status == 200:
            login = data.get("login", "unknown") if isinstance(data, dict) else "unknown"
            return ValidationResult(KeyStatus.VALID, f"GitHub: {login}")
        if status == 401:
            return ValidationResult(KeyStatus.INVALID, "GitHub: ключ отвергнут")
        if status == 403:
            # rate limit или токен без прав на /user
            return ValidationResult(KeyStatus.VALID, "GitHub: токен валиден (rate limit/scope)")
        if status is None:
            return ValidationResult(KeyStatus.CONNECTION_ERROR, "GitHub: ошибка соединения")
        return ValidationResult(self._classify_status(status), f"GitHub: HTTP {status}")

    async def validate_unverified(self, api_key: str, base_url: str) -> ValidationResult:
        """Платформы без безопасной публичной точки проверки — формат сохранён"""
        return ValidationResult(KeyStatus.UNVERIFIED, "Платформа не поддерживает онлайн-проверку")

    async def _confirm_anthropic(self, api_key: str, base_url: str,
                                  models: List[str] = None) -> ValidationResult:
        """Подтверждение для Anthropic через POST /v1/messages."""
        if not base_url:
            base_url = "https://api.anthropic.com"
        # Выбрать лучшую claude модель
        test_model = "claude-3-5-haiku-20241022"
        if models:
            for pref in ["claude-opus-4.8", "claude-opus-4.6", "claude-opus-4.5",
                         "claude-opus-4", "opus-4", "claude-4",
                         "claude-3-5-sonnet", "claude-3-5-haiku",
                         "claude-3-opus", "claude-3-haiku",
                         "claude-3-sonnet", "claude-3"]:
                for m in models:
                    bare = m.split("/")[-1] if "/" in m else m
                    if pref in bare.lower():
                        test_model = bare
                        break
                if pref in test_model.lower():
                    break
        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        challenge_prompt, expected_answer = _math_challenge()
        body = {
            "model": test_model,
            "max_tokens": 20,
            "messages": [{"role": "user", "content": challenge_prompt}],
        }
        url = f"{base_url.rstrip('/')}/v1/messages"
        status, data, _, _ = await self._fetch_with_retry("POST", url, headers=headers, json_body=body)
        if status == 200 and isinstance(data, dict):
            content_list = data.get("content", [])
            content = ""
            if isinstance(content_list, list):
                for block in content_list:
                    if isinstance(block, dict):
                        content += block.get("text", "")
            # СТРОГО: ответ должен содержать правильную сумму (отсекает мусор/квоту)
            if _content_has_answer(content, expected_answer):
                return ValidationResult(
                    KeyStatus.VALID,
                    f"\u2713 Подтверждён ({test_model}): {content.strip()[:20]}",
                    models=[test_model])
            return ValidationResult(
                KeyStatus.VALID,
                f"\u2713 Подтверждён ({test_model}): 200 OK",
                models=[test_model])
        if status == 429:
            return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Anthropic: квота")
        if status == 401:
            return ValidationResult(KeyStatus.INVALID, "Anthropic: ключ отвергнут")
        if status == 400 and isinstance(data, dict):
            _err = data.get("error")
            err_msg = ""
            if isinstance(_err, dict):
                err_msg = str(_err.get("message", ""))
            elif isinstance(_err, str):
                err_msg = _err
            else:
                err_msg = str(data.get("message", ""))
            if any(k in err_msg.lower() for k in ("credit", "balance", "billing")):
                return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Anthropic: нет средств")
            return ValidationResult(
                KeyStatus.VALID,
                f"VALID (auth ok, модель {test_model} недоступна)")
        if status is None:
            return ValidationResult(KeyStatus.CONNECTION_ERROR, "Anthropic: ошибка соединения")
        return ValidationResult(self._classify_status(status), f"Anthropic: HTTP {status}")

    async def _confirm_gemini(self, api_key: str, base_url: str,
                               models: List[str] = None) -> ValidationResult:
        """Подтверждение для Gemini через generateContent.

        Перебирает НЕСКОЛЬКО моделей: 404/403 на одной не означает, что ключ
        невалиден — другая модель может ответить. Поэтому 403/404/400(не-auth)
        → следующая модель; INVALID только при отказе auth (401 / 400 "API key not valid").
        """
        if not base_url:
            base_url = "https://generativelanguage.googleapis.com/v1beta"
        # Сформировать упорядоченный список моделей-кандидатов
        fallback = ["gemini-2.5-flash", "gemini-2.0-flash",
                    "gemini-1.5-flash", "gemini-flash-latest",
                    "gemini-1.5-pro"]
        test_models = []
        if models:
            for pref in ["gemini-3.5", "gemini-3.1", "gemini-3", "gemini-2.5",
                         "gemini-2.0", "gemini-1.5-pro", "gemini-1.5-flash"]:
                for m in models:
                    bare = m.split("/")[-1] if "/" in m else m
                    if pref in bare.lower() and bare not in test_models:
                        test_models.append(bare)
                        break
        for m in fallback:
            if m not in test_models:
                test_models.append(m)
        test_models = test_models[:5]  # не больше 5 попыток

        last_status = None
        challenge_prompt, expected_answer = _math_challenge()
        for test_model in test_models:
            url = f"{base_url.rstrip('/')}/models/{test_model}:generateContent"
            body = {
                "contents": [{"parts": [{"text": challenge_prompt}]}],
                "generationConfig": {"maxOutputTokens": 20, "temperature": 0},
            }
            headers = {"x-goog-api-key": api_key,
                       "Accept": "application/json",
                       "User-Agent": "Github-API-scan/1.0"}
            status, data, _, _ = await self._fetch_with_retry(
                "POST", url, headers=headers, json_body=body)
            last_status = status

            if status == 200 and isinstance(data, dict):
                candidates = data.get("candidates", [])
                if candidates:
                    content = ""
                    parts = candidates[0].get("content", {}).get("parts", [])
                    for p in parts:
                        content += p.get("text", "")
                    # СТРОГО: ответ должен содержать правильную сумму.
                    if _content_has_answer(content, expected_answer):
                        return ValidationResult(
                            KeyStatus.VALID,
                            f"✓ Подтверждён ({test_model}): {content.strip()[:20]}",
                            models=[test_model])
                # 200 без верного ответа → мусор/квота-обёртка → след. модель
            if status == 429:
                return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Gemini: квота")
            if status == 401:
                return ValidationResult(KeyStatus.INVALID, "Gemini: ключ отвергнут (401)")
            if status == 400 and isinstance(data, dict):
                err = data.get("error", {})
                err_msg = (err.get("message", "") if isinstance(err, dict)
                           else str(err))
                err_lower = (err_msg or "").lower()
                # Маркеры явного отказа auth (ключ мёртв). "not found" сюда НЕ
                # входит — это про модель/ресурс, не про ключ → пробуем другую.
                if any(k in err_lower for k in
                       ("api key", "api_key", "key not valid",
                        "permission_denied", "key expired")):
                    return ValidationResult(
                        KeyStatus.INVALID, "Gemini: ключ отвергнут (400)")
                continue
            if status == 403 or status == 404:
                continue
            if status is None:
                # Транзитная сетевая ошибка после retry — не делать 5× запросов,
                # выйти сразу с CONNECTION_ERROR.
                return ValidationResult(KeyStatus.CONNECTION_ERROR,
                                        "Gemini: ошибка соединения")
            # Неизвестный статус (5xx и пр.) → пробуем следующую модель,
            # а не выходим из цикла (голый break терял рабочие модели)
            continue

        if last_status is None:
            return ValidationResult(KeyStatus.CONNECTION_ERROR,
                                    "Gemini: ошибка соединения")
        if last_status == 403:
            return ValidationResult(KeyStatus.UNVERIFIED,
                                    "Gemini: доступ ограничен (403)")
        if last_status == 404:
            return ValidationResult(KeyStatus.UNVERIFIED,
                                    "Gemini: эндпоинт не найден (404)")
        if last_status >= 500:
            return ValidationResult(KeyStatus.CONNECTION_ERROR,
                                    f"Gemini: HTTP {last_status}")
        return ValidationResult(self._classify_status(last_status),
                                f"Gemini: HTTP {last_status}")

    async def confirm_key(self, api_key: str, base_url: str,
                          models: List[str] = None,
                          platform: str = "") -> ValidationResult:
        """
        Подтвердить что ключ реально работает — отправить chat-запрос.

        Логика:
        1. GET /models — получить АКТУАЛЬНЫЙ список моделей (проверка доступа).
        2. Перебрать ВСЕ модели (топ-приоритетные первыми), отправить "2+32=?".
        3. Первая ответившая 200 → CONFIRMED + mark_model_confirmed.
        4. 429 → retry (до 3 раз с задержкой), затем QUOTA_EXCEEDED.
        5. Все модели 401/403 → INVALID.
        6. Модели 404/400 → пропустить, пробовать следующие.

        Платформо-специфичные:
        - Gemini: generateContent формат
        - Anthropic: /v1/messages формат
        - Perplexity: модель "sonar" вместо anthropic/...
        """
        plat = (platform or "").lower()

        # --- Gemini: generateContent ---
        if plat == "gemini" or "googleapis.com" in (base_url or ""):
            return await self._confirm_gemini(api_key, base_url, models)

        # --- Anthropic: /v1/messages ---
        if plat == "anthropic" or "anthropic.com" in (base_url or ""):
            return await self._confirm_anthropic(api_key, base_url, models)

        if not base_url:
            return ValidationResult(KeyStatus.VALID, "VALID (нет base_url)")

        # --- Сначала GET /models для актуального списка ---
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                           "AppleWebKit/537.36 (KHTML, like Gecko) "
                           "Chrome/126.0 Safari/537.36"),
            "Accept": "application/json",
            "Origin": "https://opencode.ai" if "opencode.ai" in (base_url or "") else "",
            "Referer": "https://opencode.ai/" if "opencode.ai" in (base_url or "") else "",
        }
        actual_models = []
        for url in self._try_url_variants(base_url, "models"):
            status, data, _, _ = await self._fetch_with_retry("GET", url, headers=headers)
            if status == 200 and isinstance(data, dict):
                raw = data.get("data", [])
                if isinstance(raw, list):
                    actual_models = [m.get("id", "") if isinstance(m, dict) else str(m)
                                     for m in raw if m]
                    actual_models = [m for m in actual_models if m]
                break
            if status in (401, 403):
                return ValidationResult(KeyStatus.INVALID, "Недействителен")
            if status == 429:
                return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Квота исчерпана")

        # Использовать актуальные модели или переданные
        all_models = actual_models or models or []

        # --- Для perplexity: не фильтровать, проверять все модели ---
        # perplexity отдаёт perplexity/sonar, openai/gpt-5.5 и т.д.
        # Все они работают через /chat/completions с точным именем из /models.

        # --- Дефолтные модели если список пуст ---
        # Расширенный список — покрывает большинство relay/proxy сервисов
        if not all_models:
            all_models = [
                "gpt-4o-mini", "gpt-3.5-turbo", "gpt-4o", "gpt-4",
                "claude-3-haiku", "claude-3-5-sonnet", "claude-3-sonnet",
                "gemini-flash", "gemini-1.5-flash",
                "deepseek-chat", "qwen-turbo",
                "llama-3.1-8b-instant", "mixtral-8x7b-instruct",
            ]

        # --- Приоритет топ-моделей ---
        import re as _re
        def _norm(m):
            bare = m.lower().split("/")[-1] if "/" in m else m
            bare = _re.sub(r'-\d{4}-\d{2}-\d{2}.*$', '', bare)
            return bare.replace("-", "").replace(".", "")

        priority = [
            "gpt55", "gpt54", "gpt52", "gpt51", "gpt5",
            "claudeopus4", "claude35", "claude3",
            "glm5", "glm52",
            "kimik2", "kimi",
            "gemini3", "gemini25",
            "deepseekv4", "deepseekr1", "deepseekchat",
            "gpt4o", "gpt41", "gpt4", "gpt35turbo",
            "o3", "o1", "llama3", "qwen2", "sonar",
            "mistral", "mixtral", "grok2",
        ]
        ranked = []
        rest = [m for m in all_models if isinstance(m, str) and m.strip()]
        for pref in priority:
            for m in list(rest):
                if pref in _norm(m):
                    ranked.append(m)
                    rest.remove(m)
        ranked.extend(rest)

        # --- Перебор ВСЕХ моделей ---
        # Строгий промпт со случайной задачей: правильный ответ должен
        # содержаться в content. Отсекает мусор (китайская квота/заглушки).
        challenge_prompt, expected_answer = _math_challenge()
        body_base = {
            "messages": [{"role": "user", "content": challenge_prompt}],
            "max_tokens": 50,
            "temperature": 0,
        }
        urls = self._try_url_variants(base_url, "chat/completions")
        auth_failed_count = 0
        quota_count = 0
        working_models = []
        first_confirmed_model = None

        for model in ranked:
            payload = {**body_base, "model": model}
            for url in urls:
                status, data, _, _ = await self._fetch_with_retry(
                    "POST", url, headers=headers, json_body=payload)
                if status is None:
                    continue
                if status == 200:
                    # СТРОГАЯ проверка: ответ должен содержать правильную сумму.
                    # Мусор (китайская «余额不足»/квота, заглушки, ошибки в 200)
                    # не совпадёт → модель не считается рабочей.
                    content = ""
                    if isinstance(data, dict):
                        choices = data.get("choices", [])
                        if choices:
                            msg = choices[0] if isinstance(choices[0], dict) else {}
                            content = msg.get("message", {}).get("content", "")
                        else:
                            # Нет choices — 200 с error в теле (замаскированная квота)
                            err = data.get("error") or data.get("message", "")
                            if err and any(k in str(err).lower() for k in
                                           ("quota", "limit", "exhausted",
                                            "payment", "billing", "insufficient",
                                            "余额", "不足", "额度")):
                                quota_count += 1
                                break
                    if _content_has_answer(content, expected_answer):
                        working_models.append(model)
                        if not first_confirmed_model:
                            first_confirmed_model = model
                    # иначе: ответ не содержит сумму → мусор/квота-обёртка,
                    # модель не засчитываем, пробуем следующую
                    break  # след модель
                if status == 429 or status == 402:
                    quota_count += 1
                    break  # квота для этой модели, пробуем следующую
                if status in (401, 403):
                    auth_failed_count += 1
                    break
                if status == 404:
                    # 404 на этом варианте URL → пробуем следующий вариант
                    # (base_url может быть без /v1, а эндпоинт — /v1/chat/...)
                    continue
                if status == 400:
                    # 400 на одном URL-варианте может быть ошибкой пути (без /v1),
                    # а не модели → пробуем следующий вариант URL
                    continue
            # Если auth отвергнут на ВСЕХ моделях (или 3+, что меньше) → отозван
            if auth_failed_count >= min(3, len(ranked)):
                break

        # --- Итог ---
        if working_models:
            # Batch mark all confirmed models at once (faster than per-model)
            self.db.mark_models_confirmed_batch(api_key, working_models)
            return ValidationResult(
                KeyStatus.VALID,
                f"\u2713 Подтверждён ({first_confirmed_model}): {len(working_models)}/{len(ranked)} моделей работают",
                models=working_models)
        if quota_count > 0 and quota_count >= len(ranked) * 0.5:
            # Большинство моделей дают 429/402 → квота/оплата исчерпана
            return ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Квота исчерпана (429/402)")
        if auth_failed_count >= 3:
            return ValidationResult(KeyStatus.INVALID, "Недействителен (auth)")
        # Ни одна модель не ответила 200 — ключ VALID через /models, но чат не работает
        return ValidationResult(
            KeyStatus.VALID,
            f"VALID (проверено {len(ranked)} моделей, чат не отвечает)",
            models=actual_models or models)

    async def _validate_simple_account(
        self, api_key: str, base_url: str, platform: str,
        auth: str = "bearer", header: str = "", path: str = "/user"
    ) -> ValidationResult:
        """
        Универсальный валидатор: header + GET на /user|/account|/me|/usage.

        Покрывает расширенные провайдеры (elevenlabs, stability, tavily,
        firecrawl, apify, ...), метаданные берутся из _EXTRA_PROVIDERS.
        Шаблон по образцу validate_replicate.

        auth: 'bearer' | 'token' | 'basic' | 'apikey' | 'custom'
          - bearer:  Authorization: Bearer {key}
          - token:   Authorization: Token {key}
          - basic:   Authorization: Basic base64(key:)   (Langfuse: public+secret)
          - apikey:  {header}: {key}                     (ElevenLabs xi-api-key)
          - custom:  {header}: {key}                     (HeyGen X-Api-Key)
        path: проверочный путь относительно base_url (напр. '/user', '/usage').
        """
        meta = _EXTRA_PROVIDERS.get(platform, {})
        if not base_url:
            base_url = meta.get("url", "")
        if not base_url:
            return ValidationResult(KeyStatus.UNVERIFIED, "Нет base_url")
        if auth == "bearer":
            auth = meta.get("auth", "bearer")
        if header == "" and auth in ("apikey", "custom"):
            header = meta.get("header", "Authorization")
        if path == "/user":
            path = meta.get("path", "/user")
        # Нет проверочного path — не делать холостой запрос в корень API
        # (вернёт 404 → ложный UNVERIFIED/INVALID). Сохраняем ключ как UNVERIFIED.
        if not path:
            return ValidationResult(
                KeyStatus.UNVERIFIED, f"{platform.capitalize()}: нет проверочного эндпоинта")

        base = self._normalize_base_url(base_url)
        circuit_result = await self._check_circuit_breaker(base)
        if circuit_result:
            return circuit_result

        # Сформировать headers по схеме auth
        if auth in ("apikey", "custom"):
            headers = {header: api_key}
        elif auth == "token":
            headers = {"Authorization": f"Token {api_key}"}
        elif auth == "bearer":
            headers = {"Authorization": f"Bearer {api_key}"}
        elif auth == "basic":
            # Langfuse: HTTP Basic с public:secret — здесь только проверка,
            # ключ один → base64(key:). Реальный secret у Langfuse отдельно,
            # но Bearer/Basic с одним токеном тоже работает для /projects.
            import base64 as _b64
            try:
                cred = _b64.b64encode(api_key.encode()).decode()
            except Exception:
                cred = api_key
            headers = {"Authorization": f"Basic {cred}"}
        else:
            headers = {"Authorization": f"Bearer {api_key}"}

        url = f"{base.rstrip('/')}{path}"
        status, data, _, _ = await self._fetch_with_retry("GET", url, headers=headers)
        name = platform.capitalize()
        if status == 200:
            return ValidationResult(KeyStatus.VALID, f"{name} действителен")
        if status == 429:
            return ValidationResult(KeyStatus.QUOTA_EXCEEDED, f"{name}: квота")
        if status == 401:
            # Для basic-auth провайдеров (Langfuse: требуется public:secret,
            # а у нас только один токен) отказ auth недостоверен — ключ может
            # быть валиден. Не хороним как INVALID, оставляем UNVERIFIED.
            if auth == "basic":
                return ValidationResult(
                    KeyStatus.UNVERIFIED, f"{name}: auth неполон (401)")
            return ValidationResult(KeyStatus.INVALID, f"{name}: ключ отвергнут")
        if status == 403:
            return ValidationResult(KeyStatus.UNVERIFIED,
                                    f"{name}: доступ ограничен (403)")
        if status == 404:
            return ValidationResult(KeyStatus.UNVERIFIED,
                                    f"{name}: HTTP 404 (endpoint не найден)")
        if status is None:
            return ValidationResult(KeyStatus.CONNECTION_ERROR,
                                    f"{name}: ошибка соединения")
        return ValidationResult(self._classify_status(status),
                                f"{name}: HTTP {status}")

    async def _validate_extra(self, api_key: str, base_url: str,
                              platform: str) -> ValidationResult:
        """Диспетчер расширенных провайдеров: читает EXTRA_PROVIDERS."""
        meta = _EXTRA_PROVIDERS.get(platform)
        if not meta:
            return await self.validate_unverified(api_key, base_url)
        return await self._validate_simple_account(
            api_key, base_url, platform,
            auth=meta.get("auth", "bearer"),
            header=meta.get("header", ""),
            path=meta.get("path", "/user"))

    # Платформы, совместимые с OpenAI-протоколом (Bearer auth, /models)
    _OPENAI_COMPATIBLE = frozenset({
        "openai", "relay", "xai", "cerebras", "openrouter", "open_ai",
        "anyscale", "voyage", "lepton", "zhipu", "yi", "baichuan",
        "moonshot", "stepfun", "siliconflow", "dashscope", "volcengine",
        "internlm", "minimax", "llamacloud",
    })
    # Платформы без безопасной онлайн-проверки — сохраняем как UNVERIFIED
    _UNVERIFIABLE = frozenset({
        "aws_secret_key", "shadeform", "modal",
        "google_api_key", "firebase", "heroku",
        "figma_token",
        "runpod", "lambdalabs", "coreweave",
        "digitalocean", "linode", "vultr", "hetzner", "scaleway",
    })

    async def validate_single(self, result: 'ScanResult') -> ValidationResult:
        """Проверить один результат (единая точка входа)"""
        platform = result.platform.lower()

        # Основные ИИ-платформы (специфичные валидаторы)
        if platform == "azure" or result.is_azure:
            return await self.validate_azure(result.api_key, result.base_url)
        elif platform == "gemini":
            return await self.validate_gemini(result.api_key, result.base_url)
        elif platform == "anthropic":
            return await self.validate_anthropic(result.api_key, result.base_url)
        # ИИ-платформы с OpenAI-совместимым /models
        elif platform == "huggingface":
            return await self.validate_huggingface(result.api_key, result.base_url)
        elif platform == "groq":
            return await self.validate_groq(result.api_key, result.base_url)
        elif platform == "deepseek":
            return await self.validate_deepseek(result.api_key, result.base_url)
        elif platform == "cohere":
            return await self.validate_cohere(result.api_key, result.base_url)
        elif platform == "mistral":
            return await self.validate_mistral(result.api_key, result.base_url)
        elif platform == "together":
            return await self.validate_together(result.api_key, result.base_url)
        elif platform == "replicate":
            return await self.validate_replicate(result.api_key, result.base_url)
        elif platform == "jina":
            return await self.validate_jina(result.api_key, result.base_url)
        elif platform == "perplexity":
            return await self.validate_perplexity(result.api_key, result.base_url)
        elif platform == "fireworks":
            return await self.validate_fireworks(result.api_key, result.base_url)
        # Облачные провайдеры
        elif platform == "aws_access_key":
            return await self.validate_aws_access_key(result.api_key, result.base_url)
        elif platform == "aws_secret_key":
            return await self.validate_aws_secret_key(result.api_key, result.base_url)
        elif platform == "steam":
            return await self.validate_steam(result.api_key, result.base_url)
        elif platform == "github":
            return await self.validate_github(result.api_key, result.base_url)
        # Расширенный каталог (_EXTRA_PROVIDERS) — универсальный валидатор
        elif platform in _EXTRA_PROVIDERS:
            return await self._validate_extra(
                result.api_key, result.base_url, platform)
        # Платформы без безопасной онлайн-проверки → UNVERIFIED
        elif platform in self._UNVERIFIABLE:
            return await self.validate_unverified(result.api_key, result.base_url)
        # OpenCode Zen (Cloudflare-gated OpenAI gateway) — отдельный валидатор:
        # без браузерного UA реле отдаёт 403/1010, что не отказ ключа.
        elif (platform in ("opencode_zen", "opencode-zen", "opencode")
              or "opencode.ai" in (result.base_url or "").lower()):
            return await self.validate_opencode_zen(result.api_key, result.base_url)
        # OpenAI-совместимые (openai/relay/xai/cerebras/openrouter) → общий OpenAI-валидатор
        elif platform in self._OPENAI_COMPATIBLE:
            return await self.validate_openai(result.api_key, result.base_url)
        # Неизвестная платформа: если есть base_url — пробуем как OpenAI-совместимый relay
        elif result.base_url:
            return await self.validate_openai(result.api_key, result.base_url)
        # Нет base_url и неизвестная платформа — сохраняем как UNVERIFIED
        else:
            return await self.validate_unverified(result.api_key, result.base_url)
    
    async def process_result(self, result: 'ScanResult'):
        """
        Асинхронная обработка одного результата
        
        Включает второй уровень защиты от дубликатов: проверка наличия Key в базе данных перед проверкой
        """
        async with self.semaphore:
            masked = mask_key(result.api_key)
            
            # ========== Второй уровень защиты: Дедупликация по Key ==========
            # Проверить базу данных перед отправкой любого сетевого запроса
            if self.db.key_exists(result.api_key):
                self._log(f"[SKIP] Key уже в базе данных: {masked}", "SKIP")
                if self.dashboard:
                    self.dashboard.increment_stat("skipped_duplicate")
                return
            
            # Добавить в базу (с защитой уникальных ограничений)
            leaked_key = LeakedKey(
                platform=result.platform,
                api_key=result.api_key,
                base_url=result.base_url,
                status=KeyStatus.PENDING.value,
                source_url=result.source_url,
                found_time=datetime.now()
            )
            
            if not self.db.insert_key(leaked_key):
                # В случае параллельного доступа другой поток мог вставить раньше
                self._log(f"[SKIP] Конфликт вставки Key: {masked}", "SKIP")
                return
            
            # Проверка
            self._log(f"Проверка {masked}...", "INFO")
            vr = await self.validate_single(result)
            
            # Глубокое определение (только для действительных OpenAI/Relay Key)
            if vr.status == KeyStatus.VALID and result.platform.lower() in ['openai', 'relay']:
                # Параллельное определение GPT-4 и баланса
                gpt4_task = asyncio.create_task(self.probe_gpt4(result.api_key, result.base_url))
                billing_task = asyncio.create_task(self.probe_billing(result.api_key, result.base_url))
                quota_task = asyncio.create_task(self.probe_quota_by_request(result.api_key, result.base_url))
                
                has_gpt4, billing_result, quota_result = await asyncio.gather(
                    gpt4_task, billing_task, quota_task
                )
                
                if has_gpt4:
                    vr.model_tier = "GPT-4"
                    vr.is_high_value = True
                
                # Использовать результат проверки баланса
                if billing_result.get('balance', 0) > 0:
                    vr.balance_usd = billing_result['balance']
                    vr.is_high_value = True
                
                # Использовать результат реального запроса для обновления состояния
                if not quota_result.get('has_quota', True):
                    if quota_result.get('error_type') == 'quota':
                        vr.status = KeyStatus.QUOTA_EXCEEDED
                        vr.info = quota_result.get('message', 'Квота исчерпана')
                    # error_type == 'auth' НЕ понижает VALID → INVALID:
                    # /models уже подтвердил валидность ключа (HTTP 200).
                    # POST /chat/completions может вернуть 401 по другим причинам
                    # (неподдерживаемая модель, rate limit, разные правила auth
                    # на разных endpoints relay). Доверяем результату /models.
            
            # Обновить базу данных
            balance_str = vr.info
            if vr.balance_usd > 0:
                balance_str = f"${vr.balance_usd:.2f} | {vr.info}"
            if vr.model_tier:
                balance_str = f"{vr.model_tier} | {balance_str}"
            
            self.db.update_key_status(
                result.api_key,
                vr.status,
                balance_str,
                model_tier=vr.model_tier,
                rpm=vr.rpm,
                is_high_value=vr.is_high_value
            )

            # Сохранить список моделей для валидных ключей (вкладка «Модели»)
            if vr.status == KeyStatus.VALID and vr.models:
                try:
                    self.db.save_key_models(result.api_key, vr.models)
                except Exception as e:
                    logger.debug(f"save_key_models error: {e}")

            # Собрать rate-limits, баланс, org plan для валидных ключей
            if vr.status == KeyStatus.VALID:
                try:
                    await self._save_key_metadata(
                        result.api_key, result.platform, result.base_url)
                except Exception as e:
                    logger.debug(f"save_key_metadata error: {e}")

            # Подтверждение: реальный chat completion запрос ("2+32=")
            if vr.status == KeyStatus.VALID and result.platform.lower() in ('openai', 'relay', 'opencode_zen', 'xai',
                    'openrouter', 'cerebras', 'groq', 'deepseek',
                    'perplexity', 'together', 'mistral', 'fireworks',
                    'moonshot', 'siliconflow', 'dashscope',
                    'gemini', 'anthropic'):
                try:
                    confirmed = await self.confirm_key(
                        result.api_key, result.base_url, vr.models,
                        platform=result.platform)
                    if confirmed.status == KeyStatus.VALID and "Подтверждён" in confirmed.info:
                        vr.status = KeyStatus.CONFIRMED
                        vr.info = confirmed.info
                        if confirmed.models and not vr.models:
                            vr.models = confirmed.models
                        # Записать CONFIRMED в БД (первый update_key_status был до)
                        self.db.update_key_status(
                            result.api_key, KeyStatus.CONFIRMED, vr.info,
                            is_high_value=vr.is_high_value)
                        self._log(f"✓✓ Подтверждён! {masked}: {confirmed.info[:40]}", "VALID")
                except Exception as e:
                    logger.debug(f"confirm_key error: {e}")
            if self.dashboard:
                source_short = result.source_url.split('/')[-1] if '/' in result.source_url else result.source_url
                
                if vr.status == KeyStatus.VALID:
                    self.dashboard.add_valid_key(
                        platform=result.platform,
                        masked_key=masked,
                        balance=balance_str,
                        source=source_short,
                        is_high_value=vr.is_high_value
                    )
                    level = "VALID" if not vr.is_high_value else "HIGH"
                    self._log(f"✓ Действителен! {vr.model_tier or result.platform.upper()} {masked}", level)
                
                elif vr.status == KeyStatus.QUOTA_EXCEEDED:
                    self.dashboard.add_valid_key(
                        platform=result.platform,
                        masked_key=masked,
                        balance=f"Квота исчерпана",
                        source=source_short
                    )
                    self.dashboard.increment_stat("quota_exceeded")
                    self._log(f"⚠ Квота исчерпана {masked}", "WARN")
                
                elif vr.status == KeyStatus.CONNECTION_ERROR:
                    self.dashboard.increment_stat("connection_errors")
                    self._log(f"✗ Ошибка соединения {masked}", "ERROR")
                
                else:
                    self.dashboard.increment_stat("invalid_keys")
    
    async def run_batch(self, results: list):
        """Пакетная проверка"""
        tasks = [self.process_result(r) for r in results]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def revalidate_failed_keys(self, limit: int = 0) -> Dict[str, int]:
        """
        Повторная проверка ключей со статусом connection_error / pending.

        Возвращает словарь со статистикой: {'revalidated': N, 'valid': N,
        'invalid': N, 'quota': N, 'connection_error': N, 'unverified': N}.

        Это решает проблему «99% ERROR»: ранее транзитные ошибки сети
        навсегда помечали ключ как connection_error, и он никогда не
        перепроверялся. Теперь с улучшенными валидаторами (нормализация
        URL + retry) эти ключи могут быть правильно классифицированы.
        """
        from types import SimpleNamespace
        failed = self.db.get_failed_keys(limit=limit)
        stats = {"revalidated": len(failed), "valid": 0, "invalid": 0,
                 "quota": 0, "connection_error": 0, "unverified": 0,
                 "pending": 0}

        if not failed:
            self._log("Нет ключей для повторной проверки", "INFO")
            return stats

        # Сбросить прерыватель цепи — старые блокировки доменов не должны мешать
        self._circuit_breaker.reset()

        # ========== Фаза 1: Bulk-реклассификация платформ без онлайн-проверки ==========
        # Платформы из _UNVERIFIABLE и aws_secret_key не требуют сетевых запросов —
        # обновляем напрямую в БД. Это мгновенно убирает тысячи «connection_error».
        bulk_platforms = self._UNVERIFIABLE | {"aws_secret_key"}
        bulk_keys = [k for k in failed if k.platform.lower() in bulk_platforms]
        network_keys = [k for k in failed if k.platform.lower() not in bulk_platforms]

        if bulk_keys:
            self._log(f"Bulk-реклассификация {len(bulk_keys)} ключей (без сети)...", "INFO")
            updates = [
                (k.api_key, KeyStatus.UNVERIFIED,
                 "Платформа не поддерживает онлайн-проверку", "", 0, False)
                for k in bulk_keys
            ]
            self.db.update_keys_status_batch(updates)
            stats["unverified"] += len(bulk_keys)
            self._log(f"  → {len(bulk_keys)} ключей → UNVERIFIED (batch)", "INFO")

        if not network_keys:
            self._log("Сетевых ключей для проверки нет", "INFO")
            return stats

        self._log(f"Сетевая проверка {len(network_keys)} ключей...", "INFO")
        failed = network_keys  # далее работаем только с сетевыми

        sem = asyncio.Semaphore(50)  # ограничить конкурентность
        done = 0
        total = len(failed)

        async def revalidate_one(key: 'LeakedKey'):
            nonlocal done
            async with sem:
                masked = mask_key(key.api_key)
                # Адаптер LeakedKey → SimpleNamespace (совместим с validate_single)
                result = SimpleNamespace(
                    platform=key.platform,
                    api_key=key.api_key,
                    base_url=key.base_url or "",
                    source_url=key.source_url or "",
                    is_azure=(key.platform.lower() == "azure"),
                    is_relay=(key.platform.lower() == "relay"),
                    context="",
                )
                try:
                    vr = await self.validate_single(result)
                except Exception as e:
                    logger.debug(f"Revalidate error: {type(e).__name__}: {e}")
                    return

                balance_str = vr.info
                if vr.balance_usd > 0:
                    balance_str = f"${vr.balance_usd:.2f} | {vr.info}"
                if vr.model_tier:
                    balance_str = f"{vr.model_tier} | {balance_str}"

                self.db.update_key_status(
                    key.api_key, vr.status, balance_str,
                    model_tier=vr.model_tier, rpm=vr.rpm,
                    is_high_value=vr.is_high_value
                )

                # Сохранить модели для валидных ключей (вкладка «Модели»)
                if vr.status == KeyStatus.VALID and vr.models:
                    try:
                        self.db.save_key_models(key.api_key, vr.models)
                    except Exception as e:
                        logger.debug(f"save_key_models error: {e}")

                # Собрать rate-limits, баланс, org plan для валидных ключей
                if vr.status == KeyStatus.VALID:
                    try:
                        await self._save_key_metadata(
                            key.api_key, key.platform, key.base_url)
                    except Exception as e:
                        logger.debug(f"save_key_metadata error: {e}")

                if vr.status == KeyStatus.VALID:
                    stats["valid"] += 1
                    self._log(f"✓ [revalidate] Действителен {masked}", "VALID")
                elif vr.status == KeyStatus.INVALID:
                    stats["invalid"] += 1
                elif vr.status == KeyStatus.QUOTA_EXCEEDED:
                    stats["quota"] += 1
                elif vr.status == KeyStatus.CONNECTION_ERROR:
                    stats["connection_error"] += 1
                elif vr.status == KeyStatus.UNVERIFIED:
                    stats["unverified"] += 1
                else:
                    stats["pending"] += 1

                done += 1
                if done % 100 == 0 or done == total:
                    self._log(
                        f"  Прогресс: {done}/{total} "
                        f"(V:{stats['valid']} I:{stats['invalid']} "
                        f"Q:{stats['quota']} E:{stats['connection_error']} "
                        f"U:{stats['unverified']})", "INFO")

        tasks = [revalidate_one(k) for k in failed]
        await asyncio.gather(*tasks, return_exceptions=True)

        self._log(
            f"Повторная проверка завершена: "
            f"{stats['valid']} валидных, {stats['invalid']} невалидных, "
            f"{stats['quota']} квота, {stats['connection_error']} ошибок соединения, "
            f"{stats['unverified']} непроверяемых",
            "INFO"
        )
        return stats


# ============================================================================
#                              Вспомогательные функции
# ============================================================================

# Импорт ScanResult (отложенный импорт для избежания циклических зависимостей)
def get_scan_result_class():
    from scanner import ScanResult
    return ScanResult


async def run_validator_loop(
    result_queue: 'asyncio.Queue',
    db: Database,
    stop_event: 'asyncio.Event',
    dashboard = None
):
    """Запустить асинхронный цикл проверки"""
    validator = AsyncValidator(db, dashboard)
    
    try:
        while not stop_event.is_set():
            try:
                # Пакетное получение задач из очереди
                batch = []
                try:
                    while len(batch) < 50:  # Максимум 50 в пакете
                        result = result_queue.get_nowait()
                        batch.append(result)
                except asyncio.QueueEmpty:
                    pass
                
                if batch:
                    if dashboard:
                        dashboard.update_stats(queue_size=result_queue.qsize())
                    await validator.run_batch(batch)
                else:
                    await asyncio.sleep(0.5)
                    
            except Exception as e:
                if dashboard:
                    dashboard.add_log(f"Ошибка проверки: {str(e)[:30]}", "ERROR")
                await asyncio.sleep(1)
    finally:
        await validator.close()


# ============================================================================
#                     Синхронная обертка (совместимость с threading)
# ============================================================================

import queue as sync_queue


def _validator_thread_worker(
    result_queue: sync_queue.Queue,
    db: Database,
    stop_event: threading.Event,
    dashboard = None
):
    """
    Рабочая функция потока валидатора
    
    Запускает цикл событий asyncio в потоке для обеспечения асинхронной проверки
    """
    async def async_worker():
        validator = AsyncValidator(db, dashboard)

        # --- Фоновая валидация pending ключей из БД ---
        async def pending_drainer():
            """Берёт pending/connection_error ключи из БД пачками и валидирует."""
            from types import SimpleNamespace
            processed = 0
            logger.info("pending_drainer запущен")
            while not stop_event.is_set():
                try:
                    pending_keys = db.get_failed_keys(limit=500)
                    if not pending_keys:
                        # БЕЗ периодического лога «нет pending ключей» — он
                        # спамил каждые 5с × N потоков. Молча ждём.
                        await asyncio.sleep(5)
                        continue

                    logger.info(
                        f"pending_drainer: взято {len(pending_keys)} ключей "
                        f"(всего: {processed})")
                    if dashboard:
                        dashboard.add_log(
                            f"⏳ Валидация {len(pending_keys)} pending ключей "
                            f"(всего: {processed})", "INFO")

                    # Bulk-обработка unverifiable платформ (без сети)
                    bulk_platforms = validator._UNVERIFIABLE | {"aws_secret_key"}
                    bulk_keys = [k for k in pending_keys
                                 if k.platform.lower() in bulk_platforms]
                    network_keys = [k for k in pending_keys
                                    if k.platform.lower() not in bulk_platforms]

                    if bulk_keys:
                        updates = [
                            (k.api_key, KeyStatus.UNVERIFIED,
                             "Платформа не поддерживает онлайн-проверку", "", 0, False)
                            for k in bulk_keys
                        ]
                        db.update_keys_status_batch(updates)
                        logger.info(
                            f"pending_drainer: bulk {len(bulk_keys)} ключей → "
                            f"UNVERIFIED (без сети, batch)")
                        processed += len(bulk_keys)

                    if not network_keys:
                        if dashboard:
                            dashboard.add_log(
                                f"⚡ Bulk: {len(bulk_keys)} → UNVERIFIED",
                                "INFO")
                        continue

                    pending_keys = network_keys
                    # Валидировать напрямую через validate_single (без key_exists)
                    sem_local = asyncio.Semaphore(100)
                    done = 0
                    total = len(pending_keys)

                    async def revalidate_one(key):
                        nonlocal done
                        async with sem_local:
                            result = SimpleNamespace(
                                platform=key.platform,
                                api_key=key.api_key,
                                base_url=key.base_url or "",
                                source_url=key.source_url or "",
                                is_azure=(key.platform.lower() == "azure"),
                                is_relay=(key.platform.lower() == "relay"),
                                context="",
                            )
                            try:
                                vr = await validator.validate_single(result)
                                balance_str = vr.info
                                if vr.balance_usd > 0:
                                    balance_str = f"${vr.balance_usd:.2f}"

                                # CONFIRMED: реальный chat completion для VALID
                                # Все платформы с API — confirm_key сам определяет формат
                                confirm_platforms = {
                                    'openai', 'relay', 'xai', 'openrouter', 'cerebras', 'groq',
                                    'deepseek', 'perplexity', 'together', 'mistral', 'fireworks',
                                    'moonshot', 'siliconflow', 'dashscope',
                                    'gemini', 'anthropic', 'replicate', 'huggingface',
                                    'jina', 'steam', 'github', 'cohere',
                                }
                                if vr.status == KeyStatus.VALID and key.platform.lower() in confirm_platforms:
                                    try:
                                        confirmed = await validator.confirm_key(
                                            key.api_key, result.base_url, vr.models,
                                            platform=key.platform)
                                        if confirmed.status == KeyStatus.VALID and "Подтверждён" in confirmed.info:
                                            vr.status = KeyStatus.CONFIRMED
                                            vr.info = confirmed.info
                                        elif confirmed.status == KeyStatus.QUOTA_EXCEEDED:
                                            vr.status = KeyStatus.QUOTA_EXCEEDED
                                        elif confirmed.status == KeyStatus.INVALID:
                                            vr.status = KeyStatus.INVALID
                                            vr.info = "Ключ отозван"
                                    except Exception as ce:
                                        logger.debug(f"confirm error: {ce}")

                                # update_key_status ТОЛЬКО для терминальных статусов.
                                # UNVERIFIED/CONNECTION_ERROR → только increment,
                                # иначе verified_time закроет ключ для unverified_drainer.
                                if vr.status in (KeyStatus.VALID, KeyStatus.CONFIRMED,
                                                  KeyStatus.INVALID, KeyStatus.QUOTA_EXCEEDED):
                                    validator.db.update_key_status(
                                        key.api_key, vr.status, balance_str,
                                        is_high_value=vr.is_high_value)
                                else:
                                    # UNVERIFIED/CONNECTION_ERROR — не трогаем verified_time
                                    validator.db.increment_confirm_attempts(key.api_key)

                                # Инкремент попыток подтверждения (анти-цикл)
                                validator.db.increment_confirm_attempts(key.api_key)

                                # confirm_key уже проверил все модели и пометил
                                # рабочие через mark_model_confirmed.

                                done += 1
                                if done % 50 == 0:
                                    logger.info(
                                        f"pending_drainer: прогресс {done}/{total}")
                            except Exception as e:
                                done += 1
                                logger.debug(
                                    f"revalidate_one error: {type(e).__name__}: {e}")
                                logger.error(
                                    f"revalidate_one traceback for "
                                    f"{key.platform}/{mask_key(key.api_key)}:",
                                    exc_info=True)

                    tasks = [revalidate_one(k) for k in pending_keys]
                    await asyncio.gather(*tasks, return_exceptions=True)
                    processed += len(pending_keys)

                    # Лог результатов
                    key_ids = [k.api_key for k in pending_keys]
                    placeholders = ",".join("?" * len(key_ids))
                    with db._lock:
                        with db._get_connection() as conn:
                            rows = conn.execute(
                                f"SELECT platform, status, COUNT(*) "
                                f"FROM leaked_keys "
                                f"WHERE api_key IN ({placeholders}) "
                                f"GROUP BY platform, status",
                                tuple(key_ids)).fetchall()
                    parts = [f"{r[0]}:{r[1]}={r[2]}" for r in rows]
                    summary = (f"✅ Пачка {len(pending_keys)}: "
                               f"{' | '.join(parts)} (всего: {processed})")
                    logger.info(summary)
                    if dashboard:
                        dashboard.add_log(summary, "INFO")
                except Exception as e:
                    logger.error(f"pending_drainer error: {e}", exc_info=True)
                    if dashboard:
                        dashboard.add_log(
                            f"Ошибка pending: {str(e)[:80]}", "ERROR")
                    await asyncio.sleep(2)

        # --- Фоновое подтверждение VALID → CONFIRMED ---
        async def confirm_drainer():
            """Берёт VALID/CONFIRMED ключи и:
            1. confirm_key — подтверждает что ключ работает (VALID→CONFIRMED)
            2. confirm_models — проверяет ВСЕ модели chat-запросом
            """
            import sqlite3 as _sqlite3
            confirm_validator = AsyncValidator(db, dashboard)
            total_confirmed = 0
            logger.info("confirm_drainer запущен")
            await asyncio.sleep(15)
            try:
                while not stop_event.is_set():
                    conn_raw = None
                    try:
                        conn_raw = _sqlite3.connect(db.db_path, timeout=5)
                        conn_raw.row_factory = _sqlite3.Row
                        # VALID + CONFIRMED ключи. Порог < 20: valid-ключи часто
                        # на attempts=10-15 (многократный confirm), всё равно
                        # перепроверяем — они живые (status=valid).
                        rows = conn_raw.execute(
                            "SELECT lk.api_key, lk.base_url, lk.platform, "
                            "  GROUP_CONCAT(km.model_name) as models "
                            "FROM leaked_keys lk "
                            "LEFT JOIN key_models km ON km.key_id = lk.id "
                            "WHERE lk.status IN ('valid','confirmed') "
                            "  AND lk.confirm_attempts < 20 "
                            "GROUP BY lk.api_key "
                            "ORDER BY lk.confirm_attempts ASC, lk.verified_time ASC "
                            "LIMIT 50"
                        ).fetchall()
                    finally:
                        if conn_raw:
                            conn_raw.close()

                    if not rows:
                        await asyncio.sleep(30)
                        continue

                    logger.info(f"confirm_drainer: взято {len(rows)} ключей")
                    confirmed_count = 0
                    sem_c = asyncio.Semaphore(8)

                    async def confirm_one(row):
                        nonlocal confirmed_count
                        async with sem_c:
                            r = dict(row)
                            models = [m.strip() for m in (r.get("models") or "").split(",") if m.strip()]
                            # Если моделей нет — используем дефолтные для confirm_key
                            # (confirm_key сам подставит gpt-4o-mini и т.д.)
                            if not models:
                                models = None  # confirm_key использует дефолтные
                            try:
                                # 1. confirm_key — одна модель для статуса
                                ck = await confirm_validator.confirm_key(
                                    r["api_key"], r["base_url"], models,
                                    platform=r["platform"])
                                db.increment_confirm_attempts(r["api_key"])

                                if ck.status == KeyStatus.VALID and "Подтверждён" in ck.info:
                                    db.update_key_status(
                                        r["api_key"], KeyStatus.CONFIRMED,
                                        balance=ck.info)
                                    confirmed_count += 1
                                elif ck.status == KeyStatus.QUOTA_EXCEEDED:
                                    db.update_key_status(
                                        r["api_key"], KeyStatus.QUOTA_EXCEEDED,
                                        balance="Квота исчерпана")
                                elif ck.status == KeyStatus.INVALID:
                                    db.update_key_status(
                                        r["api_key"], KeyStatus.INVALID,
                                        balance="Ключ отозван при перепроверке")

                                # confirm_key уже проверил ВСЕ модели и пометил
                                # рабочие через mark_model_confirmed.
                                # confirm_models больше не нужен — дублирование.
                            except Exception as e:
                                logger.debug(
                                    f"confirm_one error {r['api_key'][:8]}...: "
                                    f"{type(e).__name__}: {e}")

                    tasks = [confirm_one(r) for r in rows]
                    await asyncio.gather(*tasks, return_exceptions=True)
                    total_confirmed += confirmed_count

                    summary = (f"\u2713 Подтверждено {confirmed_count}/{len(rows)} ключей, "
                               f"(всего CONFIRMED: {total_confirmed})")
                    logger.info(summary)
                    if dashboard:
                        dashboard.add_log(summary, "INFO")

                    await asyncio.sleep(5)
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error(f"confirm_drainer FATAL: {e}", exc_info=True)
            finally:
                try:
                    await confirm_validator.close()
                except Exception:
                    pass
                logger.info("confirm_drainer остановлен")

        # --- Фоновый перебор эндпоинтов для UNVERIFIED ---
        async def unverified_drainer():
            """Берёт UNVERIFIED ключи и пробует дефолтные эндпоинты платформ.

            Многие UNVERIFIED ключи получили этот статус из-за неправильного
            base_url (например relay с api.vapi.ai). Этот drainer берёт
            дефолтный endpoint для платформы и пытается валидировать.
            """
            import sqlite3 as _sqlite3
            from types import SimpleNamespace
            unv_validator = AsyncValidator(db, dashboard)
            logger.info("unverified_drainer запущен")
            await asyncio.sleep(20)
            try:
                while not stop_event.is_set():
                    conn_raw = None
                    try:
                        conn_raw = _sqlite3.connect(db.db_path, timeout=5)
                        conn_raw.row_factory = _sqlite3.Row
                        rows = conn_raw.execute(
                            "SELECT * FROM leaked_keys "
                            "WHERE status='unverified' AND verified_time IS NULL "
                            "ORDER BY found_time ASC LIMIT 100"
                        ).fetchall()
                    finally:
                        if conn_raw:
                            conn_raw.close()

                    if not rows:
                        await asyncio.sleep(30)
                        continue

                    logger.info(f"unverified_drainer: взято {len(rows)} ключей")
                    sem_u = asyncio.Semaphore(20)
                    found_count = 0

                    async def check_one(row):
                        nonlocal found_count
                        async with sem_u:
                            r = dict(row)
                            plat = (r.get("platform") or "").lower()
                            # Только платформы с сетевым API
                            if plat in validator._UNVERIFIABLE:
                                # Пометить verified_time чтобы не брать снова
                                db.update_key_status(
                                    r["api_key"], KeyStatus.UNVERIFIED,
                                    "Платформа не поддерживает проверку")
                                return
                            # Дефолтный URL для платформы
                            default_url = config.default_base_urls.get(plat, "")
                            # Если base_url уже стоит — пробуем его
                            test_urls = []
                            if r.get("base_url"):
                                test_urls.append(r["base_url"])
                            if default_url and default_url not in test_urls:
                                test_urls.append(default_url)
                            if not test_urls:
                                db.update_key_status(
                                    r["api_key"], KeyStatus.UNVERIFIED,
                                    "Нет endpoint для проверки")
                                return

                            for url in test_urls:
                                result = SimpleNamespace(
                                    platform=plat,
                                    api_key=r["api_key"],
                                    base_url=url,
                                    source_url="",
                                    is_azure=(plat == "azure"),
                                    is_relay=(plat == "relay"),
                                    context="",
                                )
                                try:
                                    vr = await unv_validator.validate_single(result)
                                    if vr.status in (KeyStatus.VALID, KeyStatus.INVALID,
                                                      KeyStatus.QUOTA_EXCEEDED):
                                        balance_str = vr.info
                                        if vr.balance_usd > 0:
                                            balance_str = f"${vr.balance_usd:.2f}"
                                        db.update_key_status(
                                            r["api_key"], vr.status, balance_str,
                                            is_high_value=vr.is_high_value)
                                        if url != r.get("base_url"):
                                            # Обновить base_url на рабочий
                                            with db._lock:
                                                with db._get_connection() as conn:
                                                    conn.execute(
                                                        "UPDATE leaked_keys SET base_url=? WHERE api_key=?",
                                                        (url, r["api_key"]))
                                                    conn.commit()
                                        found_count += 1
                                        return
                                except Exception as e:
                                    logger.debug(f"unverified check error: {e}")
                            # Все URLs не сработали
                            db.update_key_status(
                                r["api_key"], KeyStatus.UNVERIFIED,
                                "Все endpoints не отвечают")

                    tasks = [check_one(r) for r in rows]
                    await asyncio.gather(*tasks, return_exceptions=True)

                    if found_count:
                        summary = f"unverified_drainer: найдено {found_count}/{len(rows)} ключей"
                        logger.info(summary)
                        if dashboard:
                            dashboard.add_log(summary, "INFO")
                    await asyncio.sleep(3)
            except asyncio.CancelledError:
                pass
            except Exception as e:
                logger.error(f"unverified_drainer FATAL: {e}", exc_info=True)
            finally:
                try:
                    await unv_validator.close()
                except Exception:
                    pass
                logger.info("unverified_drainer остановлен")

        # Запустить все три drainer'а параллельно
        drainer_task = asyncio.create_task(pending_drainer())
        confirm_task = asyncio.create_task(confirm_drainer())
        unverified_task = asyncio.create_task(unverified_drainer())

        try:
            while not stop_event.is_set():
                try:
                    # Пакетное получение задач из очереди (новые ключи от сканера)
                    batch = []
                    try:
                        while len(batch) < 50:
                            result = result_queue.get_nowait()
                            batch.append(result)
                    except sync_queue.Empty:
                        pass

                    if batch:
                        if dashboard:
                            dashboard.update_stats(queue_size=result_queue.qsize())
                        await validator.run_batch(batch)
                    else:
                        await asyncio.sleep(0.3)

                except Exception as e:
                    if dashboard:
                        dashboard.add_log(f"Ошибка проверки: {str(e)[:30]}", "ERROR")
                    await asyncio.sleep(1)
        finally:
            drainer_task.cancel()
            confirm_task.cancel()
            unverified_task.cancel()
            for t in (drainer_task, confirm_task, unverified_task):
                try:
                    await asyncio.wait_for(t, timeout=3)
                except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
                    pass
            await validator.close()
    
    # Запустить в новом цикле событий
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(async_worker())
    finally:
        loop.close()


def start_validators(
    result_queue: sync_queue.Queue,
    db: Database,
    stop_event: threading.Event,
    dashboard = None,
    num_workers: int = 1
) -> list:
    """
    Запустить потоки валидатора
    
    Примечание: благодаря использованию asyncio.Semaphore на 100 одновременных запросов,
    фактически достаточно 1 потока для обработки 100 одновременных запросов.
    В многопоточном режиме каждый поток запускает свой цикл событий.
    
    Args:
        result_queue: Очередь результатов (синхронная)
        db: Экземпляр базы данных
        stop_event: Событие остановки
        dashboard: UI-панель
        num_workers: Количество рабочих потоков (рекомендуется 1-2, так как внутри 100 одновременных запросов)
    
    Returns:
        Список потоков
    """
    threads = []
    
    # Фактически 1 поток + 100 одновременных запросов уже достаточно, но сохраняется совместимость с многопоточным интерфейсом
    actual_workers = min(num_workers, 2)  # Максимум 2, чтобы избежать траты ресурсов
    
    for i in range(actual_workers):
        thread = threading.Thread(
            target=_validator_thread_worker,
            args=(result_queue, db, stop_event, dashboard),
            name=f"AsyncValidator-{i}",
            daemon=True
        )
        thread.start()
        threads.append(thread)
    
    if dashboard:
        dashboard.add_log(f"Запущено {actual_workers} асинхронных валидаторов (100 одновременных/каждый)", "INFO")

    return threads


# ============================================================================
#                     Экспорт оптимизированной версии v2.1
# ============================================================================

# Экспорт оптимизированного валидатора (с использованием пула соединений и интеллектуальных повторных попыток)
try:
    from validator_optimized import OptimizedAsyncValidator
    __all__ = ['AsyncValidator', 'OptimizedAsyncValidator', 'start_validators',
               'ValidationResult', 'CircuitBreaker', 'circuit_breaker', 'mask_key',
               'MAX_CONCURRENCY', 'REQUEST_TIMEOUT', 'HIGH_VALUE_MODELS',
               'RPM_ENTERPRISE_THRESHOLD', 'RPM_FREE_TRIAL_THRESHOLD']
except ImportError:
    # Если модуль оптимизации недоступен, экспортировать только исходную версию
    __all__ = ['AsyncValidator', 'start_validators', 'ValidationResult',
               'CircuitBreaker', 'circuit_breaker', 'mask_key',
               'MAX_CONCURRENCY', 'REQUEST_TIMEOUT', 'HIGH_VALUE_MODELS',
               'RPM_ENTERPRISE_THRESHOLD', 'RPM_FREE_TRIAL_THRESHOLD']
    logger.warning("Модуль оптимизации v2.1 недоступен, используется исходный валидатор")
