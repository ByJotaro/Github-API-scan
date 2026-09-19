"""
Модуль конфигурации - централизованное управление всеми параметрами

Данный модуль предоставляет:
- Настройки прокси (обязательно для континентального Китая)
- Пул GitHub Token (ротация нескольких токенов)
- Библиотеку регулярных выражений
- URL по умолчанию для платформ
"""

import os
import re
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, FrozenSet


# ============================================================================
#                          Конфигурация Прерывателя цепи (Circuit Breaker)
# ============================================================================

# Белый список защищённых доменов - никогда не отключаются
PROTECTED_DOMAINS: FrozenSet[str] = frozenset({
    # Официальные API
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    # Суффиксы доменов Azure
    "openai.azure.com",
    # Загрузка файлов GitHub
    "github.com",
    "raw.githubusercontent.com",
})

# HTTP-коды ошибок приложения - не вызывают отключение (связь с сервером в норме)
SAFE_HTTP_STATUS_CODES: FrozenSet[int] = frozenset({
    400,  # Bad Request - неверный формат запроса
    401,  # Unauthorized - невалидный ключ
    403,  # Forbidden - недостаточно прав
    404,  # Not Found - конечная точка не найдена
    422,  # Unprocessable Entity - неверные параметры запроса
    429,  # Rate Limit - превышен лимит запросов
})

# HTTP-коды ошибок шлюза - вызывают отключение (сервис недоступен)
CIRCUIT_BREAKER_HTTP_CODES: FrozenSet[int] = frozenset({
    502,  # Bad Gateway
    503,  # Service Unavailable
    504,  # Gateway Timeout
})

# Параметры Прерывателя цепи
CIRCUIT_BREAKER_FAILURE_THRESHOLD = 50  # Порог последовательных неудач (высокий: сканируем тысячи ключей)
CIRCUIT_BREAKER_RECOVERY_TIMEOUT = 30   # Время восстановления Прерывателя цепи (сек)
CIRCUIT_BREAKER_HALF_OPEN_REQUESTS = 10 # Количество пробных запросов в полузакрытом состоянии


# ============================================================================
#                              Библиотека регулярных выражений
# ============================================================================

REGEX_PATTERNS = {
    # ============================================================================
    #                          Основные ИИ-платформы (высокий приоритет)
    # ============================================================================

    # NOTE: stability (sk-) и promptlayer (pl-) НЕ имеют уникального prefix
    # (делят с openai/пр.) — regex-детекция даёт коллизии/FP. Они покрываются
    # только через dorks (STABILITY_API_KEY, ...) + валидацию через
    # _validate_simple_account, когда base_url содержит их домен.

    # OpenAI: стандартный ключ (sk-xxx) и ключ проекта (sk-proj-xxx)
    # Новый формат: sk-proj-xxx (ключ проекта), sk-svcacct-xxx (сервисный аккаунт)
    "openai": r'(?<!example_)(?<!test_)(?<!demo_)(?<!fake_)(?<!sample_)(?<!dev_)(?<!staging_)sk-(?:proj-|svcacct-)?(?!(?:placeholder|example|test|demo|your|xxx|fake|sample|dev|staging|sandbox|xxxxxx|abcdef|123456|insert|replace))[a-zA-Z0-9\-_]{20,}',

    # Google Gemini / Google AI Studio: начинается с AIza, 39 символов
    "gemini": r'(?<!test)(?<!example)(?<!sample)(?<!dev)AIza[0-9A-Za-z\-_]{35}',

    # Anthropic Claude: начинается с sk-ant-
    "anthropic": r'(?<!example_)(?<!test_)(?<!dev_)(?<!staging_)sk-ant-(?!(?:api0|xxx|test|demo|example|sample|dev|staging|sandbox|placeholder))[a-zA-Z0-9\-_]{20,}',

    # Azure OpenAI: 32-значный шестнадцатеричный код
    "azure": r'(?<![a-f0-9])(?!0{32})(?!f{32})(?!a{32})(?!e{32})[a-f0-9]{32}(?![a-f0-9])',

    # ============================================================================
    #                          Новые ИИ-платформы (средний приоритет)
    # ============================================================================

    # HuggingFace: начинается с hf_
    "huggingface": r'hf_[a-zA-Z0-9]{34,}',

    # Groq: начинается с gsk_, 52 символа
    "groq": r'gsk_[a-zA-Z0-9]{52}',

    # DeepSeek: начинается с sk-, 48+ символов (отличается от OpenAI по длине)
    "deepseek": r'sk-[a-zA-Z0-9]{48,}',

    # Cohere: 40-символьный Base64
    "cohere": r'(?<!test)(?<!example)[a-zA-Z0-9]{40}(?=.*cohere)',

    # Mistral AI: 32 символа
    "mistral": r'(?<!test)(?<!example)[a-zA-Z0-9]{32}(?=.*mistral)',

    # Together AI: 64-символьный шестнадцатеричный код
    "together": r'[a-f0-9]{64}(?=.*together)',

    # Replicate: начинается с r8_
    "replicate": r'r8_[a-zA-Z0-9]{37,}',

    # Perplexity: начинается с pplx-
    "perplexity": r'pplx-[a-zA-Z0-9]{48,}',

    # Fireworks AI: начинается с fw_
    "fireworks": r'fw_[a-zA-Z0-9]{40,}',

    # Anyscale: начинается с esecret_
    "anyscale": r'esecret_[a-zA-Z0-9]{40,}',

    # xAI (Grok): начинается с xai-
    "xai": r'xai-[a-zA-Z0-9\-]{40,}',

    # OpenRouter: начинается с sk-or-v1-
    "openrouter": r'sk-or-v1-[a-zA-Z0-9]{40,}',

    # Cerebras: начинается с csk-
    "cerebras": r'csk-[a-zA-Z0-9]{40,}',

    # Voyage AI: начинается с va-
    "voyage": r'va-[a-zA-Z0-9]{40,}',

    # Jina AI: начинается с jina_
    "jina": r'jina_[a-zA-Z0-9]{40,}',

    # Lepton AI: начинается с lep-
    "lepton": r'lep-[a-zA-Z0-9]{40,}',

    # Modal: начинается с ak-
    "modal": r'ak-[a-zA-Z0-9]{40,}',

    # ============================================================================
    #                          GitHub API токены
    # ============================================================================
    # Personal access token (classic): ghp_xxxxxxxxxxxx
    # Fine-grained personal access token: github_pat_xxxxxxxx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    # OAuth access token: gho_xxxxxxxxxxxx
    # User-to-server token: ghu_xxxxxxxxxxxx
    # Server-to-server token: ghs_xxxxxxxxxxxx
    # Refresh token: ghr_xxxxxxxxxxxx
    "github": r'ghp_[a-zA-Z0-9_]{36,}|github_pat_[a-zA-Z0-9_]{22,}_[a-zA-Z0-9]{59,}|gh[ours]_[a-zA-Z0-9_]{36,}',

    # ============================================================================
    #                          API облачных провайдеров (низкий приоритет)
    # ============================================================================

    # AWS Access Key: начинается с AKIA, 20 символов
    "aws_access_key": r'AKIA[0-9A-Z]{16}',

    # AWS Secret Key: standalone 40-char base64 candidate; scanner applies
    # an AWS/secret/access-key context guard before accepting it.
    "aws_secret_key": r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',

    # Steam Web API Key: 32-значный шестнадцатеричный код
    "steam": r'(?<![A-F0-9])[0-9A-F]{32}(?![A-F0-9])(?=.*steam)',

    # ============================================================================
    #                          Китайские AI-провайдеры
    # ============================================================================

    # Zhipu GLM (Z.ai): OpenAI-совместимый sk-
    "zhipu": r'(?<!test)(?<!example)sk-[a-zA-Z0-9]{40,}(?=.*(?:zhipu|z\.ai|bigmodel))',

    # 01.AI (Yi): OpenAI-совместимый sk-
    "yi": r'(?<!test)(?<!example)sk-[a-zA-Z0-9]{40,}(?=.*(?:yi|01\.ai|lingyiwanwu))',

    # Baichuan: OpenAI-совместимый sk-
    "baichuan": r'(?<!test)(?<!example)sk-[a-zA-Z0-9]{40,}(?=.*(?:baichuan))',

    # Moonshot (Kimi): OpenAI-совместимый sk-
    "moonshot": r'(?<!test)(?<!example)sk-[a-zA-Z0-9]{40,}(?=.*(?:moonshot|kimi))',

    # StepFun: OpenAI-совместимый sk-
    "stepfun": r'(?<!test)(?<!example)sk-[a-zA-Z0-9]{40,}(?=.*(?:stepfun))',

    # Minimax: JWT eyJ
    "minimax": r'eyJ[a-zA-Z0-9\-_]{40,}(?=.*minimax)',

    # SiliconFlow: sk- + siliconflow context
    "siliconflow": r'(?<!test)(?<!example)sk-[a-zA-Z0-9]{40,}(?=.*(?:siliconflow))',

    # DashScope (Alibaba Qwen): sk- + dashscope context
    "dashscope": r'(?<!test)(?<!example)sk-[a-zA-Z0-9]{40,}(?=.*(?:dashscope|aliyun))',

    # Volcengine (ByteDance): sk- + volces context
    "volcengine": r'(?<!test)(?<!example)sk-[a-zA-Z0-9]{40,}(?=.*(?:volces|volcengine))',

    # InternLM: sk- + intern context
    "internlm": r'(?<!test)(?<!example)sk-[a-zA-Z0-9]{40,}(?=.*(?:intern-ai|internlm))',

    # ============================================================================
    #                          VPS и облачные провайдеры
    # ============================================================================

    # DigitalOcean: dop_v1_
    "digitalocean": r'dop_v1_[a-zA-Z0-9]{64,}',

    # Linode/Akamai: 64 hex
    "linode": r'(?<![a-f0-9])[a-f0-9]{64}(?![a-f0-9])(?=.*linode)',

    # Vultr: 36 hex
    "vultr": r'(?<![a-f0-9])[a-f0-9]{36}(?![a-f0-9])(?=.*vultr)',

    # Hetzner: Bearer token
    "hetzner": r'(?<!test)(?<!example)[a-zA-Z0-9]{64}(?=.*hetzner)',

    # Scaleway: SCW
    "scaleway": r'SCW[a-zA-Z0-9]{40,}',

    # ============================================================================
    #                          GPU Cloud провайдеры
    # ============================================================================

    # RunPod: RPv2:
    "runpod": r'RPv2:[a-zA-Z0-9\-]{40,}',

    # Lambda Labs: sk_live_
    "lambdalabs": r'sk_live_[a-zA-Z0-9]{40,}',

    # CoreWeave: Bearer
    "coreweave": r'(?<!test)(?<!example)[a-zA-Z0-9]{64}(?=.*coreweave)',

    # Shadeform: sf_
    "shadeform": r'sf_[a-zA-Z0-9]{40,}',

    # ============================================================================
    #                          Расширенный каталог AI (2025-2026)
    #   Реестр метаданных — см. EXTRA_PROVIDERS ниже. prefix-детектируемые.
    # ========================================================================

    # ElevenLabs (Voice): sk_ + 32 символа
    "elevenlabs": r'sk_[a-zA-Z0-9]{32}',

    # (stability/promptlayer определены в начале, до openai — см. выше)

    # Tavily (Search/RAG): tvly-
    "tavily": r'tvly-[a-zA-Z0-9]{30,}',

    # --- Категория B: RAG + Browser ---
    # Firecrawl: fc-
    "firecrawl": r'fc-[a-zA-Z0-9]{30,}',
    # Apify: apify_api_
    "apify": r'apify_api_[a-zA-Z0-9]{20,}',

    # --- Категория C: LLM Ops + Vector + Code + Agents ---
    # LangFuse: sk-lf- / pk-lf-
    "langfuse": r'(?:sk|pk)-lf-[a-zA-Z0-9]{30,}',
    # Astra DB (DataStax): AstraCS:
    "astra": r'AstraCS:[a-zA-Z0-9]{30,}',
    # Sourcegraph Cody: sgp_
    "sourcegraph": r'sgp_[a-zA-Z0-9]{30,}',
    # Wordware: ww_
    "wordware": r'ww_[a-zA-Z0-9]{30,}',
    # LlamaIndex Cloud: llc- / llx-
    "llamacloud": r'll[xc]-[a-zA-Z0-9]{30,}',
}

COMPILED_REGEX_PATTERNS: Dict[str, re.Pattern] = {
    platform: re.compile(pattern)
    for platform, pattern in REGEX_PATTERNS.items()
}

# ============================================================================
#   Реестр метаданных расширенных провайдеров (единый источник auth/endpoint).
#   validator.py читает отсюда header/auth_scheme/path для _validate_simple_account.
#   Поля: domain, url, auth ('bearer'|'token'|'basic'|'apikey'|'custom'),
#   header (имя header для custom/apikey), path (проверочный путь), high_value.
# ============================================================================
EXTRA_PROVIDERS: Dict[str, dict] = {
    # --- Категория A: Voice + Image/Video ---
    "elevenlabs": {"domain": "elevenlabs.io",
                   "url": "https://api.elevenlabs.io/v1",
                   "auth": "apikey", "header": "xi-api-key",
                   "path": "/user", "high_value": True},
    "stability": {"domain": "stability.ai",
                  "url": "https://api.stability.ai/v2beta",
                  "auth": "bearer", "path": "/account", "high_value": True},
    "heygen": {"domain": "heygen.com",
               "url": "https://api.heygen.com/v2",
               "auth": "custom", "header": "X-Api-Key",
               "path": "/user", "high_value": True},
    "runway": {"domain": "runwayml.com",
               "url": "https://api.dev.runwayml.com/v1",
               "auth": "bearer", "path": "/users", "high_value": True},
    "tavily": {"domain": "tavily.com",
               "url": "https://api.tavily.com",
               "auth": "bearer", "path": "/usage", "high_value": True},
    # --- Категория B: RAG + Browser ---
    "firecrawl": {"domain": "firecrawl.dev",
                  "url": "https://api.firecrawl.dev/v1",
                  "auth": "bearer", "path": "", "high_value": True},
    "apify": {"domain": "apify.com",
              "url": "https://api.apify.com/v2",
              "auth": "bearer", "path": "/users/me", "high_value": False},
    "promptlayer": {"domain": "promptlayer.com",
                    "url": "https://api.promptlayer.com",
                    "auth": "bearer", "path": "/rest/track-request",
                    "high_value": False},
    # exa — dorks-only (нет уникального prefix)
    # --- Категория C: LLM Ops + Vector + Code + Agents ---
    "langfuse": {"domain": "langfuse.com",
                 "url": "https://cloud.langfuse.com/api/public",
                 "auth": "basic", "path": "/projects", "high_value": True},
    "astra": {"domain": "datastax.com",
              "url": "https://api.astra.datastax.com/v2",
              "auth": "bearer", "path": "", "high_value": True},
    "sourcegraph": {"domain": "sourcegraph.com",
                    "url": "https://sourcegraph.com/.api",
                    "auth": "token", "path": "/users", "high_value": False},
    "wordware": {"domain": "wordware.ai",
                 "url": "https://app.wordware.ai/api",
                 "auth": "bearer", "path": "", "high_value": False},
    # llamacloud — OpenAI-compat: validate через validate_openai (не в EXTRA_PROVIDERS)
}

# Регулярное выражение для распознавания Azure
AZURE_URL_PATTERN = r'https://[\w\-]+\.openai\.azure\.com'
AZURE_CONTEXT_KEYWORDS = ['azure', 'openai.azure.com', 'azure_endpoint', 'AZURE_OPENAI']

# Регулярные выражения для извлечения Base URL (для контекстного анализа)
BASE_URL_PATTERNS = [
    # Присвоение URL с именем переменной (расширенный список имён)
    r'(?:base_url|api_base|OPENAI_API_BASE|OPENAI_BASE_URL|OPENAI_API_BASE_URL|'
    r'ANTHROPIC_API_BASE|ANTHROPIC_BASE_URL|'
    r'host|endpoint|api_endpoint|API_URL|API_ENDPOINT|'
    r'BASE_API_URL|LLM_BASE_URL|MODEL_API_BASE|'
    r'proxy_url|PROXY|OPENAI_PROXY|'
    r'API_BASE_URL|api_host|server_url|service_url)\s*[=:]\s*["\']?(https?://[^\s"\'<>]+)["\']?',
    # Универсальный HTTP URL
    r'(https?://[a-zA-Z0-9\-_.]+(?::\d+)?(?:/[a-zA-Z0-9\-_./]*)?)',
]

# Приоритет ключевых слов URL (для сортировки извлечённых URL)
URL_PRIORITY_KEYWORDS = ['base', 'api', 'host', 'endpoint', 'proxy', 'openai', 'relay', 'anthropic', 'llm', 'model']

COMPILED_BASE_URL_PATTERNS = [re.compile(p, re.IGNORECASE | re.MULTILINE) for p in BASE_URL_PATTERNS]
COMPILED_AZURE_URL_PATTERN = re.compile(AZURE_URL_PATTERN, re.IGNORECASE)


# ============================================================================
#                              Класс конфигурации
# ============================================================================

@dataclass
class Config:
    """
    Глобальный класс конфигурации
    
    Основные параметры:
    - proxy_url: адрес прокси (обязательно для континентального Китая)
    - github_tokens: список GitHub Token
    """
    
    # ==================== Настройки прокси ====================
    # Режим прямого подключения (без прокси)
    # Для использования прокси установите переменную окружения PROXY_URL или измените здесь
    proxy_url: str = field(
        default_factory=lambda: os.getenv("PROXY_URL", "")  # Режим прямого подключения
    )
    
    # ==================== Пул GitHub Token ====================
    # Ротация нескольких токенов позволяет эффективно обходить лимиты запросов
    # Без аутентификации: 10 запросов/мин, с аутентификацией: 30 запросов/мин
    # Несколько токенов значительно ускоряют сканирование
    # 
    # Способы настройки:
    # 1. Добавить токены напрямую в этот список (не рекомендуется, легко утечь)
    # 2. Установить переменную окружения GITHUB_TOKENS (рекомендуется, через запятую)
    # 3. Создать config_local.py для переопределения (рекомендуется)
    github_tokens: List[str] = field(default_factory=lambda: (
        # Сначала читаем из переменных окружения
        os.getenv("GITHUB_TOKENS", "").split(",") if os.getenv("GITHUB_TOKENS") else [
            # ===== По умолчанию пусто, настройте через переменную окружения или config_local.py =====
            # Пример формата:
            # "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            # "ghp_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
        ]
    ))
    
    # Индекс ротации Token
    _token_index: int = 0
    
    # ==================== Конфигурация базы данных ====================
    db_path: str = "leaked_keys.db"

    # ==================== Конфигурация Pastebin ====================
    # Pastebin Pro API Key (опционально, для Scraping API)
    # Бесплатные пользователи могут не настраивать, но эффективность сканирования ниже
    pastebin_api_key: str = field(
        default_factory=lambda: os.getenv("PASTEBIN_API_KEY", "")
    )
    
    # ==================== Конфигурация потоков ====================
    consumer_threads: int = 20  # Количество потоков валидатора (IO-интенсивные задачи, можно больше)

    # ==================== Сетевая конфигурация ====================
    request_timeout: int = 15  # Тайм-аут HTTP-запроса (сек)

    # ==================== Конфигурация Прерывателя цепи ====================
    circuit_breaker_enabled: bool = True  # Включить ли Прерыватель цепи

    # ==================== Конфигурация валидации (повторные попытки) ====================
    # Число повторных попыток при транзитных ошибках (тайм-аут/соединение/5xx).
    # Раньше один тайм-аут навсегда помечал ключ как connection_error.
    validator_max_retries: int = 3
    # Базовая задержка между попытками (сек), удваивается каждый раз (экспоненциальный backoff)
    validator_retry_backoff: float = 1.5
    # Пере-проверять ключи со статусом connection_error/pending при повторном обнаружении
    revalidate_failed_keys: bool = True

    # ==================== Конфигурация сканирования ====================
    context_window: int = 10  # Окно контекста (N строк до и после)

    # Интервал повторного сканирования ключевых слов (часов).
    # Ключевые слова, полностью просканированные позже этого срока, при рестарте
    # пропускаются БЕЗ запросов к GitHub API (возобновление с последней точки).
    # 0 = всегда перепроверять (поведение старой версии).
    rescan_interval_hours: int = 24
    
    # Ключевые слова для поиска - режим снайперского поиска (Sniper Dorks) v2.0
    # Стратегия: точные имена файлов + исключение тестов/примеров + мультиплатформенное покрытие
    search_keywords: List[str] = field(default_factory=lambda: [
        # ============================================================================
        #                          1. Высокоценные цели OpenAI
        # ============================================================================
        'filename:.env OPENAI_API_KEY NOT staging NOT sandbox NOT example',
        'filename:.env.local OPENAI_API_KEY NOT test',
        'filename:.env.production OPENAI_API_KEY',
        'filename:.env.prod OPENAI_API_KEY',
        'filename:secrets.yaml openai_api_key NOT example',
        'filename:secrets.json OPENAI_API_KEY NOT test',
        'filename:config.json sk-proj- NOT example NOT test',
        'sk-proj- language:python NOT test NOT example NOT mock NOT staging',
        'sk-proj- language:javascript NOT test NOT example NOT mock',
        '"Authorization: Bearer sk-" NOT test NOT example',
        'OPENAI_API_KEY= sk- NOT test NOT example NOT staging',

        # ============================================================================
        #                          2. Anthropic Claude
        # ============================================================================
        'filename:.env ANTHROPIC_API_KEY NOT staging NOT example',
        'filename:.env CLAUDE_API_KEY NOT sandbox NOT test',
        'filename:.env.production ANTHROPIC_API_KEY',
        'sk-ant-api03 NOT test NOT example NOT staging',
        '"x-api-key" sk-ant- NOT test NOT example',
        'anthropic_api_key language:python NOT test NOT example',

        # ============================================================================
        #                          3. Google Gemini / AI Studio
        # ============================================================================
        'filename:.env GEMINI_API_KEY NOT test NOT example',
        'filename:.env GOOGLE_AI_KEY NOT staging',
        'AIzaSy language:json NOT example NOT test NOT dev',
        'AIzaSy language:python NOT test NOT example',
        'generativelanguage.googleapis.com key= NOT test',

        # ============================================================================
        #                          4. Azure OpenAI
        # ============================================================================
        'filename:.env AZURE_OPENAI_API_KEY NOT staging NOT example',
        'filename:.env AZURE_OPENAI_KEY NOT test',
        'openai.azure.com api-key NOT example NOT test NOT staging',
        'AZURE_OPENAI_ENDPOINT language:python NOT test',

        # ============================================================================
        #                          5. Ретранслятор / One-API / New-API
        # ============================================================================
        'filename:.env OPENAI_BASE_URL NOT sandbox NOT example',
        'filename:.env BASE_URL openai NOT staging NOT test',
        'filename:config.py ONEAPI NOT test',
        'filename:config.py one-api NOT example',
        'new-api sk- NOT test NOT demo NOT example',
        'one-api sk- NOT test NOT demo',
        'api.openai-proxy sk- NOT test',

        # ============================================================================
        #                          6. HuggingFace
        # ============================================================================
        'filename:.env HUGGINGFACE_API_KEY NOT test NOT example',
        'filename:.env HF_TOKEN NOT staging',
        'filename:.env HUGGINGFACE_TOKEN NOT test',
        'hf_ language:python NOT test NOT example NOT mock',
        '"Authorization: Bearer hf_" NOT test',

        # ============================================================================
        #                          7. Groq
        # ============================================================================
        'filename:.env GROQ_API_KEY NOT test NOT example',
        'gsk_ language:python NOT test NOT example',
        'api.groq.com Authorization NOT test',

        # ============================================================================
        #                          8. DeepSeek
        # ============================================================================
        'filename:.env DEEPSEEK_API_KEY NOT test NOT example',
        'api.deepseek.com sk- NOT test NOT example',
        'deepseek language:python sk- NOT test',

        # ============================================================================
        #                          9. Новые ИИ-платформы
        # ============================================================================
        # Cohere
        'filename:.env COHERE_API_KEY NOT test NOT example',
        'cohere.ai api-key NOT test',

        # Mistral
        'filename:.env MISTRAL_API_KEY NOT test NOT example',
        'api.mistral.ai NOT test NOT example',

        # Together AI
        'filename:.env TOGETHER_API_KEY NOT test',
        'api.together.xyz NOT test NOT example',

        # Replicate
        'filename:.env REPLICATE_API_TOKEN NOT test',
        'r8_ language:python NOT test NOT example',

        # Perplexity
        'filename:.env PERPLEXITY_API_KEY NOT test',
        'pplx- language:python NOT test',

        # Fireworks
        'filename:.env FIREWORKS_API_KEY NOT test',
        'fw_ language:python NOT test NOT example',

        # ============================================================================
        #                          10. API облачных провайдеров
        # ============================================================================
        # AWS
        'filename:.env AWS_ACCESS_KEY_ID NOT test NOT example NOT staging',
        'filename:.env AWS_SECRET_ACCESS_KEY NOT test NOT example',
        'AKIA language:python NOT test NOT example NOT mock',

        # Steam Web API
        'filename:.env STEAM_API_KEY NOT test NOT example',
        'STEAM_WEB_API_KEY extension:env NOT test',

        # ============================================================================
        #                          11. Высокоценные пути к файлам
        # ============================================================================
        'path:deploy/ .env NOT test NOT example',
        'path:production/ .env NOT staging',
        'path:config/ secrets NOT test NOT example',
        'path:scripts/ api_key NOT test NOT example',
        'filename:docker-compose.yml OPENAI NOT test',
        'filename:docker-compose.yml API_KEY NOT example',
        'filename:Dockerfile ENV OPENAI NOT test',

        # ============================================================================
        #                          12. Новые AI-провайдеры
        # ============================================================================
        # xAI (Grok)
        'filename:.env XAI_API_KEY NOT test NOT example',
        'xai- extension:env NOT test',

        # OpenRouter
        'filename:.env OPENROUTER_API_KEY NOT test NOT example',
        'sk-or-v1- extension:env NOT test',

        # Cerebras
        'filename:.env CEREBRAS_API_KEY NOT test NOT example',
        'csk- extension:env NOT test',

        # Voyage AI
        'filename:.env VOYAGE_API_KEY NOT test NOT example',
        'va- extension:env NOT test',

        # Jina AI
        'filename:.env JINA_API_KEY NOT test NOT example',
        'jina_ extension:env NOT test',

        # Lepton AI
        'filename:.env LEPTON_API_KEY NOT test NOT example',
        'lep- extension:env NOT test',

        # ============================================================================
        #                          13. Steam Web API
        # ============================================================================
        'filename:.env STEAM_API_KEY NOT test NOT example',
        'filename:.env STEAM_WEB_API_KEY NOT test NOT example',

        # ============================================================================
        #                          14. Комбо-запросы (максимальный recall)
        # ============================================================================
        # Один запрос находит ключи нескольких провайдеров
        '"sk-proj-" OR "sk-ant-" OR "pplx-" OR "gsk_" OR "hf_" OR "r8_" OR "xai-" filename:.env',
        'filename:.env OPENAI_API_KEY OR ANTHROPIC_API_KEY OR GEMINI_API_KEY OR DEEPSEEK_API_KEY',
        'filename:.env.local "sk-proj-" OR "AIza" OR "sk-ant-"',
        '"sk-proj-" extension:env -path:test -path:example -path:docs',

        # ============================================================================
        #          15. Мега-комбо: все AI-провайдеры (максимальный coverage)
        # ============================================================================
        '"sk-proj-" OR "sk-ant-" OR "AIza" OR "gsk_" OR "pplx-" OR "hf_" OR "xai-" OR "sk-or-v1-" OR "csk-" OR "va-" OR "jina_" OR "fw_" OR "r8_" OR "lep_" OR "esecret_" filename:.env',
        '"sk-proj-" OR "sk-ant-" OR "AIza" OR "gsk_" OR "pplx-" OR "hf_" OR "xai-" OR "sk-or-v1-" OR "csk-" OR "fw_" OR "r8_" OR "lep_" extension:env -path:test -path:example -path:docs',

        # ============================================================================
        #          16. Китайские AI-провайдеры (низкая конкуренция)
        # ============================================================================
        '"open.bigmodel.cn" "sk-" language:python',
        '"open.bigmodel.cn" "sk-" extension:env',
        '"dashscope" "sk-" extension:env',
        '"siliconflow" "sk-" language:python',
        '"siliconflow" "sk-" extension:env',
        '"moonshot.cn" "sk-" extension:env',
        '"baichuan-ai" "sk-" extension:env',
        '"lingyiwanwu" "sk-" extension:env',
        '"stepfun.com" "sk-" extension:env',
        '"volces.com" "ark" "sk-" extension:env',
        '"intern-ai.org.cn" "sk-" extension:env',
        '"minimax.chat" "Bearer eyJ" extension:env',

        # ============================================================================
        #          17. GPU-облака (высокая ценность — compute ресурсы)
        # ============================================================================
        '"RPv2:" extension:env NOT test',
        '"RPv2:" language:python NOT test',
        '"sk_live_" lambdalabs extension:env NOT test',
        '"sk_live_" "lambda" extension:env NOT test',
        '"sf_" shadeform extension:env NOT test',
        '"dop_v1_" extension:env NOT test',
        '"SCW" scaleway extension:env NOT test',
        '"LTAI" alibaba extension:env NOT test',
        '"AKID" tencent extension:env NOT test',

        # ============================================================================
        #          18. AI-инфраструктура: прокси и шлюзы (master-ключи)
        # ============================================================================
        '"LITELLM_MASTER_KEY" "sk-" NOT test',
        '"LITELLM_MASTER_KEY" extension:env NOT test',
        '"one-api" "SESSION_SECRET" NOT test',
        '"new-api" "ROOT_KEY" NOT test',
        '"new-api" "REDIS_CONN" filename:.env NOT test',
        '"fastgpt" "ROOT_KEY" NOT test',
        '"dify" "SECRET_KEY" NOT test',
        '"helicone" "sk-" extension:env NOT test',
        '"portkey" "pk-" extension:env NOT test',
        '"langsmith" "lsv2_pt_" NOT test',

        # ============================================================================
        #          19. AI фреймворки (часто с ключами в коде)
        # ============================================================================
        '"from langchain" "OPENAI_API_KEY" extension:py',
        '"from llama_index" "OPENAI_API_KEY" extension:ipynb',
        '"crewai" "OPENAI_API_KEY" extension:py',
        '"autogen" "AZURE_OPENAI" language:python',
        '"langflow" "API_KEY" NOT test',
        '"from autogen" "OPENAI_API_KEY" extension:py',
        '"from crewai" "OPENAI_API_KEY" extension:py',

        # ============================================================================
        #          20. Jupyter notebooks (кладбище ключей)
        # ============================================================================
        'extension:ipynb "sk-proj-" OR "sk-ant-" OR "AIza" OR "OPENAI_API_KEY"',
        'extension:ipynb "os.environ" "OPENAI_API_KEY"',
        'extension:ipynb "getpass" "sk-"',
        'extension:ipynb "api_key" "sk-" OR "AIza" OR "gsk_"',
        'extension:ipynb "from transformers" "HUGGINGFACE" OR "hf_"',

        # ============================================================================
        #          21. Docker/Deploy с секретами
        # ============================================================================
        'filename:docker-compose.yml "OPENAI_API_KEY" OR "ANTHROPIC_API_KEY" OR "GEMINI"',
        'filename:docker-compose.yml "LITELLM_MASTER_KEY" OR "sk-" OR "AIza"',
        'filename:Dockerfile "ENV" "API_KEY" NOT test',
        'filename:appsettings.json "ApiKey" OR "OpenAI" NOT test',

        # ============================================================================
        #          22. Конфиги и секреты
        # ============================================================================
        'filename:config.json "api_key" "sk-" NOT test',
        'filename:settings.py "API_KEY" "sk-proj-" NOT test',
        'filename:credentials.json "private_key" NOT test',
        'filename:secrets.json "OPENAI" OR "ANTHROPIC" NOT test',
        'filename:api-keys.json "sk-" OR "AIza" NOT test',

        # ============================================================================
        #          23. Свежие утечки (последние 30 дней)
        # ============================================================================
        '"sk-proj-" extension:env pushed:>2026-05-18 -path:test -path:example',
        '"sk-ant-" extension:env pushed:>2026-05-18 -path:test',
        '"AIza" extension:env pushed:>2026-05-18 -path:test',
        '"gsk_" extension:env pushed:>2026-05-18',
        '"sk-or-v1-" extension:env pushed:>2026-05-18',

        # ============================================================================
        #          24. Новички (stars < 10) — выше шанс активного ключа
        # ============================================================================
        '"sk-proj-" extension:env stars:<10',
        '"AIza" extension:env stars:<10',
        '"sk-ant-" extension:env stars:<10',

        # ============================================================================
        #          25. Commit messages с ключами
        # ============================================================================
        '"add api key" "sk-proj-"',
        '"add openai" ".env"',
        '"fix api key" "sk-ant-"',
        '"update config" "AIza"',
        '"initial commit" "OPENAI_API_KEY"',

        # ============================================================================
        #          26. Telegram/Discord боты + AI
        # ============================================================================
        '"telegram" "OPENAI_API_KEY" language:python NOT test',
        '"discord" "ANTHROPIC_API_KEY" language:javascript NOT test',
        '"aiogram" "sk-proj-" extension:py',
        '"python-telegram-bot" "OPENAI_API_KEY"',

        # ============================================================================
        #          27. SaaS boilerplates
        # ============================================================================
        '"saas-starter" "OPENAI_API_KEY" language:typescript',
        '"nextjs-boilerplate" "API_KEY" NOT test',
        '"supabase" "openai" "sk-" filename:.env',
        '"gradio" "HUGGINGFACE" OR "OPENAI" extension:py',
        '"streamlit" "OPENAI_API_KEY" extension:py',
        '"fastapi" "OPENAI_API_KEY" extension:py NOT test',

        # ============================================================================
        #          28. Региональные облака (низкая конкуренция)
        # ============================================================================
        '"scaleway" "SCW" extension:env NOT test',
        '"hetzner" "api" extension:env NOT test',
        '"ovh" "api_key" extension:env NOT test',
        '"digitalocean" "dop_v1_" extension:env NOT test',
        '"vultr" "api" extension:env NOT test',
        '"linode" "api" extension:env NOT test',

        # ============================================================================
        #          29. Voice / Speech AI (низкая конкуренция, high-value)
        # ============================================================================
        'filename:.env ELEVENLABS_API_KEY NOT test NOT example',
        '"xi-api-key" "sk_" NOT test NOT example',
        'filename:.env DEEPGRAM_API_KEY NOT test',
        'filename:.env ASSEMBLYAI_API_KEY NOT test',
        'filename:.env PLAY_HT_API_KEY NOT test',
        'filename:.env REV_ACCESS_TOKEN NOT test',
        'filename:.env GLADIA_API_KEY NOT test',
        'filename:.env SPEECHMATICS_API_KEY NOT test',

        # ============================================================================
        #          30. Image / Video Generation (high-value)
        # ============================================================================
        'filename:.env STABILITY_API_KEY NOT test NOT example',
        '"sk-" "stability.ai" NOT test NOT example',
        'filename:.env LEONARDO_API_KEY NOT test',
        'filename:.env RUNWAYML_API_SECRET NOT test',
        'filename:.env LUMA_API_KEY NOT test',
        'filename:.env KLING_API_KEY NOT test',
        'filename:.env HEYGEN_API_KEY NOT test',
        'filename:.env SYNTHESIA_API_KEY NOT test',
        'filename:.env IDEOGRAM_API_KEY NOT test',
        '"FAL_KEY" extension:env NOT test',
        'filename:.env CLIPDROP_API_KEY NOT test',

        # ============================================================================
        #          31. RAG / Search AI (Vector DB + embeddings)
        # ============================================================================
        'filename:.env TAVILY_API_KEY NOT test NOT example',
        '"tvly-" extension:env NOT test',
        'filename:.env EXA_API_KEY NOT test',
        'filename:.env PINECONE_API_KEY NOT test',
        'filename:.env WEAVIATE_API_KEY NOT test',
        'filename:.env QDRANT_API_KEY NOT test',
        'filename:.env ZILLIZ_API_KEY NOT test',
        'filename:.env UPSTASH_VECTOR_TOKEN NOT test',
        '"mongodb+srv://" "cluster0" extension:env NOT test',

        # ============================================================================
        #          32. Browser / Scraping AI (низкая конкуренция)
        # ============================================================================
        'filename:.env FIRECRAWL_API_KEY NOT test NOT example',
        '"fc-" "firecrawl" NOT test NOT example',
        'filename:.env BROWSERBASE_API_KEY NOT test',
        'filename:.env SCRAPINGBEE_API_KEY NOT test',
        'filename:.env ZENROWS_API_KEY NOT test',
        'filename:.env BRIGHTDATA_TOKEN NOT test',
        '"apify_api_" extension:env NOT test',
        'filename:.env OXYLABS_API_KEY NOT test',

        # ============================================================================
        #          33. LLM Ops / Observability (ключи видят ВСЕ запросы)
        # ============================================================================
        'filename:.env LANGFUSE_SECRET_KEY NOT test NOT example',
        '"sk-lf-" extension:env NOT test',
        'filename:.env WANDB_API_KEY NOT test',
        'filename:.env LANGSMITH_API_KEY NOT test',
        '"lsv2_pt_" extension:env NOT test',
        'filename:.env HELICONE_API_KEY NOT test',
        'filename:.env PORTKEY_API_KEY NOT test',
        'filename:.env ARIZE_API_KEY NOT test',
        'filename:.env BRAINTRUST_API_KEY NOT test',
        'filename:.env HUMANLOOP_API_KEY NOT test',

        # ============================================================================
        #          34. Code AI + Agents + Workflow
        # ============================================================================
        'filename:.env CODEIUM_API_KEY NOT test',
        'filename:.env TABNINE_API_KEY NOT test',
        '"sgp_" extension:env NOT test',
        'filename:.env CREWAI_API_KEY NOT test',
        '"ww_" extension:env NOT test',
        'filename:.env COMPOSIO_API_KEY NOT test',
        'filename:.env N8N_API_KEY NOT test',
        'filename:.env FLOWISE NOT test',
        'filename:.env LANGFLOW_API_KEY NOT test',

        # ============================================================================
        #          35. Synthetic Data / Fine-tuning
        # ============================================================================
        'filename:.env GRETEL_API_KEY NOT test',
        'filename:.env SCALE_API_KEY NOT test',
        'filename:.env LABELBOX_API_KEY NOT test',
        'filename:.env MOSTLY_AI_API_KEY NOT test',

        # ============================================================================
        #          36. Gist-специфичные запросы (gist.github.com — высокая плотность ключей)
        # ============================================================================
        # GitHub используется is:gist для фильтрации gist-результатов.
        # Gists содержат ~10x больше ключей на единицу контента — люди копируют .env
        # напрямую без code review.
        'is:gist filename:.env "sk-proj-" OR "sk-ant-" OR "AIza"',
        'is:gist filename:.env OPENAI_API_KEY OR ANTHROPIC_API_KEY OR GEMINI',
        'is:gist "sk-proj-" extension:env -path:test -path:example',
        'is:gist "AIza" extension:env NOT test',
        'is:gist "sk-ant-" extension:env NOT test',
        'is:gist "gsk_" extension:env NOT test',
        'is:gist "pplx-" extension:env NOT test',
        'is:gist "sk-or-v1-" extension:env NOT test',
        'is:gist "hf_" extension:env NOT test',
        'is:gist "r8_" extension:env NOT test',
        'is:gist "xai-" extension:env NOT test',
        'is:gist "csk-" extension:env NOT test',
        'is:gist "ghp_" extension:env NOT test',
        'is:gist "LITELLM_MASTER_KEY" NOT test',
        'is:gist "ak-" extension:env NOT test',
        'is:gist "sk-live-" extension:env NOT test',
        'is:gist "sk_live_" extension:env NOT test',
        'is:gist "AKIA" extension:env NOT test',
        'is:gist "dop_v1_" extension:env NOT test',

        # ====================================================================
        #     Высокоприоритетные dorks: production/billing/paid configs
        # ====================================================================
        # Production .env files (выше шанс на реальные paid ключи)
        'path:production/ filename:.env sk- NOT test NOT example',
        'path:prod/ filename:.env OPENAI_API_KEY NOT test',
        'path:deploy/ filename:.env sk-proj- NOT example',
        'path:config/ filename:.env ANTHROPIC_API_KEY NOT test',
        'path:secrets/ filename:.env sk- NOT example NOT staging',
        'path:private/ filename:.env AIza NOT test',
        'path:credentials/ filename:.json sk-proj- NOT example',

        # Docker compose with real API keys (production setups)
        'filename:docker-compose.yml OPENAI_API_KEY NOT test NOT example',
        'filename:docker-compose.yaml ANTHROPIC_API_KEY NOT test',
        'filename:docker-compose.yml sk-proj- NOT example',
        'filename:docker-compose.yaml GEMINI_API_KEY NOT test',

        # Kubernetes secrets (production deployments)
        'filename:secret.yaml OPENAI_API_KEY NOT test',
        'filename:secret.yaml sk-proj- NOT example',
        'filename:secret.json ANTHROPIC_API_KEY NOT test',

        # Terraform / IaC with API keys
        'filename:.tf OPENAI_API_KEY NOT test NOT example',
        'filename:.tf ANTHROPIC_API_KEY NOT test',
        'filename:main.tf sk-proj- NOT example',
        'filename:variables.tf AIza NOT test',

        # Config files with multiple providers (high-value targets)
        'filename:config.yaml OPENAI_API_KEY ANTHROPIC_API_KEY NOT test',
        'filename:settings.py OPENAI_API_KEY NOT test NOT example',
        'filename:settings.json sk-proj- sk-ant- NOT example',
        'filename:constants.py OPENAI_API_KEY ANTHROPIC_API_KEY NOT test',
        'filename:constants.json sk-proj- NOT example',
        'filename:secrets.toml sk- NOT test NOT example',

        # LiteLLM / proxy configs (relay keys with base_url)
        'filename:litellm_config.yaml sk- NOT test',
        'filename:.litellm sk-proj- NOT example',
        'LITELLM_MASTER_KEY sk- NOT test NOT example',
        'filename:proxy_config.json sk-proj- NOT test',
        'filename:gateway_config.yaml sk- NOT example',

        # New AI providers (2024-2026 — less scanned, more likely to find)
        'filename:.env MISTRAL_API_KEY NOT test NOT example',
        'mistral_api_key language:python NOT test NOT example',
        'filename:.env TOGETHER_API_KEY NOT test',
        'filename:.env COHERE_API_KEY NOT test',
        'filename:.env FIREWORKS_API_KEY NOT test',
        'filename:.env REPLICATE_API_TOKEN NOT test',
        'filename:.env PERPLEXITY_API_KEY NOT test',
        'filename:.env DEEPSEEK_API_KEY NOT test',
        'filename:.env GROQ_API_KEY NOT test',
        'filename:.env XAI_API_KEY NOT test',
        'filename:.env OPENROUTER_API_KEY NOT test',
        'filename:.env CEREBRAS_API_KEY NOT test',
        'filename:.env RUNPOD_API_KEY NOT test',
        'filename:.env SILICONFLOW_API_KEY NOT test',
        'filename:.env DASHSCOPE_API_KEY NOT test',
        'filename:.env MOONSHOT_API_KEY NOT test',

        # HuggingFace tokens in production
        'filename:.env HUGGINGFACE_TOKEN NOT test NOT example',
        'filename:.env HF_TOKEN NOT test NOT staging',
        'hf_token language:python NOT test NOT example',

        # Anthropic in non-.env files (broader coverage)
        'sk-ant-api03 language:typescript NOT test NOT example',
        'sk-ant-api03 language:go NOT test NOT example',
        'sk-ant-api03 language:rust NOT test NOT example',
        '"x-api-key" "sk-ant-" language:python NOT test',
        '"x-api-key" "sk-ant-" language:javascript NOT test',

        # OpenAI in non-.env files (broader coverage)
        'sk-proj- language:go NOT test NOT example NOT mock',
        'sk-proj- language:rust NOT test NOT example NOT mock',
        'sk-proj- language:java NOT test NOT example NOT mock',
        'sk-proj- language:ruby NOT test NOT example NOT mock',
        '"Authorization" "Bearer sk-proj-" NOT test NOT example',

        # Gemini in various formats
        'AIzaSy language:python NOT test NOT example NOT dev NOT demo',
        'AIzaSy language:javascript NOT test NOT example NOT dev',
        'GEMINI_API_KEY= AIzaSy NOT test NOT example',
        'GOOGLE_AI_KEY= AIzaSy NOT test NOT example',

        # OpenRouter (aggregator — high value, multiple models)
        'sk-or-v1- language:python NOT test NOT example',
        'sk-or-v1- language:javascript NOT test NOT example',
        'sk-or-v1- filename:.env NOT test',
        'OPENROUTER_API_KEY sk-or-v1- NOT test',

        # Groq (fast inference — popular)
        'gsk_ language:python NOT test NOT example',
        'gsk_ filename:.env NOT test NOT example',
        'GROQ_API_KEY gsk_ NOT test',

        # xAI / Grok
        'xai- language:python NOT test NOT example',
        'xai- filename:.env NOT test',
        'XAI_API_KEY xai- NOT test',
    ])
    
    # ==================== URL по умолчанию для платформ ====================
    default_base_urls: Dict[str, str] = field(default_factory=lambda: {
        # Основные ИИ-платформы
        "openai": "https://api.openai.com",
        "gemini": "https://generativelanguage.googleapis.com/v1beta",
        "anthropic": "https://api.anthropic.com",
        "azure": "",
        # Новые ИИ-платформы
        "huggingface": "https://api-inference.huggingface.co",
        "groq": "https://api.groq.com/openai/v1",
        "deepseek": "https://api.deepseek.com",
        "cohere": "https://api.cohere.ai/v1",
        "mistral": "https://api.mistral.ai/v1",
        "together": "https://api.together.xyz/v1",
        "replicate": "https://api.replicate.com/v1",
        "perplexity": "https://api.perplexity.ai",
        "fireworks": "https://api.fireworks.ai/inference/v1",
        "anyscale": "https://api.endpoints.anyscale.com/v1",
        # Новые AI-провайдеры
        "xai": "https://api.x.ai",
        "openrouter": "https://openrouter.ai/api",
        "cerebras": "https://api.cerebras.ai",
        "voyage": "https://api.voyageai.com",
        "jina": "https://api.jina.ai",
        "opencode_zen": "https://opencode.ai/zen/v1",
        "lepton": "https://api.lepton.ai",
        "modal": "https://api.modal.com",
        # GitHub API
        "github": "https://api.github.com",
        # Китайские AI-провайдеры
        "zhipu": "https://open.bigmodel.cn/api/paas/v4",
        "yi": "https://api.lingyiwanwu.com/v1",
        "baichuan": "https://api.baichuan-ai.com/v1",
        "moonshot": "https://api.moonshot.cn/v1",
        "stepfun": "https://api.stepfun.com/v1",
        "minimax": "https://api.minimax.chat/v1",
        "siliconflow": "https://api.siliconflow.cn/v1",
        "dashscope": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "volcengine": "https://ark.cn-beijing.volces.com/api/v3",
        "internlm": "https://internlm-chat.intern-ai.org.cn/v1",
        # Облачные провайдеры
        "aws_access_key": "",
        "aws_secret_key": "",
        "steam": "https://api.steampowered.com",
        # GPU Cloud
        "digitalocean": "https://api.digitalocean.com/v2",
        "linode": "https://api.linode.com/v4",
        "vultr": "https://api.vultr.com/v2",
        "hetzner": "https://api.hetzner.cloud/v1",
        "scaleway": "https://api.scaleway.com",
        "runpod": "https://api.runpod.io",
        "lambdalabs": "https://cloud.lambdalabs.com/api/v1",
        "coreweave": "https://api.coreweave.com",
        # Расширенный каталог (Voice/Image/RAG/Browser/LLMOps/Vector/Code)
        # — синхронизировано с EXTRA_PROVIDERS выше.
        "elevenlabs": "https://api.elevenlabs.io/v1",
        "stability": "https://api.stability.ai/v2beta",
        "heygen": "https://api.heygen.com/v2",
        "runway": "https://api.dev.runwayml.com/v1",
        "tavily": "https://api.tavily.com",
        "firecrawl": "https://api.firecrawl.dev/v1",
        "apify": "https://api.apify.com/v2",
        "promptlayer": "https://api.promptlayer.com",
        "langfuse": "https://cloud.langfuse.com/api/public",
        "astra": "https://api.astra.datastax.com/v2",
        "sourcegraph": "https://sourcegraph.com/.api",
        "wordware": "https://app.wordware.ai/api",
        "llamacloud": "https://api.cloud.llamaindex.ai",
    })
    
    @property
    def proxies(self) -> Optional[Dict[str, str]]:
        """Возвращает прокси в формате requests"""
        if self.proxy_url:
            return {"http": self.proxy_url, "https": self.proxy_url}
        return None
    
    def get_token(self) -> str:
        """Получить текущий Token"""
        if not self.github_tokens:
            return ""
        return self.github_tokens[self._token_index % len(self.github_tokens)]
    
    def rotate_token(self) -> str:
        """Переключиться на следующий Token"""
        if not self.github_tokens:
            return ""
        self._token_index = (self._token_index + 1) % len(self.github_tokens)
        return self.github_tokens[self._token_index]
    
    def get_random_token(self) -> str:
        """Случайным образом получить Token"""
        if not self.github_tokens:
            return ""
        return random.choice(self.github_tokens)


# Глобальный экземпляр конфигурации
config = Config()

# ============================================================================
#                          Переопределение локальной конфигурации (config_local.py)
# ============================================================================
# Попытка импорта локального файла конфигурации для переопределения настроек по умолчанию
# config_local.py должен содержать реальные токены и конфиденциальные настройки
# Этот файл игнорируется .gitignore и не попадает в Git
try:
    from config_local import *
    
    # Если config_local.py определяет GITHUB_TOKENS, обновить конфигурацию
    # Guard: пустой список НЕ должен затирать токены из env (иначе смена
    # языка TUI без config_local.py роняет auth до 10 req/min).
    if 'GITHUB_TOKENS' in dir() and GITHUB_TOKENS:
        config.github_tokens = GITHUB_TOKENS

    # Если определён PROXY_URL, обновить конфигурацию
    if 'PROXY_URL' in dir() and PROXY_URL:
        config.proxy_url = PROXY_URL

    # Если определены другие параметры, их тоже можно обновить здесь.
    # Guard: пустые значения не затирают дефолты/env.
    if 'DB_PATH' in dir() and DB_PATH:
        config.db_path = DB_PATH
    if 'CONSUMER_THREADS' in dir() and CONSUMER_THREADS:
        config.consumer_threads = CONSUMER_THREADS
    if 'REQUEST_TIMEOUT' in dir() and REQUEST_TIMEOUT:
        config.request_timeout = REQUEST_TIMEOUT

    # Pastebin API Key
    if 'PASTEBIN_API_KEY' in dir() and PASTEBIN_API_KEY:
        config.pastebin_api_key = PASTEBIN_API_KEY

    try:
        from tui_i18n import t as _cfg_t, resolve_lang as _cfg_lang
        _lg = _cfg_lang()
        if _lg == "ru":
            print("[OK] Локальный файл конфигурации config_local.py загружен")
        else:
            print("[OK] Local config file config_local.py loaded")
    except Exception:
        print("[OK] config_local.py loaded")
except ImportError:
    # config_local.py не существует, используются настройки по умолчанию
    if not config.github_tokens or not any(config.github_tokens):
        try:
            from tui_i18n import resolve_lang as _cfg_lang
            _lg = _cfg_lang()
        except Exception:
            _lg = "en"
        if _lg == "ru":
            print("[WARNING] GitHub Tokens не настроены!")
            print("   Создайте config_local.py или задайте GITHUB_TOKENS")
            print("   Шаблон: config_local.py.example")
        else:
            print("[WARNING] GitHub Tokens are not configured!")
            print("   Create config_local.py or set GITHUB_TOKENS")
            print("   Template: config_local.py.example")
except Exception as e:
    print(f"[WARNING] Failed to load config_local.py: {e}")
