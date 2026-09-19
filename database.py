"""
Модуль базы данных - SQLite персистентное хранение и дедупликация данных

Структура таблиц:
1. leaked_keys - таблица утекших ключей
   - api_key: уникальный индекс
   - status: статус проверки (valid/invalid/quota_exceeded/connection_error)
   
2. scanned_blobs - таблица отсканированных файлов SHA (персистентная дедупликация)
   - file_sha: Git Blob SHA (дедупликация между репозиториями)
   - scan_time: время сканирования
"""

import sqlite3
import threading
import re as _re
from datetime import datetime, timedelta
from typing import Optional, List
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse

from loguru import logger


DEFAULT_SOURCE_PROGRESS_STALE_SECONDS = 180
# Порог «воркер умер»: active-источник без heartbeat дольше этого -> stopped.
SOURCE_PROGRESS_REAP_SECONDS = 600


# Сегменты путей, которые являются эндпоинтами, а не частью API-корня.
_ENDPOINT_SEGMENTS = frozenset({
    'chat', 'completions', 'embeddings', 'models', 'messages',
    'audio', 'transcriptions', 'translations', 'images',
    'generations', 'files', 'fine_tunes', 'fine-tunes',
    'moderations', 'responses', 'edits', 'invitations',
})


# Канонические API-корни для известных провайдеров.
# Все URL с этим доменом приводятся к одному canonical endpoint.
_CANONICAL_ENDPOINTS = {
    # (хост, обязательный path-префикс) -> canonical endpoint
    ("api.perplexity.ai", None): "https://api.perplexity.ai/v1",
    ("api.openai.com", None): "https://api.openai.com/v1",
    ("api.deepseek.com", None): "https://api.deepseek.com/v1",
    ("api.x.ai", None): "https://api.x.ai/v1",
    ("api.cerebras.ai", None): "https://api.cerebras.ai/v1",
    ("api.together.xyz", None): "https://api.together.xyz/v1",
    ("api.mistral.ai", None): "https://api.mistral.ai/v1",
    ("api.fireworks.ai", None): "https://api.fireworks.ai/inference/v1",
    ("api.groq.com", None): "https://api.groq.com/openai/v1",
    ("api.siliconflow.cn", None): "https://api.siliconflow.cn/v1",
    ("api.moonshot.cn", None): "https://api.moonshot.cn/v1",
    ("api.stepfun.com", None): "https://api.stepfun.com/v1",
    ("api.lingyiwanwu.com", None): "https://api.lingyiwanwu.com/v1",
    ("api.baichuan-ai.com", None): "https://api.baichuan-ai.com/v1",
    ("openrouter.ai", None): "https://openrouter.ai/api/v1",
    ("api.openrouter.ai", None): "https://openrouter.ai/api/v1",
    ("generativelanguage.googleapis.com", None): "https://generativelanguage.googleapis.com/v1beta",
    ("places.googleapis.com", None): "https://places.googleapis.com/v1",
    ("api-inference.huggingface.co", None): "https://api-inference.huggingface.co",
    ("api.anthropic.com", None): "https://api.anthropic.com/v1",
    ("api.voyageai.com", None): "https://api.voyageai.com/v1",
    ("api.lepton.ai", None): "https://api.lepton.ai/v1",
    ("api.modal.com", None): "https://api.modal.com",
    ("open.bigmodel.cn", None): "https://open.bigmodel.cn/api/paas/v4",
    ("dashscope.aliyuncs.com", None): "https://dashscope.aliyuncs.com/compatible-mode/v1",
    ("ark.cn-beijing.volces.com", None): "https://ark.cn-beijing.volces.com/api/v3",
    ("api.minimax.chat", None): "https://api.minimax.chat/v1",
    ("api.runpod.io", None): "https://api.runpod.io",
    ("api.together.ai", None): "https://api.together.ai/v1",
    ("api.hyperbolic.xyz", None): "https://api.hyperbolic.xyz/v1",
    ("api.nvidia.com", None): "https://api.nvidia.com/v1",
    ("integrate.api.nvidia.com", None): "https://integrate.api.nvidia.com/v1",
    ("ai-gateway.vercel.sh", None): "https://ai-gateway.vercel.sh/api/v1",
    ("api.qnaigc.com", None): "https://api.qnaigc.com/v1",
    ("api.chatanywhere.com.cn", None): "https://api.chatanywhere.com.cn/v1",
    ("api.openai-proxy.org", None): "https://api.openai-proxy.org/v1",
    ("opencode.ai", None): "https://opencode.ai/zen/v1",
}


def _canonical_endpoint(host: str, path: str) -> Optional[str]:
    """Вернуть канонический endpoint для известного хоста (или None)."""
    host = host.lower().strip()
    # точное совпадение хоста
    if (host, None) in _CANONICAL_ENDPOINTS:
        return _CANONICAL_ENDPOINTS[(host, None)]
    # wildcard *.somehost
    parts = host.split(".")
    if len(parts) >= 2:
        wildcard = "*." + ".".join(parts[1:])
        if (wildcard, None) in _CANONICAL_ENDPOINTS:
            return _CANONICAL_ENDPOINTS[(wildcard, None)]
    return None


def normalize_base_url(base_url: str) -> str:
    """Привести base_url к API-корню для группировки по провайдерам.

    Примеры:
      https://api.perplexity.ai/chat/completions -> https://api.perplexity.ai/v1
      https://api.deepseek.com/v1/chat/completions -> https://api.deepseek.com/v1
      https://api.perplexity.ai -> https://api.perplexity.ai/v1
      https://api.openai.com -> https://api.openai.com/v1
      https://openrouter.ai/api/v1/chat/completions -> https://openrouter.ai/api/v1
    """
    if not base_url:
        return base_url
    try:
        parsed = urlparse(base_url.strip())
    except ValueError:
        return base_url
    if not parsed.scheme or not parsed.netloc:
        return base_url

    host = parsed.netloc.lower().strip()
    path = parsed.path or ""

    # 1. Силовая канонизация известных доменов
    canonical = _canonical_endpoint(host, path)
    if canonical:
        return canonical

    # 2. Общая нормализация для неизвестных хостов
    host = f"{parsed.scheme}://{parsed.netloc}"
    segments = [s for s in path.split('/') if s]

    # Удалить хвостовые сегменты-эндпоинты
    while segments and segments[-1] in _ENDPOINT_SEGMENTS:
        segments.pop()

    # Найти сегмент-версию (v1, v1beta, v2 …) и обрезать после него
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


class KeyStatus(Enum):
    """Перечисление статусов API Key"""
    PENDING = "pending"              # ожидает проверки
    VALID = "valid"                  # действителен (auth прошёл)
    CONFIRMED = "confirmed"          # подтверждён работающий (реальный chat completion)
    INVALID = "invalid"              # недействителен (аутентификация не удалась)
    QUOTA_EXCEEDED = "quota_exceeded"  # действителен, но квота исчерпана
    CONNECTION_ERROR = "connection_error"  # ошибка подключения (промежуточный сервер недоступен)
    UNVERIFIED = "unverified"        # невозможно проверить (например, Azure не имеет полного endpoint)


@dataclass
class LeakedKey:
    """
    Модель данных утекших ключей
    
    Основные поля:
    - api_key: API ключ (уникальный индекс)
    - base_url: привязанный API адрес (ключ к решению 401)
    - status: статус проверки
    - model_tier: уровень модели (GPT-4/GPT-3.5)
    - rpm: ограничение частоты запросов
    - is_high_value: является ли ключ высокой ценности
    """
    platform: str           # openai, azure, gemini, anthropic
    api_key: str            # API Key
    base_url: str           # Привязанный Base URL
    status: str = KeyStatus.PENDING.value
    balance: str = ""       # Баланс/информация о модели
    source_url: str = ""    # Ссылка-источник GitHub
    model_tier: str = ""    # Уровень модели: GPT-4, GPT-3.5, Gemini-Pro и т.д.
    rpm: int = 0            # Rate Per Minute
    is_high_value: bool = False  # Является ли ключ высокой ценности
    found_time: datetime = None
    id: int = None
    
    def __post_init__(self):
        if self.found_time is None:
            self.found_time = datetime.now()


class Database:
    """
    Класс управления SQLite базой данных
    
    Особенности:
    - потокобезопасность (использование блокировок)
    - уникальные индексы для предотвращения дубликатов
    - поддержка запросов с несколькими статусами
    """
    def __init__(self, db_path: str = "leaked_keys.db"):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._conn: Optional[sqlite3.Connection] = None
        self._exists_cache: set = set()
        self._exists_cache_max = 500_000
        self._blob_cache: set = set()
        self._init_db()
        self._warmup_exists_cache()
        self._warmup_blob_cache()

    @contextmanager
    def _get_connection(self):
        """Контекстный менеджер — переиспользует persistent connection.

        PRAGMA-настройки (WAL, cache_size, mmap) задаются один раз,
        а не при каждом вызове — экономит ~8 запросов на операцию.
        Потокобезопасность обеспечивается self._lock + check_same_thread=False.
        """
        if self._conn is None:
            conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=-64000")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA mmap_size=268435456")
            conn.execute("PRAGMA wal_autocheckpoint=1000")
            self._conn = conn
        yield self._conn

    def close(self):
        """Закрыть persistent connection."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def _cache_add(self, api_key: str) -> None:
        """Добавить ключ в in-memory кэш существования."""
        if len(self._exists_cache) >= self._exists_cache_max:
            self._exists_cache.clear()
        self._exists_cache.add(api_key)

    def _warmup_exists_cache(self) -> None:
        """Загрузить все api_key из БД в кэш при старте.

        Один SELECT вместо N индивидуальных key_exists-запросов.
        Для 57K ключей — ~100мс вместо 57K round-trips.
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT api_key FROM leaked_keys")
                count = 0
                for row in cursor:
                    self._exists_cache.add(row[0])
                    count += 1
                if count:
                    logger.info(f"Кэш key_exists разогрет: {count} ключей")
        except Exception as e:
            logger.warning(f"Не удалось разогреть кэш: {e}")

    def _warmup_blob_cache(self) -> None:
        """Загрузить все file_sha из scanned_blobs в кэш при старте."""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT file_sha FROM scanned_blobs")
                count = 0
                for row in cursor:
                    self._blob_cache.add(row[0])
                    count += 1
                if count:
                    logger.info(f"Кэш blob_scanned разогрет: {count} SHA")
        except Exception as e:
            logger.warning(f"Не удалось разогреть blob-кэш: {e}")
    
    def _init_db(self):
        """Инициализация структуры таблиц базы данных"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Создание основной таблицы (оптимизированная структура)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS leaked_keys (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        platform TEXT NOT NULL,
                        api_key TEXT NOT NULL UNIQUE,
                        base_url TEXT NOT NULL,
                        status TEXT DEFAULT 'pending',
                        balance TEXT DEFAULT '',
                        source_url TEXT DEFAULT '',
                        model_tier TEXT DEFAULT '',
                        rpm INTEGER DEFAULT 0,
                        is_high_value BOOLEAN DEFAULT 0,
                        found_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                        verified_time DATETIME,
                        tpd INTEGER DEFAULT 0,
                        concurrency_limit INTEGER DEFAULT 0,
                        balance_usd REAL DEFAULT -1,
                        org_plan TEXT DEFAULT '',
                        rate_tier TEXT DEFAULT '',
                        rate_headers TEXT DEFAULT ''
                    )
                """)

                # Попытка добавить новые поля (совместимость со старыми базами данных)
                for col, decl in [
                    ("model_tier", "TEXT DEFAULT ''"),
                    ("rpm", "INTEGER DEFAULT 0"),
                    ("is_high_value", "BOOLEAN DEFAULT 0"),
                    ("tpd", "INTEGER DEFAULT 0"),
                    ("concurrency_limit", "INTEGER DEFAULT 0"),
                    ("balance_usd", "REAL DEFAULT -1"),
                    ("org_plan", "TEXT DEFAULT ''"),
                    ("rate_tier", "TEXT DEFAULT ''"),
                    ("rate_headers", "TEXT DEFAULT ''"),
                    ("confirm_attempts", "INTEGER DEFAULT 0"),
                ]:
                    try:
                        cursor.execute(
                            f"ALTER TABLE leaked_keys ADD COLUMN {col} {decl}")
                    except sqlite3.OperationalError:
                        pass
                
                # Создание индексов
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_platform ON leaked_keys(platform)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_status ON leaked_keys(status)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_base_url ON leaked_keys(base_url)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_verified_time ON leaked_keys(verified_time, status)
                """)
                
                # ========== Создание таблицы отсканированных файлов SHA (персистентная дедупликация) ==========
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scanned_blobs (
                        file_sha TEXT PRIMARY KEY,
                        scan_time DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # ========== Таблица отсканированных ключевых слов (пропуск без запросов при рестарте) ==========
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scanned_keywords (
                        keyword TEXT PRIMARY KEY,
                        scan_time DATETIME,
                        result_count INTEGER DEFAULT 0,
                        fully_scanned BOOLEAN DEFAULT 0
                    )
                """)

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS source_state (
                        name TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                """)

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scanned_source_items (
                        source TEXT NOT NULL,
                        item_id TEXT NOT NULL,
                        scanned_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (source, item_id)
                    )
                """)

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS source_progress (
                        source TEXT PRIMARY KEY,
                        status TEXT NOT NULL DEFAULT 'starting',
                        phase TEXT NOT NULL DEFAULT '',
                        current INTEGER NOT NULL DEFAULT 0,
                        total INTEGER NOT NULL DEFAULT 0,
                        processed INTEGER NOT NULL DEFAULT 0,
                        found INTEGER NOT NULL DEFAULT 0,
                        errors INTEGER NOT NULL DEFAULT 0,
                        message TEXT NOT NULL DEFAULT '',
                        heartbeat TEXT NOT NULL
                    )
                """)
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_source_progress_status ON source_progress(status)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_source_progress_heartbeat ON source_progress(heartbeat)")

                # ========== Таблица моделей по ключам (вкладка «Модели») ==========
                # Связь валидного ключа с моделями, которые он обслуживает
                # (получены из GET /models или эвристически из model_tier).
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS key_models (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        key_id INTEGER NOT NULL,
                        model_name TEXT NOT NULL,
                        platform TEXT NOT NULL DEFAULT '',
                        base_url TEXT NOT NULL DEFAULT '',
                        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                        is_confirmed BOOLEAN DEFAULT 0,
                        UNIQUE(key_id, model_name),
                        FOREIGN KEY(key_id) REFERENCES leaked_keys(id)
                    )
                """)
                # Добавить колонку is_confirmed для старых баз
                try:
                    cursor.execute(
                        "ALTER TABLE key_models ADD COLUMN is_confirmed BOOLEAN DEFAULT 0")
                except sqlite3.OperationalError:
                    pass
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_km_model
                    ON key_models(model_name)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_km_key
                    ON key_models(key_id)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_km_confirmed
                    ON key_models(model_name, is_confirmed)
                """)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_status_platform
                    ON leaked_keys(status, platform)
                """)
                # Покрывающий индекс для get_failed_keys — самый частый запрос
                # (pending/unverified + verified_time IS NULL) OR (connection_error + attempts < 3)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_failed_keys
                    ON leaked_keys(status, verified_time, confirm_attempts)
                """)
                # Индекс для get_stats (COUNT GROUP BY status)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_status_only
                    ON leaked_keys(status)
                """)
                # Индекс для get_valid_keys (WHERE status = 'valid')
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_platform_status
                    ON leaked_keys(platform, status)
                """)
                # Индекс для ORDER BY found_time (get_failed_keys, export)
                cursor.execute("""
                    CREATE INDEX IF NOT EXISTS idx_found_time
                    ON leaked_keys(found_time)
                """)

                conn.commit()
                
                # Подсчет количества отсканированных файлов
                cursor.execute("SELECT COUNT(*) FROM scanned_blobs")
                blob_count = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM leaked_keys")
                key_count = cursor.fetchone()[0]
                
                try:
                    from tui_i18n import tf as _i18n_tf, resolve_lang as _i18n_lang
                    logger.info(_i18n_tf(
                        "log_db_init_done", _i18n_lang(),
                        path=self.db_path, blobs=blob_count, keys=key_count,
                    ))
                except Exception:
                    logger.info(
                        f"Database ready: {self.db_path} "
                        f"(scanned files: {blob_count}, keys: {key_count})")

                # Нормализация существующих base_url (один раз при старте)
                self._normalize_existing_urls(cursor, conn)

    def _normalize_existing_urls(self, cursor, conn):
        """Нормализовать base_url всех существующих записей."""
        rows = cursor.execute(
            "SELECT id, base_url FROM leaked_keys WHERE base_url != ''"
        ).fetchall()
        updated = 0
        for row in rows:
            key_id = row[0]
            original = row[1]
            normalized = normalize_base_url(original)
            if normalized != original:
                cursor.execute(
                    "UPDATE leaked_keys SET base_url=? WHERE id=?",
                    (normalized, key_id))
                updated += 1
        # Также нормализовать в key_models
        rows = cursor.execute(
            "SELECT id, base_url FROM key_models WHERE base_url != ''"
        ).fetchall()
        for row in rows:
            key_id = row[0]
            original = row[1]
            normalized = normalize_base_url(original)
            if normalized != original:
                cursor.execute(
                    "UPDATE key_models SET base_url=? WHERE id=?",
                    (normalized, key_id))
        if updated:
            conn.commit()
            logger.info(f"Нормализовано base_url: {updated} ключей")
    
    # ========================================================================
    #                           Дедупликация файловых SHA (первый уровень защиты)
    # ========================================================================
    
    def is_blob_scanned(self, file_sha: str) -> bool:
        """
        Проверка, был ли отсканирован файловый SHA (in-memory cache + DB).
        """
        if not file_sha:
            return False
        if file_sha in self._blob_cache:
            return True
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT 1 FROM scanned_blobs WHERE file_sha = ? LIMIT 1",
                    (file_sha,)
                )
                exists = cursor.fetchone() is not None
                if exists:
                    self._blob_cache.add(file_sha)
                return exists
    
    def mark_blob_scanned(self, file_sha: str) -> bool:
        """
        Отметить файловый SHA как отсканированный

        Args:
            file_sha: Git Blob SHA

        Returns:
            успешность вставки
        """
        if not file_sha:
            return False
        self._blob_cache.add(file_sha)
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute(
                        "INSERT OR IGNORE INTO scanned_blobs (file_sha, scan_time) VALUES (?, ?)",
                        (file_sha, datetime.now().isoformat())
                    )
                    conn.commit()
                    return cursor.rowcount > 0
                except sqlite3.IntegrityError:
                    return False

    def mark_blobs_scanned_batch(self, file_shas: List[str]) -> int:
        """Массовая отметка SHA как отсканированных — один commit на партию."""
        if not file_shas:
            return 0
        now = datetime.now().isoformat()
        rows = [(sha, now) for sha in file_shas if sha]
        if not rows:
            return 0
        for sha, _ in rows:
            self._blob_cache.add(sha)
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.executemany(
                    "INSERT OR IGNORE INTO scanned_blobs (file_sha, scan_time) VALUES (?, ?)",
                    rows
                )
                conn.commit()
                return cursor.rowcount
    
    def get_scanned_blob_count(self) -> int:
        """Получить количество отсканированных файлов"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM scanned_blobs")
                return cursor.fetchone()[0]
    
    # ========================================================================
    #                           Дедупликация ключей (второй уровень защиты)
    # ========================================================================

    def key_exists(self, api_key: str) -> bool:
        """
        Проверка, существует ли уже ключ.

        Используется для проверки перед валидацией, чтобы избежать повторной
        проверки уже сохраненных ключей.

        Оптимизация: in-memory set кэш устраняет ~99% DB lookups после
        разогрева — критично при сканировании десятков тысяч ключей.
        """
        if api_key in self._exists_cache:
            return True
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT 1 FROM leaked_keys WHERE api_key = ? LIMIT 1",
                    (api_key,)
                )
                exists = cursor.fetchone() is not None
                if exists:
                    if len(self._exists_cache) >= self._exists_cache_max:
                        self._exists_cache.clear()
                    self._exists_cache.add(api_key)
                return exists
    
    def insert_key(self, key: LeakedKey) -> bool:
        """
        Вставка нового утекшего ключа

        Returns:
            успешность вставки (возвращает False, если уже существует)
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                try:
                    cursor.execute("""
                        INSERT INTO leaked_keys
                        (platform, api_key, base_url, status, balance, source_url, model_tier, rpm, is_high_value, found_time)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        key.platform,
                        key.api_key,
                        normalize_base_url(key.base_url),
                        key.status,
                        key.balance,
                        key.source_url,
                        key.model_tier,
                        key.rpm,
                        1 if key.is_high_value else 0,
                        key.found_time.isoformat() if key.found_time else datetime.now().isoformat()
                    ))
                    conn.commit()
                    self._cache_add(key.api_key)
                    return True
                except sqlite3.IntegrityError:
                    self._cache_add(key.api_key)
                    return False

    def insert_keys_batch(self, keys: List[LeakedKey]) -> int:
        """Массовая вставка ключей — один commit на всю партию.

        Возвращает количество успешно вставленных ключей.
        Дубликаты IGNORE — попадают в кэш, но не считаются вставленными.
        """
        if not keys:
            return 0
        rows = [(
            k.platform, k.api_key, normalize_base_url(k.base_url),
            k.status, k.balance, k.source_url, k.model_tier, k.rpm,
            1 if k.is_high_value else 0,
            k.found_time.isoformat() if k.found_time else datetime.now().isoformat()
        ) for k in keys]
        inserted = 0
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                for row in rows:
                    try:
                        cursor.execute(
                            "INSERT INTO leaked_keys "
                            "(platform, api_key, base_url, status, balance, "
                            "source_url, model_tier, rpm, is_high_value, found_time) "
                            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            row
                        )
                        self._cache_add(row[1])
                        inserted += 1
                    except sqlite3.IntegrityError:
                        self._cache_add(row[1])
                conn.commit()
                return inserted
    
    def update_key_status(
        self,
        api_key: str,
        status: KeyStatus,
        balance: str = "",
        model_tier: str = "",
        rpm: int = 0,
        is_high_value: bool = False
    ) -> bool:
        """
        Обновление статуса проверки ключа.

        При переходе в НЕДОСТУПНЫЙ статус (quota_exceeded/invalid) сбрасывает
        is_confirmed=0 для всех моделей ключа — иначе модель остаётся
        «доступной» (прокси/дашборд берут is_confirmed=1), хотя ключ мёртв.

        Args:
            api_key: API Key
            status: новый статус
            balance: баланс/дополнительная информация
            model_tier: уровень модели
            rpm: ограничение RPM
            is_high_value: является ли ключ высокой ценности
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE leaked_keys
                    SET status = ?, balance = ?, model_tier = ?, rpm = ?, is_high_value = ?, verified_time = ?
                    WHERE api_key = ?
                """, (
                    status.value, balance, model_tier, rpm,
                    1 if is_high_value else 0,
                    datetime.now().isoformat(), api_key
                ))
                affected = cursor.rowcount
                # Сброс is_confirmed моделей при понижении до недоступного статуса
                if status in (KeyStatus.QUOTA_EXCEEDED, KeyStatus.INVALID):
                    cursor.execute(
                        "UPDATE key_models SET is_confirmed=0 "
                        "WHERE key_id=(SELECT id FROM leaked_keys WHERE api_key=?)",
                        (api_key,))
                conn.commit()
                return affected > 0

    def update_keys_status_batch(
        self,
        updates: List[tuple],
    ) -> int:
        """Массовое обновление статусов — один commit на всю партию.

        Args:
            updates: list of (api_key, status, balance, model_tier, rpm,
                     is_high_value) tuples

        Returns:
            количество обновлённых строк.
        """
        if not updates:
            return 0
        now = datetime.now().isoformat()
        dead_statuses = {KeyStatus.QUOTA_EXCEEDED, KeyStatus.INVALID}
        updated = 0
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                for api_key, status, balance, model_tier, rpm, is_high_value in updates:
                    cursor.execute(
                        "UPDATE leaked_keys SET status=?, balance=?, "
                        "model_tier=?, rpm=?, is_high_value=?, verified_time=? "
                        "WHERE api_key=?",
                        (status.value if isinstance(status, KeyStatus) else status,
                         balance, model_tier, rpm,
                         1 if is_high_value else 0, now, api_key)
                    )
                    updated += cursor.rowcount
                    if status in dead_statuses:
                        cursor.execute(
                            "UPDATE key_models SET is_confirmed=0 "
                            "WHERE key_id=(SELECT id FROM leaked_keys "
                            "WHERE api_key=?)",
                            (api_key,))
                conn.commit()
                return updated

    def update_key_meta(
        self,
        api_key: str,
        tpd: int = 0,
        concurrency_limit: int = 0,
        balance_usd: float = -1,
        org_plan: str = "",
        rate_tier: str = "",
        rate_headers: str = "",
    ) -> bool:
        """Обновить расширенные метаданные ключа (rate limits, баланс, org plan)."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                sets = []
                vals: list = []
                if tpd:
                    sets.append("tpd = ?"); vals.append(tpd)
                if concurrency_limit:
                    sets.append("concurrency_limit = ?"); vals.append(concurrency_limit)
                if balance_usd >= 0:
                    sets.append("balance_usd = ?"); vals.append(balance_usd)
                if org_plan:
                    sets.append("org_plan = ?"); vals.append(org_plan)
                if rate_tier:
                    sets.append("rate_tier = ?"); vals.append(rate_tier)
                if rate_headers:
                    sets.append("rate_headers = ?"); vals.append(rate_headers)
                if not sets:
                    return False
                vals.append(api_key)
                cursor.execute(
                    f"UPDATE leaked_keys SET {', '.join(sets)} WHERE api_key = ?",
                    vals,
                )
                conn.commit()
                return cursor.rowcount > 0
        """Получить все ключи с указанным статусом"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT * FROM leaked_keys WHERE status = ?",
                    (status.value,)
                )
                return [self._row_to_key(row) for row in cursor.fetchall()]
    
    def get_valid_keys(self, platform: Optional[str] = None) -> List[LeakedKey]:
        """Получить все действительные ключи (включая quota_exceeded, так как они технически действительны)"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                valid_statuses = (KeyStatus.VALID.value, KeyStatus.QUOTA_EXCEEDED.value)
                
                if platform:
                    cursor.execute("""
                        SELECT * FROM leaked_keys 
                        WHERE status IN (?, ?) AND platform = ?
                    """, (*valid_statuses, platform))
                else:
                    cursor.execute("""
                        SELECT * FROM leaked_keys WHERE status IN (?, ?)
                    """, valid_statuses)
                
                return [self._row_to_key(row) for row in cursor.fetchall()]

    def get_valid_keys_count(self) -> int:
        """Получить количество действительных ключей"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT COUNT(*) FROM leaked_keys WHERE status IN (?, ?)",
                    (KeyStatus.VALID.value, KeyStatus.QUOTA_EXCEEDED.value)
                )
                return cursor.fetchone()[0]
    
    def get_all_keys(self) -> List[LeakedKey]:
        """Получить все ключи"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM leaked_keys ORDER BY found_time DESC")
                return [self._row_to_key(row) for row in cursor.fetchall()]
    
    def get_stats(self) -> dict:
        """Получить статистическую информацию"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Общее количество
                cursor.execute("SELECT COUNT(*) FROM leaked_keys")
                total = cursor.fetchone()[0]
                
                # Количество по статусам
                cursor.execute("""
                    SELECT status, COUNT(*) as count 
                    FROM leaked_keys GROUP BY status
                """)
                statuses = {row[0]: row[1] for row in cursor.fetchall()}
                
                # Количество по платформам
                cursor.execute("""
                    SELECT platform, COUNT(*) as count 
                    FROM leaked_keys GROUP BY platform
                """)
                platforms = {row[0]: row[1] for row in cursor.fetchall()}
                
                # Действительные (valid + quota_exceeded)
                valid_count = statuses.get('valid', 0) + statuses.get('quota_exceeded', 0)
                
                return {
                    "total": total,
                    "valid": valid_count,
                    "statuses": statuses,
                    "platforms": platforms
                }
    
    @staticmethod
    def _row_to_key(row: sqlite3.Row) -> LeakedKey:
        """Преобразование строки базы данных в объект LeakedKey"""
        # Совместимость со старыми базами данных (без новых полей)
        row_dict = dict(row)
        return LeakedKey(
            id=row_dict.get("id"),
            platform=row_dict.get("platform", ""),
            api_key=row_dict.get("api_key", ""),
            base_url=row_dict.get("base_url", ""),
            status=row_dict.get("status", "pending"),
            balance=row_dict.get("balance") or "",
            source_url=row_dict.get("source_url") or "",
            model_tier=row_dict.get("model_tier") or "",
            rpm=row_dict.get("rpm") or 0,
            is_high_value=bool(row_dict.get("is_high_value", 0)),
            found_time=datetime.fromisoformat(row_dict["found_time"]) if row_dict.get("found_time") else None
        )

    def upsert_source_progress(
        self,
        source: str,
        *,
        processed_increment: int = 0,
        found_increment: int = 0,
        errors_increment: int = 0,
        **fields,
    ) -> None:
        """Атомарно обновить состояние и счётчики источника."""
        allowed = {
            "status", "phase", "current", "total", "processed",
            "found", "errors", "message",
        }
        unknown = set(fields) - allowed
        if unknown:
            names = ", ".join(sorted(unknown))
            raise TypeError(f"Unknown source progress fields: {names}")

        increments = {
            "processed": processed_increment,
            "found": found_increment,
            "errors": errors_increment,
        }
        heartbeat = datetime.now().isoformat()
        columns = ["source"]
        values = [source]
        placeholders = ["?"]
        assignments = []

        for name, value in fields.items():
            columns.append(name)
            values.append(value + increments[name] if name in increments else value)
            placeholders.append("?")
            assignments.append(f"{name} = excluded.{name}")

        for name, increment in increments.items():
            if name in fields or not increment:
                continue
            columns.append(name)
            values.append(increment)
            placeholders.append("?")
            assignments.append(f"{name} = source_progress.{name} + excluded.{name}")

        columns.append("heartbeat")
        values.append(heartbeat)
        placeholders.append("?")
        assignments.append("heartbeat = excluded.heartbeat")
        sql = (
            f"INSERT INTO source_progress ({', '.join(columns)}) "
            f"VALUES ({', '.join(placeholders)}) "
            f"ON CONFLICT(source) DO UPDATE SET {', '.join(assignments)}"
        )

        with self._lock:
            with self._get_connection() as conn:
                try:
                    conn.execute(sql, values)
                    conn.commit()
                except sqlite3.Error:
                    conn.rollback()
                    raise

    def increment_source_progress(
        self, source: str, processed: int = 0, found: int = 0, errors: int = 0
    ) -> None:
        """Совместимый shorthand для атомарного увеличения счётчиков."""
        self.upsert_source_progress(
            source,
            processed_increment=processed,
            found_increment=found,
            errors_increment=errors,
        )

    def safe_upsert_source_progress(self, source: str, **fields) -> bool:
        """Best-effort telemetry: ошибка БД не должна остановить worker."""
        try:
            self.upsert_source_progress(source, **fields)
            return True
        except sqlite3.Error as exc:
            logger.warning(f"Не удалось обновить telemetry {source}: {exc}")
            return False

    def get_source_progress(
        self, stale_after_seconds: float = DEFAULT_SOURCE_PROGRESS_STALE_SECONDS
    ) -> List[dict]:
        now = datetime.now()
        with self._lock:
            with self._get_connection() as conn:
                rows = conn.execute(
                    "SELECT * FROM source_progress ORDER BY source"
                ).fetchall()

        progress = []
        active_statuses = {"starting", "running"}
        for row in rows:
            item = dict(row)
            if item["status"] not in active_statuses:
                item["stale"] = False
            else:
                try:
                    heartbeat = datetime.fromisoformat(item["heartbeat"])
                    item["stale"] = (
                        now - heartbeat
                    ).total_seconds() > stale_after_seconds
                except (TypeError, ValueError):
                    item["stale"] = True
            progress.append(item)
        return progress

    def reap_stale_source_progress(
        self, stale_after_seconds: float = SOURCE_PROGRESS_REAP_SECONDS
    ) -> int:
        """Пометить мёртвые active-источники как stopped (воркер умер).

        Сканер/TUI может быть убит (kill, краш, _kill_stale_*) — строка
        source_progress остаётся running/waiting/starting навсегда, и дашборд
        вечно показывает STALE. Этот вызов переводит такие строки в stopped,
        чтобы UI отражал реальность. Живые (свежий heartbeat) и не-active
        статусы (disabled/stopped/error) не трогаются.

        Возвращает число зарейпленных строк (best-effort: 0 при ошибке БД).
        """
        cutoff = (datetime.now() - timedelta(seconds=stale_after_seconds)).isoformat()
        with self._lock:
            with self._get_connection() as conn:
                try:
                    cur = conn.execute(
                        "UPDATE source_progress SET status='stopped', phase='stopped', "
                        "message='' WHERE status IN ('starting','running','waiting') "
                        "AND heartbeat < ?",
                        (cutoff,),
                    )
                    conn.commit()
                    return cur.rowcount
                except sqlite3.Error:
                    conn.rollback()
                    return 0

    # ========================================================================
    #                           Персистентность прогресса сканирования (возобновление с места останова)
    # ========================================================================

    def save_progress(self, current_index: int, total: int, is_completed: bool = False):
        """Сохранить прогресс сканирования"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scan_progress (
                        id INTEGER PRIMARY KEY, current_index INTEGER,
                        total INTEGER, is_completed BOOLEAN, update_time DATETIME
                    )
                """)
                cursor.execute("""
                    INSERT OR REPLACE INTO scan_progress (id, current_index, total, is_completed, update_time)
                    VALUES (1, ?, ?, ?, ?)
                """, (current_index, total, 1 if is_completed else 0, datetime.now().isoformat()))
                conn.commit()

    def load_progress(self) -> dict:
        """Загрузить прогресс сканирования"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scan_progress (
                        id INTEGER PRIMARY KEY, current_index INTEGER,
                        total INTEGER, is_completed BOOLEAN, update_time DATETIME
                    )
                """)
                conn.commit()
                cursor.execute("SELECT current_index, total, is_completed FROM scan_progress WHERE id = 1")
                row = cursor.fetchone()
                if row:
                    return {"current_index": row[0], "total": row[1], "is_completed": bool(row[2])}
                return {"current_index": 0, "total": 0, "is_completed": False}

    def reset_progress(self):
        """Сбросить прогресс сканирования"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scan_progress (
                        id INTEGER PRIMARY KEY, current_index INTEGER,
                        total INTEGER, is_completed BOOLEAN, update_time DATETIME
                    )
                """)
                cursor.execute("DELETE FROM scan_progress WHERE id = 1")
                conn.commit()

    def get_source_state(self, name: str, default: str = "") -> str:
        with self._lock:
            with self._get_connection() as conn:
                row = conn.execute(
                    "SELECT value FROM source_state WHERE name = ?", (name,)
                ).fetchone()
                return row[0] if row else default

    def set_source_state(self, name: str, value: str) -> None:
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    "INSERT INTO source_state (name, value) VALUES (?, ?) "
                    "ON CONFLICT(name) DO UPDATE SET value = excluded.value",
                    (name, value),
                )
                conn.commit()

    def is_source_item_scanned(self, source: str, item_id: str) -> bool:
        with self._lock:
            with self._get_connection() as conn:
                row = conn.execute(
                    "SELECT 1 FROM scanned_source_items WHERE source = ? AND item_id = ?",
                    (source, item_id),
                ).fetchone()
                return row is not None

    def mark_source_item_scanned(self, source: str, item_id: str) -> None:
        with self._lock:
            with self._get_connection() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO scanned_source_items (source, item_id) VALUES (?, ?)",
                    (source, item_id),
                )
                conn.commit()

    # ========================================================================
    #                  Дедупликация ключевых слов (пропуск без запросов)
    # ========================================================================

    def is_keyword_scanned(self, keyword: str, max_age_hours: int = 24) -> bool:
        """
        Проверить, было ли ключевое слово полностью просканировано недавно.

        Если fully_scanned=1 и сканирование выполнено позже (now - max_age_hours),
        ключевое слово считается актуальным и может быть пропущено БЕЗ запросов
        к GitHub API при рестарте (возобновление с последней точки).

        Args:
            keyword: поисковый dork
            max_age_hours: срок актуальности результата (часов); 0 = всегда перепроверять
        Returns:
            True, если ключевое слово можно пропустить
        """
        if max_age_hours <= 0:
            return False
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT fully_scanned, scan_time FROM scanned_keywords WHERE keyword = ?",
                    (keyword,)
                )
                row = cursor.fetchone()
                if not row or not row[0]:
                    return False
                scan_time = row[1]
                try:
                    if isinstance(scan_time, str):
                        st = datetime.fromisoformat(scan_time)
                    else:
                        st = scan_time
                    age = datetime.now() - st
                    return age.total_seconds() <= max_age_hours * 3600
                except (ValueError, TypeError):
                    return False

    def mark_keyword_scanned(self, keyword: str, result_count: int = 0,
                             fully_scanned: bool = True):
        """Отметить ключевое слово как просканированное"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scanned_keywords (
                        keyword TEXT PRIMARY KEY,
                        scan_time DATETIME,
                        result_count INTEGER DEFAULT 0,
                        fully_scanned BOOLEAN DEFAULT 0
                    )
                """)
                cursor.execute("""
                    INSERT OR REPLACE INTO scanned_keywords
                    (keyword, scan_time, result_count, fully_scanned)
                    VALUES (?, ?, ?, ?)
                """, (keyword, datetime.now().isoformat(),
                      result_count, 1 if fully_scanned else 0))
                conn.commit()

    def clear_scanned_keywords(self) -> int:
        """Очистить таблицу отсканированных ключевых слов (форсировать полный пересканирование)."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scanned_keywords")
                conn.commit()
                return cursor.rowcount

    def count_scanned_keywords(self) -> int:
        """Количество полностью просканированных ключевых слов"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                try:
                    return cursor.execute(
                        "SELECT COUNT(*) FROM scanned_keywords WHERE fully_scanned=1"
                    ).fetchone()[0]
                except sqlite3.Error:
                    return 0

    # ========================================================================
    #                  Пере-валидация ошибочных ключей
    # ========================================================================

    def get_key_status(self, api_key: str) -> Optional[str]:
        """Вернуть текущий статус ключа или None, если ключа нет"""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT status FROM leaked_keys WHERE api_key = ? LIMIT 1",
                    (api_key,)
                )
                row = cursor.fetchone()
                return row[0] if row else None

    def get_failed_keys(self, limit: int = 0,
                        statuses: list = None) -> List[LeakedKey]:
        """
        Получить ключи для повторной валидации.

        Берёт pending + unverified + connection_error ключи, которые ЕЩЁ НЕ
        проверялись (verified_time IS NULL) или проверялись мало раз
        (confirm_attempts < 3). Это prevents бесконечных циклов.
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                if statuses is None:
                    statuses = [KeyStatus.PENDING.value,
                                KeyStatus.UNVERIFIED.value,
                                KeyStatus.CONNECTION_ERROR.value]
                # pending/unverified: только непроверенные (verified_time IS NULL)
                # connection_error: до 3 попыток (confirm_attempts < 3).
                # Параметр statuses зарезервирован, но логика фиксирована под
                # эти три статуса (фактически все вызовы идут со statuses=None).
                sql = (
                    f"SELECT * FROM leaked_keys "
                    f"WHERE ("
                    f"  (status IN ({', '.join(['?'] * 2)}) AND verified_time IS NULL) "
                    f"  OR "
                    f"  (status = ? AND confirm_attempts < 3)"
                    f") "
                    f"ORDER BY found_time ASC"
                )
                params: list = [
                    KeyStatus.PENDING.value, KeyStatus.UNVERIFIED.value,
                    KeyStatus.CONNECTION_ERROR.value,
                ]
                if limit and limit > 0:
                    sql += " LIMIT ?"
                    params.append(limit)
                cursor.execute(sql, tuple(params))
                return [self._row_to_key(row) for row in cursor.fetchall()]

    def increment_confirm_attempts(self, api_key: str) -> int:
        """Увеличить счётчик попыток подтверждения. Возвращает новое значение."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE leaked_keys SET confirm_attempts = "
                    "COALESCE(confirm_attempts, 0) + 1 WHERE api_key = ?",
                    (api_key,))
                conn.commit()
                row = cursor.execute(
                    "SELECT confirm_attempts FROM leaked_keys WHERE api_key = ?",
                    (api_key,)).fetchone()
                return row[0] if row else 0

    # ========================================================================
    #                  Обслуживание (очистка / уплотнение БД)
    # ========================================================================

    def cleanup_old_blobs(self, max_age_days: int = 30) -> int:
        """
        Удалить старые записи scanned_blobs (старше max_age_days).

        scanned_blobs хранит только SHA-строки (не содержимое файлов), поэтому
        таблица компактна, но при длительной эксплуатации может расти.
        Очистка старых записей разрешает повторное сканирование изменившихся файлов.
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "DELETE FROM scanned_blobs "
                    "WHERE scan_time < datetime('now', ?)",
                    (f'-{int(max_age_days)} days',)
                )
                conn.commit()
                return cursor.rowcount

    def vacuum(self) -> None:
        """Уплотнить базу данных (освободить место на диске)"""
        with self._lock:
            with self._get_connection() as conn:
                conn.execute("VACUUM")

    # ========================================================================
    #                  Модели по ключам (вкладка «Модели»)
    # ========================================================================

    def save_key_models(self, api_key: str, models: List[str],
                        confirmed: bool = False) -> int:
        """Сохранить список моделей, поддерживаемых ключом.

        Заменяет предыдущий набор моделей для данного ключа.
        Если confirmed=True — модели помечаются как подтверждённые.
        """
        if not models:
            return 0
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                key_row = cursor.execute(
                    "SELECT id, platform, base_url FROM leaked_keys "
                    "WHERE api_key = ? LIMIT 1", (api_key,)
                ).fetchone()
                if not key_row:
                    return 0
                key_id, platform, base_url = key_row
                cursor.execute(
                    "DELETE FROM key_models WHERE key_id = ?", (key_id,)
                )
                now = datetime.now().isoformat()
                rows = []
                seen = set()
                for m in models:
                    m = (m or "").strip()
                    if not m or m.lower() in seen:
                        continue
                    seen.add(m.lower())
                    rows.append((key_id, m, platform or "", base_url or "",
                                 now, 1 if confirmed else 0))
                if rows:
                    cursor.executemany(
                        "INSERT OR IGNORE INTO key_models "
                        "(key_id, model_name, platform, base_url, first_seen, is_confirmed) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        rows,
                    )
                conn.commit()
                return len(rows)

    def mark_model_confirmed(self, api_key: str, model_name: str) -> bool:
        """Пометить конкретную модель как подтверждённую (без удаления остальных)."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE key_models SET is_confirmed=1 "
                    "WHERE model_name=? AND key_id IN "
                    "(SELECT id FROM leaked_keys WHERE api_key=?)",
                    (model_name, api_key))
                conn.commit()
                return cursor.rowcount > 0

    def mark_models_confirmed_batch(self, api_key: str, model_names: List[str]) -> int:
        """Пометить несколько моделей как подтверждённые одним запросом.

        Быстрее чем mark_model_confirmed в цикле — один SELECT key_id + executemany.
        """
        if not model_names:
            return 0
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                key_row = cursor.execute(
                    "SELECT id FROM leaked_keys WHERE api_key=? LIMIT 1",
                    (api_key,)).fetchone()
                if not key_row:
                    return 0
                key_id = key_row[0]
                rows = [(key_id, m) for m in model_names if m]
                cursor.executemany(
                    "UPDATE key_models SET is_confirmed=1 "
                    "WHERE key_id=? AND model_name=?",
                    rows)
                conn.commit()
                return cursor.rowcount

    def get_models_by_key(self, api_key: str) -> List[str]:
        """Вернуть список моделей для конкретного ключа."""
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                rows = cursor.execute(
                    "SELECT km.model_name FROM key_models km "
                    "JOIN leaked_keys lk ON lk.id = km.key_id "
                    "WHERE lk.api_key = ? "
                    "ORDER BY km.model_name", (api_key,)
                ).fetchall()
                return [r[0] for r in rows]

    def get_all_models_with_counts(self) -> List[dict]:
        """Вернуть все модели с количеством поддерживающих их ключей.

        Каждая запись: {model_name, key_count, platforms (list), base_urls (list)}.
        Только ключи со статусом valid/quota_exceeded учитываются.
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                rows = cursor.execute("""
                    SELECT km.model_name,
                           COUNT(DISTINCT km.key_id) AS key_count,
                           GROUP_CONCAT(DISTINCT km.platform) AS platforms,
                           GROUP_CONCAT(DISTINCT km.base_url) AS base_urls
                    FROM key_models km
                    JOIN leaked_keys lk ON lk.id = km.key_id
                    WHERE lk.status IN ('valid', 'quota_exceeded')
                    GROUP BY km.model_name
                    ORDER BY key_count DESC
                """).fetchall()
                result = []
                for r in rows:
                    result.append({
                        "model_name": r[0],
                        "key_count": r[1],
                        "platforms": [p for p in (r[2] or "").split(",") if p],
                        "base_urls": [u for u in (r[3] or "").split(",") if u],
                    })
                return result

    def get_keys_for_model(self, model_name: str) -> List[dict]:
        """Вернуть все валидные ключи, поддерживающие указанную модель.

        Каждая запись: {id, platform, api_key, base_url, status, model_tier, rpm}.
        """
        with self._lock:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                rows = cursor.execute("""
                    SELECT lk.id, lk.platform, lk.api_key, lk.base_url,
                           lk.status, lk.model_tier, lk.rpm, lk.is_high_value,
                           lk.verified_time
                    FROM key_models km
                    JOIN leaked_keys lk ON lk.id = km.key_id
                    WHERE km.model_name = ?
                      AND lk.status IN ('valid', 'quota_exceeded')
                    ORDER BY lk.is_high_value DESC, lk.verified_time DESC
                """, (model_name,)).fetchall()
                return [
                    {
                        "id": r[0], "platform": r[1], "api_key": r[2],
                        "base_url": r[3], "status": r[4], "model_tier": r[5],
                        "rpm": r[6], "is_high_value": bool(r[7]),
                        "verified_time": r[8],
                    }
                    for r in rows
                ]
