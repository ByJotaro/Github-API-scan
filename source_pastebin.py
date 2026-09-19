"""
Сканер Pastebin - сканирование API ключей из публичных Paste Pastebin

Источники данных:
1. Pastebin Scraping API (требуется Pro аккаунт)
2. PastebinScraper публичный список (бесплатно)
"""

import re
import time
import asyncio
import threading
import queue
from typing import List, Optional, Set
from dataclasses import dataclass

import aiohttp
from aiohttp import ClientTimeout, TCPConnector
import ssl

from config import config, COMPILED_REGEX_PATTERNS, COMPILED_BASE_URL_PATTERNS
from scanner import ScanResult, calculate_entropy, is_test_key, ENTROPY_THRESHOLD
from database import Database


# Конфигурация Pastebin
PASTEBIN_SCRAPE_URL = "https://scrape.pastebin.com/api_scraping.php"
PASTEBIN_RAW_URL = "https://scrape.pastebin.com/api_scrape_item.php?i="
PASTEBIN_PUBLIC_URL = "https://pastebin.com/raw/"
PASTEBIN_ARCHIVE_URL = "https://pastebin.com/archive"
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)

# Конфигурация параллелизма.
# Таймаут поднят 15/8 → 40/12: pastebin отдаёт /raw до 10-15с на отдельных
# пастах (замер: одиночная паста 10.3с, батч 41/50 ошибок при total=15).
# Семафор 30 шире коннектора 20 — оставлено: очередь, а не скорость.
ASYNC_CONCURRENCY = 30
ASYNC_TIMEOUT = ClientTimeout(total=40, connect=12)


@dataclass
class PasteMetadata:
    """Метаданные Paste"""
    key: str
    title: str
    syntax: str
    size: int
    date: str
    url: str


@dataclass
class BatchOutcome:
    processed: int = 0
    found: int = 0
    errors: int = 0


class PastebinScanner:
    """
    Сканер Pastebin

    Поддерживает два режима:
    1. Scraping API (требуется Pro API ключ)
    2. Парсинг публичного списка Paste (бесплатно, но медленно)
    """

    def __init__(
        self,
        result_queue: queue.Queue,
        stop_event: threading.Event,
        dashboard=None,
        api_key: str = "",
        db: Optional[Database] = None,
    ):
        self.result_queue = result_queue
        self.stop_event = stop_event
        self.dashboard = dashboard
        self.db = db
        self.api_key = api_key  # Pastebin Pro API Key
        self._telemetry_healthy = True
        self._telemetry_message = ""

        # Обработанные ключи Paste
        self._processed_pastes: Set[str] = set()
        self._processed_lock = threading.Lock()

        # Компиляция регулярных выражений
        self._key_patterns = {
            k: v
            for k, v in COMPILED_REGEX_PATTERNS.items()
            if k != "azure"  # Azure требует особой обработки
        }

        # Статистика
        self.stats = {
            "pastes_scanned": 0,
            "keys_found": 0,
        }

        # aiohttp session
        self._session: Optional[aiohttp.ClientSession] = None

    def _log(self, message: str, level: str = "INFO"):
        """Вывод логов"""
        if self.dashboard:
            self.dashboard.add_log(f"[Pastebin] {message}", level)

    def _telemetry_error(self, message: str, count: int = 1):
        self._telemetry_healthy = False
        self._telemetry_message = message
        if self.db:
            self.db.safe_upsert_source_progress(
                "pastebin", status="error", phase="error", message=message,
                errors_increment=count,
            )

    def _telemetry_running(self, phase: str):
        self._telemetry_healthy = True
        self._telemetry_message = ""
        if self.db:
            self.db.safe_upsert_source_progress(
                "pastebin", status="running", phase=phase, message=""
            )

    def _telemetry_waiting(self):
        if not self.db:
            return
        if self._telemetry_healthy:
            self.db.safe_upsert_source_progress(
                "pastebin", status="running", phase="waiting", message=""
            )
        else:
            self.db.safe_upsert_source_progress(
                "pastebin", status="error", phase="error",
                message=self._telemetry_message,
            )

    async def _get_session(self) -> aiohttp.ClientSession:
        """Получение aiohttp session"""
        if self._session is None or self._session.closed:
            connector = TCPConnector(
                limit=20,
                limit_per_host=10,
                ssl=ssl.create_default_context(),
                force_close=False,
                use_dns_cache=True,
                ttl_dns_cache=600,
                keepalive_timeout=60,
                enable_cleanup_closed=True,
                resolver=aiohttp.resolver.ThreadedResolver(),
            )
            self._session = aiohttp.ClientSession(
                connector=connector, timeout=ASYNC_TIMEOUT, trust_env=True
            )
        return self._session

    async def _close_session(self):
        """Закрытие session"""
        if self._session and not self._session.closed:
            await self._session.close()

    async def _fetch_recent_pastes(self, limit: int = 100) -> List[PasteMetadata]:
        """
        Получение списка последних публичных Paste.

        Приоритет: Scraping API (требует whitelist IP). При HTTP 401/403
        (IP не в whitelist) — fallback на публичный /archive.
        Без ключа — сразу archive (keyless-режим, а не disabled).
        """
        if not self.api_key:
            self._log("Pastebin API Key не настроен — keyless archive-режим", "WARN")
            return await self._fetch_archive_pastes(limit)

        try:
            session = await self._get_session()
            url = f"{PASTEBIN_SCRAPE_URL}?limit={limit}"
            proxy = config.proxy_url if config.proxy_url else None

            async with session.get(url, proxy=proxy) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    pastes = []
                    for item in data:
                        pastes.append(PasteMetadata(
                            key=item.get("key", ""),
                            title=item.get("title", ""),
                            syntax=item.get("syntax", ""),
                            size=int(item.get("size", 0)),
                            date=item.get("date", ""),
                            url=f"https://pastebin.com/{item.get('key', '')}"
                        ))
                    self._telemetry_running("fetch")
                    return pastes
                if resp.status in (401, 403):
                    self._log(
                        f"Scraping API HTTP {resp.status} (IP не в whitelist), "
                        "fallback на публичный /archive",
                        "WARN",
                    )
                    return await self._fetch_archive_pastes(limit)
                self._log(f"Ошибка получения списка Paste: HTTP {resp.status}", "ERROR")
                self._telemetry_error(f"Pastebin listing failed (HTTP {resp.status})")
                return []
        except Exception as e:
            self._log(f"Ошибка получения списка Paste: {type(e).__name__}", "ERROR")
            self._telemetry_error(f"Pastebin listing failed ({type(e).__name__})")
            return []

    async def _fetch_archive_pastes(self, limit: int = 100) -> List[PasteMetadata]:
        """Fallback: парсинг публичного https://pastebin.com/archive (без whitelist).

        3 попытки: одиночный TimeoutError раз в ~10 циклов раньше клал весь
        источник в error/error (замер 2026-09-19: 2-3 таймаута подряд).
        """
        last_err = ""
        for attempt in range(3):
            try:
                session = await self._get_session()
                proxy = config.proxy_url if config.proxy_url else None
                headers = {"User-Agent": BROWSER_UA}
                async with session.get(PASTEBIN_ARCHIVE_URL, proxy=proxy, headers=headers) as resp:
                    if resp.status != 200:
                        self._log(f"Archive fallback: HTTP {resp.status}", "ERROR")
                        self._telemetry_error(f"Pastebin archive failed (HTTP {resp.status})")
                        return []
                    html = await resp.text(errors="ignore")
                keys: List[str] = []
                seen = set()
                for m in re.finditer(r'href="/([A-Za-z0-9]{8})(?:\?[^"]*)?"', html):
                    k = m.group(1)
                    if k not in seen:
                        seen.add(k)
                        keys.append(k)
                    if len(keys) >= limit:
                        break
                pastes = [
                    PasteMetadata(key=k, title="", syntax="", size=0, date="", url=f"https://pastebin.com/{k}")
                    for k in keys
                ]
                if pastes:
                    self._log(f"Archive fallback: получено {len(pastes)} Paste", "SCAN")
                    self._telemetry_running("fetch")
                else:
                    self._log("Archive fallback: пасты не найдены", "WARN")
                    self._telemetry_error("Pastebin archive empty")
                return pastes
            except Exception as e:
                last_err = type(e).__name__
                if attempt < 2:
                    await asyncio.sleep(2 * (attempt + 1))
                    continue
                self._log(f"Archive fallback: {last_err} (3 попытки)", "ERROR")
                self._telemetry_error(f"Pastebin archive failed ({last_err})")
                return []
        self._telemetry_error(f"Pastebin archive failed ({last_err})")
        return []

    async def _fetch_paste_content(self, paste_key: str) -> Optional[str]:
        """Получение содержимого Paste: публичный /raw (работает без whitelist)."""
        try:
            session = await self._get_session()
            url = f"{PASTEBIN_PUBLIC_URL}{paste_key}"
            proxy = config.proxy_url if config.proxy_url else None
            headers = {"User-Agent": BROWSER_UA}

            async with session.get(url, proxy=proxy, headers=headers) as resp:
                if resp.status == 200:
                    body = await resp.text(errors="ignore")
                    # /raw отдаёт HTML вместо текста = капча/блок: не считать контентом
                    if "<!DOCTYPE html>" in body[:2000] or "<html" in body[:2000]:
                        return None
                    return body
                return None
        except Exception:
            return None

    def _extract_base_url(self, context: str, platform: str) -> tuple:
        """Как в PasterScanner: prefer baseURL/endpoint рядом с ключом."""
        candidates = []
        preferred = re.compile(
            r"(?:baseURL|base_url|endpoint|api_base|apiBase)\s*[\"']?\s*[:=]\s*[\"']"
            r"(https?://[^\"'\s,}]+)",
            re.IGNORECASE,
        )
        for match in preferred.finditer(context):
            candidates.append((0, match.start(), match.group(1)))
        for pattern in COMPILED_BASE_URL_PATTERNS:
            for match in pattern.finditer(context):
                url = (match.group(1) if match.lastindex else match.group(0)).strip()
                url = url.rstrip('/"\'')
                candidates.append((1, match.start(), url))
        for _, _, url in sorted(candidates):
            if not url.startswith(("http://", "https://")):
                continue
            if "pastebin.com" in url or "github.com" in url:
                continue
            is_relay = platform == "openai" and "api.openai.com" not in url.lower()
            return url, is_relay
        return config.default_base_urls.get(platform, ""), False

    def _extract_keys(self, content: str, source_url: str) -> List[ScanResult]:
        """Извлечение API ключей + relay/base_url как в PasterScanner."""
        results = []

        for platform, pattern in self._key_patterns.items():
            for match in pattern.finditer(content):
                api_key = match.group(0)

                # Проверка тестовых ключей
                if is_test_key(api_key):
                    continue

                # Дедуп через БД (переживает рестарт, в отличие от set)
                if self.db and self.db.key_exists(api_key):
                    continue

                # Фильтрация по энтропии
                key_body = api_key.split("-", 2)[-1] if api_key.startswith("sk-") else api_key
                if calculate_entropy(key_body) < ENTROPY_THRESHOLD:
                    continue

                # Контекст шире (1000) — base_url часто не рядом с ключом
                start = max(0, match.start() - 1000)
                end = min(len(content), match.end() + 1000)
                context = content[start:end]
                # AWS secret без контекста = base64-мусор (как в scanner.py:1179
                # и key_extractor.py:151 — там гард уже есть, здесь не было).
                if platform in ("aws_secret_key", "aws_secret"):
                    ctx_low = context.lower()
                    if not any(word in ctx_low for word in (
                        "aws_secret_access_key", "aws_secret_key",
                        "aws_secret", "secret_access_key", "secret key",
                        "access_key", "aws_access")):
                        continue
                base_url, is_relay = self._extract_base_url(context, platform)

                results.append(ScanResult(
                    platform="relay" if is_relay else platform,
                    api_key=api_key,
                    base_url=base_url,
                    source_url=source_url,
                    is_relay=is_relay,
                    context=context
                ))

        return results

    async def _scan_paste(self, paste: PasteMetadata) -> BatchOutcome:
        """Сканирование одного Paste (дедуп: память + scanned_source_items)."""
        with self._processed_lock:
            if paste.key in self._processed_pastes:
                return BatchOutcome()
            self._processed_pastes.add(paste.key)
        if self.db and self.db.is_source_item_scanned("pastebin", paste.key):
            return BatchOutcome()

        content = await self._fetch_paste_content(paste.key)
        if not content:
            return BatchOutcome(errors=1)

        self.stats["pastes_scanned"] += 1
        results = self._extract_keys(content, paste.url)
        found = 0
        errors = 0
        for result in results:
            try:
                self.result_queue.put(result, timeout=5)
                found += 1
                self.stats["keys_found"] += 1
                self._log(f"Обнаружен {result.platform.upper()} Key: {result.api_key[:12]}...", "FOUND")
            except queue.Full:
                errors += 1
        if self.db:
            self.db.mark_source_item_scanned("pastebin", paste.key)

        return BatchOutcome(processed=1, found=found, errors=errors)

    async def _scan_batch(self, pastes: List[PasteMetadata]) -> BatchOutcome:
        """Пакетное сканирование Paste"""
        semaphore = asyncio.Semaphore(ASYNC_CONCURRENCY)

        async def scan_one(paste):
            async with semaphore:
                return await self._scan_paste(paste)

        results = await asyncio.gather(
            *(scan_one(p) for p in pastes), return_exceptions=True
        )
        outcome = BatchOutcome()
        for result in results:
            if isinstance(result, BaseException):
                outcome.errors += 1
            elif isinstance(result, tuple):
                processed, found, errors = result
                outcome.processed += processed
                outcome.found += found
                outcome.errors += errors
            else:
                outcome.processed += result.processed
                outcome.found += result.found
                outcome.errors += result.errors
        return outcome

    def run(self):
        """Запуск основного цикла сканера (keyless archive-режим без ключа)."""
        self._log("Сканер Pastebin запущен", "INFO")
        if self.db:
            self.db.safe_upsert_source_progress(
                "pastebin", status="running", phase="fetch", message=""
            )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            while not self.stop_event.is_set():
                # Получение последних Paste
                pastes = loop.run_until_complete(self._fetch_recent_pastes(100))

                if pastes:
                    self._log(f"Получено {len(pastes)} Paste", "SCAN")
                    if self.db:
                        self.db.safe_upsert_source_progress(
                            "pastebin", status="running", phase="scan",
                            total=len(pastes), current=0, message="",
                        )
                    outcome = loop.run_until_complete(self._scan_batch(pastes))
                    # Толерантность: единичные raw-fails (удалён/капча) — норма.
                    # error только при полном провале батча (processed==0).
                    batch_failed = outcome.errors > 0 and outcome.processed == 0
                    if self.db:
                        self.db.safe_upsert_source_progress(
                            "pastebin",
                            status="error" if batch_failed else "running",
                            phase="error" if batch_failed else "scan",
                            current=outcome.processed, total=len(pastes),
                            message="Pastebin scan batch failed" if batch_failed else "",
                            processed_increment=outcome.processed,
                            found_increment=outcome.found,
                            errors_increment=outcome.errors,
                        )
                    if outcome.found > 0:
                        self._log(f"В этом цикле найдено {outcome.found} ключей", "INFO")

                # Ожидание следующего цикла
                for second in range(30):  # Интервал 30 секунд
                    if self.stop_event.is_set():
                        break
                    if self.db and second == 0:
                        self._telemetry_waiting()
                    time.sleep(1)
        finally:
            loop.run_until_complete(self._close_session())
            loop.close()

        if self.db:
            self.db.safe_upsert_source_progress("pastebin", status="stopped", phase="stopped")
        self._log("Сканер Pastebin остановлен", "INFO")


def start_pastebin_scanner(
    result_queue: queue.Queue,
    stop_event: threading.Event,
    dashboard=None,
    api_key: str = "",
    db: Optional[Database] = None,
) -> threading.Thread:
    """Запуск потока сканера Pastebin"""
    scanner = PastebinScanner(result_queue, stop_event, dashboard, api_key, db)

    def safe_run():
        try:
            scanner.run()
        except Exception as exc:
            if db:
                db.safe_upsert_source_progress(
                    "pastebin", status="error", phase="error",
                    message=type(exc).__name__, errors_increment=1,
                )

    thread = threading.Thread(
        target=safe_run,
        name="PastebinScanner",
        daemon=True
    )
    thread.start()
    return thread
