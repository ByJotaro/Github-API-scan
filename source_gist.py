"""
GitHub Gist сканер - сканирование API ключей из публичных Gist

Использует GitHub API для поиска публичных Gist
"""

import re
import time
import asyncio
import threading
import queue
from typing import List, Optional, Set
from dataclasses import dataclass
from datetime import datetime, timezone

import aiohttp
from aiohttp import ClientTimeout, TCPConnector
from github import Github, GithubException
import ssl

from config import config, COMPILED_REGEX_PATTERNS
from scanner import ScanResult, calculate_entropy, is_test_key, ENTROPY_THRESHOLD
from database import Database


# Конфигурация параллелизма (semaphore == connector limit: шире — очередь,
# а не скорость; уже — недогруз pipe).
ASYNC_CONCURRENCY = 20

# Ключевые слова для поиска Gist
GIST_SEARCH_KEYWORDS = [
    "OPENAI_API_KEY",
    "sk-proj-",
    "sk-ant-",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "AIzaSy",
    "hf_",
    "gsk_",
    "HUGGINGFACE_TOKEN",
    "GROQ_API_KEY",
    "DEEPSEEK_API_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "ghp_",
    "sk_live_",
]


@dataclass
class GistFile:
    """Информация о файле Gist"""
    gist_id: str
    filename: str
    raw_url: str
    html_url: str
    size: int


@dataclass
class BatchOutcome:
    processed: int = 0
    found: int = 0
    errors: int = 0


class GistScanner:
    """
    Сканер GitHub Gist

    Использует GitHub API для поиска конфиденциальных данных в публичных Gist
    """

    def __init__(
        self,
        result_queue: queue.Queue,
        stop_event: threading.Event,
        dashboard=None,
        db: Optional[Database] = None,
    ):
        self.result_queue = result_queue
        self.stop_event = stop_event
        self.dashboard = dashboard
        self.db = db
        self._telemetry_healthy = True

        # Клиент GitHub
        self._github_clients: List[Github] = []
        self._current_client_index = 0
        self._bad_github_tokens: Set[str] = set()
        self._client_lock = threading.Lock()
        self._init_github_clients()

        # Обработанные ID Gist
        self._processed_gists: Set[str] = set()
        self._processed_lock = threading.Lock()

        # Компиляция регулярных выражений
        self._key_patterns = {
            k: v
            for k, v in COMPILED_REGEX_PATTERNS.items()
            if k != "azure"
        }

        # Статистика
        self.stats = {
            "gists_scanned": 0,
            "keys_found": 0,
        }

        # aiohttp session
        self._session: Optional[aiohttp.ClientSession] = None

    def _init_github_clients(self):
        """Инициализация клиента GitHub (с запоминанием токена для каждого)."""
        # Храним пары (token, client), чтобы помечать битые токены.
        self._github_clients = []  # type: ignore[assignment]
        self._client_tokens: List[str] = []
        if config.github_tokens:
            for token in config.github_tokens:
                if not token:
                    continue
                client = Github(
                    login_or_token=token,
                    per_page=30,
                    timeout=config.request_timeout
                )
                self._github_clients.append(client)
                self._client_tokens.append(token)
        else:
            self._github_clients.append(Github(per_page=30, timeout=config.request_timeout))
            self._client_tokens.append("")

    def _get_client(self) -> Github:
        """Получение текущего (не битого) клиента GitHub с ротацией."""
        with self._client_lock:
            n = len(self._github_clients)
            if n == 0:
                # fallback: без токена
                return Github(per_page=30, timeout=config.request_timeout)
            # пропустить битые токены
            for _ in range(n):
                idx = self._current_client_index % n
                token = self._client_tokens[idx]
                if token and token in self._bad_github_tokens:
                    self._current_client_index = (idx + 1) % n
                    continue
                return self._github_clients[idx]
            # все биты — вернуть текущий
            return self._github_clients[self._current_client_index % n]

    def _mark_token_bad(self, client: Github) -> None:
        """Пометить токен текущего клиента как битый и ротировать."""
        with self._client_lock:
            idx = self._current_client_index % len(self._github_clients)
            token = self._client_tokens[idx] if idx < len(self._client_tokens) else ""
            if token:
                self._bad_github_tokens.add(token)
            self._current_client_index = (idx + 1) % len(self._github_clients)

    def _rotate_client(self):
        """Ротация клиентов"""
        with self._client_lock:
            self._current_client_index = (self._current_client_index + 1) % len(self._github_clients)

    def _log(self, message: str, level: str = "INFO"):
        """Вывод логов"""
        if self.dashboard:
            self.dashboard.add_log(f"[Gist] {message}", level)

    def _telemetry_error(self, message: str, count: int = 1):
        self._telemetry_healthy = False
        if self.db:
            self.db.safe_upsert_source_progress(
                "gist", status="error", phase="error", message=message,
                errors_increment=count,
            )

    def _telemetry_running(self, phase: str):
        self._telemetry_healthy = True
        if self.db:
            self.db.safe_upsert_source_progress(
                "gist", status="running", phase=phase, message=""
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

    async def _fetch_gist_content(self, raw_url: str) -> Optional[str]:
        """Получение содержимого файла Gist"""
        try:
            session = await self._get_session()
            proxy = config.proxy_url if config.proxy_url else None

            async with session.get(raw_url, proxy=proxy) as resp:
                if resp.status != 200:
                    self._telemetry_error(
                        f"gist content request failed (HTTP {resp.status})"
                    )
                    return None
                content = await resp.text(errors='ignore')
                self._telemetry_running("scan")
                return content
        except Exception as exc:
            self._telemetry_error(
                f"gist content request failed ({type(exc).__name__})"
            )
            return None

    def _extract_keys(self, content: str, source_url: str) -> List[ScanResult]:
        """Извлечение API ключей из содержимого"""
        results = []

        for platform, pattern in self._key_patterns.items():
            for match in pattern.finditer(content):
                api_key = match.group(0)

                # Проверка тестовых ключей
                if is_test_key(api_key):
                    continue

                # Фильтрация по энтропии
                key_body = api_key
                prefixes = ['sk-proj-', 'sk-ant-', 'sk-', 'AIza', 'hf_', 'gsk_']
                for prefix in prefixes:
                    if api_key.startswith(prefix):
                        key_body = api_key[len(prefix):]
                        break

                if calculate_entropy(key_body) < ENTROPY_THRESHOLD:
                    continue

                # Извлечение контекста
                start = max(0, match.start() - 200)
                end = min(len(content), match.end() + 200)
                context = content[start:end]

                results.append(ScanResult(
                    platform=platform,
                    api_key=api_key,
                    base_url=config.default_base_urls.get(platform, ""),
                    source_url=source_url,
                    context=context
                ))

        return results

    def _search_gists(self, keyword: str = "") -> List[GistFile]:
        """Получение публичных Gist.

        PyGithub НЕ имеет search_gists(). Используем:
        1) Github.get_gists() — публичный поток gists (с токеном если есть)
        2) fallback: GET /gists/public без токена (60 req/hr)
        keyword оставлен для совместимости, но API gists/public не фильтрует по нему.
        """
        gist_files = []

        try:
            client = self._get_client()
            # get_gists() — публичные gists (since=None → recent public)
            public_gists = client.get_gists()

            for i, gist in enumerate(public_gists):
                if self.stop_event.is_set():
                    break
                if i >= 100:
                    break

                try:
                    gist_id = gist.id

                    with self._processed_lock:
                        if gist_id in self._processed_gists:
                            continue
                        self._processed_gists.add(gist_id)

                    for filename, file_info in gist.files.items():
                        raw_url = file_info.raw_url
                        if raw_url:
                            gist_files.append(GistFile(
                                gist_id=gist_id,
                                filename=filename,
                                raw_url=raw_url,
                                html_url=gist.html_url,
                                size=file_info.size or 0
                            ))
                    self._telemetry_running("fetch")
                except Exception as exc:
                    self._telemetry_error(
                        f"gist metadata processing failed ({type(exc).__name__})"
                    )
                    continue

            if not self.stop_event.is_set():
                self._telemetry_running("fetch")
        except GithubException as exc:
            msg = str(exc).lower()
            if "rate limit" in msg:
                self._log("Превышен лимит запросов GitHub API, ожидание...", "WARN")
                self._telemetry_error("GitHub API rate limited")
                self._rotate_client()
                for _ in range(60):
                    if self.stop_event.is_set():
                        break
                    time.sleep(1)
                if self.db:
                    self.db.safe_upsert_source_progress(
                        "gist", status="running", phase="waiting", message=""
                    )
            elif "bad credentials" in msg or getattr(exc, "status", None) == 401:
                self._log("GitHub token недействителен (401), ротация / public fallback", "WARN")
                self._telemetry_error("GitHub token bad credentials")
                try:
                    self._mark_token_bad(self._get_client())
                except Exception:
                    pass
                # Fallback: public API без токена
                gist_files = self._fetch_public_gists_no_auth()
            else:
                self._log(f"Ошибка GitHub API: {type(exc).__name__}", "ERROR")
                self._telemetry_error(
                    f"GitHub API request failed ({type(exc).__name__})"
                )
                gist_files = self._fetch_public_gists_no_auth()
        except Exception as exc:
            self._log(f"Ошибка поиска: {type(exc).__name__}", "ERROR")
            self._telemetry_error(f"gist search failed ({type(exc).__name__})")
            gist_files = self._fetch_public_gists_no_auth()

        return gist_files

    def _fetch_public_gists_no_auth(self) -> List[GistFile]:
        """Fallback: GET /gists/public без токена (публичный лимит 60/hr)."""
        gist_files: List[GistFile] = []
        import urllib.request
        import urllib.error
        import json as _json

        last_err = None
        data = None
        for attempt in range(3):
            try:
                req = urllib.request.Request(
                    "https://api.github.com/gists/public?per_page=30",
                    headers={
                        "Accept": "application/vnd.github.v3+json",
                        "User-Agent": "Github-API-scan/1.0",
                    },
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = _json.loads(resp.read().decode("utf-8", errors="ignore"))
                break
            except urllib.error.HTTPError as exc:
                last_err = exc
                # 403/429 — rate limit; подождать и retry
                if exc.code in (403, 429):
                    wait = 15 * (attempt + 1)
                    self._log(f"Public gists HTTP {exc.code}, wait {wait}s...", "WARN")
                    for _ in range(wait):
                        if self.stop_event.is_set():
                            return []
                        time.sleep(1)
                    continue
                break
            except Exception as exc:
                last_err = exc
                break

        if data is None:
            self._log(f"Public gists fallback failed: {type(last_err).__name__}", "ERROR")
            self._telemetry_error(f"public gists failed ({type(last_err).__name__})")
            return []

        try:
            for item in data:
                gist_id = item.get("id", "")
                if not gist_id:
                    continue
                with self._processed_lock:
                    if gist_id in self._processed_gists:
                        continue
                    self._processed_gists.add(gist_id)
                for filename, file_info in (item.get("files") or {}).items():
                    raw_url = (file_info or {}).get("raw_url")
                    if raw_url:
                        gist_files.append(GistFile(
                            gist_id=gist_id,
                            filename=filename,
                            raw_url=raw_url,
                            html_url=item.get("html_url", ""),
                            size=(file_info or {}).get("size") or 0,
                        ))
            self._telemetry_running("fetch")
            self._log(f"Public API: получено {len(gist_files)} файлов Gist", "INFO")
        except Exception as exc:
            self._log(f"Public gists parse failed: {type(exc).__name__}", "ERROR")
            self._telemetry_error(f"public gists parse failed ({type(exc).__name__})")
        return gist_files

    async def _scan_gist_file(self, gist_file: GistFile) -> BatchOutcome:
        """Сканирование одного файла Gist"""
        content = await self._fetch_gist_content(gist_file.raw_url)
        if not content:
            return BatchOutcome(errors=1)

        self.stats["gists_scanned"] += 1
        results = self._extract_keys(content, gist_file.html_url)
        delivered = 0
        errors = 0
        for result in results:
            try:
                self.result_queue.put(result, timeout=5)
                delivered += 1
                self.stats["keys_found"] += 1
                self._log(f"Обнаружен {result.platform.upper()} Key: {result.api_key[:12]}...", "FOUND")
            except queue.Full:
                errors += 1

        return BatchOutcome(processed=1, found=delivered, errors=errors)

    async def _scan_batch(self, gist_files: List[GistFile]) -> BatchOutcome:
        """Пакетное сканирование файлов Gist"""
        semaphore = asyncio.Semaphore(ASYNC_CONCURRENCY)

        async def scan_one(gf):
            async with semaphore:
                return await self._scan_gist_file(gf)

        results = await asyncio.gather(
            *(scan_one(gf) for gf in gist_files), return_exceptions=True
        )
        outcome = BatchOutcome()
        for result in results:
            if isinstance(result, BaseException):
                outcome.errors += 1
            else:
                outcome.processed += result.processed
                outcome.found += result.found
                outcome.errors += result.errors

        if outcome.errors:
            self._telemetry_error("gist scan batch failed", outcome.errors)
        else:
            self._telemetry_running("scan")
        return outcome

    def run(self):
        """Запуск основного цикла сканера"""
        self._log("Сканер Gist запущен", "INFO")
        if self.db:
            self.db.safe_upsert_source_progress("gist", status="running", phase="fetch", message="")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            while not self.stop_event.is_set():
                total_found = 0

                self._log("Получение публичных Gist...", "SCAN")

                # Получение публичных Gist (без поиска по ключевым словам)
                gist_files = self._search_gists("")

                if gist_files:
                    self._log(f"Найдено {len(gist_files)} файлов Gist", "INFO")
                    if self.db:
                        self.db.safe_upsert_source_progress(
                            "gist", status="running", phase="scan",
                            total=len(gist_files), current=0, message="",
                        )
                    outcome = loop.run_until_complete(self._scan_batch(gist_files))
                    total_found += outcome.found
                    if self.db:
                        self.db.safe_upsert_source_progress(
                            "gist",
                            status="error" if outcome.errors else "running",
                            phase="error" if outcome.errors else "scan",
                            current=outcome.processed, total=len(gist_files),
                            message="gist scan batch failed" if outcome.errors else "",
                            processed_increment=outcome.processed,
                            found_increment=outcome.found,
                        )

                self._rotate_client()

                if total_found > 0:
                    self._log(f"В этом цикле найдено {total_found} ключей", "INFO")

                # Ожидание следующего цикла
                self._log("Ожидание 3 минут до следующего цикла...", "INFO")
                # Worker жив и retry-ит — даже после auth/network error.
                self._telemetry_healthy = True
                for second in range(180):
                    if self.stop_event.is_set():
                        break
                    if self.db and second % 30 == 0:
                        self.db.safe_upsert_source_progress(
                            "gist", status="running", phase="waiting", message=""
                        )
                    time.sleep(1)

        finally:
            loop.run_until_complete(self._close_session())
            loop.close()

        if self.db:
            self.db.safe_upsert_source_progress("gist", status="stopped", phase="stopped")
        self._log("Сканер Gist остановлен", "INFO")


def start_gist_scanner(
    result_queue: queue.Queue,
    stop_event: threading.Event,
    dashboard=None,
    db: Optional[Database] = None,
) -> threading.Thread:
    """Запуск потока сканера Gist"""
    scanner = GistScanner(result_queue, stop_event, dashboard, db)

    def safe_run():
        try:
            scanner.run()
        except Exception as exc:
            if db:
                db.safe_upsert_source_progress(
                    "gist", status="error", phase="error",
                    message=type(exc).__name__, errors_increment=1,
                )

    thread = threading.Thread(
        target=safe_run,
        name="GistScanner",
        daemon=True
    )
    thread.start()
    return thread
