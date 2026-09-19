"""
Мониторинг событий GitHub в реальном времени - отслеживание утечек API ключей в новых коммитах

Особенности:
- Использует GitHub Events API для мониторинга в реальном времени
- Отслеживает новые коммиты в PushEvent
- Мгновенная проверка обнаруженных ключей
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

from config import config, COMPILED_REGEX_PATTERNS
from scanner import ScanResult, calculate_entropy, is_test_key, ENTROPY_THRESHOLD
from database import Database


GITHUB_EVENTS_API = "https://api.github.com/events"
ASYNC_TIMEOUT = ClientTimeout(total=15, connect=10)

# Ключевые слова высокой ценности - быстрая фильтрация.
# Расширено: раньше было 7 строк и пропускало gsk_/hf_/groq/mistral/cohere.
HIGH_VALUE_KEYWORDS = [
    'sk-proj-', 'sk-ant-', 'sk-or-v1-', 'AIzaSy', 'OPENAI_API_KEY',
    'ANTHROPIC_API_KEY', 'GEMINI_API_KEY', 'GROQ_API_KEY', 'MISTRAL_API_KEY',
    'COHERE_API_KEY', 'DEEPSEEK_API_KEY', 'HUGGINGFACE_TOKEN', 'gsk_', 'hf_',
    'xai-', 'ghp_', 'github_pat_', 'gho_', 'pplx-', 'nvapi-', 'csk_',
    'tvly-', 'fc-', 'apify_api_', '.env',
]


@dataclass
class CommitFile:
    """Информация о файле коммита"""
    filename: str
    raw_url: str
    repo: str
    sha: str


class RealtimeScanner:
    """Сканер событий в реальном времени"""

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

        self._processed_shas: Set[str] = set()
        self._processed_lock = threading.Lock()

        self._key_patterns = {
            k: v
            for k, v in COMPILED_REGEX_PATTERNS.items()
            if k not in ("azure", "aws_secret_key")
        }

        self.stats = {"events_checked": 0, "commits_scanned": 0, "keys_found": 0}
        self._session: Optional[aiohttp.ClientSession] = None
        self._last_etag: Optional[str] = None
        self._telemetry_healthy = True
        self._telemetry_message = ""

    def _log(self, message: str, level: str = "INFO"):
        if self.dashboard:
            self.dashboard.add_log(f"[Realtime] {message}", level)

    def _telemetry_error(self, message: str, count: int = 1):
        self._telemetry_healthy = False
        self._telemetry_message = message
        if self.db:
            self.db.safe_upsert_source_progress(
                "realtime", status="error", phase="error", message=message,
                errors_increment=count,
            )

    def _telemetry_running(self, phase: str):
        self._telemetry_healthy = True
        self._telemetry_message = ""
        if self.db:
            self.db.safe_upsert_source_progress(
                "realtime", status="running", phase=phase, message=""
            )

    def _telemetry_waiting(self):
        if not self.db:
            return
        # Worker жив: в паузе показываем running/waiting (с последним message при ошибке).
        self.db.safe_upsert_source_progress(
            "realtime",
            status="running",
            phase="waiting" if self._telemetry_healthy else "retry",
            message="" if self._telemetry_healthy else (self._telemetry_message or "retrying"),
        )

    async def _get_session(self) -> aiohttp.ClientSession:
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
        if self._session and not self._session.closed:
            await self._session.close()

    async def _fetch_events(self) -> List[dict]:
        """Получение последних публичных событий (без токена, через публичный API)"""
        try:
            session = await self._get_session()
            headers = {"Accept": "application/vnd.github.v3+json"}

            # Пробуем токен, если есть (иначе публичный лимит 60/hr)
            token = config.get_random_token()
            if token:
                headers["Authorization"] = f"token {token}"

            if self._last_etag:
                headers["If-None-Match"] = self._last_etag

            proxy = config.proxy_url if config.proxy_url else None

            async with session.get(GITHUB_EVENTS_API, headers=headers, proxy=proxy) as resp:
                if resp.status == 304:  # Не изменено
                    self._telemetry_running("events")
                    return []
                if resp.status == 401:
                    # Токен мёртв — продолжаем без него (публичный лимит)
                    self._log("GitHub token 401 (dead). Используем публичный лимит.", "WARN")
                    self._telemetry_error("GitHub token 401 (dead)")
                    # Повторяем без токена
                    if token:
                        headers.pop("Authorization", None)
                        async with session.get(GITHUB_EVENTS_API, headers=headers, proxy=proxy) as resp2:
                            if resp2.status == 200:
                                self._last_etag = resp2.headers.get("ETag")
                                self._telemetry_running("events")
                                return await resp2.json()
                    return []
                if resp.status != 200:
                    self._telemetry_error(f"GitHub events request failed (HTTP {resp.status})")
                    return []

                self._last_etag = resp.headers.get("ETag")
                events = await resp.json()
                self._telemetry_running("events")
                return events

        except Exception as e:
            self._log(f"Ошибка получения событий: {type(e).__name__}", "ERROR")
            self._telemetry_error(f"GitHub events request failed ({type(e).__name__})")
            return []

    async def _fetch_public_gists(self) -> List[dict]:
        """Fallback: получение публичных gists (без токена)"""
        try:
            session = await self._get_session()
            async with session.get("https://api.github.com/gists/public", params={"per_page": 30}) as resp:
                if resp.status != 200:
                    return []
                return await resp.json()
        except Exception:
            return []

    async def _fetch_trending_repos(self) -> List[dict]:
        """Fallback: получение трендовых репозиториев (без токена)"""
        try:
            session = await self._get_session()
            async with session.get(
                "https://api.github.com/search/repositories",
                params={"q": "stars:>1000", "sort": "updated", "order": "desc", "per_page": 20}
            ) as resp:
                if resp.status != 200:
                    return []
                data = await resp.json()
                return data.get("items", [])
        except Exception:
            return []

    async def _fetch_commit_content(self, repo: str, sha: str) -> Optional[str]:
        """Получение содержимого patch коммита"""
        try:
            session = await self._get_session()
            url = f"https://api.github.com/repos/{repo}/commits/{sha}"
            headers = {
                "Accept": "application/vnd.github.v3+json"
            }

            token = config.get_random_token()
            if token:
                headers["Authorization"] = f"token {token}"

            proxy = config.proxy_url if config.proxy_url else None

            async with session.get(url, headers=headers, proxy=proxy) as resp:
                if resp.status != 200:
                    return None

                data = await resp.json()
                # Извлечение patch всех файлов
                patches = []
                for file in data.get("files", []):
                    patch = file.get("patch", "")
                    filename = file.get("filename", "")
                    if patch:
                        patches.append(f"# {filename}\n{patch}")

                return "\n".join(patches)

        except Exception:
            return None

    def _quick_filter(self, content: str) -> bool:
        """Быстрая фильтрация - проверка наличия ключевых слов высокой ценности"""
        content_lower = content.lower()
        return any(kw.lower() in content_lower for kw in HIGH_VALUE_KEYWORDS)

    def _extract_keys(self, content: str, source_url: str) -> List[ScanResult]:
        """Извлечение ключей"""
        results = []

        for platform, pattern in self._key_patterns.items():
            for match in pattern.finditer(content):
                api_key = match.group(0)

                if is_test_key(api_key):
                    continue

                key_body = api_key
                for prefix in ['sk-proj-', 'sk-ant-', 'sk-', 'AIza', 'hf_', 'gsk_']:
                    if api_key.startswith(prefix):
                        key_body = api_key[len(prefix):]
                        break

                if calculate_entropy(key_body) < ENTROPY_THRESHOLD:
                    continue

                start = max(0, match.start() - 100)
                end = min(len(content), match.end() + 100)

                results.append(ScanResult(
                    platform=platform,
                    api_key=api_key,
                    base_url=config.default_base_urls.get(platform, ""),
                    source_url=source_url,
                    context=content[start:end]
                ))

        return results

    async def _process_push_event(self, event: dict) -> int:
        """Обработка PushEvent"""
        found = 0
        repo = event.get("repo", {}).get("name", "")
        payload = event.get("payload", {})
        commits = payload.get("commits", [])

        for commit in commits:
            sha = commit.get("sha", "")
            message = commit.get("message", "")

            with self._processed_lock:
                if sha in self._processed_shas:
                    continue
                self._processed_shas.add(sha)

            # Быстрая фильтрация commit message
            if not self._quick_filter(message):
                # Получение полного patch
                content = await self._fetch_commit_content(repo, sha)
                if not content:
                    continue
                if not self._quick_filter(content):
                    continue
            else:
                content = await self._fetch_commit_content(repo, sha)
                if not content:
                    continue

            self.stats["commits_scanned"] += 1
            source_url = f"https://github.com/{repo}/commit/{sha}"
            results = self._extract_keys(content, source_url)

            for result in results:
                try:
                    # Использование приоритетной очереди - новые находки впереди
                    self.result_queue.put(result, timeout=1)
                    found += 1
                    self.stats["keys_found"] += 1
                    self._log(f"Обнаружено в реальном времени {result.platform.upper()}: {result.api_key[:20]}...", "FOUND")
                except queue.Full:
                    pass

        return found

    async def _scan_cycle(self) -> int:
        """Один цикл сканирования (events + fallback на gists/repos при ошибках)"""
        events = await self._fetch_events()

        # Fallback: если events пуст (401 или rate limit), пробуем публичные gists
        if not events:
            gists = await self._fetch_public_gists()
            if gists:
                self._log(f"Fallback: проверяем {len(gists)} публичных gists", "DEBUG")
                found_from_gists = 0
                for gist in gists:
                    if self.stop_event.is_set():
                        break
                    gist_id = gist.get("id", "")
                    with self._processed_lock:
                        if gist_id in self._processed_shas:
                            continue
                        self._processed_shas.add(gist_id)
                    for fname, fdata in (gist.get("files") or {}).items():
                        content = fdata.get("content", "")
                        if not content or not self._quick_filter(content):
                            continue
                        source_url = gist.get("html_url", "https://gist.github.com")
                        results = self._extract_keys(content, source_url)
                        for result in results:
                            try:
                                self.result_queue.put(result, timeout=1)
                                found_from_gists += 1
                                self.stats["keys_found"] += 1
                                self._log(f"Gist: {result.platform.upper()}: {result.api_key[:20]}...", "FOUND")
                            except queue.Full:
                                pass
                return found_from_gists

        if not events:
            return 0

        self.stats["events_checked"] += len(events)
        found = 0

        # Обработка только PushEvent
        push_events = [e for e in events if e.get("type") == "PushEvent"]

        for event in push_events:
            if self.stop_event.is_set():
                break
            found += await self._process_push_event(event)

        return found

    def run(self):
        """Запуск сканера"""
        self._log("Мониторинг в реальном времени запущен - отслеживание новых коммитов GitHub", "INFO")
        if self.db:
            self.db.safe_upsert_source_progress("realtime", status="running", phase="events")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            while not self.stop_event.is_set():
                before = self.stats["commits_scanned"]
                found = loop.run_until_complete(self._scan_cycle())
                if self.db:
                    self.db.safe_upsert_source_progress(
                        "realtime", status="running", phase="events", message="",
                        processed_increment=self.stats["commits_scanned"] - before,
                        found_increment=found,
                    )

                if found > 0:
                    self._log(f"В этом цикле найдено {found} ключей", "INFO")

                # Опрос каждые 60 секунд (публичный лимит GitHub API 60/hr)
                for second in range(60):
                    if self.stop_event.is_set():
                        break
                    if self.db and second == 0:
                        self._telemetry_waiting()
                    time.sleep(1)

        finally:
            loop.run_until_complete(self._close_session())
            loop.close()

        if self.db:
            self.db.safe_upsert_source_progress("realtime", status="stopped", phase="stopped")
        self._log("Мониторинг в реальном времени остановлен", "INFO")


def start_realtime_scanner(
    result_queue: queue.Queue,
    stop_event: threading.Event,
    dashboard=None,
    db: Optional[Database] = None,
) -> threading.Thread:
    """Запуск сканера в реальном времени"""
    scanner = RealtimeScanner(result_queue, stop_event, dashboard, db)

    def safe_run():
        try:
            scanner.run()
        except Exception as exc:
            if db:
                db.safe_upsert_source_progress(
                    "realtime", status="error", phase="error",
                    message=type(exc).__name__, errors_increment=1,
                )

    thread = threading.Thread(target=safe_run, name="RealtimeScanner", daemon=True)
    thread.start()
    return thread
