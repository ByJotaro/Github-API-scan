"""
Сканер MCP Registry - поиск API ключей в конфигурациях MCP серверов

Как работает:
1. Получает список MCP серверов из Smithery registry (открытый API, пагинация)
2. Для каждого сервера с GitHub репозиторием:
   - Скачивает .env, config, secrets файлы через raw.githubusercontent.com
   - Извлекает ключи стандартными паттернами
3. Циклический рескан: после всех серверов → заново, с пропуском уже пройденных
"""

import re
import time
import asyncio
import threading
import queue
from typing import List, Optional, Set, Tuple
from dataclasses import dataclass

import aiohttp
from aiohttp import ClientTimeout, TCPConnector
import ssl

from config import config, COMPILED_REGEX_PATTERNS
from scanner import ScanResult, calculate_entropy, is_test_key, ENTROPY_THRESHOLD
from database import Database


# Glama требует API-ключ с 2025 (401 без ключа) → discovery через
# открытый Smithery registry (без ключа, 15k+ серверов, пагинация).
SMITHERY_API = "https://registry.smithery.ai/servers"

ASYNC_TIMEOUT = ClientTimeout(total=20, connect=10)

# Файлы, которые могут содержать ключи (скачиваем из каждого репозитория)
# Порядок важен: сначала .env (самые вероятные), потом config-подобные
KEY_PATHS = [
    ".env",
    ".env.example",
    ".env.local",
    ".env.production",
    ".env.staging",
    "sample.env",
    "env.example",
    ".sample.env",
    "config.json",
    "config.yaml",
    "config.yml",
    "secrets.json",
    "secrets.yaml",
    "docker-compose.yml",
    "docker-compose.yaml",
    "docker-compose.env",
    "credentials.json",
    "credentials.yml",
    "settings.json",
    "application.yml",
    "README.md",  # Часто ключи указывают прямо в README примерах
]

# Расширения для пропуска
SKIP_EXTS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".ttf", ".zip", ".pdf", ".bin", ".exe",
    ".dll", ".so", ".dylib", ".pyc", ".lock",
})

# Состояние курсора
CURSOR_KEY = "mcp_glama_cursor"
CYCLE_KEY = "mcp_cycle"


@dataclass
class MCPServer:
    """MCP сервер из Glama или Smithery"""
    name: str
    namespace: str
    repo_url: str = ""
    env_schema: Optional[dict] = None
    description: str = ""


class MCPScanner:
    """Сканер MCP Registry"""

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

        self._key_patterns = {
            k: v
            for k, v in COMPILED_REGEX_PATTERNS.items()
            if k != "azure"
        }

        self.stats = {"servers_scanned": 0, "keys_found": 0, "cycles": 0}
        self._session: Optional[aiohttp.ClientSession] = None

    def _log(self, message: str, level: str = "INFO"):
        if self.dashboard:
            self.dashboard.add_log(f"[MCP] {message}", level)

    def _telemetry_error(self, message: str, count: int = 1):
        self._telemetry_healthy = False
        if self.db:
            self.db.safe_upsert_source_progress(
                "mcp", status="error", phase="error", message=message,
                errors_increment=count,
            )

    def _telemetry_running(self, phase: str):
        self._telemetry_healthy = True
        if self.db:
            self.db.safe_upsert_source_progress(
                "mcp", status="running", phase=phase, message=""
            )

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = TCPConnector(
                limit=50,
                limit_per_host=10,
                ssl=ssl.create_default_context(),
                force_close=False,
                use_dns_cache=True,
                ttl_dns_cache=600,
                keepalive_timeout=60,
                enable_cleanup_closed=True,
                # ThreadedResolver: системный getaddrinfo вместо pycares
                # (pycares "Could not contact DNS servers" на этом хосте).
                resolver=aiohttp.resolver.ThreadedResolver(),
            )
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=ASYNC_TIMEOUT,
                headers={"User-Agent": "MCP-Scanner/1.0"},
            )
        return self._session

    async def _close_session(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def _discover_glama_servers(self, cursor: Optional[str] = None) -> Tuple[List[MCPServer], Optional[str]]:
        """Discovery через открытый Smithery registry (Glama с 2025 требует API-ключ).

        cursor = номер страницы (строка). Возвращает (servers, next_cursor).
        Репозиториев в ответе Smithery нет — только qualifiedName/namespace:
        candidate repo = github.com/<namespace>/<qualifiedName>, существование
        проверяется дешёвым HEAD на raw .env (404 → пропуск без 42 проб).
        """
        servers: List[MCPServer] = []
        try:
            session = await self._get_session()
            page = int(cursor) if cursor and cursor.isdigit() else 1
            params = {"q": "", "page": page, "pageSize": 100}
            async with session.get(SMITHERY_API, params=params) as resp:
                if resp.status != 200:
                    self._log(f"Smithery API error: HTTP {resp.status}", "ERROR")
                    self._telemetry_error(f"Smithery discovery failed (HTTP {resp.status})")
                    return servers, cursor
                data = await resp.json()
                for sv in data.get("servers", []):
                    ns = (sv.get("namespace") or "").strip()
                    qn = (sv.get("qualifiedName") or sv.get("slug") or "").strip()
                    repo_url = ""
                    if ns and qn and "/" not in qn:
                        repo_url = f"https://github.com/{ns}/{qn}"
                    servers.append(MCPServer(
                        name=sv.get("displayName") or qn,
                        namespace=ns,
                        repo_url=repo_url,
                        env_schema=None,
                        description=sv.get("description", ""),
                    ))
                pg = data.get("pagination", {}) or {}
                total = int(pg.get("totalPages", 1) or 1)
                next_cursor = str(page + 1) if page < total else None
                self._telemetry_running("discover")
                return servers, next_cursor
        except Exception as exc:
            self._log(f"Smithery discovery error: {type(exc).__name__}", "ERROR")
            self._telemetry_error(f"Smithery discovery failed ({type(exc).__name__})")
            return servers, cursor

    async def _scan_repo(self, repo_url: str, _depth: int = 0) -> List[ScanResult]:
        """Сканировать репозиторий на наличие ключей (параллельно по файлам)"""
        if _depth > 1:  # Максимум 1 уровень fork-сканирования
            return []
        if not repo_url or "github.com" not in repo_url.lower():
            return []

        # Извлекаем owner/repo
        match = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?$", repo_url)
        if not match:
            return []
        repo_path = match.group(1).rstrip("/")

        session = await self._get_session()

        # Gate: candidate-URL из Smithery часто не существует на GitHub.
        # Один HEAD на .env/main решает: 404 → пропуск без 42 GET-проб.
        try:
            async with session.head(
                f"https://raw.githubusercontent.com/{repo_path}/main/.env",
                timeout=aiohttp.ClientTimeout(total=5),
            ) as r:
                if r.status == 404:
                    async with session.head(
                        f"https://raw.githubusercontent.com/{repo_path}/master/.env",
                        timeout=aiohttp.ClientTimeout(total=5),
                    ) as r2:
                        if r2.status == 404:
                            return []
        except Exception:
            pass

        # Для каждого файла пробуем main и master параллельно
        async def _fetch_file(file_path: str) -> Optional[str]:
            for branch in ("main", "master"):
                raw_url = f"https://raw.githubusercontent.com/{repo_path}/{branch}/{file_path}"
                try:
                    async with session.get(raw_url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200:
                            return await resp.text(errors="ignore")
                except Exception:
                    pass
            return None

        # Параллельно качаем все файлы
        contents = await asyncio.gather(*[_fetch_file(f) for f in KEY_PATHS])
        contents = [c for c in contents if c and len(c) <= 100000]

        results = []
        for content in contents:
            content_lower = content.lower()
            if not any(k in content_lower for k in (
                "api", "key", "token", "secret", "password",
                "sk-", "hf_", "ai", "openai", "anthropic",
                "gemini", "groq", "mistral", "cohere",
                "replicate", "eleven", "fireworks",
            )):
                continue
            keys = self._extract_keys(content, f"https://raw.githubusercontent.com/{repo_path}")
            results.extend(keys)

        # Fork scanning: ищем forks репозитория (часто содержат реальные .env)
        # Без токена: публичный лимит 60/hr — берём только первые 2 forks
        try:
            async with session.get(
                f"https://api.github.com/repos/{repo_path}/forks",
                params={"per_page": 3},
                timeout=aiohttp.ClientTimeout(total=10)
            ) as resp:
                if resp.status == 200:
                    forks = await resp.json()
                    for fork in forks[:2]:
                        fork_url = fork.get("html_url", "")
                        if fork_url:
                            fork_keys = await self._scan_repo(fork_url, _depth + 1)
                            results.extend(fork_keys)
        except Exception:
            pass

        return results

    def _extract_keys(self, content: str, source_url: str) -> List[ScanResult]:
        """Извлечение ключей из содержимого"""
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

                start = max(0, match.start() - 200)
                end = min(len(content), match.end() + 200)

                results.append(ScanResult(
                    platform=platform,
                    api_key=api_key,
                    base_url=config.default_base_urls.get(platform, ""),
                    source_url=source_url,
                    context=content[start:end]
                ))

        return results

    def _get_cursor(self) -> Optional[str]:
        """Получить сохранённый курсор"""
        if not self.db:
            return None
        val = self.db.get_source_state("mcp_glama_cursor")
        return val if val else None

    def _save_cursor(self, cursor: Optional[str]):
        """Сохранить курсор"""
        if self.db:
            self.db.set_source_state("mcp_glama_cursor", cursor or "")

    def _get_cycle(self) -> int:
        """Получить номер цикла"""
        if not self.db:
            return 0
        val = self.db.get_source_state("mcp_cycle")
        return int(val) if val and val.isdigit() else 0

    def _save_cycle(self, cycle: int):
        """Сохранить номер цикла"""
        if self.db:
            self.db.set_source_state("mcp_cycle", str(cycle))

    def _is_scanned(self, repo_url: str) -> bool:
        """Проверить, сканирован ли репозиторий"""
        if not self.db:
            return False
        return self.db.is_source_item_scanned("mcp", repo_url)

    def _mark_scanned(self, repo_url: str):
        """Отметить репозиторий как сканированный"""
        if self.db:
            self.db.mark_source_item_scanned("mcp", repo_url)

    def run(self):
        """Запуск сканера"""
        self._log("MCP Registry Scanner запущен", "INFO")
        if self.db:
            self.db.safe_upsert_source_progress(
                "mcp", status="running", phase="discover", message="starting"
            )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            cursor = self._get_cursor()
            cycle = self._get_cycle()
            self._log(f"Начинаем цикл {cycle}, курсор: {'есть' if cursor else 'нет'}", "INFO")

            while not self.stop_event.is_set():
                self._telemetry_running("discover")

                # Фаза 1: Discovery — получаем серверы из Glama
                servers, next_cursor = loop.run_until_complete(
                    self._discover_glama_servers(cursor)
                )

                if not servers:
                    if next_cursor is None and cursor is not None:
                        # Курсор есть, но серверы не пришли — возможно конец. Начинаем новый цикл.
                        cycle += 1
                        cursor = None
                        self._save_cursor("")
                        self._save_cycle(cycle)
                        self._log(f"Glama страницы закончились. Цикл {cycle}: перезапуск", "INFO")
                        if self.db:
                            self.db.safe_upsert_source_progress("mcp", phase="waiting")
                        # Короткая пауза перед новым циклом
                        for _ in range(30):
                            if self.stop_event.is_set():
                                break
                            time.sleep(1)
                        continue

                    self._log("Нет серверов от Glama, ждём...", "DEBUG")
                    for _ in range(30):
                        if self.stop_event.is_set():
                            break
                        time.sleep(1)
                    continue

                self._log(f"Получено {len(servers)} серверов от Glama", "INFO")

                # Фаза 2: Сканирование каждого репозитория
                scanned_count = 0
                found_count = 0

                for sv in servers:
                    if self.stop_event.is_set():
                        break

                    if not sv.repo_url:
                        continue

                    # Дедуп: пропускаем уже сканированные
                    if self._is_scanned(sv.repo_url):
                        continue

                    # Сканируем
                    keys = loop.run_until_complete(self._scan_repo(sv.repo_url))

                    for key_result in keys:
                        try:
                            self.result_queue.put(key_result, timeout=5)
                            found_count += 1
                            self.stats["keys_found"] += 1
                        except queue.Full:
                            pass

                    self._mark_scanned(sv.repo_url)
                    self.stats["servers_scanned"] += 1
                    scanned_count += 1

                    if keys:
                        self._log(f"{sv.namespace}/{sv.name}: {len(keys)} ключей", "FOUND" if len(keys) > 0 else "DEBUG")

                    # Обновляем телеметрию каждые 5
                    if scanned_count % 5 == 0:
                        if self.db:
                            self.db.safe_upsert_source_progress(
                                "mcp", phase="scan", message=f"scanned {self.stats['servers_scanned']} repos",
                                processed_increment=5,
                                found_increment=found_count,
                            )
                        found_count = 0

                if found_count > 0 and self.db:
                    self.db.safe_upsert_source_progress(
                        "mcp", phase="scan", processed_increment=0,
                        found_increment=found_count,
                    )

                if scanned_count > 0:
                    self._log(f"Страница: {scanned_count} репозиториев, {self.stats['keys_found']} всего ключей", "INFO")

                # Сохраняем курсор для следующей страницы
                cursor = next_cursor
                if cursor is not None:
                    self._save_cursor(cursor)
                else:
                    # Это была последняя страница — начинаем новый цикл
                    cycle += 1
                    self._log(f"Все серверы обработаны. Цикл {cycle} завершён. Всего ключей: {self.stats['keys_found']}", "INFO")
                    self._save_cycle(cycle)
                    self._save_cursor("")
                    cursor = None

                    # Пауза перед новым циклом
                    if self.db:
                        self.db.safe_upsert_source_progress("mcp", phase="waiting", message=f"cycle {cycle} done")
                    for _ in range(30):
                        if self.stop_event.is_set():
                            break
                        time.sleep(1)

        finally:
            loop.run_until_complete(self._close_session())
            loop.close()

        if self.db:
            self.db.safe_upsert_source_progress("mcp", status="stopped", phase="stopped")
        self._log("MCP Registry Scanner остановлен", "INFO")


def start_mcp_scanner(
    result_queue: queue.Queue,
    stop_event: threading.Event,
    dashboard=None,
    db: Optional[Database] = None,
) -> threading.Thread:
    """Запуск MCP сканера в отдельном потоке"""
    scanner = MCPScanner(result_queue, stop_event, dashboard, db)

    def safe_run():
        try:
            scanner.run()
        except Exception as exc:
            import traceback
            tb = traceback.format_exc()
            if db:
                db.safe_upsert_source_progress(
                    "mcp", status="error", phase="error",
                    message=f"{type(exc).__name__}: {exc}",
                    errors_increment=1,
                )
            print(f"[MCP] Fatal: {type(exc).__name__}: {exc}\n{tb}")
            scanner._log(f"Критическая ошибка: {type(exc).__name__}", "ERROR")

    thread = threading.Thread(target=safe_run, daemon=True, name="mcp-scanner")
    thread.start()
    return thread
