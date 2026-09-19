"""
Сканер GitLab проектов - поиск API ключей в публичных репозиториях GitLab

Как работает:
- Ищет проекты по названию (openai, llm, ai-agent и т.д.) через GitLab API (без токена)
- Качает .env/config/README через raw.githubusercontent.com (или gitlab.com raw)
- Извлекает ключи стандартными паттернами
- Циклический рескан с дедупом
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


# GitLab API
GITLAB_API = "https://gitlab.com/api/v4"
ASYNC_CONCURRENCY = 20
ASYNC_TIMEOUT = ClientTimeout(total=20, connect=10)

# GitLab project search — ищем проекты по НАЗВАНИЮ (code search требует токен)
# Затем качаем .env/config из найденных проектов
GITLAB_KEYWORDS = [
    "openai",
    "chatbot",
    "llm",
    "ai-agent",
    "gpt",
    "anthropic",
    "gemini",
    "langchain",
    "ai",
    "ml",
    "chat",
    "assistant",
    "rag",
    "embedding",
    "huggingface",
    "deepseek",
    "groq",
    "mistral",
    "cohere",
    "ollama",
    "claude",
    "perplexity",
    "replicate",
    "stability",
    "comfyui",
    "stable-diffusion",
    "transformers",
    "pytorch",
    "tensorflow",
    "neural",
    "gpt4",
    "autogpt",
    "agent",
]


@dataclass
class ProjectInfo:
    """Информация о проекте"""
    id: int
    path: str
    web_url: str


@dataclass
class BatchOutcome:
    processed: int = 0
    found: int = 0
    errors: int = 0


# Обратная совместимость (для старых тестов)
SnippetInfo = ProjectInfo


class GitLabScanner:
    """Сканер GitLab Snippets"""

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

        self._processed_ids: Set[int] = set()
        self._processed_lock = threading.Lock()

        self._key_patterns = {
            k: v
            for k, v in COMPILED_REGEX_PATTERNS.items()
            if k != "azure"
        }

        self.stats = {"snippets_scanned": 0, "keys_found": 0}
        self._session: Optional[aiohttp.ClientSession] = None

    def _log(self, message: str, level: str = "INFO"):
        if self.dashboard:
            self.dashboard.add_log(f"[GitLab] {message}", level)

    def _telemetry_error(self, message: str, count: int = 1):
        self._telemetry_healthy = False
        if self.db:
            self.db.safe_upsert_source_progress(
                "gitlab", status="error", phase="error", message=message,
                errors_increment=count,
            )

    def _telemetry_running(self, phase: str):
        self._telemetry_healthy = True
        if self.db:
            self.db.safe_upsert_source_progress(
                "gitlab", status="running", phase=phase, message=""
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
                connector=connector,
                timeout=ASYNC_TIMEOUT,
                trust_env=True,
                headers={
                    "User-Agent": "Github-API-scan/1.0 (public-snippet-scanner)",
                    "Accept": "application/json",
                },
            )
        return self._session

    async def _close_session(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def _search_projects(self, keyword: str) -> List[ProjectInfo]:
        """Поиск публичных проектов по ключевому слову"""
        projects = []
        try:
            session = await self._get_session()
            url = f"{GITLAB_API}/projects"
            params = {
                "search": keyword,
                "per_page": 50,
                "order_by": "last_activity_at",
                "sort": "desc",
            }
            proxy = config.proxy_url if config.proxy_url else None

            async with session.get(url, params=params, proxy=proxy) as resp:
                if resp.status != 200:
                    body = (await resp.text())[:200]
                    self._log(f"GitLab project search HTTP {resp.status}: {body}", "ERROR")
                    self._telemetry_error(f"GitLab listing failed (HTTP {resp.status})")
                    return []

                data = await resp.json()
                for item in data:
                    projects.append(ProjectInfo(
                        id=item.get("id", 0),
                        path=item.get("path_with_namespace", ""),
                        web_url=item.get("web_url", ""),
                    ))
                self._telemetry_running("fetch")
        except Exception as exc:
            self._log(f"Ошибка поиска проектов: {type(exc).__name__}", "ERROR")
            self._telemetry_error(f"GitLab listing failed ({type(exc).__name__})")

        return projects

    async def _fetch_file_content(self, project_id: int, file_path: str) -> Optional[str]:
        """Получение содержимого файла проекта (через API files/raw)."""
        try:
            session = await self._get_session()
            url = f"{GITLAB_API}/projects/{project_id}/repository/files/{file_path}/raw"
            params = {"ref": "HEAD"}
            proxy = config.proxy_url if config.proxy_url else None

            async with session.get(url, params=params, proxy=proxy) as resp:
                if resp.status != 200:
                    return None
                content = await resp.text(errors='ignore')
                self._telemetry_running("scan")
                return content
        except Exception:
            return None

    async def _scan_repo_raw(self, repo_path: str) -> List[ScanResult]:
        """Сканировать GitLab-проект через raw endpoints (без токена).

        repo_path: path_with_namespace вида 'group/project' (или полный URL).
        """
        results = []
        session = await self._get_session()

        # Нормализуем path: group/project (GitLab path_with_namespace)
        path = repo_path
        for prefix in ("https://gitlab.com/", "http://gitlab.com/", "gitlab.com/"):
            if path.lower().startswith(prefix):
                path = path[len(prefix):]
                break
        path = path.rstrip("/")
        if not path or path.count("/") < 1:
            return []

        # GitLab raw: /{path}/-/raw/{branch}/{file}
        # Также пробуем gitlab.com raw без auth
        key_paths = [
            ".env", ".env.example", ".env.local", ".env.production",
            "sample.env", "env.example", "config.json", "config.yaml",
            "config.yml", "secrets.json", "docker-compose.yml",
            "docker-compose.yaml", "credentials.json", "README.md",
        ]

        async def _fetch(fp: str) -> Optional[str]:
            # main/master покрывают ~99% (develop/dev — редкость, режут
            # 56→28 проб на проект без потери покрытия).
            for branch in ("main", "master"):
                url = f"https://gitlab.com/{path}/-/raw/{branch}/{fp}"
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as r:
                        if r.status == 200:
                            return await r.text(errors="ignore")
                        if r.status == 429:
                            await asyncio.sleep(2)
                except Exception:
                    pass
            return None

        # Последовательно (не gather) — GitLab часто 429 при параллели
        contents = []
        for fp in key_paths:
            if self.stop_event.is_set():
                break
            content = await _fetch(fp)
            if content:
                contents.append(content)
            await asyncio.sleep(0.15)
        for content in contents:
            if not content or len(content) > 100000:
                continue
            content_lower = content.lower()
            if not any(k in content_lower for k in (
                "api", "key", "token", "secret", "password",
                "sk-", "hf_", "ai", "openai", "anthropic",
            )):
                continue
            keys = self._extract_keys(content, f"https://gitlab.com/{path}")
            results.extend(keys)

        return results

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

    def run(self):
        """Запуск сканера"""
        self._log("Сканер GitLab запущен", "INFO")
        if self.db:
            self.db.safe_upsert_source_progress("gitlab", status="running", phase="fetch", message="")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            cycle = 0
            while not self.stop_event.is_set():
                cycle += 1
                total_found = 0
                self._log(f"Цикл {cycle} GitLab: {len(GITLAB_KEYWORDS)} ключевых слов", "INFO")

                for kw_index, keyword in enumerate(GITLAB_KEYWORDS, 1):
                    if self.stop_event.is_set():
                        break

                    if self.db:
                        self.db.safe_upsert_source_progress("gitlab", phase="fetch", current=kw_index, total=len(GITLAB_KEYWORDS), message=f"kw {kw_index}/{len(GITLAB_KEYWORDS)}")

                    projects = loop.run_until_complete(self._search_projects(keyword))
                    try:
                        from tui_i18n import tf as _i18n_tf, resolve_lang as _i18n_lang
                        self._log(
                            _i18n_tf(
                                "log_keyword_projects", _i18n_lang(),
                                kw=keyword, n=len(projects),
                            ),
                            "DEBUG",
                        )
                    except Exception:
                        self._log(
                            f"Keyword '{keyword}': {len(projects)} projects",
                            "DEBUG",
                        )

                    for proj in projects:
                        if self.stop_event.is_set():
                            break

                        # Дедуп по проекту (без keyword): один и тот же проект
                        # выпадает по десяткам generic-ключевиков (ai/ml/chat) —
                        # повторный скан = 56 raw-проб вхолостую.
                        item_id = f"{proj.path}"
                        if self.db and self.db.is_source_item_scanned("gitlab", item_id):
                            continue
                        if self.db:
                            self.db.mark_source_item_scanned("gitlab", item_id)

                        # Качаем .env/config через raw.githubusercontent.com (без токена, без rate limit)
                        repo_path = proj.path
                        results = loop.run_until_complete(self._scan_repo_raw(repo_path))
                        for key_result in results:
                            try:
                                self.result_queue.put(key_result, timeout=5)
                                total_found += 1
                                self._log(f"Обнаружен {key_result.platform.upper()}: {key_result.api_key[:15]}...", "FOUND")
                            except queue.Full:
                                pass

                        if self.db:
                            self.db.safe_upsert_source_progress("gitlab", phase="scan", processed_increment=1)

                    time.sleep(1)

                if total_found > 0:
                    self._log(f"Цикл {cycle}: найдено {total_found} ключей", "INFO")
                else:
                    self._log(f"Цикл {cycle} GitLab: ничего не найдено", "DEBUG")

                # Пауза перед следующим циклом (полный проход → заново)
                self._telemetry_healthy = True
                if self.db:
                    self.db.safe_upsert_source_progress("gitlab", phase="waiting")
                self._log("Ожидание 60с перед следующим циклом...", "INFO")
                for second in range(60):
                    if self.stop_event.is_set():
                        break
                    if self.db and second % 15 == 0:
                        self.db.safe_upsert_source_progress("gitlab", status="running", phase="waiting", message="")
                    time.sleep(1)

        finally:
            loop.run_until_complete(self._close_session())
            loop.close()

        if self.db:
            self.db.safe_upsert_source_progress("gitlab", status="stopped", phase="stopped")
        self._log("Сканер GitLab остановлен", "INFO")


def start_gitlab_scanner(
    result_queue: queue.Queue,
    stop_event: threading.Event,
    dashboard=None,
    db: Optional[Database] = None,
) -> threading.Thread:
    """Запуск сканера GitLab"""
    scanner = GitLabScanner(result_queue, stop_event, dashboard, db)

    def safe_run():
        try:
            scanner.run()
        except Exception as exc:
            if db:
                db.safe_upsert_source_progress(
                    "gitlab", status="error", phase="error",
                    message=type(exc).__name__, errors_increment=1,
                )

    thread = threading.Thread(target=safe_run, name="GitLabScanner", daemon=True)
    thread.start()
    return thread
