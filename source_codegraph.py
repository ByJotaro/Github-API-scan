"""
Сканер SourceGraph — замена SearchCode (который умер).

Как работает:
1. GraphQL запросы к SourceGraph.com с нашими ключевыми словами
2. SourceGraph возвращает репозитории, содержащие эти ключи
3. Для каждого репо — качаем .env/config/README через raw.githubusercontent.com
4. Извлекаем ключи стандартными паттернами
5. Циклический рескан с пропуском уже сканированных

SourceGraph индексирует GitHub + GitLab + Bitbucket. Бесплатно, без токена.
Лимит: ~30-60 req/min на публичном API (без авторизации).
"""

import re
import time
import json
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

SOURCEGRAPH_API = "https://sourcegraph.com/.api/graphql"
ASYNC_TIMEOUT = ClientTimeout(total=20, connect=10)

SOURCEGRAPH_KEYWORDS = [
    "sk-proj-", "sk-ant-", "AIzaSy", "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "GROQ_API_KEY",
    "MISTRAL_API_KEY", "COHERE_API_KEY", "REPLICATE_API_KEY",
    "TOGETHER_API_KEY", "PERPLEXITY_API_KEY",
    "HUGGINGFACE_TOKEN", "HF_AUTH_TOKEN",
    "DEEPSEEK_API_KEY", "DEEPSEEK_API_TOKEN",
    "OPENROUTER_API_KEY",
    "AZURE_OPENAI_KEY", "AZURE_OPENAI_API_KEY",
    "LANGSMITH_API_KEY", "LANGCHAIN_API_KEY",
    "WANDB_API_KEY", "WEIGHTS_BIASES_API_KEY",
    "ELEVENLABS_API_KEY",
    "RUNPOD_API_KEY", "RUNPOD_TOKEN",
    "MODAL_TOKEN", "MODAL_API_KEY",
    "gsk_", "pplx-", "nvapi-",
    "fireworks", "FIREWORKS_API_KEY",
    "together", "TOGETHER_TOKEN",
]

KEYWORDS_PER_CYCLE = 30  # SourceGraph лимит ~60rpm

# Файлы для скачивания из каждого репозитория
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
    "docker-compose.yml",
    "docker-compose.yaml",
    "credentials.json",
    "settings.json",
    "application.yml",
    "README.md",
]

GRAPHQL_TEMPLATE = """\
{{
  search(query: {query}, version: V3) {{
    results {{
      resultCount
      repositories {{
        name
      }}
    }}
  }}
}}
"""


class CodeGraphScanner:
    """Сканер SourceGraph — поиск ключей через code search"""

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
            k: v for k, v in COMPILED_REGEX_PATTERNS.items()
        }

        self.stats = {
            "repos_found": 0, "repos_scanned": 0, "keys_found": 0, "queries": 0,
        }
        self._session: Optional[aiohttp.ClientSession] = None
        self._kw_cycle = 0

    def _log(self, message: str, level: str = "INFO"):
        if self.dashboard:
            self.dashboard.add_log(f"[CodeGraph] {message}", level)

    def _telemetry_error(self, message: str, count: int = 1):
        self._telemetry_healthy = False
        if self.db:
            self.db.safe_upsert_source_progress(
                "codegraph", status="error", phase="error", message=message,
                errors_increment=count,
            )

    def _telemetry_running(self, phase: str):
        self._telemetry_healthy = True
        if self.db:
            self.db.safe_upsert_source_progress(
                "codegraph", status="running", phase=phase, message=""
            )

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = TCPConnector(
                limit=20,
                limit_per_host=5,
                ssl=ssl.create_default_context(),
                resolver=aiohttp.resolver.ThreadedResolver(),
            )
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=ASYNC_TIMEOUT,
                headers={
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                    "Content-Type": "application/json",
                },
            )
        return self._session

    async def _close_session(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def _query_repos(self, keyword: str) -> List[str]:
        """Запрос к SourceGraph: получить репозитории, содержащие keyword"""
        repos = []
        try:
            session = await self._get_session()
            # query = f'context:global {keyword} count:100'
            safe_kw = keyword.replace('"', '\\"')
            q_str = f'context:global {safe_kw} fork:no count:100'
            query_body = GRAPHQL_TEMPLATE.format(query=json.dumps(q_str))

            async with session.post(
                SOURCEGRAPH_API, json={"query": query_body}
            ) as resp:
                if resp.status != 200:
                    body = (await resp.text())[:200]
                    self._log(f"SourceGraph API HTTP {resp.status}: {body}", "ERROR")
                    return []

                data = await resp.json()
                res = data.get("data", {}).get("search", {}).get("results", {})
                repos_data = res.get("repositories", [])
                result_count = res.get("resultCount", 0)
                self._log(f"SourceGraph [{keyword}]: {result_count} results, {len(repos_data)} repos", "DEBUG")

                for repo in repos_data:
                    name = repo.get("name", "")
                    if name:
                        repos.append(name)

                self.stats["queries"] += 1

        except Exception as exc:
            self._log(f"SourceGraph query error [{keyword}]: {type(exc).__name__}", "ERROR")

        return repos

    async def _scan_repo(self, repo_name: str) -> List[ScanResult]:
        """Сканировать репозиторий: качать все ключевые файлы"""
        results = []

        path = repo_name.split("//")[-1] if "//" in repo_name else repo_name
        session = await self._get_session()

        async def _fetch(fp: str) -> Optional[str]:
            for branch in ("main", "master"):
                url = f"https://raw.githubusercontent.com/{path}/{branch}/{fp}"
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as r:
                        if r.status == 200:
                            return await r.text(errors="ignore")
                except Exception:
                    pass
            return None

        contents = await asyncio.gather(*[_fetch(f) for f in KEY_PATHS])
        for content in contents:
            if not content or len(content) > 100000:
                continue
            content_lower = content.lower()
            if not any(k in content_lower for k in (
                "api", "key", "token", "secret", "password",
                "sk-", "hf_", "ai", "openai", "anthropic",
                "gemini", "groq", "mistral", "cohere",
                "replicate", "eleven",
            )):
                continue
            keys = self._extract_keys(content, f"https://raw.githubusercontent.com/{path}")
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
                    context=content[start:end],
                ))

        return results

    def _get_state(self, key: str, default: str = "") -> str:
        if not self.db:
            return default
        val = self.db.get_source_state(f"codegraph_{key}")
        return val if val else default

    def _set_state(self, key: str, value: str):
        if self.db:
            self.db.set_source_state(f"codegraph_{key}", value)

    def _is_scanned(self, repo_url: str) -> bool:
        if not self.db:
            return False
        return self.db.is_source_item_scanned("codegraph", repo_url)

    def _mark_scanned(self, repo_url: str):
        if self.db:
            self.db.mark_source_item_scanned("codegraph", repo_url)

    def run(self):
        """Запуск сканера"""
        self._log("SourceGraph Scanner запущен", "INFO")
        if self.db:
            self.db.safe_upsert_source_progress(
                "codegraph", status="running", phase="discover", message="starting"
            )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            kw_offset = int(self._get_state("kw_offset", "0"))
            cycle = 0

            while not self.stop_event.is_set():
                cycle += 1
                total_found = 0
                seen_repos: Set[str] = set()

                # Выбираем батч ключевых слов
                keywords = SOURCEGRAPH_KEYWORDS[kw_offset:kw_offset + KEYWORDS_PER_CYCLE]
                if not keywords:
                    kw_offset = 0
                    keywords = SOURCEGRAPH_KEYWORDS[:KEYWORDS_PER_CYCLE]

                self._log(f"Цикл {cycle}, kw_offset={kw_offset}, {len(keywords)} keywords", "INFO")
                self._telemetry_running("discover")

                # Фаза 1: для каждого keyword получаем репозитории
                all_repos = []
                for kw in keywords:
                    if self.stop_event.is_set():
                        break
                    repos = loop.run_until_complete(self._query_repos(kw))
                    all_repos.extend(repos)
                    # Пауза для rate limit
                    time.sleep(0.5)

                # Дедуп по репозиториям
                unique_repos = list(set(all_repos))
                self.stats["repos_found"] += len(unique_repos)
                self._log(f"Найдено {len(unique_repos)} уникальных репозиториев", "INFO")

                # Фаза 2: сканируем каждый репозиторий
                scanned = 0
                for repo in unique_repos:
                    if self.stop_event.is_set():
                        break

                    if self._is_scanned(repo):
                        continue

                    keys = loop.run_until_complete(self._scan_repo(repo))
                    for key_result in keys:
                        try:
                            self.result_queue.put(key_result, timeout=5)
                            total_found += 1
                            self.stats["keys_found"] += 1
                        except queue.Full:
                            pass

                    self._mark_scanned(repo)
                    self.stats["repos_scanned"] += 1
                    scanned += 1

                    if keys:
                        short = repo.split("/")[-1]
                        self._log(f"{short}: {len(keys)} ключей", "FOUND")

                    if scanned % 10 == 0 and self.db:
                        self.db.safe_upsert_source_progress(
                            "codegraph", phase="scan",
                            processed_increment=10, found_increment=total_found,
                        )

                # Сохраняем прогресс в БД
                if self.db:
                    self.db.safe_upsert_source_progress(
                        "codegraph",
                        status="running", phase="scan",
                        processed_increment=scanned,
                        found_increment=total_found,
                        message=f"cycle {cycle}, {len(unique_repos)} repos",
                    )

                # Продвигаем offset или новый цикл
                kw_offset += KEYWORDS_PER_CYCLE
                if kw_offset >= len(SOURCEGRAPH_KEYWORDS):
                    kw_offset = 0
                self._set_state("kw_offset", str(kw_offset))

                if total_found > 0:
                    self._log(f"Цикл {cycle}: найдено {total_found} ключей", "INFO")

                # Пауза между циклами (SourceGraph rate limit)
                self._telemetry_running("waiting")
                for second in range(30):
                    if self.stop_event.is_set():
                        break
                    if self.db and second % 10 == 0:
                        self.db.safe_upsert_source_progress(
                            "codegraph", status="running", phase="waiting",
                        )
                    time.sleep(1)

        finally:
            loop.run_until_complete(self._close_session())
            loop.close()

        if self.db:
            self.db.safe_upsert_source_progress(
                "codegraph", status="stopped", phase="stopped"
            )
        self._log("SourceGraph Scanner остановлен", "INFO")


def start_codegraph_scanner(
    result_queue: queue.Queue,
    stop_event: threading.Event,
    dashboard=None,
    db: Optional[Database] = None,
) -> threading.Thread:
    """Запуск SourceGraph сканера"""
    scanner = CodeGraphScanner(result_queue, stop_event, dashboard, db)

    def safe_run():
        try:
            scanner.run()
        except Exception as exc:
            import traceback
            tb = traceback.format_exc()
            if db:
                db.safe_upsert_source_progress(
                    "codegraph", status="error", phase="error",
                    message=f"{type(exc).__name__}: {exc}",
                    errors_increment=1,
                )
            print(f"[CodeGraph] Fatal: {type(exc).__name__}: {exc}\n{tb}")

    thread = threading.Thread(target=safe_run, daemon=True, name="codegraph-scanner")
    thread.start()
    return thread
