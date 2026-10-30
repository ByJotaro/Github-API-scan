"""Общие помощники новых источников сканирования.

Единая точка извлечения ключей (раньше каждый source_*.py дублировал
40 строк), общая aiohttp-сессия с прокси и базовый цикл источника:
цикл -> извлечение -> очередь -> телеметрия.
"""

import asyncio
import queue
import re
import ssl
import threading
from typing import List, Optional

import aiohttp
from aiohttp import ClientTimeout, TCPConnector

from config import COMPILED_BASE_URL_PATTERNS, COMPILED_REGEX_PATTERNS, config
from database import Database
from scanner import (
    ENTROPY_THRESHOLD, ScanResult, calculate_entropy, is_test_key,
    key_needs_context_gate,
)

HTTP_TIMEOUT = ClientTimeout(total=25, connect=10)
# Файлы больше этого не качаем: ключи живут в тексте, а не в бинарях,
# и защищаемся от случайного гигабайтного дампа.
MAX_TEXT_BYTES = 512 * 1024
# Codeberg отдаёт 403 «old Chrome version» на UA ниже 130-й версии,
# поэтому версия должна быть свежей (проверено 2026-10-30).
BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)
TEXT_SUFFIXES = (
    ".py", ".js", ".ts", ".env", ".json", ".yaml", ".yml", ".toml",
    ".ini", ".cfg", ".conf", ".txt", ".md", ".jsonl", ".csv", ".sh",
    ".java", ".go", ".rb", ".php", ".ipynb", ".log",
)

_PREFERRED_BASE_URL = re.compile(
    r"(?:baseURL|base_url|endpoint|api_base|apiBase)\s*[\"']?\s*[:=]\s*[\"']"
    r"(https?://[^\"'\s,}]+)",
    re.IGNORECASE,
)


def make_connector(limit: int = 20) -> TCPConnector:
    """Коннектор с тем же набором настроек, что у остальных источников."""
    return TCPConnector(
        limit=limit,
        ttl_dns_cache=300,
        ssl=ssl.create_default_context(),
        enable_cleanup_closed=False,
        resolver=aiohttp.resolver.ThreadedResolver(),
    )


def extract_base_url(context: str, platform: str) -> tuple:
    """Base URL из контекста; (url, is_relay)."""
    candidates = []
    for match in _PREFERRED_BASE_URL.finditer(context):
        candidates.append((0, match.start(), match.group(1)))
    for pattern in COMPILED_BASE_URL_PATTERNS:
        for match in pattern.finditer(context):
            url = (match.group(1) if match.lastindex else match.group(0)).strip()
            url = url.rstrip('/"\'')
            candidates.append((1, match.start(), url))
    for _, _, url in sorted(candidates):
        if not url.startswith(("http://", "https://")):
            continue
        is_relay = platform == "openai" and "api.openai.com" not in url.lower()
        return url, is_relay
    return config.default_base_urls.get(platform, ""), False


def extract_key_results(
    content: str,
    source_url: str,
    db: Optional[Database] = None,
    patterns: Optional[dict] = None,
) -> List[ScanResult]:
    """Найти ключи в произвольном тексте.

    Повторяет конвейер source_paster: формат -> тестовая заглушка ->
    дедуп по БД -> энтропия -> контекстный гейт (aws/azure) -> base_url.
    """
    results: List[ScanResult] = []
    for platform, pattern in (patterns or COMPILED_REGEX_PATTERNS).items():
        if platform == "azure":
            continue
        for match in pattern.finditer(content):
            api_key = match.group(0)
            if is_test_key(api_key):
                continue
            if db is not None and db.key_exists(api_key):
                continue
            key_body = api_key.split("-", 2)[-1] if api_key.startswith("sk-") else api_key
            if calculate_entropy(key_body) < ENTROPY_THRESHOLD:
                continue
            context = content[max(0, match.start() - 1000):min(len(content), match.end() + 1000)]
            if key_needs_context_gate(platform, context):
                continue
            base_url, is_relay = extract_base_url(context, platform)
            results.append(ScanResult(
                platform="relay" if is_relay else platform,
                api_key=api_key,
                base_url=base_url,
                source_url=source_url,
                is_relay=is_relay,
                context=context,
            ))
    return results


class BaseSourceScanner:
    """Каркас источника: сессия, дедуп, эмиссия в очередь, телеметрия."""

    name = "source"
    poll_interval = 120.0

    def __init__(self, result_queue: queue.Queue, db: Database,
                 stop_event: threading.Event, dashboard=None):
        self.result_queue = result_queue
        self.db = db
        self.stop_event = stop_event
        self.dashboard = dashboard
        self._session: Optional[aiohttp.ClientSession] = None
        self.stats = {"items": 0, "keys_found": 0, "errors": 0}

    # --- логирование/телеметрия ---
    def _log(self, message: str, level: str = "INFO") -> None:
        if self.dashboard:
            self.dashboard.add_log(f"[{self.name}] {message}", level)

    def _telemetry(self, status: str, phase: str, message: str = "", **extra) -> None:
        try:
            self.db.safe_upsert_source_progress(
                self.name, status=status, phase=phase, message=message, **extra)
        except Exception:
            pass

    # --- сеть ---
    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                connector=make_connector(), timeout=HTTP_TIMEOUT,
                headers={"User-Agent": BROWSER_UA},
            )
        return self._session

    async def _fetch_text(self, url: str, session=None, **kwargs) -> Optional[str]:
        session = session or await self._get_session()
        proxy = getattr(config, "proxy_url", None) or None
        try:
            async with session.get(url, proxy=proxy, **kwargs) as resp:
                if resp.status != 200:
                    return None
                raw = await resp.content.read(MAX_TEXT_BYTES)
                return raw.decode("utf-8", errors="replace")
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None

    async def _fetch_json(self, url: str, session=None, **kwargs):
        session = session or await self._get_session()
        proxy = getattr(config, "proxy_url", None) or None
        try:
            async with session.get(url, proxy=proxy, **kwargs) as resp:
                if resp.status != 200:
                    return None
                return await resp.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return None

    # --- дедуп/эмиссия ---
    # None — элемент помечается навсегда (иммутабельные: paste, gist, id).
    # Для источников с изменяемым содержимым (huggingface: Space/dataset
    # дописывают файлы) окно задаёт, через сколько часов перепроверять.
    rescan_hours = None

    def _item_seen(self, item_id: str) -> bool:
        try:
            return self.db.is_source_item_scanned(
                self.name, item_id, max_age_hours=self.rescan_hours)
        except Exception:
            return False

    def _mark_item(self, item_id: str) -> None:
        try:
            self.db.mark_source_item_scanned(self.name, item_id)
        except Exception:
            pass

    def _emit(self, results: List[ScanResult]) -> int:
        sent = 0
        for result in results:
            try:
                self.result_queue.put(result, timeout=5)
                sent += 1
            except queue.Full:
                break
        self.stats["keys_found"] += sent
        return sent

    # --- цикл ---
    async def _cycle(self, session: aiohttp.ClientSession) -> None:  # pragma: no cover
        raise NotImplementedError

    async def _main(self) -> None:
        self._telemetry("running", "startup")
        try:
            session = await self._get_session()
            while not self.stop_event.is_set():
                try:
                    await self._cycle(session)
                    self._telemetry("running", "cycle", "")
                except Exception as exc:  # источник не должен ронять процесс
                    self.stats["errors"] += 1
                    self._log(f"цикл упал: {type(exc).__name__}", "ERROR")
                    self._telemetry("error", "cycle", type(exc).__name__,
                                    errors_increment=1)
                if self._sleep_with_heartbeat():
                    break
        finally:
            if self._session and not self._session.closed:
                await self._session.close()
            self._telemetry("stopped", "stopped")

    def _sleep_with_heartbeat(self) -> bool:
        """Пауза между циклами с обновлением heartbeat.

        Раньше поток молчал весь poll_interval (у SearchScanner — 30 минут),
        и сторож считал источник зависшим. Возвращает True, если пора выходить.
        """
        remaining = float(self.poll_interval)
        while remaining > 0:
            step = min(60.0, remaining)
            if self.stop_event.wait(step):
                return True
            remaining -= step
            try:
                self._telemetry("running", "waiting")
            except Exception:
                pass
        return False

    def run(self) -> None:
        asyncio.run(self._main())


def start_source_thread(scanner: BaseSourceScanner) -> threading.Thread:
    thread = threading.Thread(
        target=scanner.run, name=f"{scanner.name.capitalize()}Scanner",
        daemon=True)
    thread.start()
    return thread
