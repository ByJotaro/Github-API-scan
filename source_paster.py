import secrets
import asyncio
import queue
import re
import ssl
import threading
import time
from enum import Enum
from html.parser import HTMLParser
from typing import List, Optional

import aiohttp
from aiohttp import ClientTimeout, TCPConnector

from config import COMPILED_BASE_URL_PATTERNS, COMPILED_REGEX_PATTERNS, config
from database import Database
from scanner import ENTROPY_THRESHOLD, ScanResult, calculate_entropy, is_test_key


ARCHIVE_URL = "https://paster.sh/archive"
RAW_URL = "https://api.paster.sh/v1/raw/{code}"
PASTE_URL = "https://paster.sh/{code}"
REQUEST_TIMEOUT = ClientTimeout(total=20, connect=8)
ARCHIVE_CONCURRENCY = 20
PASTE_CODE_RE = re.compile(r"^[A-Za-z0-9]{6}$")
# Служебные слова навигации сайта, которые случайно матчат PASTE_CODE_RE
# (archive HTML рендерится через JS, реальных кодов паст там нет — только
#  мусор типа "paster", "assets", "canvas"). Их нельзя брутить как пасты.
PASTE_CODE_BLACKLIST = {
    "paster", "assets", "canvas", "favico", "archive", "contact",
    "button", "github", "scribe", "search", "pastes", "recent", "api",
    "about", "login", "signup", "logout", "home", "main", "style", "script",
}


class PageOutcome(Enum):
    SUCCESS = "success"
    EXHAUSTED = "exhausted"
    ERROR = "error"
    INTERRUPTED = "interrupted"


class _ArchiveParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.codes: List[str] = []
        self._seen = set()

    def handle_starttag(self, tag, attrs):
        if tag != "a":
            return
        href = dict(attrs).get("href", "").split("?", 1)[0].rstrip("/")
        code = href.rsplit("/", 1)[-1]
        if (PASTE_CODE_RE.fullmatch(code)
                and code not in self._seen
                and code.lower() not in PASTE_CODE_BLACKLIST):
            self._seen.add(code)
            self.codes.append(code)


def parse_archive(html: str) -> List[str]:
    parser = _ArchiveParser()
    parser.feed(html)
    return parser.codes


class PasterScanner:
    def __init__(
        self,
        result_queue: queue.Queue,
        db: Database,
        stop_event: threading.Event,
        dashboard=None,
    ):
        self.result_queue = result_queue
        self.db = db
        self.stop_event = stop_event
        self.dashboard = dashboard
        self._session: Optional[aiohttp.ClientSession] = None

    def _log(self, message: str, level: str = "INFO"):
        """Вывод логов (как в других source-сканерах)."""
        if self.dashboard:
            self.dashboard.add_log(f"[Paster] {message}", level)

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = TCPConnector(
                limit=20,
                ttl_dns_cache=300,
                ssl=ssl.create_default_context(),
                enable_cleanup_closed=False,
                resolver=aiohttp.resolver.ThreadedResolver(),
            )
            self._session = aiohttp.ClientSession(
                connector=connector, timeout=REQUEST_TIMEOUT
            )
        return self._session

    async def _fetch_text(self, url: str) -> Optional[str]:
        session = await self._get_session()
        return await self._fetch_text_with_session(url, session)

    async def _fetch_text_with_session(
        self, url: str, session: aiohttp.ClientSession
    ) -> Optional[str]:
        """Как _fetch_text, но с явно переданной сессией.

        Нужно для autobrute: он крутится в СВОЁМ event loop (отдельный
        поток), поэтому не может共享 self._session, созданную в loop
        архива run() — иначе RuntimeError (session bound to another loop).
        """
        try:
            proxy = getattr(config, "proxy_url", None) or None
            async with session.get(url, proxy=proxy) as response:
                if response.status != 200:
                    return None
                return await response.text(errors="replace")
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None

    def _extract_base_url(self, context: str, platform: str) -> tuple[str, bool]:
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
            if "paster.sh" in url or "github.com" in url:
                continue
            is_relay = platform == "openai" and "api.openai.com" not in url.lower()
            return url, is_relay
        return config.default_base_urls.get(platform, ""), False

    def _extract_keys(self, content: str, source_url: str) -> List[ScanResult]:
        results = []
        for platform, pattern in COMPILED_REGEX_PATTERNS.items():
            if platform == "azure":
                continue
            for match in pattern.finditer(content):
                api_key = match.group(0)
                if is_test_key(api_key):
                    continue
                if self.db.key_exists(api_key):
                    continue
                key_body = api_key.split("-", 2)[-1] if api_key.startswith("sk-") else api_key
                if calculate_entropy(key_body) < ENTROPY_THRESHOLD:
                    continue
                context = content[max(0, match.start() - 1000):min(len(content), match.end() + 1000)]
                base_url, is_relay = self._extract_base_url(context, platform)
                results.append(
                    ScanResult(
                        platform="relay" if is_relay else platform,
                        api_key=api_key,
                        base_url=base_url,
                        source_url=source_url,
                        is_relay=is_relay,
                        context=context,
                    )
                )
        return results

    def _telemetry_error(self, message: str, count: int = 1, **fields) -> None:
        fields.setdefault("errors_increment", count)
        self.db.safe_upsert_source_progress(
            "paster",
            status="error",
            phase="error",
            message=message,
            **fields,
        )

    async def _scan_one_code(self, session: aiohttp.ClientSession, code: str) -> tuple:
        """Скачать одну пасту и извлечь ключи. Возвращает (code, [ScanResult], failed)."""
        content = await self._fetch_text_with_session(RAW_URL.format(code=code), session)
        if content is None:
            return code, [], True
        return code, self._extract_keys(content, PASTE_URL.format(code=code)), False

    async def _process_page_async(self, page: int) -> PageOutcome:
        self.db.safe_upsert_source_progress(
            "paster", status="running", phase="archive", current=page,
            message=f"archive page {page}",
        )
        archive_url = ARCHIVE_URL if page == 1 else f"{ARCHIVE_URL}?page={page}"
        html = await self._fetch_text(archive_url)
        if html is None:
            self._telemetry_error("archive request failed")
            return PageOutcome.ERROR

        codes = parse_archive(html)
        if not codes:
            return PageOutcome.EXHAUSTED

        fresh = [c for c in codes if not self.db.is_source_item_scanned("paster", c)]
        self.db.safe_upsert_source_progress(
            "paster", status="running", phase="scan", total=len(codes),
            current=len(codes) - len(fresh), message="",
        )
        if not fresh:
            return PageOutcome.SUCCESS

        session = await self._get_session()
        sem = asyncio.Semaphore(ARCHIVE_CONCURRENCY)

        async def _one(code: str) -> tuple:
            async with sem:
                return await self._scan_one_code(session, code)

        results = await asyncio.gather(*(_one(c) for c in fresh))
        processed = 0
        found = 0
        for index, (code, keys, failed) in enumerate(results, 1):
            if self.stop_event.is_set():
                return PageOutcome.INTERRUPTED
            if failed:
                # 404 / сетевая ошибка на конкретной пасте — не фатально.
                continue
            delivered = 0
            try:
                for result in keys:
                    self.result_queue.put(result, timeout=5)
                    delivered += 1
            except queue.Full:
                self._telemetry_error(
                    "result queue full",
                    found_increment=delivered,
                )
                return PageOutcome.ERROR
            self.db.mark_source_item_scanned("paster", code)
            processed += 1
            found += delivered
        self.db.safe_upsert_source_progress(
            "paster", status="running", phase="scan", current=len(codes),
            total=len(codes), message="", processed_increment=processed,
            found_increment=found,
        )
        return PageOutcome.SUCCESS

    def _process_page(self, page: int) -> PageOutcome:
        async def process_and_close() -> PageOutcome:
            try:
                return await self._process_page_async(page)
            finally:
                if self._session and not self._session.closed:
                    await self._session.close()

        return asyncio.run(process_and_close())

    def run_backfill_page(self) -> PageOutcome:
        page = int(self.db.get_source_state("paster_backfill_page", "1"))
        outcome = self._process_page(page)
        if outcome is PageOutcome.SUCCESS:
            self.db.set_source_state("paster_backfill_page", str(page + 1))
        return outcome

    # Коды paster.sh: 6 символов [A-Za-z0-9] (base62).
    # /archive показывает только последние N паст -> после
    # исчерпания архива переключаемся на autobrute.
    # Вместо случайного перебора — СИСТЕМАТИЧЕСКИЙ: идём по
    # base62-индексу от 0 до 62^6-1, без пропусков и дублей.
    # Курсор (int) хранится в БД, чтобы продолжать с места при
    # перезапуске. Дедуп дополнительно через scanned_source_items.
    _BRUTE_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    _BRUTE_LEN = 6
    _BRUTE_MAX = 62 ** _BRUTE_LEN          # 62^6 ≈ 5.68e10
    _BRUTE_BATCH = 40      # кодов за один заход
    _BRUTE_PAUSE = 0.2     # между кодами (не спамим API)

    @classmethod
    def _int_to_code(cls, n: int) -> str:
        """Преобразовать base62 индекс в 6-символьный код (zero-padded)."""
        chars = []
        for _ in range(cls._BRUTE_LEN):
            chars.append(cls._BRUTE_ALPHABET[n % 62])
            n //= 62
        return "".join(reversed(chars))

    def _next_code(self) -> str:
        """Следующий систематический код (инкремент курсора из БД)."""
        cur = int(self.db.get_source_state("paster_brute_cursor", "0"))
        if cur >= self._BRUTE_MAX:
            cur = 0  # цикл завершён — начинаем заново
        code = self._int_to_code(cur)
        self.db.set_source_state("paster_brute_cursor", str(cur + 1))
        return code

    async def _autobrute_cycle(self) -> None:
        """Один заход autobrute (async, создаёт свою сессию внутри loop)."""
        # Сессия создаётся ВНУТРИ running loop (иначе TCPConnector падает с
        # "no running event loop" при создании снаружи run_until_complete).
        connector = TCPConnector(
            limit=10, ttl_dns_cache=300,
            ssl=ssl.create_default_context(), enable_cleanup_closed=False,
            resolver=aiohttp.resolver.ThreadedResolver(),
        )
        async with aiohttp.ClientSession(connector=connector, timeout=REQUEST_TIMEOUT) as session:
            self.db.safe_upsert_source_progress(
                "paster", status="running", phase="brute",
                message="autobrute systematic base62 sweep")
            for _ in range(self._BRUTE_BATCH):
                if self.stop_event.is_set():
                    return
                code = self._next_code()
                if self.db.is_source_item_scanned("paster_brute", code):
                    continue
                self.db.mark_source_item_scanned("paster_brute", code)
                content = await self._fetch_text_with_session(
                    RAW_URL.format(code=code), session)
                if content is None or not isinstance(content, str):
                    continue
                results = self._extract_keys(content, PASTE_URL.format(code=code))
                delivered = 0
                for result in results:
                    try:
                        self.result_queue.put(result, timeout=5)
                        delivered += 1
                    except queue.Full:
                        self._telemetry_error("result queue full", found_increment=delivered)
                        return
                self.db.safe_upsert_source_progress(
                    "paster", status="running", phase="brute",
                    processed_increment=1, found_increment=delivered, message="")
                await asyncio.sleep(self._BRUTE_PAUSE)

    def run_autobrute(self) -> None:
        """Фоновый цикл autobrute (отдельный поток).
        Запускается start_paster_scanner параллельно
        с run() — не блокирует основной процесс архива.

        Использует СВОЙ event loop и СВОЮ aiohttp-сессию, чтобы не
        конфликтовать с self._session, которую создаёт run() в своём
        собственном loop (иначе RuntimeError: session bound to other loop).
        """
        self._log("Paster autobrute запущен (probe random codes)...", "INFO")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            while not self.stop_event.is_set():
                try:
                    loop.run_until_complete(self._autobrute_cycle())
                except Exception as exc:  # не даём циклу упасть
                    self._log(f"Autobrute error: {type(exc).__name__}", "WARN")
                for _ in range(10):
                    if self.stop_event.is_set():
                        break
                    time.sleep(1)
        finally:
            try:
                loop.close()
            except Exception:
                pass
        self._log("Paster autobrute остановлен", "INFO")

    def run(self) -> None:
        final_outcome = PageOutcome.INTERRUPTED
        try:
            first_page = self.run_backfill_page()
            final_outcome = first_page
            if first_page is PageOutcome.EXHAUSTED:
                self.db.set_source_state("paster_backfill_complete", "1")
                return
            if first_page is not PageOutcome.SUCCESS:
                return

            while not self.stop_event.is_set():
                outcome = self.run_backfill_page()
                final_outcome = outcome
                if outcome is PageOutcome.SUCCESS:
                    continue
                if outcome is PageOutcome.EXHAUSTED:
                    self.db.set_source_state("paster_backfill_complete", "1")
                return
        finally:
            if self._session and not self._session.closed:
                asyncio.run(self._session.close())
            # На EXHAUSTED уже записан status="done" выше — не перезаписывать
            # на "stopped". "stopped" только при реальной остановке.
            if (final_outcome is not PageOutcome.ERROR
                    and final_outcome is not PageOutcome.EXHAUSTED):
                self.db.safe_upsert_source_progress(
                    "paster", status="stopped", phase="stopped", message=""
                )


def start_paster_scanner(
    result_queue: queue.Queue,
    db: Database,
    stop_event: threading.Event,
    dashboard=None,
) -> threading.Thread:
    scanner = PasterScanner(result_queue, db, stop_event, dashboard)

    def safe_run():
        # Autobrute в отдельном потоке — параллельно с run()
        brute_thread = threading.Thread(
            target=scanner.run_autobrute, name="PasterAutobrute", daemon=True)
        brute_thread.start()
        try:
            scanner.run()
        except Exception as exc:
            db.safe_upsert_source_progress(
                "paster", status="error", phase="error",
                message=type(exc).__name__, errors_increment=1,
            )
        finally:
            brute_thread.join(timeout=5)

    thread = threading.Thread(target=safe_run, name="PasterScanner", daemon=True)
    thread.start()
    return thread
