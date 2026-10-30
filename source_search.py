"""Веб-поиск по доркам: Google dorks через ключевые поисковики.

Google отдаёт HTML-результаты только через JS (проверено: google.com/search
с gbv=1 возвращает пустую оболочку без ссылок), поэтому источник работает
через два провайдера:

* Google Programmable Search (Custom Search JSON API) — если в
  config_local.py заданы GOOGLE_CSE_KEY и GOOGLE_CSE_CX;
* Bing (HTML) — без ключа, цели лежат в base64url-параметре u=a1...;
* Brave Search (HTML) — без ключа, отдаёт прямые ссылки;
* DuckDuckGo (html/lite) — без ключа, но быстро отдаёт 403 при серии
  запросов, поэтому идёт последним фолбэком.

Голый google.com/search отдаёт только JS-оболочку без результатов,
поэтому «гуглить» можно лишь через CSE-ключ.

Найденные адреса t.me/... регистрируются как каналы, и их забирает
Telegram-источник; остальные страницы скачиваются и разбираются на ключи.
"""

import asyncio
import base64
import html as html_lib
import json
import re
import time
from urllib.parse import quote, unquote, urlparse

try:  # curl_cffi проходит антибот-фильтры Brave/DDG лучше, чем aiohttp
    from curl_cffi.requests import AsyncSession as _CurlSession
except Exception:  # pragma: no cover - зависимость опциональна
    _CurlSession = None

from config import config
from database import Database
from source_common import BaseSourceScanner, extract_key_results, start_source_thread

BING = "https://www.bing.com/search?q={query}&count=20"
BRAVE = "https://search.brave.com/search?q={query}"
DDG_HTML = "https://html.duckduckgo.com/html/?q={query}"
DDG_LITE = "https://lite.duckduckgo.com/lite/?q={query}"
GOOGLE_CSE = ("https://www.googleapis.com/customsearch/v1"
              "?key={key}&cx={cx}&q={query}&num=10")

TELEGRAM_RE = re.compile(r"^https?://t\.me/(?:s/)?([A-Za-z0-9_]{4,})")
TG_RESERVED = {"joinchat", "share", "iv", "s", "addstickers", "proxy"}

DISCOVERED_KEY = "telegram_discovered"


def load_discovered_channels(db: Database) -> list:
    """Каналы, найденные поиском (JSON-список в source_state)."""
    raw = db.get_source_state(DISCOVERED_KEY)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return [c for c in data if isinstance(c, str)] if isinstance(data, list) else []


def register_channels(db: Database, channels, cap: int) -> list:
    """Добавить каналы в обнаруженные; вернуть итоговый список."""
    known = load_discovered_channels(db)
    for channel in channels:
        if channel and channel not in known and channel not in TG_RESERVED:
            known.append(channel)
    known = known[:cap]
    db.set_source_state(DISCOVERED_KEY, json.dumps(known, ensure_ascii=False))
    return known


def channel_from_url(url: str):
    """Канал из t.me-ссылки; None для не-телеграм и служебных путей."""
    match = TELEGRAM_RE.match(url or "")
    if not match:
        return None
    channel = match.group(1)
    if channel in TG_RESERVED:
        return None
    return channel


def parse_brave_links(page: str) -> list:
    """Внешние ссылки из HTML-выдачи Brave Search."""
    urls, seen = [], set()
    for raw in re.findall(r'href="(https?://[^"]+)"', page or ""):
        url = raw.replace("&amp;", "&")
        if "brave.com" in url or "search.brave.com" in url or url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls


def parse_bing_links(page: str) -> list:
    """Ссылки из HTML-выдачи Bing (base64url в u=a1..., плюс прямые href).

    Bing прячет цель в редиректе вида
    `/ck/a?!&&u=a1aHR0cHM6Ly9leGFtcGxlLmNvbQ` — HTML надо unescape,
    иначе `&amp;u=a1` не совпадёт с шаблоном.
    """
    text = html_lib.unescape(page or "")
    urls, seen = [], set()
    for encoded in re.findall(r"[?&]u=a1([A-Za-z0-9_\-]+)", text):
        padded = encoded + "=" * (-len(encoded) % 4)
        try:
            url = base64.urlsafe_b64decode(padded).decode("utf-8", "replace")
        except Exception:
            continue
        if url.startswith("http") and url not in seen and "go.microsoft.com" not in url:
            seen.add(url)
            urls.append(url)
    for url in re.findall(r'<h2[^>]*>\s*<a[^>]+href="(https?://[^"]+)"', text):
        if url in seen or "bing.com" in url or "go.microsoft.com" in url:
            continue
        seen.add(url)
        urls.append(url)
    return urls


def parse_brave_results(page: str) -> list:
    """[(url, text)] из блоков выдачи Brave (snippet -> href + текст)."""
    out = []
    for block in (page or "").split('class="snippet')[1:]:
        match = re.search(r'href="(https?://[^"]+)"', block)
        if not match:
            continue
        url = match.group(1).replace("&amp;", "&")
        if "brave.com" in url:
            continue
        text = re.sub(r"<[^>]+>", " ", block[:4000])
        out.append((url, text))
    return out


def key_prefix(dork: str) -> str:
    """Опорная строка дорка: содержимое кавычек или первый длинный токен."""
    quoted = re.findall(r'"([^"]+)"', dork or "")
    if quoted:
        return quoted[0]
    for token in re.findall(r"[A-Za-z0-9_\-]{5,}", dork or ""):
        if token.lower() != "site":
            return token
    return ""


def parse_ddg_links(page: str) -> list:
    """Уникальные URL из HTML-выдачи DuckDuckGo (редиректы uddg=...)."""
    urls, seen = [], set()
    for raw in re.findall(r"uddg=([^&\"']+)", page or ""):
        url = unquote(raw)
        if not url.startswith("http") or url in seen:
            continue
        seen.add(url)
        urls.append(url)
    return urls


class SearchScanner(BaseSourceScanner):
    name = "search"
    poll_interval = 1800.0
    # Бесплатный тариф Google CSE — 100 запросов в сутки; оставляем запас.
    CSE_DAILY_LIMIT = 90

    def __init__(self, result_queue, db: Database, stop_event, dashboard=None,
                 dorks=None, per_dork: int = 6, dorks_per_cycle: int = 1,
                 delay: float = 2.5):
        super().__init__(result_queue, db, stop_event, dashboard)
        self.dorks = list(dorks or getattr(config, "search_dorks", []) or [])
        self.per_dork = per_dork
        self.dorks_per_cycle = dorks_per_cycle
        self.delay = delay
        self.cse_key = getattr(config, "google_cse_key", "") or ""
        self.cse_cx = getattr(config, "google_cse_cx", "") or ""
        self.discovery_cap = getattr(config, "telegram_discovered_cap", 30)

    # --- провайдеры ---
    async def _fetch_search(self, url: str) -> tuple:
        """(status, text) через curl_cffi; aiohttp — если модуля нет."""
        proxy = getattr(config, "proxy_url", None) or None
        if _CurlSession is not None:
            try:
                proxies = ({"https": proxy, "http": proxy} if proxy else None)
                async with _CurlSession(timeout=25, proxies=proxies) as session:
                    resp = await session.get(url)
                    return resp.status_code, resp.text
            except Exception:
                return 0, ""
        page = await self._fetch_text(url)
        return (200 if page else 0), (page or "")

    def _cooling(self, key: str) -> bool:
        raw = self.db.get_source_state(key)
        return bool(raw and raw.isdigit() and int(raw) > time.time())

    def _set_cooldown(self, key: str, seconds: int) -> None:
        self.db.set_source_state(key, str(int(time.time()) + seconds))

    def _cse_allowed(self) -> bool:
        """Суточная квота CSE (100/день у бесплатного тарифа)."""
        today = time.strftime("%Y-%m-%d")
        if self.db.get_source_state("search_cse_day") != today:
            self.db.set_source_state("search_cse_day", today)
            self.db.set_source_state("search_cse_count", "0")
            return True
        used = self.db.get_source_state("search_cse_count") or "0"
        return int(used if used.isdigit() else 0) < self.CSE_DAILY_LIMIT

    def _cse_spent(self) -> None:
        used = self.db.get_source_state("search_cse_count") or "0"
        self.db.set_source_state(
            "search_cse_count", str(int(used if used.isdigit() else 0) + 1))

    async def _search(self, dork: str, session) -> list:
        if self.cse_key and self.cse_cx and self._cse_allowed():
            self._cse_spent()
            payload = await self._fetch_json(
                GOOGLE_CSE.format(key=quote(self.cse_key),
                                  cx=quote(self.cse_cx), query=quote(dork)),
                session=session)
            if isinstance(payload, dict) and not payload.get("error") and (
                    "items" in payload or "searchInformation" in payload):
                return [item.get("link") for item in payload.get("items") or []
                        if item.get("link")]
            reason = (payload or {}).get("error", {}).get("code") if isinstance(payload, dict) else None
            self._log(f"Google CSE недоступен ({reason or 'нет ответа'}), "
                      f"откат на Bing/Brave/DuckDuckGo", "WARN")
        for provider, url, parser, cooldown in (
            ("Bing", BING.format(query=quote(dork)), parse_bing_links,
             "search_bing_cooldown"),
            ("Brave", BRAVE.format(query=quote(dork)), parse_brave_links,
             "search_brave_cooldown"),
            ("DDG", DDG_HTML.format(query=quote(dork)), parse_ddg_links,
             "search_ddg_cooldown"),
        ):
            if self._cooling(cooldown):
                continue
            status, page = await self._fetch_search(url)
            if status in (202, 403, 429):  # 202 — антибот-страница DuckDuckGo
                self._set_cooldown(cooldown, 1800)
                self._log(f"{provider}: {status}, пауза 30 мин", "WARN")
                continue
            urls = parser(page) if page else []
            if urls:
                return self._prefer_relevant(urls, page, dork, provider)
        return []

    def _prefer_relevant(self, urls: list, page: str, dork: str,
                         provider: str) -> list:
        """Каналы оставляем только подтверждённые сниппетом.

        Brave почти игнорирует кавычки и по `site:t.me "AIzaSy"` отдаёт
        любые каналы (проверено: 38 блоков, ни одного с искомым префиксом),
        поэтому t.me-ссылки без подтверждения — мусор: они тратят запросы
        Telegram-источника. Обычные страницы оставляем — их решает парсер.
        """
        prefix = key_prefix(dork)
        if not prefix or provider != "Brave":
            return urls
        confirmed = {url for url, text in parse_brave_results(page)
                     if prefix.lower() in text.lower()}
        return [url for url in urls
                if url in confirmed or not channel_from_url(url)]

    # --- курсор дорков ---
    def _next_dorks(self) -> list:
        if not self.dorks:
            return []
        raw = self.db.get_source_state("search_dork_idx")
        idx = int(raw) if raw and raw.isdigit() else 0
        idx %= len(self.dorks)
        take = min(self.dorks_per_cycle, len(self.dorks))
        chunk = [self.dorks[(idx + i) % len(self.dorks)] for i in range(take)]
        self.db.set_source_state("search_dork_idx",
                                 str((idx + take) % len(self.dorks)))
        return chunk

    async def _cycle(self, session) -> None:
        discovered = []
        for dork in self._next_dorks():
            if self.stop_event.is_set():
                break
            urls = await self._search(dork, session)
            self._log(f"{dork}: ссылок {len(urls)}")
            for url in urls[:self.per_dork]:
                channel = channel_from_url(url)
                if channel:
                    discovered.append(channel)
                    continue
                item_id = url
                if self._item_seen(item_id):
                    continue
                page = await self._fetch_text(url, session=session)
                self._mark_item(item_id)
                if not page:
                    continue
                self.stats["items"] += 1
                results = extract_key_results(page, url, db=self.db)
                if results:
                    self._log(f"{urlparse(url).netloc}: ключей {len(results)}")
                self._emit(results)
            await asyncio.sleep(self.delay)
        if discovered:
            merged = register_channels(self.db, discovered, self.discovery_cap)
            self._log(f"каналов обнаружено: +{len(discovered)}, всего {len(merged)}")


def start_search_scanner(result_queue, db: Database, stop_event,
                         dashboard=None, **kwargs):
    scanner = SearchScanner(result_queue, db, stop_event, dashboard, **kwargs)
    return start_source_thread(scanner)
