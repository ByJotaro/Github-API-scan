"""Keyless-источники: Telegram, HuggingFace, веб-поиск, общая экстракция.

Сети нет: aiohttp-сессия подменяется фейком, БД — во временной папке.
Ключи-фикстуры помечены `secret-fixture` и не являются настоящими.
"""

import asyncio
import base64
import queue
import threading

import pytest

import source_common
import source_huggingface
import source_search
import source_telegram
from database import Database
from source_huggingface import HuggingFaceScanner
from source_search import SearchScanner, channel_from_url, parse_ddg_links
from source_telegram import TelegramScanner, extract_messages

GEMINI_KEY = "AIzaSyA1b2C3d4E5f6G7h8I9jK0lM1nO2pQ3rS4"  # secret-fixture


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "scan.db"))
    try:
        yield database
    finally:
        database.close()


def _run(coro):
    return asyncio.run(coro)


# --- source_common ----------------------------------------------------------

def test_extract_key_results_finds_key_and_skips_test_placeholders(db):
    content = f'key = "{GEMINI_KEY}"\nother = "AIzaSyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"'  # secret-fixture
    results = source_common.extract_key_results(
        content, "https://example.com/x", db=db)
    assert [r.api_key for r in results] == [GEMINI_KEY]
    assert results[0].platform == "gemini"


def test_extract_key_results_respects_db_dedup(db):
    source_common.extract_key_results(
        f'k = "{GEMINI_KEY}"', "https://example.com/1", db=db)
    # ключ ещё не в БД (источник только положил его в очередь)
    assert source_common.extract_key_results(
        f'k = "{GEMINI_KEY}"', "https://example.com/2", db=db)


def test_extract_base_url_prefers_explicit_field():
    url, is_relay = source_common.extract_base_url(
        'base_url: "https://relay.example.com/v1"', "openai")
    assert url == "https://relay.example.com/v1"
    assert is_relay is True


# --- telegram ---------------------------------------------------------------

TG_PAGE = """
<div class="tgme_widget_message_wrap">
  <div class="tgme_widget_message" data-post="leakbase/101">
    <div class="tgme_widget_message_text js-message_text" dir="auto">
      fresh keys &amp; tokens<br/>key: AIzaSyA1b2C3d4E5f6G7h8I9jK0lM1nO2pQ3rS4  <!-- secret-fixture -->
    </div>
  </div>
</div>
<div class="tgme_widget_message_wrap">
  <div class="tgme_widget_message" data-post="leakbase/102">
    <div class="tgme_widget_message_text js-message_text">
      <b>bold</b> no keys here
    </div>
  </div>
</div>
"""


def test_extract_messages_parses_ids_text_and_entities():
    messages = extract_messages(TG_PAGE)
    assert [mid for mid, _ in messages] == [101, 102]
    text = messages[0][1]
    assert "fresh keys & tokens" in text
    assert GEMINI_KEY in text
    assert "<b>" not in messages[1][1]


def test_telegram_cycle_scans_only_new_messages(db):
    scanner = TelegramScanner(queue.Queue(), db, threading.Event(),
                              channels=["leakbase"])
    calls = []

    async def fake_fetch(url, session=None, **kwargs):
        calls.append(url)
        return TG_PAGE

    scanner._fetch_text = fake_fetch
    _run(scanner._cycle(session=None))
    assert db.get_source_state("telegram_last_leakbase") == "102"

    results = []
    while not scanner.result_queue.empty():
        results.append(scanner.result_queue.get())
    assert [r.api_key for r in results] == [GEMINI_KEY]
    assert results[0].source_url == "https://t.me/leakbase/101"

    # повторный цикл: курсор на 102, новых сообщений нет
    _run(scanner._cycle(session=None))
    assert scanner.result_queue.empty()


# --- huggingface ------------------------------------------------------------

def test_huggingface_slice_rotates_and_wraps(db):
    # HF игнорирует offset: глубина берётся разбиением запроса по символам,
    # курсор крутится по плоскому списку подзапросов.
    scanner = HuggingFaceScanner(queue.Queue(), db, threading.Event(),
                                 queries=["q"], per_query=5, subs_per_cycle=3)
    n = len(source_huggingface.QUERY_SUFFIXES)
    first = scanner._next_slice()
    second = scanner._next_slice()
    assert len(first) == len(second) == 3
    assert first == ["q" + s for s in source_huggingface.QUERY_SUFFIXES[:3]]
    assert second == ["q" + s for s in source_huggingface.QUERY_SUFFIXES[3:6]]
    assert first[0] != second[0]
    # полный оборот: 39 на 3 делится без остатка -> 13-й срез снова первый
    for _ in range(n // 3 - 2):
        scanner._next_slice()
    assert scanner._next_slice() == first
    assert db.get_source_state("huggingface_sub_idx") == "3"


def test_huggingface_cycle_does_not_send_offset(db):
    scanner = HuggingFaceScanner(queue.Queue(), db, threading.Event(),
                                 queries=["q"], per_query=5, subs_per_cycle=1)
    urls = []

    async def fake_json(url, session=None, **kwargs):
        urls.append(url)
        return {"hits": []}

    scanner._fetch_json = fake_json
    _run(scanner._cycle(None))
    assert urls and "offset=" not in urls[0] and "limit=5" in urls[0]


def test_huggingface_scan_hit_builds_raw_url_per_repo_type(db):
    scanner = HuggingFaceScanner(queue.Queue(), db, threading.Event(),
                                 queries=["AIzaSy"])
    fetched = []

    async def fake_fetch(url, session=None, **kwargs):
        fetched.append(url)
        return f'ACTIVE_KEY = "{GEMINI_KEY}"'

    scanner._fetch_text = fake_fetch
    hit = {"type": "space", "name": "user/demo", "fileName": "app.py",
           "repoId": "abc"}
    _run(scanner._scan_hit(None, hit))

    assert fetched == [
        "https://huggingface.co/spaces/user/demo/raw/main/app.py"]
    result = scanner.result_queue.get_nowait()
    assert result.api_key == GEMINI_KEY
    assert result.source_url == (
        "https://huggingface.co/spaces/user/demo/blob/main/app.py")

    # повторно тот же файл не качаем
    _run(scanner._scan_hit(None, hit))
    assert len(fetched) == 1


# --- web search (дрорки) ----------------------------------------------------

DDG_PAGE = """
<div class="result">
  <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Ft.me%2Fs%2Fleakbase&amp;rut=x">one</a>
  <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Ftelegra.ph%2Fdump-01-01&amp;rut=y">two</a>
  <a class="result__a" href="//duckduckgo.com/l/?uddg=https%3A%2F%2Ft.me%2Fs%2Fleakbase&amp;rut=z">dup</a>
</div>
"""


BRAVE_PAGE = """
<a href="https://t.me/s/leakbase">leakbase</a>
<a href="https://t.me/leakbase">dup channel</a>
<a href="https://search.brave.com/help">self</a>
<a href="https://telegra.ph/dump-01-01">telegraph</a>
"""


def test_parse_bing_links_decodes_base64_targets():
    encoded = base64.urlsafe_b64encode(
        b"https://pastebin.com/languages").decode().rstrip("=")
    page = (
        '<h2><a href="https://www.bing.com/ck/a?!&amp;&amp;p=x&amp;u=a1'
        + encoded + '&amp;ptn=3">one</a></h2>'
        '<h2><a href="https://telegra.ph/dump-01-01">two</a></h2>'
        '<a href="https://go.microsoft.com/fwlink/?LinkId=521839">priv</a>'
    )
    assert source_search.parse_bing_links(page) == [
        "https://pastebin.com/languages", "https://telegra.ph/dump-01-01"]


def test_parse_brave_links_keeps_external_and_dedupes():
    assert source_search.parse_brave_links(BRAVE_PAGE) == [
        "https://t.me/s/leakbase", "https://t.me/leakbase",
        "https://telegra.ph/dump-01-01"]


def test_parse_ddg_links_decodes_and_dedupes():
    urls = parse_ddg_links(DDG_PAGE)
    assert urls == ["https://t.me/s/leakbase", "https://telegra.ph/dump-01-01"]


@pytest.mark.parametrize("url,expected", [
    ("https://t.me/s/leakbase", "leakbase"),
    ("https://t.me/leakbase/123", "leakbase"),
    ("https://t.me/leakbase?before=9", "leakbase"),
    ("https://t.me/joinchat/abc", None),
    ("https://t.me/share/url", None),
    ("https://example.com/x", None),
])
def test_channel_from_url(url, expected):
    assert channel_from_url(url) == expected


def test_register_channels_dedupes_and_caps(db):
    merged = source_search.register_channels(db, ["a1", "a2", "a1"], cap=2)
    assert merged == ["a1", "a2"]
    merged = source_search.register_channels(db, ["a3"], cap=2)
    assert merged == ["a1", "a2"]
    assert source_search.load_discovered_channels(db) == ["a1", "a2"]


def test_search_cycle_registers_channels_and_scans_pages(db):
    scanner = SearchScanner(queue.Queue(), db, threading.Event(),
                            dorks=["site:t.me AIzaSy"], per_dork=5,
                            dorks_per_cycle=1, delay=0)

    async def fake_search(url):
        return 200, DDG_PAGE

    async def fake_text(url, session=None, **kwargs):
        return f'KEY = "{GEMINI_KEY}"'

    scanner._fetch_search = fake_search
    scanner._fetch_text = fake_text
    db.set_source_state("telegram_discovered", "[]")
    _run(scanner._cycle(None))

    assert source_search.load_discovered_channels(db) == ["leakbase"]
    results = []
    while not scanner.result_queue.empty():
        results.append(scanner.result_queue.get())
    assert [r.api_key for r in results] == [GEMINI_KEY]
    assert results[0].source_url == "https://telegra.ph/dump-01-01"


def test_search_provider_cooldown_on_429(db):
    scanner = SearchScanner(queue.Queue(), db, threading.Event(),
                            dorks=["d"], dorks_per_cycle=1, delay=0)
    calls = []

    async def fake_search(url):
        calls.append(url)
        return 202, ""  # антибот-страница DuckDuckGo

    scanner._fetch_search = fake_search
    _run(scanner._cycle(None))
    # 429 у всех провайдеров -> каждый уходит в кулдаун
    assert len(calls) == 3
    assert "bing.com" in calls[0] and "search.brave.com" in calls[1]
    assert "duckduckgo" in calls[2]
    assert db.get_source_state("search_bing_cooldown")
    assert db.get_source_state("search_brave_cooldown")
    assert db.get_source_state("search_ddg_cooldown")
    # следующий цикл оба провайдера пропущены
    calls.clear()
    _run(scanner._cycle(None))
    assert calls == []


def test_search_cse_error_payload_falls_back(db):
    scanner = SearchScanner(queue.Queue(), db, threading.Event(),
                            dorks=["site:t.me AIzaSy"], dorks_per_cycle=1,
                            delay=0)
    scanner.cse_key, scanner.cse_cx = "bad", "bad"

    async def fake_json(url, session=None, **kwargs):
        return {"error": {"code": 400, "message": "API key not valid"}}

    fallback = []

    async def fake_search(url):
        fallback.append(url)
        return 200, DDG_PAGE

    scanner._fetch_json = fake_json
    scanner._fetch_search = fake_search
    _run(scanner._cycle(None))
    assert fallback  # ошибка CSE не съедает цикл, идёт keyless-путь
    assert source_search.load_discovered_channels(db) == ["leakbase"]


def test_search_cse_daily_quota_is_enforced(db):
    scanner = SearchScanner(queue.Queue(), db, threading.Event(),
                            dorks=["d"], dorks_per_cycle=1, delay=0)
    scanner.cse_key, scanner.cse_cx = "K", "CX"
    calls = []

    async def fake_json(url, session=None, **kwargs):
        calls.append(url)
        return {"items": []}

    scanner._fetch_json = fake_json
    db.set_source_state("search_cse_day", __import__("time").strftime("%Y-%m-%d"))
    db.set_source_state("search_cse_count", str(scanner.CSE_DAILY_LIMIT))
    async def fake_search(url):
        return 429, ""
    scanner._fetch_search = fake_search
    _run(scanner._cycle(None))
    assert calls == []  # квота исчерпана -> CSE не дёргаем


def test_search_uses_google_cse_when_keys_present(db, monkeypatch):
    scanner = SearchScanner(queue.Queue(), db, threading.Event(),
                            dorks=["site:t.me x"], dorks_per_cycle=1, delay=0)
    scanner.cse_key, scanner.cse_cx = "K", "CX"
    urls = []

    async def fake_json(url, session=None, **kwargs):
        urls.append(url)
        return {"items": [{"link": "https://t.me/s/chan1"}]}

    scanner._fetch_json = fake_json
    _run(scanner._cycle(None))
    assert "customsearch/v1" in urls[0] and "key=K" in urls[0]
    assert source_search.load_discovered_channels(db) == ["chan1"]


def test_telegram_merges_discovered_channels(db):
    source_search.register_channels(db, ["disc1"], cap=10)
    scanner = TelegramScanner(queue.Queue(), db, threading.Event(),
                              channels=["conf1"])
    assert scanner._active_channels() == ["conf1", "disc1"]
