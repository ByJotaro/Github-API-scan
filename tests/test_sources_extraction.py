"""Extraction, retry, dedup and telemetry tests for the secondary source scanners.

Covers: source_pastebin, source_gitlab, source_gist, source_mcp,
source_paster, source_realtime, source_codegraph.

No network is used: every aiohttp/urllib surface is replaced by a fake
session, every sleep is patched out, and databases live in tmp dirs only.
"""

import asyncio
import json
import queue
import threading
import urllib.error
import urllib.request
from unittest.mock import AsyncMock, Mock, call, patch

import aiohttp
import pytest
from github import GithubException

import source_codegraph
import source_gist
import source_gitlab
import source_mcp
import source_pastebin
import source_realtime
from config import config
from database import Database
from source_codegraph import CodeGraphScanner
from source_gist import BatchOutcome as GistBatchOutcome
from source_gist import GistFile, GistScanner
from source_gitlab import GitLabScanner, ProjectInfo
from source_mcp import MCPScanner
from source_pastebin import BatchOutcome, PasteMetadata, PastebinScanner
from source_paster import PageOutcome, PasterScanner
from source_realtime import RealtimeScanner

# --- fixtures ---------------------------------------------------------------
# Keys are generated locally: high entropy, no TEST_KEY_PATTERNS substrings,
# and each one matches exactly the platform named in the constant.
OPENAI_KEY = "sk-aB3dE5fG7hI9jK2lM4nO6pQ8rS0tU1vW"  # secret-fixture
GEMINI_KEY = "AIzaSyA1b2C3d4E5f6G7h8I9jK0lM1nO2pQ3rS4"  # secret-fixture
GITHUB_KEY = "ghp_aB3dE5fG7hI9jK2lM4nO6pQ8rS0tU1vW2xY4"  # secret-fixture
AWS_SECRET = "aB3dE5fG7hI9jK2lM4nO6pQ8rS0tU1vW2xY4zA6b"  # secret-fixture
AZURE_KEY = "0123456789abcdef0123456789abcdef"
LOW_ENTROPY_KEY = "sk-" + "a" * 24
TEST_WORD_KEY = "sk-aB3dE5fG7hI9exampleK2lM4nO6pQ8rS0tU1"
RELAY_URL = "https://relay.acme-llm.net/v1"

PASTEBIN_ARCHIVE_HTML = """<html><body>
<a href="/aB3dE5fG">first</a>
<a href="/aB3dE5fG?dl=1">duplicate</a>
<a href="/Z9yX8wV7">second</a>
<a href="/short7">not a paste id</a>
<a href="/Q2wE4rT6">third</a>
<a href="/M5nB7vC9">fourth</a>
</body></html>"""


class FakeResponse:
    """Minimal aiohttp response: async context manager + text/json."""

    def __init__(self, status=200, text="", payload=None, headers=None):
        self.status = status
        self.headers = headers or {}
        self._text = text
        self._payload = payload

    async def text(self, errors=None, **_):
        return self._text

    async def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc_info):
        return False


class FakeSession:
    """Routes every request through ``handler(method, url, kwargs)``.

    Returning an Exception instance from the handler makes the request raise,
    which is how network failures are simulated.
    """

    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def _request(self, method, url, kwargs):
        self.calls.append((method, url, kwargs))
        result = self.handler(method, url, kwargs)
        if isinstance(result, Exception):
            raise result
        return result

    def get(self, url, **kwargs):
        return self._request("GET", url, kwargs)

    def post(self, url, **kwargs):
        return self._request("POST", url, kwargs)

    def head(self, url, **kwargs):
        return self._request("HEAD", url, kwargs)


def attach_session(scanner, session):
    """Make ``await scanner._get_session()`` return the fake session."""

    async def _get_session():
        return session

    scanner._get_session = _get_session
    return scanner


class FakeDB:
    """Recording stand-in for Database: telemetry + dedup surfaces only."""

    def __init__(self, existing_keys=(), scanned=(), state=None):
        self.calls = []
        self.existing_keys = set(existing_keys)
        self.scanned = set(scanned)
        self.state = dict(state or {})
        self.marked = []

    def safe_upsert_source_progress(self, source, **fields):
        self.calls.append((source, dict(fields)))
        return True

    def key_exists(self, api_key):
        return api_key in self.existing_keys

    def is_source_item_scanned(self, source, item_id, max_age_hours=None):
        return (source, item_id) in self.scanned

    def mark_source_item_scanned(self, source, item_id):
        self.scanned.add((source, item_id))
        self.marked.append((source, item_id))

    def get_source_state(self, name, default=""):
        return self.state.get(name, default)

    def set_source_state(self, name, value):
        self.state[name] = value

    def entries(self, source=None):
        return [fields for name, fields in self.calls if source is None or name == source]

    def phases(self, source=None):
        return [(f.get("status"), f.get("phase")) for f in self.entries(source)]


class FullQueue:
    """Queue that is always full (put raises queue.Full immediately)."""

    def put(self, *args, **kwargs):
        raise queue.Full

    def qsize(self):
        return 0


@pytest.fixture
def tmp_db(tmp_path):
    db = Database(str(tmp_path / "scan.db"))
    yield db
    db.close()


# --- source_pastebin --------------------------------------------------------


def make_pastebin(db=None, api_key=""):
    return PastebinScanner(queue.Queue(), threading.Event(), db=db, api_key=api_key)


def test_pastebin_archive_html_parsing_dedup_and_limit():
    db = FakeDB()
    scanner = make_pastebin(db)
    session = FakeSession(lambda m, u, k: FakeResponse(200, text=PASTEBIN_ARCHIVE_HTML))
    attach_session(scanner, session)

    pastes = asyncio.run(scanner._fetch_archive_pastes(limit=3))

    assert [p.key for p in pastes] == ["aB3dE5fG", "Z9yX8wV7", "Q2wE4rT6"]
    assert pastes[0].url == "https://pastebin.com/aB3dE5fG"
    assert session.calls[0][1] == source_pastebin.PASTEBIN_ARCHIVE_URL
    assert ("running", "fetch") in db.phases("pastebin")


def test_pastebin_archive_retries_twice_then_succeeds():
    db = FakeDB()
    scanner = make_pastebin(db)
    attempts = {"n": 0}

    def handler(method, url, kwargs):
        attempts["n"] += 1
        if attempts["n"] <= 2:
            return aiohttp.ClientError("connection dropped")
        return FakeResponse(200, text=PASTEBIN_ARCHIVE_HTML)

    attach_session(scanner, FakeSession(handler))
    with patch("source_pastebin.asyncio.sleep", new=AsyncMock()) as sleep:
        pastes = asyncio.run(scanner._fetch_archive_pastes(limit=2))

    assert [p.key for p in pastes] == ["aB3dE5fG", "Z9yX8wV7"]
    assert [c.args for c in sleep.await_args_list] == [(2,), (4,)]
    assert attempts["n"] == 3
    assert ("running", "fetch") in db.phases("pastebin")
    assert not [f for f in db.entries("pastebin") if f.get("status") == "error"]


def test_pastebin_archive_three_failures_reports_telemetry_error():
    db = FakeDB()
    scanner = make_pastebin(db)
    attach_session(
        scanner, FakeSession(lambda m, u, k: aiohttp.ClientError("down"))
    )
    with patch("source_pastebin.asyncio.sleep", new=AsyncMock()) as sleep:
        pastes = asyncio.run(scanner._fetch_archive_pastes(limit=2))

    assert pastes == []
    assert sleep.await_count == 2
    errors = [f for f in db.entries("pastebin") if f.get("status") == "error"]
    assert errors[-1]["phase"] == "error"
    assert errors[-1]["message"] == "Pastebin archive failed (ClientError)"
    assert errors[-1]["errors_increment"] == 1


def test_pastebin_archive_http_error_is_not_retried():
    db = FakeDB()
    scanner = make_pastebin(db)
    session = FakeSession(lambda m, u, k: FakeResponse(503))
    attach_session(scanner, session)

    pastes = asyncio.run(scanner._fetch_archive_pastes(limit=2))

    assert pastes == []
    assert len(session.calls) == 1
    errors = [f for f in db.entries("pastebin") if f.get("status") == "error"]
    assert errors[-1]["message"] == "Pastebin archive failed (HTTP 503)"


def test_pastebin_recent_pastes_without_api_key_uses_archive():
    scanner = make_pastebin(FakeDB())
    calls = {}

    async def fake_archive(limit=100):
        calls["limit"] = limit
        return [PasteMetadata("aB3dE5fG", "", "", 0, "", "https://pastebin.com/aB3dE5fG")]

    scanner._fetch_archive_pastes = fake_archive

    pastes = asyncio.run(scanner._fetch_recent_pastes(7))

    assert calls == {"limit": 7}
    assert [p.key for p in pastes] == ["aB3dE5fG"]


def test_pastebin_recent_pastes_401_falls_back_to_archive():
    scanner = make_pastebin(FakeDB(), api_key="pro-key")
    session = FakeSession(lambda m, u, k: FakeResponse(401, text="not whitelisted"))
    attach_session(scanner, session)
    archive = AsyncMock(return_value=[])
    scanner._fetch_archive_pastes = archive

    pastes = asyncio.run(scanner._fetch_recent_pastes(5))

    assert pastes == []
    archive.assert_awaited_once_with(5)
    assert "limit=5" in session.calls[0][1]


def test_pastebin_recent_pastes_parses_scraping_api_payload():
    db = FakeDB()
    scanner = make_pastebin(db, api_key="pro-key")
    payload = [
        {"key": "aB3dE5fG", "title": "cfg", "syntax": "text",
         "size": "12", "date": "2026-01-01"},
    ]
    attach_session(scanner, FakeSession(lambda m, u, k: FakeResponse(200, payload=payload)))

    pastes = asyncio.run(scanner._fetch_recent_pastes(5))

    assert len(pastes) == 1
    assert pastes[0].size == 12
    assert pastes[0].url == "https://pastebin.com/aB3dE5fG"
    assert ("running", "fetch") in db.phases("pastebin")


def test_pastebin_extract_keys_marks_relay_with_base_url():
    scanner = make_pastebin()
    content = (
        f"OPENAI_API_KEY={OPENAI_KEY}\n"
        f'base_url = "{RELAY_URL}"\n'
    )

    results = scanner._extract_keys(content, "https://pastebin.com/aB3dE5fG")

    assert len(results) == 1
    assert results[0].platform == "relay"
    assert results[0].is_relay is True
    assert results[0].base_url == RELAY_URL
    assert results[0].source_url == "https://pastebin.com/aB3dE5fG"


def test_pastebin_extract_keys_uses_default_platform_url():
    scanner = make_pastebin()

    results = scanner._extract_keys(f"OPENAI_API_KEY={OPENAI_KEY}\n", "url")

    assert [r.platform for r in results] == ["openai"]
    assert results[0].base_url == config.default_base_urls["openai"]
    assert results[0].is_relay is False


def test_pastebin_extract_keys_filters_test_keys_low_entropy_and_db_dupes():
    scanner = make_pastebin()
    assert scanner._extract_keys(f"x={TEST_WORD_KEY}\n", "url") == []
    assert scanner._extract_keys(f"x={LOW_ENTROPY_KEY}\n", "url") == []

    dup_db = FakeDB(existing_keys={OPENAI_KEY})
    assert make_pastebin(dup_db)._extract_keys(f"x={OPENAI_KEY}\n", "url") == []


def test_pastebin_aws_secret_requires_context():
    scanner = make_pastebin()

    accepted = scanner._extract_keys(
        f"aws_secret_access_key = '{AWS_SECRET}'\n", "url"
    )
    rejected = scanner._extract_keys(f"value = '{AWS_SECRET}'\n", "url")

    assert [r.platform for r in accepted] == ["aws_secret_key"]
    assert accepted[0].api_key == AWS_SECRET
    assert rejected == []


def test_pastebin_paste_content_rejects_html_and_errors():
    scanner = make_pastebin()

    attach_session(
        scanner,
        FakeSession(lambda m, u, k: FakeResponse(200, text="<!DOCTYPE html><html>captcha")),
    )
    assert asyncio.run(scanner._fetch_paste_content("aB3dE5fG")) is None

    attach_session(
        scanner, FakeSession(lambda m, u, k: FakeResponse(200, text="plain secret"))
    )
    assert asyncio.run(scanner._fetch_paste_content("aB3dE5fG")) == "plain secret"

    attach_session(scanner, FakeSession(lambda m, u, k: FakeResponse(404)))
    assert asyncio.run(scanner._fetch_paste_content("aB3dE5fG")) is None

    attach_session(scanner, FakeSession(lambda m, u, k: aiohttp.ClientError("x")))
    assert asyncio.run(scanner._fetch_paste_content("aB3dE5fG")) is None


def test_pastebin_scan_paste_dedups_memory_and_marks_db():
    db = FakeDB()
    result_queue = queue.Queue()
    scanner = PastebinScanner(result_queue, threading.Event(), db=db)
    fetch = AsyncMock(return_value=f"OPENAI_API_KEY={OPENAI_KEY}\n")
    scanner._fetch_paste_content = fetch
    paste = PasteMetadata("aB3dE5fG", "", "", 0, "", "https://pastebin.com/aB3dE5fG")

    first = asyncio.run(scanner._scan_paste(paste))
    second = asyncio.run(scanner._scan_paste(paste))

    assert (first.processed, first.found, first.errors) == (1, 1, 0)
    assert (second.processed, second.found, second.errors) == (0, 0, 0)
    fetch.assert_awaited_once()
    assert result_queue.qsize() == 1
    assert ("pastebin", "aB3dE5fG") in db.marked


def test_pastebin_scan_paste_skips_item_already_in_db():
    db = FakeDB(scanned={("pastebin", "aB3dE5fG")})
    scanner = PastebinScanner(queue.Queue(), threading.Event(), db=db)
    fetch = AsyncMock(return_value="OPENAI_API_KEY=" + OPENAI_KEY)
    scanner._fetch_paste_content = fetch
    paste = PasteMetadata("aB3dE5fG", "", "", 0, "", "url")

    outcome = asyncio.run(scanner._scan_paste(paste))

    assert (outcome.processed, outcome.found, outcome.errors) == (0, 0, 0)
    fetch.assert_not_awaited()


def test_pastebin_scan_paste_counts_fetch_failure_and_queue_full():
    scanner = PastebinScanner(queue.Queue(), threading.Event(), db=FakeDB())
    scanner._fetch_paste_content = AsyncMock(return_value=None)
    missing = PasteMetadata("aB3dE5fG", "", "", 0, "", "url")
    assert asyncio.run(scanner._scan_paste(missing)).errors == 1

    scanner._fetch_paste_content = AsyncMock(return_value="OPENAI_API_KEY=" + OPENAI_KEY)
    scanner.result_queue = FullQueue()
    full_paste = PasteMetadata("Z9yX8wV7", "", "", 0, "", "url")
    full_outcome = asyncio.run(scanner._scan_paste(full_paste))

    assert (full_outcome.processed, full_outcome.found, full_outcome.errors) == (1, 0, 1)
    assert scanner.stats["keys_found"] == 0


def test_pastebin_scan_batch_aggregates_partial_errors():
    scanner = make_pastebin(FakeDB())

    async def fake_scan(paste):
        if paste.key == "err":
            raise RuntimeError("boom")
        if paste.key == "tuple":
            return (1, 0, 0)
        return BatchOutcome(processed=1, found=2)

    scanner._scan_paste = fake_scan
    pastes = [PasteMetadata(k, "", "", 0, "", "") for k in ("ok", "tuple", "err")]

    outcome = asyncio.run(scanner._scan_batch(pastes))

    assert (outcome.processed, outcome.found, outcome.errors) == (2, 2, 1)


def test_pastebin_run_emits_expected_telemetry_phases():
    db = FakeDB()
    stop = threading.Event()
    scanner = PastebinScanner(queue.Queue(), stop, db=db)
    paste = PasteMetadata("aB3dE5fG", "", "", 0, "", "https://pastebin.com/aB3dE5fG")

    async def fake_fetch(limit=100):
        return [paste]

    async def fake_batch(pastes):
        return BatchOutcome(processed=1, found=1)

    scanner._fetch_recent_pastes = fake_fetch
    scanner._scan_batch = fake_batch

    with patch("time.sleep", side_effect=lambda *_: stop.set()):
        scanner.run()

    assert db.phases("pastebin") == [
        ("running", "fetch"),
        ("running", "scan"),
        ("running", "scan"),
        ("running", "waiting"),
        ("stopped", "stopped"),
    ]
    scan_result = db.entries("pastebin")[2]
    assert scan_result["processed_increment"] == 1
    assert scan_result["found_increment"] == 1
    assert scan_result["errors_increment"] == 0


def test_pastebin_telemetry_waiting_reports_retry_after_error():
    db = FakeDB()
    scanner = make_pastebin(db)

    scanner._telemetry_running("fetch")
    scanner._telemetry_waiting()
    scanner._telemetry_error("listing failed")
    scanner._telemetry_waiting()

    assert db.phases("pastebin") == [
        ("running", "fetch"),
        ("running", "waiting"),
        ("error", "error"),
        ("error", "error"),
    ]
    assert db.entries("pastebin")[-1]["message"] == "listing failed"


# --- source_gitlab ----------------------------------------------------------


def make_gitlab(db=None):
    return GitLabScanner(queue.Queue(), threading.Event(), db=db)


def test_gitlab_extract_keys_positive():
    scanner = make_gitlab()
    content = f"GEMINI_API_KEY={GEMINI_KEY}\nGITHUB_TOKEN={GITHUB_KEY}\n"

    results = scanner._extract_keys(content, "https://gitlab.com/g/p")

    assert {r.platform for r in results} == {"gemini", "github"}
    gemini = next(r for r in results if r.platform == "gemini")
    assert gemini.base_url == config.default_base_urls["gemini"]
    assert gemini.source_url == "https://gitlab.com/g/p"
    assert gemini.api_key == GEMINI_KEY


def test_gitlab_extract_keys_filters_test_and_low_entropy():
    scanner = make_gitlab()
    assert scanner._extract_keys(f"x={TEST_WORD_KEY}\n", "url") == []
    assert scanner._extract_keys(f"x={LOW_ENTROPY_KEY}\n", "url") == []


def test_gitlab_search_projects_parses_and_emits_fetch_telemetry():
    db = FakeDB()
    scanner = make_gitlab(db)
    payload = [{"id": 1, "path_with_namespace": "g/p", "web_url": "https://gitlab.com/g/p"}]
    session = FakeSession(lambda m, u, k: FakeResponse(200, payload=payload))
    attach_session(scanner, session)

    projects = asyncio.run(scanner._search_projects("openai"))

    assert projects == [ProjectInfo(id=1, path="g/p", web_url="https://gitlab.com/g/p")]
    method, url, kwargs = session.calls[0]
    assert method == "GET" and url == source_gitlab.GITLAB_API + "/projects"
    assert kwargs["params"]["search"] == "openai"
    assert kwargs["params"]["per_page"] == 50
    assert db.phases("gitlab") == [("running", "fetch")]


def test_gitlab_search_projects_http_error():
    db = FakeDB()
    scanner = make_gitlab(db)
    attach_session(scanner, FakeSession(lambda m, u, k: FakeResponse(500, text="boom")))

    assert asyncio.run(scanner._search_projects("openai")) == []
    assert db.phases("gitlab") == [("error", "error")]
    assert db.entries("gitlab")[0]["message"] == "GitLab listing failed (HTTP 500)"


def test_gitlab_search_projects_exception():
    db = FakeDB()
    scanner = make_gitlab(db)
    attach_session(scanner, FakeSession(lambda m, u, k: aiohttp.ClientError("down")))

    assert asyncio.run(scanner._search_projects("openai")) == []
    assert db.entries("gitlab")[0]["message"] == "GitLab listing failed (ClientError)"


def test_gitlab_scan_repo_raw_rejects_invalid_path():
    scanner = make_gitlab()
    session = FakeSession(lambda m, u, k: FakeResponse(404))
    attach_session(scanner, session)

    assert asyncio.run(scanner._scan_repo_raw("noslash")) == []
    assert session.calls == []


def test_gitlab_scan_repo_raw_429_backoff_then_success():
    scanner = make_gitlab()

    def handler(method, url, kwargs):
        if url.endswith("/main/.env"):
            return FakeResponse(429)
        if url.endswith("/master/.env"):
            return FakeResponse(200, text=f"OPENAI_API_KEY={OPENAI_KEY}\n")
        return FakeResponse(404)

    attach_session(scanner, FakeSession(handler))
    with patch("source_gitlab.asyncio.sleep", new=AsyncMock()) as sleep:
        results = asyncio.run(scanner._scan_repo_raw("group/project"))

    assert [r.api_key for r in results] == [OPENAI_KEY]
    assert call(2) in sleep.await_args_list
    assert call(0.15) in sleep.await_args_list


def test_gitlab_scan_repo_raw_normalizes_full_url():
    scanner = make_gitlab()
    session = FakeSession(lambda m, u, k: FakeResponse(404))
    attach_session(scanner, session)

    with patch("source_gitlab.asyncio.sleep", new=AsyncMock()):
        assert asyncio.run(
            scanner._scan_repo_raw("https://gitlab.com/group/project")
        ) == []

    assert session.calls[0][1].startswith("https://gitlab.com/group/project/-/raw/main/")


def test_gitlab_run_skips_already_scanned_projects(monkeypatch):
    db = FakeDB(scanned={("gitlab", "group/project")})
    stop = threading.Event()
    scanner = GitLabScanner(queue.Queue(), stop, db=db)

    async def fake_search(keyword):
        return [ProjectInfo(id=1, path="group/project", web_url="")]

    scan = AsyncMock(return_value=[])
    scanner._search_projects = fake_search
    scanner._scan_repo_raw = scan
    monkeypatch.setattr(source_gitlab, "GITLAB_KEYWORDS", ["kw"])

    with patch("time.sleep", side_effect=lambda *_: stop.set()):
        scanner.run()

    scan.assert_not_awaited()
    phases = db.phases("gitlab")
    assert phases[0] == ("running", "fetch")
    assert (None, "fetch") in phases
    assert (None, "waiting") in phases
    assert phases[-1] == ("stopped", "stopped")


# --- source_gist ------------------------------------------------------------


def make_gist(db=None):
    return GistScanner(queue.Queue(), threading.Event(), db=db)


def test_gist_extract_keys_positive_and_filters():
    scanner = make_gist()
    results = scanner._extract_keys(f"OPENAI_API_KEY={OPENAI_KEY}\n", "https://gist.github.com/x")

    assert [r.platform for r in results] == ["openai"]
    assert results[0].base_url == config.default_base_urls["openai"]
    assert results[0].source_url == "https://gist.github.com/x"

    assert scanner._extract_keys(f"x={TEST_WORD_KEY}\n", "u") == []
    assert scanner._extract_keys(f"x={LOW_ENTROPY_KEY}\n", "u") == []


def test_gist_fetch_gist_content_reports_errors_and_success():
    db = FakeDB()
    scanner = make_gist(db)

    attach_session(scanner, FakeSession(lambda m, u, k: FakeResponse(404)))
    assert asyncio.run(scanner._fetch_gist_content("https://raw")) is None
    assert db.entries("gist")[-1]["message"] == "gist content request failed (HTTP 404)"

    attach_session(scanner, FakeSession(lambda m, u, k: aiohttp.ClientError("down")))
    assert asyncio.run(scanner._fetch_gist_content("https://raw")) is None
    # Сообщение несёт текст исключения: иначе NameError не отличить от сети.
    assert db.entries("gist")[-1]["message"] == (
        "gist content request failed (ClientError: down)"
    )

    attach_session(scanner, FakeSession(lambda m, u, k: FakeResponse(200, text="secret")))
    assert asyncio.run(scanner._fetch_gist_content("https://raw")) == "secret"
    assert db.entries("gist")[-1] == {
        "status": "running",
        "phase": "scan",
        "message": "",
    }


def test_gist_token_rotation_skips_bad_tokens(monkeypatch):
    monkeypatch.setattr(source_gist.config, "github_tokens", ["tok_a", "tok_b"])
    # Тест не должен зависеть от живого dead_github_tokens.txt.
    monkeypatch.setattr(source_gist.config, "dead_tokens", lambda: [])
    scanner = make_gist()

    assert scanner._client_tokens == ["tok_a", "tok_b"]
    first = scanner._get_client()
    assert first is scanner._github_clients[0]

    scanner._mark_token_bad(first)

    assert scanner._bad_github_tokens == {"tok_a"}
    assert scanner._get_client() is scanner._github_clients[1]

    scanner._rotate_client()
    assert scanner._get_client() is scanner._github_clients[1]


class _FakeGistFileInfo:
    def __init__(self, raw_url, size=11):
        self.raw_url = raw_url
        self.size = size


class _FakeGist:
    def __init__(self, gist_id, files):
        self.id = gist_id
        self.files = files
        self.html_url = f"https://gist.github.com/{gist_id}"


class _FakeGithubClient:
    def __init__(self, gists):
        self._gists = gists
        self.calls = 0

    def get_gists(self):
        self.calls += 1
        return list(self._gists)


def test_gist_search_gists_dedups_processed_ids():
    db = FakeDB()
    scanner = make_gist(db)
    gist = _FakeGist(
        "g1",
        {"a.env": _FakeGistFileInfo("https://gist.githubusercontent.com/g1/raw/a", 7)},
    )
    scanner._get_client = Mock(return_value=_FakeGithubClient([gist]))

    files = scanner._search_gists("")

    assert [f.gist_id for f in files] == ["g1"]
    assert files[0].raw_url == "https://gist.githubusercontent.com/g1/raw/a"
    assert files[0].size == 7
    assert files[0].html_url == "https://gist.github.com/g1"
    assert scanner._search_gists("") == []
    assert ("running", "fetch") in db.phases("gist")


def test_gist_search_gists_rate_limit_rotates_and_waits():
    db = FakeDB()
    scanner = make_gist(db)
    client = Mock()
    client.get_gists.side_effect = GithubException(
        403, {"message": "API rate limit exceeded"}, {}
    )
    scanner._get_client = Mock(return_value=client)
    scanner._rotate_client = Mock()

    with patch("time.sleep") as sleep:
        assert scanner._search_gists("") == []

    assert sleep.call_count == 60
    scanner._rotate_client.assert_called_once()
    assert ("error", "error") in db.phases("gist")
    error_entry = next(f for f in db.entries("gist") if f["status"] == "error")
    assert error_entry["message"] == "GitHub API rate limited"
    assert db.entries("gist")[-1]["phase"] == "waiting"


def test_gist_search_gists_bad_credentials_marks_token_and_falls_back(monkeypatch):
    monkeypatch.setattr(source_gist.config, "github_tokens", ["tok_a"])
    monkeypatch.setattr(source_gist.config, "dead_tokens", lambda: [])
    db = FakeDB()
    scanner = make_gist(db)
    client = Mock()
    client.get_gists.side_effect = GithubException(
        401, {"message": "Bad credentials"}, {}
    )
    scanner._get_client = Mock(return_value=client)
    scanner._fetch_public_gists_no_auth = Mock(return_value=[])

    assert scanner._search_gists("") == []

    scanner._fetch_public_gists_no_auth.assert_called_once_with()
    assert scanner._bad_github_tokens == {"tok_a"}
    error_entry = next(f for f in db.entries("gist") if f["status"] == "error")
    assert error_entry["message"] == "GitHub token bad credentials"


class _FakeUrlResponse:
    def __init__(self, payload: bytes):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def read(self):
        return self._payload


def test_gist_public_gists_retries_after_403(monkeypatch):
    db = FakeDB()
    scanner = make_gist(db)
    payload = [
        {
            "id": "g1",
            "html_url": "https://gist.github.com/g1",
            "files": {"a.env": {"raw_url": "https://gist.githubusercontent.com/g1/raw", "size": 5}},
        }
    ]
    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, None)
        return _FakeUrlResponse(json.dumps(payload).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    with patch("time.sleep") as sleep:
        files = scanner._fetch_public_gists_no_auth()

    assert [f.gist_id for f in files] == ["g1"]
    assert files[0].size == 5
    assert sleep.call_count == 15
    assert scanner._fetch_public_gists_no_auth() == []


def test_gist_public_gists_gives_up_after_three_rate_limits(monkeypatch):
    db = FakeDB()
    scanner = make_gist(db)

    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 429, "Too Many Requests", {}, None)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    with patch("time.sleep") as sleep:
        assert scanner._fetch_public_gists_no_auth() == []

    assert sleep.call_count == 15 + 30 + 45
    error_entry = next(f for f in db.entries("gist") if f["status"] == "error")
    assert error_entry["message"] == "public gists failed (HTTPError)"


def test_gist_scan_batch_reports_errors_and_success():
    db = FakeDB()
    scanner = make_gist(db)

    async def failing(gist_file):
        if gist_file.gist_id == "bad":
            raise RuntimeError("boom")
        return GistBatchOutcome(processed=1, found=1)

    scanner._scan_gist_file = failing
    files = [
        GistFile("ok", "a.env", "https://raw/a", "https://gist/g", 1),
        GistFile("bad", "b.env", "https://raw/b", "https://gist/g", 1),
    ]

    outcome = asyncio.run(scanner._scan_batch(files))

    assert (outcome.processed, outcome.found, outcome.errors) == (1, 1, 1)
    assert ("error", "error") in db.phases("gist")
    assert db.entries("gist")[-1]["errors_increment"] == 1

    async def ok(gist_file):
        return GistBatchOutcome(processed=1, found=0)

    scanner._scan_gist_file = ok
    asyncio.run(scanner._scan_batch(files))
    assert db.entries("gist")[-1]["status"] == "running"
    assert db.entries("gist")[-1]["phase"] == "scan"


# --- source_mcp -------------------------------------------------------------


def make_mcp(db=None):
    return MCPScanner(queue.Queue(), threading.Event(), db=db)


def test_mcp_extract_keys_positive_and_filters():
    scanner = make_mcp()
    results = scanner._extract_keys(
        f"OPENAI_API_KEY={OPENAI_KEY}\nGITHUB_TOKEN={GITHUB_KEY}\n",
        "https://raw.githubusercontent.com/a/b",
    )

    assert {r.platform for r in results} == {"openai", "github"}
    assert all(r.source_url == "https://raw.githubusercontent.com/a/b" for r in results)
    assert all(
        r.base_url == config.default_base_urls[r.platform] for r in results
    )
    assert scanner._extract_keys(f"x={TEST_WORD_KEY}\n", "u") == []
    assert scanner._extract_keys(f"x={LOW_ENTROPY_KEY}\n", "u") == []


def test_mcp_discovery_parses_servers_and_pagination():
    db = FakeDB()
    scanner = make_mcp(db)
    payload = {
        "servers": [
            {"namespace": "ns1", "qualifiedName": "server-one", "displayName": "S1"},
            {"namespace": "", "qualifiedName": "loose", "displayName": "S2"},
        ],
        "pagination": {"totalPages": 2},
    }
    session = FakeSession(lambda m, u, k: FakeResponse(200, payload=payload))
    attach_session(scanner, session)

    servers, cursor = asyncio.run(scanner._discover_glama_servers(None))

    assert cursor == "2"
    assert servers[0].repo_url == "https://github.com/ns1/server-one"
    assert servers[1].repo_url == ""
    assert session.calls[0][2]["params"]["page"] == 1
    assert db.phases("mcp") == [("running", "discover")]

    last_servers, last_cursor = asyncio.run(scanner._discover_glama_servers("2"))

    assert last_cursor is None
    assert session.calls[-1][2]["params"]["page"] == 2
    assert len(last_servers) == 2


def test_mcp_discovery_http_error_keeps_cursor():
    db = FakeDB()
    scanner = make_mcp(db)
    attach_session(scanner, FakeSession(lambda m, u, k: FakeResponse(500, text="boom")))

    servers, cursor = asyncio.run(scanner._discover_glama_servers("5"))

    assert servers == [] and cursor == "5"
    assert db.entries("mcp")[0]["message"] == "Smithery discovery failed (HTTP 500)"


def test_mcp_discovery_exception_reports_telemetry():
    db = FakeDB()
    scanner = make_mcp(db)
    attach_session(scanner, FakeSession(lambda m, u, k: aiohttp.ClientError("down")))

    servers, cursor = asyncio.run(scanner._discover_glama_servers(None))

    assert servers == [] and cursor is None
    assert db.entries("mcp")[0]["message"] == "Smithery discovery failed (ClientError)"


def test_mcp_scan_repo_head_gate_skips_missing_repo():
    scanner = make_mcp()
    session = FakeSession(lambda m, u, k: FakeResponse(404))
    attach_session(scanner, session)

    assert asyncio.run(scanner._scan_repo("https://github.com/a/b")) == []
    assert [c[0] for c in session.calls] == ["HEAD", "HEAD"]


def test_mcp_scan_repo_rejects_foreign_and_too_deep_repos():
    scanner = make_mcp()
    session = FakeSession(lambda m, u, k: FakeResponse(200))
    attach_session(scanner, session)

    assert asyncio.run(scanner._scan_repo("https://gitlab.com/a/b")) == []
    assert asyncio.run(scanner._scan_repo("https://github.com/a/b", _depth=2)) == []
    assert session.calls == []


def test_mcp_scan_repo_collects_env_and_follows_forks(monkeypatch):
    monkeypatch.setattr(source_mcp, "KEY_PATHS", [".env"])
    scanner = make_mcp()

    def handler(method, url, kwargs):
        if method == "HEAD":
            return FakeResponse(200 if url.endswith("/master/.env") else 404)
        if url.endswith("/forks"):
            return FakeResponse(403)
        if url.endswith("/main/.env"):
            return FakeResponse(200, text=f"OPENAI_API_KEY={OPENAI_KEY}\n")
        return FakeResponse(404)

    session = FakeSession(handler)
    attach_session(scanner, session)

    results = asyncio.run(scanner._scan_repo("https://github.com/owner/repo"))

    assert [r.api_key for r in results] == [OPENAI_KEY]
    assert results[0].source_url == "https://raw.githubusercontent.com/owner/repo"
    assert any(c[1].endswith("/forks") for c in session.calls)


def test_mcp_cursor_cycle_and_repo_dedup_state():
    db = FakeDB()
    scanner = make_mcp(db)

    assert scanner._get_cursor() is None
    scanner._save_cursor("3")
    assert db.state["mcp_glama_cursor"] == "3"
    assert scanner._get_cursor() == "3"

    assert scanner._get_cycle() == 0
    scanner._save_cycle(2)
    assert db.state["mcp_cycle"] == "2"
    assert scanner._get_cycle() == 2

    repo = "https://github.com/a/b"
    assert scanner._is_scanned(repo) is False
    scanner._mark_scanned(repo)
    assert scanner._is_scanned(repo) is True


# --- source_paster ----------------------------------------------------------


class RecordingDB:
    """Real Database + recorded telemetry calls."""

    def __init__(self, inner):
        self.inner = inner
        self.calls = []

    def safe_upsert_source_progress(self, source, **fields):
        self.calls.append((source, dict(fields)))
        return self.inner.safe_upsert_source_progress(source, **fields)

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def entries(self, source=None):
        return [fields for name, fields in self.calls if source is None or name == source]

    def phases(self, source=None):
        return [(f.get("status"), f.get("phase")) for f in self.entries(source)]


def _paster_page_scanner(db, html, contents, result_queue=None, stop_event=None):
    scanner = PasterScanner(
        result_queue or queue.Queue(), db, stop_event or threading.Event()
    )
    scanner._fetch_text = AsyncMock(return_value=html)

    async def fake_fetch_with_session(url, session):
        code = url.rsplit("/", 1)[-1]
        return contents.get(code)

    async def fake_get_session():
        return object()

    scanner._fetch_text_with_session = fake_fetch_with_session
    scanner._get_session = fake_get_session
    return scanner


def test_paster_extract_keys_marks_relay_and_filters():
    scanner = PasterScanner(queue.Queue(), FakeDB(), threading.Event())
    content = f'OPENAI_API_KEY={OPENAI_KEY}\nbase_url = "{RELAY_URL}"\n'

    results = scanner._extract_keys(content, "https://paster.sh/ABC123")

    assert len(results) == 1
    assert results[0].platform == "relay"
    assert results[0].base_url == RELAY_URL
    assert results[0].is_relay is True

    assert scanner._extract_keys(f"x={TEST_WORD_KEY}\n", "u") == []
    assert scanner._extract_keys(f"x={LOW_ENTROPY_KEY}\n", "u") == []


def test_paster_extract_keys_dedups_via_db():
    scanner = PasterScanner(
        queue.Queue(), FakeDB(existing_keys={OPENAI_KEY}), threading.Event()
    )

    assert scanner._extract_keys(f"x={OPENAI_KEY}\n", "u") == []


def test_paster_process_page_archive_failure(tmp_db):
    db = RecordingDB(tmp_db)
    scanner = _paster_page_scanner(db, None, {})

    assert asyncio.run(scanner._process_page_async(1)) is PageOutcome.ERROR
    assert db.phases("paster") == [("running", "archive"), ("error", "error")]
    assert db.entries("paster")[-1]["message"] == "archive request failed"


def test_paster_process_page_exhausted(tmp_db):
    db = RecordingDB(tmp_db)
    scanner = _paster_page_scanner(db, "<html>no paste links</html>", {})

    assert asyncio.run(scanner._process_page_async(2)) is PageOutcome.EXHAUSTED
    assert db.phases("paster") == [("running", "archive")]
    assert db.entries("paster")[0]["current"] == 2


def test_paster_process_page_partial_fetch_failures(tmp_db):
    db = RecordingDB(tmp_db)
    html = '<a href="/ABC123">a</a><a href="/DEF456">b</a><a href="/GHI789">c</a>'
    contents = {
        "ABC123": f"OPENAI_API_KEY={OPENAI_KEY}\n",
        "DEF456": None,
        "GHI789": None,
    }
    result_queue = queue.Queue()
    scanner = _paster_page_scanner(db, html, contents, result_queue=result_queue)

    outcome = asyncio.run(scanner._process_page_async(1))

    assert outcome is PageOutcome.SUCCESS
    assert result_queue.qsize() == 1
    assert db.is_source_item_scanned("paster", "ABC123") is True
    assert db.is_source_item_scanned("paster", "DEF456") is False
    assert db.is_source_item_scanned("paster", "GHI789") is False
    final = db.entries("paster")[-1]
    assert final["phase"] == "scan"
    assert final["processed_increment"] == 1
    assert final["found_increment"] == 1
    assert final["current"] == 3 and final["total"] == 3


def test_paster_process_page_skips_already_scanned_codes(tmp_db):
    db = RecordingDB(tmp_db)
    for code in ("ABC123", "DEF456"):
        tmp_db.mark_source_item_scanned("paster", code)
    html = '<a href="/ABC123">a</a><a href="/DEF456">b</a>'
    scanner = _paster_page_scanner(db, html, {})
    fetched = []
    original = scanner._fetch_text_with_session

    async def tracking_fetch(url, session):
        fetched.append(url)
        return await original(url, session)

    scanner._fetch_text_with_session = tracking_fetch

    assert asyncio.run(scanner._process_page_async(1)) is PageOutcome.SUCCESS
    assert fetched == []
    # current counts already-scanned codes in this pre-scan checkpoint.
    assert db.entries("paster")[-1]["current"] == 2
    assert db.entries("paster")[-1]["total"] == 2


def test_paster_process_page_queue_full_is_error(tmp_db):
    db = RecordingDB(tmp_db)
    html = '<a href="/ABC123">a</a>'
    scanner = _paster_page_scanner(
        db, html, {"ABC123": f"OPENAI_API_KEY={OPENAI_KEY}\n"},
        result_queue=FullQueue(),
    )

    assert asyncio.run(scanner._process_page_async(1)) is PageOutcome.ERROR
    error_entry = next(f for f in db.entries("paster") if f["status"] == "error")
    assert error_entry["message"] == "result queue full"
    assert tmp_db.is_source_item_scanned("paster", "ABC123") is False


def test_paster_process_page_stop_interrupts_between_results(tmp_db):
    db = RecordingDB(tmp_db)
    stop = threading.Event()
    html = '<a href="/ABC123">a</a><a href="/DEF456">b</a>'
    contents = {
        "ABC123": f"OPENAI_API_KEY={OPENAI_KEY}\n",
        "DEF456": f"GITHUB_TOKEN={GITHUB_KEY}\n",
    }

    class StopOnPut:
        def __init__(self):
            self.items = []

        def put(self, item, timeout=None):
            self.items.append(item)
            stop.set()

    result_queue = StopOnPut()
    scanner = _paster_page_scanner(
        db, html, contents, result_queue=result_queue, stop_event=stop
    )

    assert asyncio.run(scanner._process_page_async(1)) is PageOutcome.INTERRUPTED
    assert len(result_queue.items) == 1


# --- source_realtime --------------------------------------------------------


def make_realtime(db=None, result_queue=None):
    return RealtimeScanner(
        result_queue or queue.Queue(), threading.Event(), db=db
    )


def test_realtime_extract_keys_excludes_azure_and_aws():
    scanner = make_realtime(FakeDB())

    assert "azure" not in scanner._key_patterns
    assert "aws_secret_key" not in scanner._key_patterns

    content = f"OPENAI_API_KEY={OPENAI_KEY}\nAWS_SECRET_ACCESS_KEY={AWS_SECRET}\n"
    results = scanner._extract_keys(content, "u")

    assert [r.platform for r in results] == ["openai"]
    assert results[0].base_url == config.default_base_urls["openai"]
    assert scanner._extract_keys(f"x={TEST_WORD_KEY}\n", "u") == []


def test_realtime_quick_filter():
    scanner = make_realtime(FakeDB())

    assert scanner._quick_filter("PLEASE UPDATE .env") is True
    assert scanner._quick_filter("key=sk-proj-abc") is True
    assert scanner._quick_filter("plain documentation text") is False


def test_realtime_push_event_dedups_shas():
    result_queue = queue.Queue()
    scanner = make_realtime(FakeDB(), result_queue=result_queue)
    scanner._fetch_commit_content = AsyncMock(
        return_value=f"OPENAI_API_KEY={OPENAI_KEY}\n"
    )
    event = {
        "repo": {"name": "a/b"},
        "payload": {
            "commits": [
                {"sha": "s1", "message": "plain message"},
                {"sha": "s1", "message": "plain message"},
            ]
        },
    }

    found = asyncio.run(scanner._process_push_event(event))

    assert found == 1
    scanner._fetch_commit_content.assert_awaited_once_with("a/b", "s1")
    assert scanner.stats["commits_scanned"] == 1
    assert result_queue.qsize() == 1


def test_realtime_push_event_filters_message_then_content():
    scanner = make_realtime(FakeDB())

    async def fetch(repo, sha):
        if sha == "s1":
            return f"OPENAI_API_KEY={OPENAI_KEY}\n"
        return "nothing interesting here"

    scanner._fetch_commit_content = fetch
    event = {
        "repo": {"name": "a/b"},
        "payload": {
            "commits": [
                {"sha": "s1", "message": "update .env"},
                {"sha": "s2", "message": "plain message"},
            ]
        },
    }

    found = asyncio.run(scanner._process_push_event(event))

    assert found == 1
    assert scanner.stats["commits_scanned"] == 1


def test_realtime_scan_cycle_without_events_does_not_touch_gists():
    """Пустой events-фид не роняет поток и не сканирует gists.

    Раньше эта ветка вызывала несуществующий _fetch_public_gists и падала
    на каждом пустом цикле; публичные gists — отдельный источник.
    """
    result_queue = queue.Queue()
    scanner = make_realtime(FakeDB(), result_queue=result_queue)
    scanner._fetch_events = AsyncMock(return_value=[])

    assert asyncio.run(scanner._scan_cycle()) == 0
    assert result_queue.qsize() == 0
    assert not hasattr(scanner, "_fetch_public_gists")


def test_realtime_fetch_events_401_retries_without_token(monkeypatch):
    db = FakeDB()
    scanner = make_realtime(db)
    monkeypatch.setattr(source_realtime.config, "get_random_token", lambda: "dead-token")
    marked = []
    # не писать в живой dead_github_tokens.txt из теста
    monkeypatch.setattr(source_realtime.config, "mark_token_dead",
                        lambda t: marked.append(t))
    seen_headers = []

    def handler(method, url, kwargs):
        headers = dict(kwargs.get("headers") or {})
        seen_headers.append(headers)
        if "Authorization" in headers:
            return FakeResponse(401, text="bad credentials")
        return FakeResponse(
            200, payload=[{"type": "PushEvent"}], headers={"ETag": "e1"}
        )

    attach_session(scanner, FakeSession(handler))

    events = asyncio.run(scanner._fetch_events())

    assert events == [{"type": "PushEvent"}]
    assert "Authorization" in seen_headers[0]
    assert "Authorization" not in seen_headers[1]
    assert scanner._last_etag == "e1"
    # 401 у токена больше не клеймится как ошибка источника: анонимный
    # фолбэк отработал, статус остаётся running/events.
    assert db.phases("realtime") == [("running", "events")]
    assert marked == ["dead-token"]


def test_realtime_fetch_events_304_and_http_error():
    db = FakeDB()
    scanner = make_realtime(db)
    attach_session(scanner, FakeSession(lambda m, u, k: FakeResponse(304)))

    assert asyncio.run(scanner._fetch_events()) == []
    assert db.phases("realtime") == [("running", "events")]

    attach_session(scanner, FakeSession(lambda m, u, k: FakeResponse(500, text="x")))
    assert asyncio.run(scanner._fetch_events()) == []
    assert db.entries("realtime")[-1]["message"] == (
        "GitHub events request failed (HTTP 500)"
    )


def test_realtime_fetch_events_exception_reports_telemetry():
    db = FakeDB()
    scanner = make_realtime(db)
    attach_session(scanner, FakeSession(lambda m, u, k: aiohttp.ClientError("down")))

    assert asyncio.run(scanner._fetch_events()) == []
    assert db.entries("realtime")[-1]["message"] == (
        "GitHub events request failed (ClientError)"
    )


def test_realtime_telemetry_waiting_switches_to_retry():
    db = FakeDB()
    scanner = make_realtime(db)

    scanner._telemetry_running("events")
    scanner._telemetry_waiting()
    scanner._telemetry_error("GitHub events request failed (HTTP 500)")
    scanner._telemetry_waiting()

    assert db.phases("realtime") == [
        ("running", "events"),
        ("running", "waiting"),
        ("error", "error"),
        ("running", "retry"),
    ]
    assert db.entries("realtime")[-1]["message"] == (
        "GitHub events request failed (HTTP 500)"
    )


# --- source_codegraph -------------------------------------------------------


def make_codegraph(db=None):
    return CodeGraphScanner(queue.Queue(), threading.Event(), db=db)


def test_codegraph_extract_keys_includes_azure():
    scanner = make_codegraph(FakeDB())
    content = f"AZURE_OPENAI_KEY={AZURE_KEY}\nOPENAI_API_KEY={OPENAI_KEY}\n"

    results = scanner._extract_keys(content, "u")

    assert {r.platform for r in results} == {"azure", "openai"}
    assert all(
        r.base_url == config.default_base_urls[r.platform] for r in results
    )
    assert scanner._extract_keys(f"x={TEST_WORD_KEY}\n", "u") == []
    assert scanner._extract_keys(f"x={LOW_ENTROPY_KEY}\n", "u") == []


def test_codegraph_query_repos_parses_and_counts_queries():
    scanner = make_codegraph(FakeDB())
    payload = {
        "data": {
            "search": {
                "results": {
                    "resultCount": 2,
                    "repositories": [
                        {"name": "github.com/a/b"},
                        {"name": "github.com/c/d"},
                    ],
                }
            }
        }
    }
    session = FakeSession(lambda m, u, k: FakeResponse(200, payload=payload))
    attach_session(scanner, session)

    repos = asyncio.run(scanner._query_repos("sk-proj-"))

    assert repos == ["github.com/a/b", "github.com/c/d"]
    assert scanner.stats["queries"] == 1
    assert session.calls[0][0] == "POST"
    assert session.calls[0][1] == source_codegraph.SOURCEGRAPH_API
    assert "context:global sk-proj- fork:no count:100" in session.calls[0][2]["json"]["query"]


def test_codegraph_query_repos_http_error_and_garbage():
    scanner = make_codegraph(FakeDB())
    attach_session(scanner, FakeSession(lambda m, u, k: FakeResponse(500, text="oops")))

    assert asyncio.run(scanner._query_repos("kw")) == []
    assert scanner.stats["queries"] == 0

    attach_session(scanner, FakeSession(lambda m, u, k: FakeResponse(200, payload={})))
    assert asyncio.run(scanner._query_repos("kw")) == []
    assert scanner.stats["queries"] == 1

    attach_session(scanner, FakeSession(lambda m, u, k: aiohttp.ClientError("down")))
    assert asyncio.run(scanner._query_repos("kw")) == []
    assert scanner.stats["queries"] == 1


def test_codegraph_state_is_prefixed_and_dedup_is_recorded():
    db = FakeDB()
    scanner = make_codegraph(db)

    scanner._set_state("kw_offset", "30")
    assert db.state["codegraph_kw_offset"] == "30"
    assert scanner._get_state("kw_offset") == "30"

    assert scanner._is_scanned("github.com/a/b") is False
    scanner._mark_scanned("github.com/a/b")
    assert scanner._is_scanned("github.com/a/b") is True


def test_codegraph_run_emits_expected_telemetry_phases():
    db = FakeDB()
    stop = threading.Event()
    scanner = CodeGraphScanner(queue.Queue(), stop, db=db)

    async def fake_query(keyword):
        stop.set()
        return []

    scanner._query_repos = fake_query

    with patch("time.sleep"):
        scanner.run()

    phases = db.phases("codegraph")
    assert phases[:2] == [("running", "discover"), ("running", "discover")]
    assert ("running", "scan") in phases
    assert ("running", "waiting") in phases
    assert phases[-1] == ("stopped", "stopped")


# --- telemetry contract for every source ------------------------------------

SOURCE_FACTORIES = {
    "pastebin": lambda db: PastebinScanner(queue.Queue(), threading.Event(), db=db),
    "gitlab": lambda db: GitLabScanner(queue.Queue(), threading.Event(), db=db),
    "gist": lambda db: GistScanner(queue.Queue(), threading.Event(), db=db),
    "mcp": lambda db: MCPScanner(queue.Queue(), threading.Event(), db=db),
    "paster": lambda db: PasterScanner(queue.Queue(), db, threading.Event()),
    "realtime": lambda db: RealtimeScanner(queue.Queue(), threading.Event(), db=db),
    "codegraph": lambda db: CodeGraphScanner(queue.Queue(), threading.Event(), db=db),
}


@pytest.mark.parametrize("source_name", sorted(SOURCE_FACTORIES))
def test_all_sources_emit_telemetry_contract(source_name):
    db = FakeDB()
    scanner = SOURCE_FACTORIES[source_name](db)

    if hasattr(scanner, "_telemetry_running"):
        scanner._telemetry_running("scan")
        assert db.calls[0] == (
            source_name,
            {"status": "running", "phase": "scan", "message": ""},
        )

    scanner._telemetry_error("boom", 2)

    error_source, error_fields = db.calls[-1]
    assert error_source == source_name
    assert error_fields["status"] == "error"
    assert error_fields["phase"] == "error"
    assert error_fields["message"] == "boom"
    assert error_fields["errors_increment"] == 2


# --- context gate: aws_secret_key / azure -----------------------------------
# 40-char base64 и 32-char hex — самые частые ложные срабатывания (на живой БД
# aws_secret_key дал 470k строк мусора). Все источники обязаны требовать
# маркер в окне вокруг матча.

AWS_NO_CONTEXT = f"token = '{AWS_SECRET}'\n"
AWS_WITH_CONTEXT = f"aws_secret_access_key = '{AWS_SECRET}'\n"
AZURE_NO_CONTEXT = f"value = '{AZURE_KEY}'\n"
AZURE_WITH_CONTEXT = f"AZURE_OPENAI_KEY={AZURE_KEY}\n"


@pytest.mark.parametrize(
    "factory",
    [make_gist, make_gitlab, make_mcp],
    ids=["gist", "gitlab", "mcp"],
)
def test_aws_secret_requires_context_marker(factory):
    scanner = factory()
    assert [r.platform for r in scanner._extract_keys(AWS_WITH_CONTEXT, "u")] == [
        "aws_secret_key"]
    assert scanner._extract_keys(AWS_NO_CONTEXT, "u") == []
    # эти источники azure не сканируют вовсе (32-char hex = шум)
    assert scanner._extract_keys(AZURE_WITH_CONTEXT, "u") == []


def test_codegraph_aws_and_azure_require_context_marker():
    scanner = make_codegraph(FakeDB())
    assert [r.platform for r in scanner._extract_keys(AWS_WITH_CONTEXT, "u")] == [
        "aws_secret_key"]
    assert scanner._extract_keys(AWS_NO_CONTEXT, "u") == []
    assert [r.platform for r in scanner._extract_keys(AZURE_WITH_CONTEXT, "u")] == [
        "azure"]
    assert scanner._extract_keys(AZURE_NO_CONTEXT, "u") == []


def test_paster_aws_secret_requires_context():
    scanner = PasterScanner(queue.Queue(), FakeDB(), threading.Event())
    assert [r.platform for r in scanner._extract_keys(AWS_WITH_CONTEXT, "u")] == [
        "aws_secret_key"]
    assert scanner._extract_keys(AWS_NO_CONTEXT, "u") == []
