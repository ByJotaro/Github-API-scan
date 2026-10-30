"""Token rotation, rate-limit handling and dedup tests for search helpers.

Covers: extended_search.GistSearcher and gitlab_searcher.GitLabSearcher.

No network: both searchers accept a session object, so a fake session that
records calls and returns canned payloads is injected directly.
"""

import asyncio
from unittest.mock import patch
from urllib.parse import quote

import gitlab_searcher
from config import config
from extended_search import GistSearcher
from gitlab_searcher import GitLabSearcher


class FakeResponse:
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
    """Records requests; a handler returning an Exception makes the call raise."""

    def __init__(self, handler):
        self.handler = handler
        self.calls = []
        self.closed = False

    def _request(self, method, url, kwargs):
        self.calls.append((method, url, kwargs))
        result = self.handler(method, url, kwargs)
        if isinstance(result, Exception):
            raise result
        return result

    def get(self, url, **kwargs):
        return self._request("GET", url, kwargs)

    async def close(self):
        self.closed = True


SEARCH_URL = "https://api.github.com/search/code?q=x"


# --- extended_search.GistSearcher: token rotation ---------------------------


def test_get_headers_skips_rate_limited_token():
    searcher = GistSearcher(["tok0", "tok1", "tok2"])
    searcher._rate_limited = {0}

    headers = searcher._get_headers()

    assert headers == {
        "Authorization": "token tok1",
        "Accept": "application/vnd.github+json",
    }
    assert searcher.token_idx == 2


def test_get_headers_resets_rate_limited_set_when_everything_is_spent():
    searcher = GistSearcher(["tok0", "tok1"])
    searcher._rate_limited = {0, 1}

    headers = searcher._get_headers()

    assert headers["Authorization"] == "token tok0"
    assert searcher._rate_limited == set()


def test_get_headers_rotates_across_calls():
    searcher = GistSearcher(["tok0", "tok1"])

    assert searcher._get_headers()["Authorization"] == "token tok0"
    assert searcher._get_headers()["Authorization"] == "token tok1"
    assert searcher._get_headers()["Authorization"] == "token tok0"


# --- extended_search.GistSearcher: pagination + 403 handling ----------------


def test_paginated_get_stops_on_short_page():
    searcher = GistSearcher(["tok0"])
    session = FakeSession(
        lambda m, u, k: FakeResponse(200, payload={"items": [{"id": i} for i in range(4)]})
    )
    searcher.session = session

    items = asyncio.run(searcher._paginated_get(SEARCH_URL, {}))

    assert len(items) == 4
    assert len(session.calls) == 1
    assert session.calls[0][1].endswith("&page=1")


def test_paginated_get_walks_full_pages_until_max_pages():
    searcher = GistSearcher(["tok0"])
    session = FakeSession(
        lambda m, u, k: FakeResponse(200, payload={"items": [{"id": i} for i in range(30)]})
    )
    searcher.session = session

    items = asyncio.run(searcher._paginated_get(SEARCH_URL, {}))

    assert len(items) == 90
    assert [c[1] for c in session.calls] == [
        f"{SEARCH_URL}&page={page}" for page in (1, 2, 3)
    ]


def test_paginated_get_respects_custom_max_pages():
    searcher = GistSearcher(["tok0"])
    session = FakeSession(
        lambda m, u, k: FakeResponse(200, payload={"items": [{"id": i} for i in range(30)]})
    )
    searcher.session = session

    items = asyncio.run(searcher._paginated_get(SEARCH_URL, {}, max_pages=1))

    assert len(items) == 30
    assert len(session.calls) == 1


def test_paginated_get_marks_current_token_when_remaining_is_zero():
    searcher = GistSearcher(["tok0", "tok1"])
    first_page_headers = searcher._get_headers()  # token index 0, token_idx -> 1

    def handler(method, url, kwargs):
        if url.endswith("&page=1"):
            return FakeResponse(200, payload={"items": [{"id": i} for i in range(30)]})
        return FakeResponse(
            403, text="rate limited", headers={"X-RateLimit-Remaining": "0"}
        )

    session = FakeSession(handler)
    searcher.session = session

    items = asyncio.run(searcher._paginated_get(SEARCH_URL, first_page_headers))

    assert len(items) == 30
    # Page 2 rotates to token index 1, so that is the token the 403 belongs to.
    assert searcher._rate_limited == {1}
    assert len(session.calls) == 2


def test_paginated_get_403_with_budget_left_does_not_mark_token():
    searcher = GistSearcher(["tok0"])
    session = FakeSession(
        lambda m, u, k: FakeResponse(
            403, text="forbidden", headers={"X-RateLimit-Remaining": "5"}
        )
    )
    searcher.session = session

    assert asyncio.run(searcher._paginated_get(SEARCH_URL, {})) == []
    assert searcher._rate_limited == set()


def test_paginated_get_survives_request_exception():
    searcher = GistSearcher(["tok0"])
    session = FakeSession(lambda m, u, k: RuntimeError("connection reset"))
    searcher.session = session

    assert asyncio.run(searcher._paginated_get(SEARCH_URL, {})) == []
    assert len(session.calls) == 1


# --- extended_search.GistSearcher: search_* wrappers ------------------------


def test_search_gists_returns_nothing_and_spends_no_requests():
    """`gist:true` — невалидный квалификатор: /search/code отдаёт total=0.

    Проверено живым токеном 2026-10-30. Стратегия удалена, чтобы каждый
    дорк не тратил два запроса code search впустую; gists сканирует
    отдельный GistScanner.
    """
    searcher = GistSearcher(["tok0"])
    calls = {"n": 0}

    def handler(method, url, kwargs):
        calls["n"] += 1
        return FakeResponse(200, payload={"items": []})

    searcher.session = FakeSession(handler)
    assert asyncio.run(searcher.search_gists("sk-proj-")) == []
    assert calls["n"] == 0

def test_search_commits_uses_cloak_preview_and_truncates_message():
    searcher = GistSearcher(["tok0"])
    items = [
        {
            "html_url": "https://github.com/a/b/commit/1",
            "sha": "c1",
            "repository": {"full_name": "a/b"},
            "commit": {"message": "m" * 300},
        }
    ]
    session = FakeSession(lambda m, u, k: FakeResponse(200, payload={"items": items}))
    searcher.session = session

    results = asyncio.run(searcher.search_commits("keyword"))

    assert len(results) == 1
    assert results[0]["type"] == "commit"
    assert results[0]["repo"] == "a/b"
    assert results[0]["sha"] == "c1"
    assert results[0]["message"] == "m" * 120
    headers = session.calls[0][2]["headers"]
    assert headers["Accept"] == "application/vnd.github.cloak-preview"
    assert "search/commits?" in session.calls[0][1]


def test_search_issues_maps_fields():
    searcher = GistSearcher(["tok0"])
    items = [
        {
            "html_url": "https://github.com/a/b/issues/7",
            "title": "leaked key",
            "body": "b" * 500,
        }
    ]
    session = FakeSession(lambda m, u, k: FakeResponse(200, payload={"items": items}))
    searcher.session = session

    results = asyncio.run(searcher.search_issues("keyword"))

    assert results == [
        {
            "url": "https://github.com/a/b/issues/7",
            "title": "leaked key",
            "body": "b" * 200,
            "type": "issue",
        }
    ]
    assert "search/issues?" in session.calls[0][1]


def test_gist_searcher_close_is_idempotent_and_marks_session_closed():
    searcher = GistSearcher(["tok0"])
    asyncio.run(searcher.close())  # no session yet — must not raise

    session = FakeSession(lambda m, u, k: FakeResponse(200))
    searcher.session = session

    asyncio.run(searcher.close())
    assert session.closed is True

    asyncio.run(searcher.close())  # already closed — still no raise


# --- gitlab_searcher.GitLabSearcher -----------------------------------------


def make_gitlab(tokens=None):
    return GitLabSearcher(tokens=tokens if tokens is not None else ["tok0"])


def test_gitlab_default_tokens_come_from_config():
    searcher = GitLabSearcher()

    assert searcher.tokens is config.github_tokens


def test_gitlab_get_headers_is_public():
    searcher = make_gitlab()

    headers = searcher._get_headers()

    assert headers == {
        "Accept": "application/json",
        "User-Agent": "GitHub-API-Scan/1.0",
    }
    assert "Authorization" not in headers


def test_gitlab_search_code_429_returns_empty_and_warns():
    searcher = make_gitlab()
    session = FakeSession(lambda m, u, k: FakeResponse(429, text="slow down"))
    searcher.session = session

    with patch.object(gitlab_searcher.logger, "warning") as warn:
        results = asyncio.run(searcher.search_code("OPENAI_API_KEY"))

    assert results == []
    warn.assert_called_once_with("GitLab rate limit hit")
    assert "scope=blobs" in session.calls[0][1]
    assert "per_page=50" in session.calls[0][1]


def test_gitlab_search_code_maps_blobs_and_caps_at_five():
    searcher = make_gitlab()

    def handler(method, url, kwargs):
        if "/search?" in url:
            return FakeResponse(
                200, payload=[{"filename": f"f{i}.env"} for i in range(7)]
            )
        return FakeResponse(
            200,
            payload=[{"path_with_namespace": "g/p", "default_branch": "dev"}],
        )

    session = FakeSession(handler)
    searcher.session = session

    results = asyncio.run(searcher.search_code("OPENAI_API_KEY"))

    assert len(results) == 5
    assert results[0] == {
        "url": "https://gitlab.com/g/p/-/blob/dev/f0.env",
        "path": "f0.env",
        "project": "g/p",
        "branch": "dev",
        "type": "gitlab_blob",
    }
    blob_url = session.calls[1][1]
    assert quote("g/p", safe="") in blob_url
    assert "search=OPENAI_API_KEY" in blob_url


def test_gitlab_search_code_skips_projects_without_path():
    searcher = make_gitlab()

    def handler(method, url, kwargs):
        if "/search?" in url:
            return FakeResponse(200, payload=[])
        return FakeResponse(
            200,
            payload=[
                {"default_branch": "main"},
                {"path_with_namespace": "g/p", "default_branch": "main"},
            ],
        )

    session = FakeSession(handler)
    searcher.session = session

    asyncio.run(searcher.search_code("kw"))

    assert len([c for c in session.calls if "/search?" in c[1]]) == 1


def test_gitlab_search_code_partial_blob_failure_keeps_other_projects():
    searcher = make_gitlab()

    def handler(method, url, kwargs):
        if "/search?" in url:
            if "p0" in url:
                return FakeResponse(500, text="boom")
            return FakeResponse(200, payload=[{"filename": "ok.env"}])
        return FakeResponse(
            200,
            payload=[
                {"path_with_namespace": "g/p0", "default_branch": "main"},
                {"path_with_namespace": "g/p1", "default_branch": "main"},
            ],
        )

    session = FakeSession(handler)
    searcher.session = session

    results = asyncio.run(searcher.search_code("kw"))

    assert [r["project"] for r in results] == ["g/p1"]
    assert results[0]["path"] == "ok.env"


def test_gitlab_search_code_blob_json_exception_is_contained():
    searcher = make_gitlab()

    def handler(method, url, kwargs):
        if "/search?" in url:
            return FakeResponse(200, payload=ValueError("bad json"))
        return FakeResponse(
            200, payload=[{"path_with_namespace": "g/p", "default_branch": "main"}]
        )

    searcher.session = FakeSession(handler)

    assert asyncio.run(searcher.search_code("kw")) == []


def test_gitlab_search_code_queries_only_first_ten_projects():
    searcher = make_gitlab()
    projects = [
        {"path_with_namespace": f"g/p{i}", "default_branch": "main"} for i in range(12)
    ]

    def handler(method, url, kwargs):
        if "/search?" in url:
            return FakeResponse(200, payload=[])
        return FakeResponse(200, payload=projects)

    session = FakeSession(handler)
    searcher.session = session

    assert asyncio.run(searcher.search_code("kw")) == []
    assert len([c for c in session.calls if "/search?" in c[1]]) == 10


def test_gitlab_search_code_project_list_exception_returns_empty():
    searcher = make_gitlab()
    session = FakeSession(lambda m, u, k: RuntimeError("connection reset"))
    searcher.session = session

    with patch.object(gitlab_searcher.logger, "debug") as debug:
        assert asyncio.run(searcher.search_code("kw")) == []

    assert debug.call_count == 1
    assert "GitLab search error" in debug.call_args.args[0]


def test_gitlab_searcher_close_closes_session():
    searcher = make_gitlab()
    asyncio.run(searcher.close())  # no session — no raise

    session = FakeSession(lambda m, u, k: FakeResponse(200))
    searcher.session = session

    asyncio.run(searcher.close())
    assert session.closed is True
    asyncio.run(searcher.close())
