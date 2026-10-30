"""proxy_server.py: routing, auth/pool rotation, upstream errors, streaming.

Никакой сети и никакого внешнего bind:
- приложение берётся из ProxyServer.start() через мокнутые web.AppRunner /
  web.TCPSite (реальный bind не происходит);
- HTTP-запросы идут через aiohttp TestServer/TestClient на 127.0.0.1 с
  эфемерным портом (port=0), клиент закрывается в finally внутри asyncio.run;
- апстрим — фейковая сессия (ProxyServer.session), реальные соединения не
  открываются;
- БД всегда во временном каталоге.
"""
from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import proxy_server as ps  # noqa: E402
from aiohttp.test_utils import TestClient, TestServer  # noqa: E402
from database import Database  # noqa: E402


# ===========================================================================
#                      Фейковый aiohttp-апстрим (без сети)
# ===========================================================================

class FakeContent:
    """Асинхронный итератор тела ответа (как resp.content у aiohttp)."""

    def __init__(self, chunks):
        self._chunks = list(chunks)

    def __aiter__(self):
        async def gen():
            for chunk in self._chunks:
                yield chunk

        return gen()


class FakeResponse:
    def __init__(self, status: int = 200, payload=None, text: str | None = None,
                 chunks=None):
        self.status = status
        if text is not None:
            self._text = text
        elif payload is not None:
            self._text = json.dumps(payload)
        else:
            self._text = ""
        self.content = FakeContent(chunks or [])

    async def text(self) -> str:
        return self._text


class FakeRequestContext:
    def __init__(self, response: FakeResponse):
        self._response = response

    async def __aenter__(self) -> FakeResponse:
        return self._response

    async def __aexit__(self, *exc_info) -> bool:
        return False


class FakeSession:
    """Заменитель aiohttp.ClientSession: отдаёт заготовленные ответы."""

    def __init__(self, responses=()):
        self.responses = list(responses)
        self.calls: list = []
        self.closed = False

    def post(self, url, json=None, headers=None):
        self.calls.append({"url": url, "json": json, "headers": headers})
        if not self.responses:
            raise AssertionError("FakeSession: no queued response")
        return FakeRequestContext(self.responses.pop(0))

    async def close(self):
        self.closed = True


# ===========================================================================
#                      Фикстуры / хелперы БД и приложения
# ===========================================================================

@pytest.fixture(autouse=True)
def _clean_trace():
    ps.TRACE.clear()
    ps._trace_counter = 0
    yield
    ps.TRACE.clear()


@pytest.fixture
def proxy_db(tmp_path):
    """Временная БД + minimal pool_models (его создаёт TUI, не Database)."""
    database = Database(str(tmp_path / "proxy.db"))
    with database._lock, database._get_connection() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS pool_models (model_name TEXT PRIMARY KEY)")
        conn.commit()
    try:
        yield database
    finally:
        database.close()


def _seed_pool_entry(db, model, endpoint, keys, *, platform="openai",
                     zone="model", source="model", priority=0, enabled=1):
    with db._lock, db._get_connection() as conn:
        conn.execute(
            "INSERT INTO active_pool (model_name, endpoint, platform, "
            "api_keys, zone, source, priority, enabled) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (model, endpoint, platform, json.dumps(list(keys)), zone, source,
             priority, enabled),
        )
        conn.commit()


def _seed_key_model(db, api_key, model, base_url, *, status="confirmed",
                    is_confirmed=1, platform="openai"):
    with db._lock, db._get_connection() as conn:
        cursor = conn.execute(
            "INSERT INTO leaked_keys (platform, api_key, base_url, status, "
            "found_time) VALUES (?, ?, ?, ?, ?)",
            (platform, api_key, base_url, status, "2026-01-01T00:00:00"),
        )
        conn.execute(
            "INSERT INTO key_models (key_id, model_name, platform, base_url, "
            "is_confirmed) VALUES (?, ?, ?, ?, ?)",
            (cursor.lastrowid, model, platform, base_url, is_confirmed),
        )
        conn.commit()


def _server(db, *, model="m1", endpoint="https://relay.example.com/v1",
            keys=("sk-key-1",), platform="openai", seed=True) -> ps.ProxyServer:
    server = ps.ProxyServer(db, port=0, host="127.0.0.1")
    if seed:
        _seed_pool_entry(db, model, endpoint, keys, platform=platform)
        server.pool._load_cache()
    return server


async def _make_client(server: ps.ProxyServer, monkeypatch):
    """Получить app из ProxyServer.start() без реального bind.

    Возвращает (TestClient, captured): captured содержит app/bind/cleanup.
    """
    captured: dict = {}

    class FakeRunner:
        def __init__(self, app):
            self.app = app
            captured["app"] = app
            captured["runner"] = self

        async def setup(self):
            captured["setup"] = True

        async def cleanup(self):
            captured["cleaned"] = True

    class FakeSite:
        def __init__(self, runner, host, port):
            captured["bind"] = (host, port)

        async def start(self):
            captured["started"] = True

    monkeypatch.setattr(ps.web, "AppRunner", FakeRunner)
    monkeypatch.setattr(ps.web, "TCPSite", FakeSite)

    task = asyncio.ensure_future(server.start())
    for _ in range(200):
        if captured.get("started"):
            break
        await asyncio.sleep(0)
    else:  # pragma: no cover - защита от зависания
        task.cancel()
        raise AssertionError("ProxyServer.start() не дошёл до site.start()")
    task.cancel()
    await task
    # start() отменён -> finally уже отработал; сохраняем факты для проверок
    # после asyncio.run (bind не выполнялся, cleanup вызван).
    server._test_bind = captured.get("bind")
    server._test_cleaned = captured.get("cleaned", False)

    client = TestClient(TestServer(captured["app"]))
    await client.start_server()
    return client, captured


# ===========================================================================
#                          Чистые функции / конвертеры
# ===========================================================================

def test_mask_key():
    assert ps._mask_key("short") == "shor..."
    assert ps._mask_key("sk-1234567890abcdef") == "sk-12345...cdef"
    # ровно 12 символов -> длинная ветка (len < 12 False)
    assert ps._mask_key("abcdefghijkl") == "abcdefgh...ijkl"


@pytest.mark.parametrize(
    "endpoint,path,expected",
    [
        ("https://api.openai.com", "chat/completions",
         "https://api.openai.com/v1/chat/completions"),
        ("https://api.openai.com/v1", "chat/completions",
         "https://api.openai.com/v1/chat/completions"),
        ("https://api.openai.com/v1/chat/completions", "completions",
         "https://api.openai.com/v1/completions"),
        ("https://api.anthropic.com/v1", "messages",
         "https://api.anthropic.com/v1/messages"),
        ("https://x.y/v1beta", "chat/completions",
         "https://x.y/v1beta/chat/completions"),
        ("https://x.y/", "embeddings", "https://x.y/v1/embeddings"),
        ("https://x.y/v1/models", "models", "https://x.y/v1/models"),
    ],
)
def test_upstream_url(endpoint, path, expected):
    assert ps._upstream_url(endpoint, path) == expected


@pytest.mark.parametrize(
    "endpoint,platform,expected",
    [
        ("https://api.anthropic.com/v1", "", True),
        ("https://proxy.example.com", "Anthropic", True),
        ("https://api.openai.com/v1", "openai", False),
        ("", "", False),
    ],
)
def test_is_anthropic_endpoint(endpoint, platform, expected):
    assert ps.is_anthropic_endpoint(endpoint, platform) is expected


def test_anthropic_to_openai_request():
    body = {
        "messages": [
            {"role": "system", "content": "S1"},
            {"role": "system", "content": "S2"},
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi"},
        ],
        "temperature": 0.3,
    }

    converted = ps.anthropic_to_openai_request(body, "claude-x")

    assert converted["model"] == "claude-x"
    assert converted["max_tokens"] == 8192  # дефолт вместо обрезающих 100
    assert converted["temperature"] == 0.3
    assert converted["system"] == "S1\nS2"
    assert [m["role"] for m in converted["messages"]] == ["user", "assistant"]
    assert converted["messages"][0]["content"] == "hello"

    # Явный max_tokens уважается, system отсутствует -> None
    explicit = ps.anthropic_to_openai_request(
        {"messages": [{"role": "user", "content": "x"}], "max_tokens": 32},
        "claude-y")
    assert explicit["max_tokens"] == 32
    assert explicit["system"] is None
    assert explicit["temperature"] == 0


def test_anthropic_to_openai_response():
    data = {
        "id": "msg_1",
        "content": [{"text": "hel"}, {"text": "lo"}, "not-a-dict"],
        "usage": {"input_tokens": 3, "output_tokens": 2},
        "stop_reason": "end_turn",
    }

    converted = ps.anthropic_to_openai_response(data, "claude-z")

    assert converted["id"] == "msg_1"
    assert converted["object"] == "chat.completion"
    assert converted["model"] == "claude-z"
    assert converted["choices"][0]["message"] == {
        "role": "assistant", "content": "hello"}
    assert converted["choices"][0]["finish_reason"] == "end_turn"
    assert converted["usage"] == {
        "prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5}

    # Пустой ответ не падает на отсутствующих ключах.
    empty = ps.anthropic_to_openai_response({}, "m")
    assert empty["choices"][0]["finish_reason"] == "stop"
    assert empty["usage"]["total_tokens"] == 0


def test_trace_push_and_get():
    ps.push_trace("m1", 1, "sk-...abcd", "https://ep", 429, "quota")
    ps.push_trace_summary("m1", True, 2, "ok")

    events = ps.get_trace(2)

    assert len(events) == 2
    assert events[0]["status"] == 429
    assert events[0]["attempt"] == 1
    assert events[0]["key"] == "sk-...abcd"
    assert events[1]["summary"] is True
    assert events[1]["attempt"] == -1
    assert events[1]["status"] == 200
    assert events[1]["detail"].startswith("✓ ")

    failed = ps.push_trace_summary("m2", False, 3, "нет ключей")
    assert ps.get_trace(1)[0]["status"] == 503
    assert ps.get_trace(1)[0]["detail"].startswith("✗ ")
    assert failed is None


def test_trace_ring_buffer_is_bounded():
    for index in range(ps.TRACE.maxlen + 10):
        ps.push_trace("m", 1, "k", "e", 200)

    assert len(ps.TRACE) == ps.TRACE.maxlen
    # get_trace(n > len) возвращает всё, что есть, без падения
    assert len(ps.get_trace(10_000)) == ps.TRACE.maxlen


# ===========================================================================
#                          ActivePool (ротация и пул)
# ===========================================================================

def test_pool_round_robin_and_sticky(proxy_db):
    server = _server(proxy_db, keys=("sk-k1", "sk-k2"))

    sources = server.pool._get_sources_for_model("m1")
    assert [s["endpoint"] for s in sources] == ["https://relay.example.com/v1"]

    picks = [server.pool._get_next_key("m1", sources)[0] for _ in range(4)]
    assert picks == ["sk-k1", "sk-k2", "sk-k1", "sk-k2"]

    server.pool._selection_mode = "sticky"
    sticky = [server.pool._get_next_key("m1", sources)[0] for _ in range(3)]
    assert sticky == ["sk-k1"] * 3


def test_pool_cooldown_is_skipped_and_expires(proxy_db):
    server = _server(proxy_db, keys=("sk-k1", "sk-k2"))
    sources = server.pool._get_sources_for_model("m1")

    server.pool._put_cooldown("sk-k1", seconds=60)
    assert server.pool._cooldowns["sk-k1"] > time.time() + 50

    picks = [server.pool._get_next_key("m1", sources)[0] for _ in range(3)]
    assert picks == ["sk-k2"] * 3  # k1 в кулдауне

    # Истёкший кулдаун вычищается, ключ возвращается в ротацию.
    server.pool._put_cooldown("sk-k1", seconds=-1)
    server.pool._cooldowns["sk-k1"] = time.time() - 1
    assert server.pool._get_next_key("m1", sources)[0] in ("sk-k1", "sk-k2")
    assert "sk-k1" not in server.pool._cooldowns


def test_pool_all_keys_in_cooldown_returns_none(proxy_db):
    server = _server(proxy_db, keys=("sk-only",))
    sources = server.pool._get_sources_for_model("m1")
    server.pool._put_cooldown("sk-only", seconds=60)

    assert server.pool._get_next_key("m1", sources) == (None, None, None)
    assert server.pool._get_next_key("m1", []) == (None, None, None)


def test_pool_model_zone_filtering(proxy_db):
    # ProxyServer создаёт таблицу active_pool; сеем после этого.
    server = ps.ProxyServer(proxy_db, port=0)

    # 'z-model' явно в pool_models -> берём только zone='model'
    _seed_pool_entry(proxy_db, "z-model", "https://a.example.com/v1", ["sk-a"],
                     zone="model", source="model")
    _seed_pool_entry(proxy_db, "z-model", "https://b.example.com/v1", ["sk-b"],
                     zone="endpoint", source="endpoint")
    # 'z-endpoint' только через провайдера -> zone='endpoint'
    _seed_pool_entry(proxy_db, "z-endpoint", "https://c.example.com/v1", ["sk-c"],
                     zone="endpoint", source="endpoint")
    # 'z-auto' в пуле, но без записи в pool_models и zone=endpoint -> zone=''
    _seed_pool_entry(proxy_db, "z-auto", "https://d.example.com/v1", ["sk-d"],
                     zone="model", source="model")

    with proxy_db._lock, proxy_db._get_connection() as conn:
        conn.execute("INSERT INTO pool_models (model_name) VALUES ('z-model')")
        conn.commit()

    server.pool._load_cache()

    assert server.pool._model_zone("z-model") == "model"
    assert server.pool._model_zone("z-endpoint") == "endpoint"
    assert server.pool._model_zone("z-auto") == ""

    model_sources = server.pool._get_sources_for_model("z-model")
    assert [s["endpoint"] for s in model_sources] == ["https://a.example.com/v1"]
    endpoint_sources = server.pool._get_sources_for_model("z-endpoint")
    assert [s["endpoint"] for s in endpoint_sources] == ["https://c.example.com/v1"]
    auto_sources = server.pool._get_sources_for_model("z-auto")
    assert [s["endpoint"] for s in auto_sources] == ["https://d.example.com/v1"]


def test_pool_zone_lookup_survives_missing_pool_models(tmp_path):
    # Свежая БД без pool_models: _model_zone обязан вернуть '' без исключения.
    fresh = Database(str(tmp_path / "fresh.db"))
    try:
        server = ps.ProxyServer(fresh, port=0)
        _seed_pool_entry(fresh, "m", "https://e.example.com/v1", ["sk-1"])
        server.pool._load_cache()
        assert server.pool._model_zone("m") == ""
        assert len(server.pool._get_sources_for_model("m")) == 1
    finally:
        fresh.close()


def test_pool_find_endpoints_requires_confirmed(proxy_db):
    endpoint = "https://relay.example.com/v1"
    _seed_key_model(proxy_db, "sk-conf", "cm", endpoint,
                    status="confirmed", is_confirmed=1)
    _seed_key_model(proxy_db, "sk-valid", "cm", endpoint,
                    status="valid", is_confirmed=0)
    _seed_key_model(proxy_db, "sk-other", "cm", "https://other.example.com/v1",
                    status="confirmed", is_confirmed=1)

    server = ps.ProxyServer(proxy_db, port=0)

    found = server.pool._find_endpoints_for_model("cm")
    by_endpoint = {entry["endpoint"]: entry["keys"] for entry in found}
    assert by_endpoint == {
        endpoint: ["sk-conf"],
        "https://other.example.com/v1": ["sk-other"],
    }


def test_pool_sources_fall_back_to_confirmed_keys(proxy_db):
    endpoint = "https://relay.example.com/v1"
    _seed_key_model(proxy_db, "sk-conf", "auto-model", endpoint)

    server = ps.ProxyServer(proxy_db, port=0)
    assert server.pool._cache == {}  # в пуле модели нет

    sources = server.pool._get_sources_for_model("auto-model")
    assert sources == [{"endpoint": endpoint, "platform": "openai",
                        "keys": ["sk-conf"]}]


def test_pool_add_remove_clear_and_list(proxy_db):
    server = ps.ProxyServer(proxy_db, port=0)
    assert server.pool.list_models() == []
    assert server.pool.get_all_available_models() == []

    # Модель без источника нигде не подтверждена -> отказ
    assert "не найдена" in server.pool.add_model("ghost")

    result = server.pool.add_model("m-new", "https://new.example.com/v1")
    assert "Добавлено" in result
    assert server.pool.list_models() == ["m-new"]
    assert server.pool.get_all_available_models() == ["m-new"]

    assert "Удалено" in server.pool.remove_model("m-new")
    assert server.pool.list_models() == []

    server.pool.add_model("m2", "https://new.example.com/v1")
    assert server.pool.clear_pool() == "Пул очищен"
    assert server.pool.list_models() == []


def test_pool_add_endpoint_positive_and_negative(proxy_db):
    endpoint = "https://ep.example.com/v1"
    _seed_key_model(proxy_db, "sk-ep", "ep-model", endpoint)

    server = ps.ProxyServer(proxy_db, port=0)
    assert "Не найдено моделей" in server.pool.add_endpoint(
        "https://unknown.example.com/v1")

    result = server.pool.add_endpoint(endpoint)
    assert "Добавлено 1 моделей" in result
    entry = server.pool._cache["ep-model"][0]
    assert entry["endpoint"] == endpoint
    assert entry["keys"] == ["sk-ep"]
    assert entry["zone"] == "endpoint"


def test_pool_reorder_toggle_and_remove_source(proxy_db):
    endpoint = "https://relay.example.com/v1"
    server = _server(proxy_db, keys=("sk-1",))

    server.pool.reorder_endpoint(endpoint, "up")
    with proxy_db._lock, proxy_db._get_connection() as conn:
        priority = conn.execute(
            "SELECT priority FROM active_pool WHERE endpoint=?", (endpoint,)
        ).fetchone()[0]
    assert priority == 1

    server.pool.toggle_source("m1", endpoint)
    assert server.pool._cache["m1"] is not None  # кэш перезагружен
    with proxy_db._lock, proxy_db._get_connection() as conn:
        enabled = conn.execute(
            "SELECT enabled FROM active_pool WHERE endpoint=?", (endpoint,)
        ).fetchone()[0]
    assert enabled == 0
    # Выключенный источник не попадает в маршрутизацию.
    assert server.pool._get_sources_for_model("m1") == []

    server.pool.toggle_source("m1", endpoint)
    server.pool.remove_source("m1", endpoint)
    assert server.pool._cache.get("m1", []) == []


def test_pool_stats_aggregation(proxy_db):
    server = _server(proxy_db, keys=("sk-1",))

    server.pool._record_stat("sk-1", 200)
    server.pool._record_stat("sk-1", 200)
    server.pool._record_stat("sk-1", 429)
    server.pool._put_cooldown("sk-2", 30)

    stats = server.pool.get_stats()

    assert stats["pool_models"] == 1
    assert stats["pool_sources"] == 1
    assert stats["cooldown_keys"] == 1
    assert (stats["total_calls"], stats["total_ok"], stats["total_errors"]) == (3, 2, 1)
    assert stats["success_rate"] == 66.7
    assert stats["key_stats"]["sk-1"] == {"calls": 3, "errors": 1, "ok": 2,
                                          "last_status": 429}


def test_pool_model_sources_detail(proxy_db):
    endpoint = "https://relay.example.com/v1"
    _seed_key_model(proxy_db, "sk-conf", "ms-model", endpoint,
                    status="confirmed", is_confirmed=1)
    _seed_key_model(proxy_db, "sk-valid", "ms-model", endpoint,
                    status="valid", is_confirmed=0)

    server = _server(proxy_db, model="ms-model", endpoint=endpoint, keys=("sk-conf",))

    detail = server.pool.model_sources("ms-model")
    assert len(detail) == 1
    assert detail[0]["endpoint"] == endpoint
    assert detail[0]["keys"] == 2
    assert detail[0]["confirmed"] == 1
    assert detail[0]["zone"] == "model"


# ===========================================================================
#                        HTTP: маршруты, CORS, служебные ручки
# ===========================================================================

def test_start_registers_routes_and_cleans_up(proxy_db, monkeypatch):
    server = _server(proxy_db)
    server.session = FakeSession()

    async def scenario():
        client, captured = await _make_client(server, monkeypatch)
        try:
            routes = _route_set(captured["app"])
            for path in ("/v1/models", "/v1/chat/completions", "/v1/completions",
                         "/v1/embeddings", "/models", "/chat/completions",
                         "/stats", "/health", "/v1/usage", "/pool/list",
                         "/pool/add/model", "/pool/add/endpoint", "/pool/remove",
                         "/pool/clear", "/pool/selection_mode", "/pool/reorder",
                         "/trace", "/pool/toggle", "/pool/remove_source",
                         "/pool/model_sources"):
                assert any(p == path for p, _m in routes), path
            assert ("/v1/models", "GET") in routes
            assert ("/models", "GET") in routes
            assert ("/v1/chat/completions", "POST") in routes
            assert ("/chat/completions", "POST") in routes
            assert ("/pool/selection_mode", "GET") in routes
            assert ("/pool/selection_mode", "POST") in routes
            assert any(method == "OPTIONS" for _p, method in routes)

            response = await client.get("/v1/models")
            assert response.status == 200
            assert response.headers["Access-Control-Allow-Origin"] == "*"
            assert response.headers["Access-Control-Allow-Methods"] == "GET, POST, OPTIONS"
            assert "x-request-id" in response.headers

            preflight = await client.options("/v1/chat/completions")
            assert preflight.status == 204
            assert preflight.headers["Access-Control-Max-Age"] == "86400"

            # wildcard OPTIONS-роут ловит путь, но не GET -> 405, не 404
            missing = await client.get("/no-such-route")
            assert missing.status == 405
        finally:
            await client.close()

    asyncio.run(scenario())

    assert captured_cleanup_ok(server)
    # bind был запрошен строго на 127.0.0.1 с нашим тестовым портом 0
    assert captured_bind(server) == ("127.0.0.1", 0)


def _route_set(app) -> set:
    """(path, method) всех маршрутов приложения (aiohttp 3.8..3.14 совместимо)."""
    routes = set()
    for route in app.router.routes():
        resource = getattr(route, "resource", None)
        path = getattr(resource, "canonical", None) or getattr(route, "path", None)
        method = getattr(route, "method", None)
        if path:
            routes.add((path, method.upper() if isinstance(method, str) else method))
    return routes


# Вспомогательные функции: _make_client отдаёт captured, но проверка bind/
# cleanup нужна после asyncio.run, поэтому состояние складываем на server.
def captured_bind(server):
    return getattr(server, "_test_bind", None)


def captured_cleanup_ok(server):
    return getattr(server, "_test_cleaned", False)


def test_models_endpoint_and_alias(proxy_db, monkeypatch):
    server = _server(proxy_db, model="m-alpha", keys=("sk-1",))
    _seed_pool_entry(proxy_db, "m-beta", "https://b.example.com/v1", ["sk-2"])
    server.pool._load_cache()

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        try:
            for path in ("/v1/models", "/models"):
                response = await client.get(path)
                payload = await response.json()
                assert response.status == 200
                assert payload["object"] == "list"
                ids = [item["id"] for item in payload["data"]]
                assert ids == ["m-alpha", "m-beta"]
                assert payload["data"][0]["owned_by"] == "proxy"
        finally:
            await client.close()

    asyncio.run(scenario())


def test_health_stats_and_usage(proxy_db, monkeypatch):
    server = _server(proxy_db, keys=("sk-1",))
    server.pool._record_stat("sk-1", 200)

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        try:
            health = await client.get("/health")
            body = await health.json()
            assert body["status"] == "ok"
            assert body["pool_models"] == 1
            assert body["total_calls"] == 1
            assert body["success_rate"] == 100

            stats = await (await client.get("/stats")).json()
            assert stats["pool_models"] == 1
            assert stats["total_ok"] == 1

            usage = await (await client.get("/v1/usage")).json()
            assert usage["data"]["total_calls"] == 1
        finally:
            await client.close()

    asyncio.run(scenario())


def test_pool_management_endpoints(proxy_db, monkeypatch):
    endpoint = "https://ep.example.com/v1"
    _seed_key_model(proxy_db, "sk-ep", "ep-model", endpoint)

    async def scenario():
        server = ps.ProxyServer(proxy_db, port=0)
        client, _captured = await _make_client(server, monkeypatch)
        try:
            # add/model
            response = await client.post(
                "/pool/add/model", json={"model": "m-x",
                                         "endpoint": "https://x.example.com/v1"})
            assert "Добавлено" in (await response.json())["result"]

            # add/endpoint (модель из key_models)
            response = await client.post("/pool/add/endpoint",
                                         json={"endpoint": endpoint})
            assert "Добавлено 1 моделей" in (await response.json())["result"]

            # list
            listing = await (await client.get("/pool/list")).json()
            assert "m-x" in listing["models"]
            assert "ep-model" in listing["models"]
            assert listing["detail"]["m-x"][0]["endpoint"] == "https://x.example.com/v1"

            # remove
            response = await client.post("/pool/remove", json={"model": "m-x"})
            assert "Удалено" in (await response.json())["result"]
            assert "m-x" not in (await (await client.get("/pool/list")).json())["models"]

            # clear
            response = await client.post("/pool/clear")
            assert (await response.json())["result"] == "Пул очищен"
            assert (await (await client.get("/pool/list")).json())["models"] == []
        finally:
            await client.close()

    asyncio.run(scenario())


def test_selection_mode_endpoints(proxy_db, monkeypatch):
    server = _server(proxy_db)

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        try:
            current = await (await client.get("/pool/selection_mode")).json()
            assert current == {"mode": "round_robin"}

            updated = await (await client.post(
                "/pool/selection_mode", json={"mode": "sticky"})).json()
            assert updated == {"mode": "sticky"}
            assert server.pool._selection_mode == "sticky"

            bad = await client.post("/pool/selection_mode", json={"mode": "random"})
            assert bad.status == 400
            assert "round_robin|sticky" in (await bad.json())["error"]
            assert server.pool._selection_mode == "sticky"  # не изменился
        finally:
            await client.close()

    asyncio.run(scenario())


def test_reorder_toggle_remove_source_endpoints(proxy_db, monkeypatch):
    endpoint = "https://relay.example.com/v1"
    server = _server(proxy_db, keys=("sk-1",))

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        try:
            bad = await client.post(
                "/pool/reorder", json={"endpoint": endpoint, "direction": "sideways"})
            assert bad.status == 400  # direction строго up|down
            bad = await client.post("/pool/reorder", json={"direction": "up"})
            assert bad.status == 400  # endpoint обязателен

            ok = await (await client.post(
                "/pool/reorder",
                json={"endpoint": endpoint, "direction": "up"})).json()
            assert ok["ok"] is True

            bad = await client.post("/pool/toggle", json={"model": "m1"})
            assert bad.status == 400
            ok = await (await client.post(
                "/pool/toggle",
                json={"model": "m1", "endpoint": endpoint})).json()
            assert ok["ok"] is True

            bad = await client.post("/pool/remove_source", json={"model": "m1"})
            assert bad.status == 400
            ok = await (await client.post(
                "/pool/remove_source",
                json={"model": "m1", "endpoint": endpoint})).json()
            assert ok["ok"] is True

            no_model = await client.get("/pool/model_sources")
            assert no_model.status == 400
        finally:
            await client.close()

    asyncio.run(scenario())


def test_model_sources_endpoint(proxy_db, monkeypatch):
    endpoint = "https://relay.example.com/v1"
    _seed_key_model(proxy_db, "sk-conf", "ms", endpoint,
                    status="confirmed", is_confirmed=1)
    server = _server(proxy_db, model="ms", endpoint=endpoint, keys=("sk-conf",))

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        try:
            body = await (await client.get(
                f"/pool/model_sources?model=ms")).json()
            assert body["sources"][0]["endpoint"] == endpoint
            assert body["sources"][0]["confirmed"] == 1
        finally:
            await client.close()

    asyncio.run(scenario())


def test_trace_endpoint(proxy_db, monkeypatch):
    server = _server(proxy_db)

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        try:
            ps.push_trace("m1", 1, "k", "e", 200)
            ps.push_trace_summary("m1", True, 1, "ok")

            body = await (await client.get("/trace?n=1")).json()
            assert len(body["events"]) == 1
            assert body["events"][0]["summary"] is True

            default = await (await client.get("/trace")).json()
            assert len(default["events"]) == 2
        finally:
            await client.close()

    asyncio.run(scenario())


# ===========================================================================
#                     HTTP: chat/completions — валидация и ротация
# ===========================================================================

@pytest.mark.parametrize(
    "payload,expected_status,expected_fragment",
    [
        ("not-json", 400, "Invalid JSON"),
        ({"messages": []}, 400, "Model not specified"),
        ({"model": "m1"}, 400, "messages required"),
    ],
)
def test_chat_request_validation(proxy_db, monkeypatch, payload, expected_status,
                                 expected_fragment):
    server = _server(proxy_db)

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        try:
            if isinstance(payload, str):
                response = await client.post(
                    "/v1/chat/completions", data=payload,
                    headers={"Content-Type": "application/json"})
            else:
                response = await client.post("/v1/chat/completions", json=payload)
            assert response.status == expected_status
            assert expected_fragment in (await response.json())["error"]["message"]
            assert server.session is None  # апстрим не дёргали
        finally:
            await client.close()

    asyncio.run(scenario())


def test_chat_unknown_model_returns_404(proxy_db, monkeypatch):
    server = _server(proxy_db, model="known-model")

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        try:
            response = await client.post(
                "/v1/chat/completions",
                json={"model": "absent", "messages": [{"role": "user",
                                                       "content": "x"}]})
            assert response.status == 404
            error = (await response.json())["error"]
            assert error["type"] == "not_found"
            assert "absent" in error["message"]
        finally:
            await client.close()

    asyncio.run(scenario())


def test_chat_model_alias_matches_substring(proxy_db, monkeypatch):
    server = _server(proxy_db, model="gpt-4o-mini-2024", keys=("sk-alias",))

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        server.session = FakeSession([FakeResponse(200, {"choices": []})])
        try:
            response = await client.post(
                "/v1/chat/completions",
                json={"model": "4o-mini", "messages": [{"role": "user",
                                                        "content": "x"}]})
            assert response.status == 200
            # Тело запроса уходит как есть (модель клиента сохраняется).
            assert server.session.calls[0]["json"]["model"] == "4o-mini"
            assert ps.get_trace(1)[0]["summary"] is True
        finally:
            await client.close()

    asyncio.run(scenario())


def test_chat_success_replaces_authorization_with_pool_key(proxy_db, monkeypatch):
    server = _server(proxy_db, keys=("sk-pool-key-123456",))
    upstream_payload = {"id": "chatcmpl-1", "choices": [
        {"message": {"role": "assistant", "content": "hi"}}]}

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        server.session = FakeSession([FakeResponse(200, upstream_payload)])
        try:
            response = await client.post(
                "/v1/chat/completions",
                json={"model": "m1", "messages": [{"role": "user", "content": "x"}],
                      "temperature": 0.2},
                headers={"Authorization": "Bearer client-side-key"})
            assert response.status == 200
            assert await response.json() == upstream_payload

            call = server.session.calls[0]
            assert call["url"] == "https://relay.example.com/v1/chat/completions"
            assert call["headers"]["Authorization"] == "Bearer sk-pool-key-123456"
            assert call["headers"]["Content-Type"] == "application/json"
            # Клиентские параметры прокси не фильтрует.
            assert call["json"]["temperature"] == 0.2

            stats = server.pool.get_stats()
            assert stats["total_ok"] == 1
            trace = ps.get_trace(2)
            assert trace[0]["status"] == 200
            assert trace[1]["summary"] is True
        finally:
            await client.close()

    asyncio.run(scenario())


def test_chat_quota_429_puts_key_on_cooldown_and_exhausts(proxy_db, monkeypatch):
    key = "sk-quota-key-123456"
    server = _server(proxy_db, keys=(key,))
    server.pool._selection_mode = "round_robin"

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        server.session = FakeSession([FakeResponse(429, {"error": "quota"})])
        try:
            response = await client.post(
                "/v1/chat/completions",
                json={"model": "m1", "messages": [{"role": "user", "content": "x"}]})
            assert response.status == 503
            error = (await response.json())["error"]
            assert error["type"] == "all_keys_exhausted"
            assert len(error["tried"]) == 1
            assert error["last_error"]["status"] == 429
            # единственный ключ уходит в адаптивный кулдаун
            assert server.pool._cooldowns[key] > time.time()
            assert server.pool._cooldown_durations[key] == 120  # 60 -> 120
        finally:
            await client.close()

    asyncio.run(scenario())


def test_chat_auth_401_excludes_key_for_an_hour(proxy_db, monkeypatch):
    key = "sk-revoked-key-123456"
    server = _server(proxy_db, keys=(key,))

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        server.session = FakeSession([FakeResponse(401, {"error": "invalid key"})])
        try:
            response = await client.post(
                "/v1/chat/completions",
                json={"model": "m1", "messages": [{"role": "user", "content": "x"}]})
            assert response.status == 503
            assert server.pool._cooldowns[key] > time.time() + 3500
        finally:
            await client.close()

    asyncio.run(scenario())


def test_chat_500_rotates_to_next_key(proxy_db, monkeypatch):
    server = _server(proxy_db, keys=("sk-first-key-123456", "sk-second-key-123456"))

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        server.session = FakeSession([
            FakeResponse(503, {"error": "upstream down"}),
            FakeResponse(200, {"choices": [{"message": {"content": "ok"}}]}),
        ])
        try:
            response = await client.post(
                "/v1/chat/completions",
                json={"model": "m1", "messages": [{"role": "user", "content": "x"}]})
            assert response.status == 200
            assert (await response.json())["choices"][0]["message"]["content"] == "ok"
            assert len(server.session.calls) == 2
            auths = [call["headers"]["Authorization"] for call in server.session.calls]
            assert auths == ["Bearer sk-first-key-123456",
                             "Bearer sk-second-key-123456"]
            # первый ключ в коротком кулдауне (15с), второй — рабочий
            assert "sk-first-key-123456" in server.pool._cooldowns
        finally:
            await client.close()

    asyncio.run(scenario())


def test_chat_streaming_passthrough(proxy_db, monkeypatch):
    server = _server(proxy_db, keys=("sk-stream-key-123456",))
    chunks = [b"data: {\"delta\":1}\n\n", b"data: [DONE]\n\n"]

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        server.session = FakeSession([FakeResponse(200, chunks=chunks)])
        try:
            response = await client.post(
                "/v1/chat/completions",
                json={"model": "m1", "stream": True,
                      "messages": [{"role": "user", "content": "x"}]})
            assert response.status == 200
            assert response.headers["Content-Type"].startswith("text/event-stream")
            assert response.headers["Cache-Control"] == "no-cache"
            assert await response.read() == b"".join(chunks)
            assert server.pool.get_stats()["total_ok"] == 1
            attempt, summary = ps.get_trace(2)
            assert attempt["detail"] == "✓ stream chat"
            assert summary["detail"].startswith("✓ chat stream")
        finally:
            await client.close()

    asyncio.run(scenario())


def test_chat_anthropic_endpoint_converts_both_ways(proxy_db, monkeypatch):
    endpoint = "https://api.anthropic.com/v1"
    server = _server(proxy_db, endpoint=endpoint, keys=("sk-ant-test-123456",),
                    platform="anthropic")
    upstream = {
        "id": "msg_42",
        "content": [{"text": "answer"}],
        "usage": {"input_tokens": 7, "output_tokens": 5},
        "stop_reason": "end_turn",
    }

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        server.session = FakeSession([FakeResponse(200, upstream)])
        try:
            response = await client.post(
                "/v1/chat/completions",
                json={"model": "m1", "messages": [
                    {"role": "system", "content": "be brief"},
                    {"role": "user", "content": "q"},
                ]})
            assert response.status == 200
            body = await response.json()
            assert body["object"] == "chat.completion"
            assert body["choices"][0]["message"]["content"] == "answer"
            assert body["usage"]["total_tokens"] == 12

            call = server.session.calls[0]
            assert call["url"] == "https://api.anthropic.com/v1/messages"
            assert call["headers"]["x-api-key"] == "sk-ant-test-123456"
            assert call["headers"]["anthropic-version"] == "2023-06-01"
            assert call["json"]["system"] == "be brief"
            assert call["json"]["max_tokens"] == 8192
            assert [m["role"] for m in call["json"]["messages"]] == ["user"]
        finally:
            await client.close()

    asyncio.run(scenario())


def test_embeddings_to_anthropic_is_rejected(proxy_db, monkeypatch):
    server = _server(proxy_db, endpoint="https://api.anthropic.com/v1",
                    keys=("sk-ant-test-123456",), platform="anthropic")

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        server.session = FakeSession([])  # апстрим не должен вызываться
        try:
            response = await client.post(
                "/v1/embeddings", json={"model": "m1", "input": "text"})
            assert response.status == 503
            assert (await response.json())["error"]["type"] == "all_keys_exhausted"
            assert server.session.calls == []
            details = [event["detail"] for event in ps.get_trace(5)]
            assert any("Anthropic не поддерживает embedding" in d for d in details)
            # Ключ получил короткий кулдаун 10с
            assert "sk-ant-test-123456" in server.pool._cooldowns
        finally:
            await client.close()

    asyncio.run(scenario())


def test_completions_requires_prompt_and_works(proxy_db, monkeypatch):
    server = _server(proxy_db, keys=("sk-compl-key-123456",))

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        try:
            bad = await client.post("/v1/completions",
                                    json={"model": "m1"})
            assert bad.status == 400
            assert "prompt required" in (await bad.json())["error"]["message"]

            server.session = FakeSession([FakeResponse(200, {"choices": []})])
            ok = await client.post(
                "/completions", json={"model": "m1", "prompt": "hello"})
            assert ok.status == 200
            assert server.session.calls[0]["url"] == (
                "https://relay.example.com/v1/completions")
        finally:
            await client.close()

    asyncio.run(scenario())


def test_embeddings_requires_input(proxy_db, monkeypatch):
    server = _server(proxy_db)

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        try:
            response = await client.post("/v1/embeddings", json={"model": "m1"})
            assert response.status == 400
            assert "input required" in (await response.json())["error"]["message"]
        finally:
            await client.close()

    asyncio.run(scenario())


def test_chat_upstream_204_is_tolerated(proxy_db, monkeypatch):
    server = _server(proxy_db, keys=("sk-204-key-123456",))

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        server.session = FakeSession([FakeResponse(204)])
        try:
            response = await client.post(
                "/v1/chat/completions",
                json={"model": "m1", "messages": [{"role": "user", "content": "x"}]})
            # 204 не 200 -> прокси считает попытку неудачной и исчерпывает ключи
            assert response.status == 503
        finally:
            await client.close()

    asyncio.run(scenario())


def test_chat_upstream_exception_rotates(proxy_db, monkeypatch):
    server = _server(proxy_db, keys=("sk-net-key-123456",))

    class ExplodingSession(FakeSession):
        def post(self, url, json=None, headers=None):
            self.calls.append({"url": url})
            raise OSError("connection reset by peer")

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        server.session = ExplodingSession()
        try:
            response = await client.post(
                "/v1/chat/completions",
                json={"model": "m1", "messages": [{"role": "user", "content": "x"}]})
            assert response.status == 503
            error = (await response.json())["error"]
            assert "connection reset" in str(error["last_error"]["body"])
            assert "sk-net-key-123456" in server.pool._cooldowns
        finally:
            await client.close()

    asyncio.run(scenario())


def test_chat_upstream_timeout_cools_down(proxy_db, monkeypatch):
    key = "sk-timeout-key-123456"
    server = _server(proxy_db, keys=(key,))

    class TimeoutSession(FakeSession):
        def post(self, url, json=None, headers=None):
            self.calls.append({"url": url})
            raise asyncio.TimeoutError()

    async def scenario():
        client, _captured = await _make_client(server, monkeypatch)
        server.session = TimeoutSession()
        try:
            response = await client.post(
                "/v1/chat/completions",
                json={"model": "m1", "messages": [{"role": "user", "content": "x"}]})
            assert response.status == 503
            # Ветка таймаута не заполняет last_error — фиксируем как есть.
            assert (await response.json())["error"]["last_error"] == {}
            assert server.pool._cooldowns[key] > time.time() + 25
            assert any(event["status"] is None and "timeout" in event["detail"]
                       for event in ps.get_trace(5))
        finally:
            await client.close()

    asyncio.run(scenario())


# ===========================================================================
#                     Сессия апстрима: настоящая ClientSession
# ===========================================================================

def test_get_session_lifecycle_without_network(proxy_db):
    server = ps.ProxyServer(proxy_db, port=0)

    async def scenario():
        first = await server._get_session()
        second = await server._get_session()
        assert first is second
        assert first.closed is False
        await first.close()

        third = await server._get_session()
        assert third is not first
        assert third.closed is False
        await third.close()

    asyncio.run(scenario())
