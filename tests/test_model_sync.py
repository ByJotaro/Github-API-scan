"""Тесты синхронизации списков моделей (model_sync.py + key_models).

Провайдеры добавляют и убирают модели, а key_models раньше заполнялась только
при валидации ключа. Здесь проверяется сверка: новые модели появляются,
убранные уходят после двух пропусков, is_confirmed переживает синхронизацию,
а active_pool пересобирается из живого состояния БД.
"""
import asyncio
import json
import sqlite3

import pytest

import model_sync
from database import Database, KeyStatus, LeakedKey
from proxy_server import ActivePool


# ---------------------------------------------------------------------------
# Хелперы
# ---------------------------------------------------------------------------

def make_key(api_key="sk-test-1", **overrides):
    payload = {
        "platform": "openai",
        "api_key": api_key,
        "base_url": "https://api.openai.com/v1",
    }
    payload.update(overrides)
    return LeakedKey(**payload)


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "models.db"))
    with database._lock, database._get_connection() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS pool_models "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "model_name TEXT NOT NULL UNIQUE, "
            "added_time DATETIME DEFAULT CURRENT_TIMESTAMP)")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS pool_endpoints "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "endpoint TEXT NOT NULL UNIQUE, "
            "added_time DATETIME DEFAULT CURRENT_TIMESTAMP)")
        conn.commit()
    try:
        yield database
    finally:
        database.close()


def rows(db, sql, params=()):
    with db._lock, db._get_connection() as conn:
        return [tuple(r) for r in conn.execute(sql, params).fetchall()]


def add_key(db, api_key="sk-a", status="valid", **overrides):
    db.insert_keys_batch([make_key(api_key=api_key, **overrides)])
    db.update_key_status(api_key, KeyStatus(status))
    return api_key


# ---------------------------------------------------------------------------
# sync_key_models
# ---------------------------------------------------------------------------

def test_sync_key_models_adds_new_and_preserves_confirmed(db):
    add_key(db, "sk-a")

    assert db.sync_key_models("sk-a", ["m1", "m2"])["added"] == 2
    assert sorted(db.get_models_by_key("sk-a")) == ["m1", "m2"]

    db.sync_key_models("sk-a", ["m1", "m2"], confirmed=["m2"])
    confirmed = dict(rows(
        db, "SELECT model_name, is_confirmed FROM key_models "
            "ORDER BY model_name"))
    assert confirmed == {"m1": 0, "m2": 1}

    # Повторная синхронизация (список провайдера тот же + новая модель)
    stats = db.sync_key_models("sk-a", ["m1", "m2", "m3"])
    assert stats["added"] == 1
    assert stats["kept"] == 2
    assert stats["removed"] == 0
    # is_confirmed не сбрасывается повторной синхронизацией
    confirmed = dict(rows(
        db, "SELECT model_name, is_confirmed FROM key_models "
            "ORDER BY model_name"))
    assert confirmed == {"m1": 0, "m2": 1, "m3": 0}


def test_sync_key_models_removes_only_after_three_misses(db):
    add_key(db, "sk-a")
    db.sync_key_models("sk-a", ["keep", "gone"], confirmed=["gone"])

    # Первый пропуск: модель снимается с подтверждения, но остаётся
    stats = db.sync_key_models("sk-a", ["keep"])
    assert stats["removed"] == 0
    assert stats["demoted"] == 1
    assert dict(rows(db, "SELECT model_name, miss_count FROM key_models")) == {
        "keep": 0, "gone": 1}
    assert dict(rows(db, "SELECT model_name, is_confirmed FROM key_models"))[
        "gone"] == 0

    # Второй пропуск: модель ещё жива (relay мог отдать урезанный список)
    stats = db.sync_key_models("sk-a", ["keep"])
    assert stats["removed"] == 0
    assert dict(rows(db, "SELECT model_name, miss_count FROM key_models"))[
        "gone"] == 2

    # Третий пропуск подряд: провайдер реально убрал модель
    stats = db.sync_key_models("sk-a", ["keep"])
    assert stats["removed"] == 1
    assert [r[0] for r in rows(db, "SELECT model_name FROM key_models")] == ["keep"]

    # Вернувшаяся модель снова добавляется (после удаления)
    db.sync_key_models("sk-a", ["keep", "gone"])
    assert sorted(db.get_models_by_key("sk-a")) == ["gone", "keep"]


def test_sync_key_models_empty_authoritative_list_keeps_rows(db):
    add_key(db, "sk-a")
    db.sync_key_models("sk-a", ["m1", "m2"])
    stats = db.sync_key_models("sk-a", [])
    assert stats == {"added": 0, "removed": 0, "demoted": 0, "kept": 0}
    assert sorted(db.get_models_by_key("sk-a")) == ["m1", "m2"]


def test_sync_key_models_non_authoritative_never_deletes(db):
    add_key(db, "sk-a")
    db.sync_key_models("sk-a", ["m1"])
    # Чат подтвердил модель, которой нет в /models — только upsert
    db.sync_key_models("sk-a", ["m2"], confirmed=["m2"], authoritative=False)
    assert sorted(db.get_models_by_key("sk-a")) == ["m1", "m2"]
    assert dict(rows(db, "SELECT model_name, miss_count FROM key_models"))[
        "m1"] == 0


def test_sync_key_models_unknown_key_is_noop(db):
    assert db.sync_key_models("nope", ["m1"]) == {
        "added": 0, "removed": 0, "demoted": 0, "kept": 0}


# ---------------------------------------------------------------------------
# Разбор /models и URL-варианты
# ---------------------------------------------------------------------------

def test_parse_models_openai_gemini_and_plain_list():
    assert model_sync.parse_models(
        {"data": [{"id": "gpt-5"}, {"id": " gpt-5 "}, {"id": "gpt-5.5"}]}
    ) == ["gpt-5", "gpt-5.5"]
    assert model_sync.parse_models(
        {"models": [{"name": "models/gemini-2.5-flash"}]}
    ) == ["gemini-2.5-flash"]
    assert model_sync.parse_models(["a", {"id": "b"}]) == ["a", "b"]
    assert model_sync.parse_models({"data": {"models": ["x"]}}) == ["x"]
    assert model_sync.parse_models({"data": []}) == []
    assert model_sync.parse_models(None) == []


def test_model_urls_and_auth_headers():
    assert model_sync.model_urls("https://relay.test") == [
        "https://relay.test/v1/models", "https://relay.test/models"]
    assert model_sync.model_urls("https://relay.test/v1") == [
        "https://relay.test/v1/models"]
    assert model_sync.model_urls(
        "https://relay.test/v1/chat/completions") == [
        "https://relay.test/v1/models"]
    assert model_sync.model_urls("") == []
    assert "x-goog-api-key" in model_sync.auth_headers(
        "k", "https://generativelanguage.googleapis.com/v1beta", "gemini")
    assert model_sync.auth_headers(
        "k", "https://api.anthropic.com/v1")["x-api-key"] == "k"
    assert model_sync.auth_headers(
        "k", "https://relay.test/v1")["Authorization"] == "Bearer k"


# ---------------------------------------------------------------------------
# Полный цикл: HTTP /models -> БД -> состояние
# ---------------------------------------------------------------------------

def test_refresh_models_fetches_models_and_records_state(tmp_path):
    from aiohttp import web

    async def scenario():
        app = web.Application()

        async def handle_models(request):
            if request.headers.get("Authorization") == "Bearer bad-key":
                return web.json_response({"error": "unauthorized"}, status=401)
            return web.json_response(
                {"data": [{"id": "brand-new"}, {"id": "old-model"}]})

        app.router.add_get("/v1/models", handle_models)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        base_url = f"http://127.0.0.1:{port}"

        database = Database(str(tmp_path / "refresh.db"))
        try:
            database.insert_keys_batch([
                make_key(api_key="bad-key", base_url=base_url),
                make_key(api_key="good-key", base_url=base_url),
            ])
            database.update_key_status("bad-key", KeyStatus.CONFIRMED)
            database.update_key_status("good-key", KeyStatus.VALID)
            # Старый снапшот ключа: модель, которой провайдер уже не отдаёт
            database.sync_key_models("good-key", ["old-model", "retired"])

            stats = await model_sync.refresh_models(database, force=True)
            assert stats["ok"] == 1, stats
            assert stats["failed"] == 0, stats

            # 401 у первого ключа не мешает: второй ключ отдал список
            models = set(database.get_models_by_key("good-key"))
            assert {"brand-new", "old-model", "retired"} <= models
            state = rows(database,
                         "SELECT status, models_count FROM model_sync_state "
                         "WHERE base_url=?", (base_url,))
            assert state == [("ok", 2)]
        finally:
            database.close()
            await runner.cleanup()

    asyncio.run(scenario())


def test_refresh_models_marks_error_without_deleting(tmp_path):
    from aiohttp import web

    async def scenario():
        app = web.Application()

        async def handle_models(request):
            return web.json_response({"error": "boom"}, status=500)

        app.router.add_get("/v1/models", handle_models)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        base_url = f"http://127.0.0.1:{port}"

        database = Database(str(tmp_path / "err.db"))
        try:
            add_key(database, "k1", status="valid", base_url=base_url)
            database.sync_key_models("k1", ["known-model"])
            stats = await model_sync.refresh_models(database, force=True)
            assert stats["failed"] == 1
            assert database.get_models_by_key("k1") == ["known-model"]
            state = rows(database,
                         "SELECT status FROM model_sync_state WHERE base_url=?",
                         (base_url,))
            assert state == [("error",)]
        finally:
            database.close()
            await runner.cleanup()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# active_pool: живое состояние вместо снапшота
# ---------------------------------------------------------------------------

def test_resync_pool_updates_keys_prunes_and_readds(db):
    add_key(db, "k1", status="confirmed", base_url="https://relay.test/v1")
    with db._lock, db._get_connection() as conn:
        conn.execute("INSERT INTO pool_models (model_name) VALUES ('m1')")
        conn.commit()
    db.sync_key_models("k1", ["m1"], confirmed=["m1"])

    pool = ActivePool(db)
    assert pool.resync_pool() == {"added": 1, "updated": 0, "removed": 0}
    keys = json.loads(rows(db, "SELECT api_keys FROM active_pool")[0][0])
    assert keys == ["k1"]

    # Новый confirmed-ключ той же модели -> ключи пары обновляются
    add_key(db, "k2", status="confirmed", base_url="https://relay.test/v1")
    db.sync_key_models("k2", ["m1"], confirmed=["m1"])
    assert pool.resync_pool() == {"added": 0, "updated": 1, "removed": 0}
    keys = sorted(json.loads(rows(db, "SELECT api_keys FROM active_pool")[0][0]))
    assert keys == ["k1", "k2"]

    # Пользователь выключил пару — настройка переживает сверку
    with db._lock, db._get_connection() as conn:
        conn.execute("UPDATE active_pool SET enabled=0")
        conn.commit()
    pool.resync_pool()
    assert rows(db, "SELECT enabled FROM active_pool") == [(0,)]

    # Провайдер убрал модель: три прогона /models без неё -> из пула уходит
    for key in ("k1", "k2"):
        for _ in range(3):
            db.sync_key_models(key, ["other-model"])
    stats = pool.resync_pool()
    assert stats["removed"] == 1
    assert rows(db, "SELECT model_name FROM active_pool") == []
    assert pool.get_all_available_models() == []

    # Модель вернулась -> пара восстанавливается (pool_models — желаемое состояние)
    db.sync_key_models("k1", ["m1"], confirmed=["m1"])
    assert pool.resync_pool()["added"] == 1
    assert pool.get_all_available_models() == ["m1"]
    # enabled=0 сохранился через удаление/восстановление нельзя: строка была
    # удалена вместе с парой, по умолчанию снова включена — это ожидаемо.


def test_resync_pool_endpoint_zone_picks_keys(db):
    add_key(db, "k1", status="confirmed", base_url="https://relay.test/v1")
    db.sync_key_models("k1", ["m-std"], confirmed=["m-std"])
    with db._lock, db._get_connection() as conn:
        conn.execute("INSERT INTO pool_endpoints (endpoint) VALUES "
                     "('https://relay.test/v1')")
        conn.commit()

    pool = ActivePool(db)
    stats = pool.resync_pool()
    assert stats["added"] == 1
    zone, keys = rows(db, "SELECT zone, api_keys FROM active_pool")[0]
    assert zone == "endpoint"
    assert json.loads(keys) == ["k1"]


# ---------------------------------------------------------------------------
# HTTP pool-API и сверка пула: желаемое состояние не откатывается
# ---------------------------------------------------------------------------

def _seed_endpoint_model(db, api_key="k1", model="m1",
                         endpoint="https://relay.test/v1"):
    add_key(db, api_key, status="confirmed", base_url=endpoint)
    db.sync_key_models(api_key, [model], confirmed=[model])


def test_pool_api_add_model_survives_resync(db):
    _seed_endpoint_model(db)
    pool = ActivePool(db)
    assert "Добавлено" in pool.add_model("m1")
    assert pool.get_all_available_models() == ["m1"]

    # resync (каждые 5 минут в прокси) не должен откатить добавление
    assert pool.resync_pool() == {"added": 0, "updated": 0, "removed": 0}
    assert pool.get_all_available_models() == ["m1"]


def test_pool_api_remove_model_survives_resync(db):
    _seed_endpoint_model(db)
    pool = ActivePool(db)
    pool.add_model("m1")
    pool.remove_model("m1")
    pool.resync_pool()
    assert pool.get_all_available_models() == []


def test_pool_api_add_endpoint_survives_resync(db):
    _seed_endpoint_model(db)
    pool = ActivePool(db)
    assert "Добавлено 1 моделей" in pool.add_endpoint("https://relay.test/v1")
    pool.resync_pool()
    assert pool.get_all_available_models() == ["m1"]

    pool.clear_pool()
    pool.resync_pool()
    assert pool.get_all_available_models() == []
    assert rows(db, "SELECT model_name FROM pool_models") == []


def test_pool_remove_source_exclusion_survives_resync(db):
    _seed_endpoint_model(db)
    pool = ActivePool(db)
    pool.add_model("m1")
    pool.remove_source("m1", "https://relay.test/v1")
    pool.resync_pool()
    assert pool.get_all_available_models() == []

    # Повторное добавление модели снимает исключение
    pool.add_model("m1")
    pool.resync_pool()
    assert pool.get_all_available_models() == ["m1"]


def test_pool_add_model_creates_desired_tables_on_bare_db(tmp_path):
    """Прокси без TUI: pool_models/pool_endpoints могут отсутствовать."""
    database = Database(str(tmp_path / "bare.db"))
    try:
        add_key(database, "k1", status="confirmed",
                base_url="https://relay.test/v1")
        database.sync_key_models("k1", ["m1"], confirmed=["m1"])
        pool = ActivePool(database)
        assert "Добавлено" in pool.add_model("m1")
        assert pool.get_all_available_models() == ["m1"]
        pool.resync_pool()
        assert pool.get_all_available_models() == ["m1"]
    finally:
        database.close()


def test_resync_pool_on_bare_db_creates_tables_and_returns_zeros(tmp_path):
    """Прокси без TUI: pool_models/pool_endpoints ещё не созданы.

    resync_pool читал их до _ensure_desired_tables и молча возвращал нули
    через широкий except («no such table»).
    """
    database = Database(str(tmp_path / "bare_resync.db"))
    try:
        pool = ActivePool(database)
        assert pool.resync_pool() == {"added": 0, "updated": 0, "removed": 0}
        names = {r[0] for r in rows(
            database, "SELECT name FROM sqlite_master WHERE type='table'")}
        assert {"pool_models", "pool_endpoints", "pool_exclusions"} <= names
    finally:
        database.close()


def test_resync_pool_async_does_not_block_event_loop(db):
    """resync_pool ~1.5 с на живой БД: в event loop он морозит /v1/*."""
    import time as _time
    from proxy_server import ProxyServer

    server = ProxyServer(db, port=0)
    ticks = {"n": 0}

    def slow_resync():
        _time.sleep(0.3)
        return {"added": 1, "updated": 0, "removed": 0}

    server.pool.resync_pool = slow_resync

    async def scenario():
        async def ticker():
            for _ in range(30):
                await asyncio.sleep(0.02)
                ticks["n"] += 1

        result, _ = await asyncio.gather(server._resync_pool_async(), ticker())
        return result

    assert asyncio.run(scenario()) == {"added": 1, "updated": 0, "removed": 0}
    # Пока resync спит в потоке, цикл успел прокрутить тикер
    assert ticks["n"] >= 10
