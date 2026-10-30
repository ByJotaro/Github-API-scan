"""Тесты AsyncDatabase (async_database.py, aiosqlite): только tmp_path, без сети.

Каждый тест запускает свой event loop через asyncio.run, поэтому плагин
pytest-asyncio не нужен. Все соединения закрываются в finally.
"""

import asyncio
import importlib.util
import sqlite3
from contextlib import asynccontextmanager

import pytest

from async_database import AsyncDatabase, try_enable_uvloop
from database import KeyStatus, LeakedKey


def make_key(api_key="sk-async-1", **overrides):
    payload = {
        "platform": "openai",
        "api_key": api_key,
        "base_url": "https://api.openai.com/v1",
    }
    payload.update(overrides)
    return LeakedKey(**payload)


def sql_rows(db_path, sql, params=()):
    conn = sqlite3.connect(str(db_path))
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def sql_value(db_path, sql, params=()):
    rows = sql_rows(db_path, sql, params)
    return rows[0][0] if rows else None


@asynccontextmanager
async def opened(path):
    db = AsyncDatabase(str(path))
    await db.init()
    try:
        yield db
    finally:
        await db.close()


# ============================================================================
# Инициализация схемы и идемпотентность
# ============================================================================

def test_init_creates_schema_and_is_idempotent(tmp_path):
    path = tmp_path / "async.db"

    async def scenario():
        async with opened(path) as db:
            await db.queue_insert(make_key(api_key="sk-a"))
            await db._flush_queue()
            assert await db.key_exists("sk-a") is True

        # повторный init на том же файле не падает и видит старые данные
        async with opened(path) as db:
            assert await db.key_exists("sk-a") is True
            assert (await db.get_stats())["total"] == 1

    asyncio.run(scenario())

    tables = {
        row[0]
        for row in sql_rows(path, "SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert {"leaked_keys", "scanned_blobs"} <= tables
    indexes = {
        row[0]
        for row in sql_rows(path, "SELECT name FROM sqlite_master WHERE type='index'")
    }
    assert {"idx_status", "idx_platform"} <= indexes


def test_init_creates_columns_used_by_update_key_status(tmp_path):
    path = tmp_path / "async-columns.db"

    async def scenario():
        async with opened(path) as db:
            await db.queue_insert(make_key(api_key="sk-cols"))
            await db._flush_queue()
            await db.update_key_status("sk-cols", KeyStatus.VALID)

    asyncio.run(scenario())
    columns = {
        row[1] for row in sql_rows(path, "PRAGMA table_info(leaked_keys)")
    }
    assert {
        "platform", "api_key", "base_url", "status", "balance", "source_url",
        "model_tier", "rpm", "is_high_value", "found_time", "verified_time",
    } <= columns


def test_stats_on_empty_database(tmp_path):
    path = tmp_path / "empty.db"

    async def scenario():
        async with opened(path) as db:
            assert await db.get_stats() == {
                "total": 0,
                "valid": 0,
                "statuses": {},
                "platforms": {},
            }

    asyncio.run(scenario())


# ============================================================================
# Очередь записи и flush
# ============================================================================

def test_queue_insert_is_deferred_until_flush(tmp_path):
    path = tmp_path / "queue.db"

    async def scenario():
        async with opened(path) as db:
            db._batch_size = 5
            await db.queue_insert(make_key(api_key="sk-q1"))
            await db.queue_insert(make_key(api_key="sk-q2"))
            assert len(db._write_queue) == 2
            assert (await db.get_stats())["total"] == 0
            assert await db.key_exists("sk-q1") is False

            await db._flush_queue()
            assert db._write_queue == []
            assert (await db.get_stats())["total"] == 2
            assert await db.key_exists("sk-q1") is True
            assert await db.key_exists("sk-q2") is True

            # пустая очередь — no-op без исключений
            await db._flush_queue()

    asyncio.run(scenario())


def test_batch_threshold_schedules_automatic_flush(tmp_path):
    path = tmp_path / "batch.db"

    async def scenario():
        async with opened(path) as db:
            db._batch_size = 2
            await db.queue_insert(make_key(api_key="sk-b1"))
            await db.queue_insert(make_key(api_key="sk-b2"))
            for _ in range(50):
                if (await db.get_stats())["total"] == 2:
                    break
                await asyncio.sleep(0.01)
            assert (await db.get_stats())["total"] == 2
            assert db._write_queue == []

    asyncio.run(scenario())


def test_periodic_flush_writes_queue_without_explicit_call(tmp_path):
    path = tmp_path / "periodic.db"

    async def scenario():
        async with opened(path) as db:
            db._flush_interval = 0.01  # ускоряем фоновый цикл для теста
            await db.queue_insert(make_key(api_key="sk-periodic"))
            for _ in range(50):
                if (await db.get_stats())["total"] == 1:
                    break
                await asyncio.sleep(0.01)
            assert (await db.get_stats())["total"] == 1
            assert db._write_queue == []

    asyncio.run(scenario())
    assert sql_value(path, "SELECT COUNT(*) FROM leaked_keys") == 1


def test_duplicate_queue_insert_is_ignored(tmp_path):
    path = tmp_path / "dup.db"

    async def scenario():
        async with opened(path) as db:
            key = make_key(api_key="sk-dup")
            await db.queue_insert(key)
            await db.queue_insert(key)
            await db._flush_queue()
            await db.queue_insert(key)
            await db._flush_queue()
            assert (await db.get_stats())["total"] == 1

    asyncio.run(scenario())


def test_flush_queue_skips_bad_row_and_writes_valid_ones(tmp_path):
    path = tmp_path / "bad-row.db"

    async def scenario():
        async with opened(path) as db:
            # platform=None нарушает NOT NULL — строка должна быть пропущена
            await db.queue_insert(
                LeakedKey(platform=None, api_key="sk-broken", base_url="u")
            )
            await db.queue_insert(make_key(api_key="sk-good"))
            await db._flush_queue()
            assert await db.key_exists("sk-good") is True
            assert await db.key_exists("sk-broken") is False
            assert (await db.get_stats())["total"] == 1

    asyncio.run(scenario())
    assert sql_value(path, "SELECT COUNT(*) FROM leaked_keys") == 1


def test_close_flushes_pending_queue_and_cancels_background_task(tmp_path):
    path = tmp_path / "close.db"

    async def scenario():
        db = AsyncDatabase(str(path))
        await db.init()
        await db.queue_insert(make_key(api_key="sk-close"))
        assert sql_value(path, "SELECT COUNT(*) FROM leaked_keys") == 0

        await db.close()
        assert db._flush_task.done() is True
        assert sql_value(path, "SELECT COUNT(*) FROM leaked_keys") == 1

        # после close каждый вызов открывает новое соединение — чтение работает
        assert await db.key_exists("sk-close") is True
        # повторный close безопасен
        await db.close()

    asyncio.run(scenario())


def test_close_without_init_is_safe(tmp_path):
    path = tmp_path / "no-init.db"

    async def scenario():
        db = AsyncDatabase(str(path))
        await db.close()
        assert db._flush_task is None

    asyncio.run(scenario())


# ============================================================================
# Чтение/обновление ключей и статистика
# ============================================================================

def test_key_exists_roundtrip(tmp_path):
    path = tmp_path / "exists.db"

    async def scenario():
        async with opened(path) as db:
            assert await db.key_exists("sk-none") is False
            await db.queue_insert(make_key(api_key="sk-here"))
            await db._flush_queue()
            assert await db.key_exists("sk-here") is True
            assert await db.key_exists("sk-other") is False
            assert await db.key_exists("") is False

    asyncio.run(scenario())


def test_update_key_status_and_stats(tmp_path):
    path = tmp_path / "status.db"

    async def scenario():
        async with opened(path) as db:
            await db.queue_insert(make_key(api_key="sk-s1"))
            await db.queue_insert(make_key(api_key="sk-s2", platform="azure"))
            await db._flush_queue()

            await db.update_key_status(
                "sk-s1",
                KeyStatus.VALID,
                balance="$1",
                model_tier="gpt-4",
                rpm=12,
                is_high_value=True,
            )
            # несуществующий ключ не должен бросать исключение
            await db.update_key_status("sk-missing", KeyStatus.INVALID)

            stats = await db.get_stats()
            assert stats["total"] == 2
            assert stats["valid"] == 1
            assert stats["statuses"] == {"valid": 1, "pending": 1}
            assert stats["platforms"] == {"openai": 1, "azure": 1}

    asyncio.run(scenario())

    row = sql_rows(
        path,
        "SELECT status, balance, model_tier, rpm, is_high_value, verified_time "
        "FROM leaked_keys WHERE api_key='sk-s1'",
    )[0]
    assert row[:5] == ("valid", "$1", "gpt-4", 12, 1)
    assert row[5] is not None


def test_quota_exceeded_counts_as_valid_in_stats(tmp_path):
    path = tmp_path / "quota.db"

    async def scenario():
        async with opened(path) as db:
            await db.queue_insert(make_key(api_key="sk-q"))
            await db._flush_queue()
            await db.update_key_status("sk-q", KeyStatus.QUOTA_EXCEEDED)
            stats = await db.get_stats()
            assert stats["valid"] == 1
            assert stats["statuses"] == {"quota_exceeded": 1}

    asyncio.run(scenario())


# ============================================================================
# Дедупликация blob SHA
# ============================================================================

def test_blob_scanned_roundtrip(tmp_path):
    path = tmp_path / "blob.db"

    async def scenario():
        async with opened(path) as db:
            assert await db.is_blob_scanned("sha-1") is False
            assert await db.mark_blob_scanned("sha-1") is True
            assert await db.is_blob_scanned("sha-1") is True
            # повторная отметка идемпотентна и не сообщает об ошибке
            assert await db.mark_blob_scanned("sha-1") is True
            assert await db.is_blob_scanned("sha-2") is False

    asyncio.run(scenario())
    assert sql_value(path, "SELECT COUNT(*) FROM scanned_blobs") == 1


# ============================================================================
# Конкурентность корутин
# ============================================================================

def test_concurrent_coroutines_queue_insert_and_blob_marks(tmp_path):
    path = tmp_path / "concurrent.db"
    total = 20

    async def scenario():
        async with opened(path) as db:
            async def writer(index):
                await db.queue_insert(make_key(api_key=f"sk-{index}"))
                assert await db.mark_blob_scanned(f"sha-{index}") is True

            await asyncio.gather(*[writer(i) for i in range(total)])
            await db._flush_queue()

            stats = await db.get_stats()
            assert stats["total"] == total
            for index in range(total):
                assert await db.key_exists(f"sk-{index}") is True

            blob_count = sql_value(path, "SELECT COUNT(*) FROM scanned_blobs")
            assert blob_count == total

    asyncio.run(scenario())


def test_concurrent_status_updates_and_reads(tmp_path):
    path = tmp_path / "concurrent-status.db"
    total = 8

    async def scenario():
        async with opened(path) as db:
            for index in range(total):
                await db.queue_insert(make_key(api_key=f"sk-c{index}"))
            await db._flush_queue()

            await asyncio.gather(*[
                db.update_key_status(f"sk-c{index}", KeyStatus.INVALID)
                for index in range(total)
            ])
            results = await asyncio.gather(*[
                db.key_exists(f"sk-c{index}") for index in range(total)
            ])
            assert results == [True] * total

            stats = await db.get_stats()
            assert stats["total"] == total
            assert stats["statuses"] == {"invalid": total}
            assert stats["valid"] == 0

    asyncio.run(scenario())


# ============================================================================
# try_enable_uvloop
# ============================================================================

def test_try_enable_uvloop_matches_availability():
    # Не зависит от сети; просто проверяем, что детект не падает
    # и соответствует наличию модуля.
    result = try_enable_uvloop()
    assert isinstance(result, bool)
    assert result is (importlib.util.find_spec("uvloop") is not None)
