"""CRUD- и инвариантные тесты синхронного слоя Database (database.py).

Все базы создаются в tmp_path; сеть не используется. Реальные файлы проекта
(leaked_keys.db) не затрагиваются.
"""

import sqlite3
import threading
from datetime import datetime, timedelta

import pytest

from database import Database, KeyStatus, LeakedKey, normalize_base_url


CORE_TABLES = {
    "leaked_keys",
    "scanned_blobs",
    "scanned_keywords",
    "source_state",
    "scanned_source_items",
    "source_progress",
    "key_models",
}


def make_key(api_key="sk-test-1", **overrides):
    payload = {
        "platform": "openai",
        "api_key": api_key,
        "base_url": "https://api.openai.com/v1",
    }
    payload.update(overrides)
    return LeakedKey(**payload)


def query(db, sql, params=()):
    """Прочитать данные отдельным соединением (Database держит своё)."""
    conn = sqlite3.connect(db.db_path)
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


def scalar(db, sql, params=()):
    rows = query(db, sql, params)
    return rows[0][0] if rows else None


def execute(db, sql, params=()):
    conn = sqlite3.connect(db.db_path)
    try:
        conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


@pytest.fixture()
def db(tmp_path):
    database = Database(str(tmp_path / "keys.db"))
    try:
        yield database
    finally:
        database.close()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("https://api.perplexity.ai/chat/completions", "https://api.perplexity.ai/v1"),
        ("https://api.deepseek.com/v1/chat/completions", "https://api.deepseek.com/v1"),
        ("https://openrouter.ai/api/v1/chat/completions", "https://openrouter.ai/api/v1"),
        ("https://api.anthropic.com/v1/messages", "https://api.anthropic.com/v1"),
        ("https://unknown.example/v2/models", "https://unknown.example/v2"),
        ("https://unknown.example/a/b", "https://unknown.example/a/b"),
        ("https://unknown.example/", "https://unknown.example"),
        ("", ""),
        ("not-a-url", "not-a-url"),
    ],
)
def test_normalize_base_url_contract(raw, expected):
    """normalize_base_url — база группировки провайдеров и дедупликации URL."""
    assert normalize_base_url(raw) == expected


# ============================================================================
# Инициализация схемы, идемпотентность, повторное открытие
# ============================================================================

def test_init_creates_core_tables_and_indexes(db):
    tables = {
        row[0]
        for row in query(db, "SELECT name FROM sqlite_master WHERE type='table'")
    }
    assert CORE_TABLES <= tables

    indexes = {
        row[0]
        for row in query(db, "SELECT name FROM sqlite_master WHERE type='index'")
    }
    assert {
        "idx_platform",
        "idx_status",
        "idx_base_url",
        "idx_verified_time",
        "idx_source_progress_status",
        "idx_km_model",
        "idx_failed_keys",
    } <= indexes


def test_double_init_and_reopen_preserve_data(tmp_path):
    path = str(tmp_path / "idempotent.db")

    first = Database(path)
    try:
        assert first.insert_key(make_key(api_key="sk-dup")) is True
        assert first.get_stats()["total"] == 1
    finally:
        first.close()

    # Повторный Database(path) не падает и не теряет данные.
    second = Database(path)
    try:
        assert second.get_stats()["total"] == 1
        assert second.key_exists("sk-dup") is True
        assert second.insert_key(make_key(api_key="sk-dup")) is False
        assert second.insert_key(make_key(api_key="sk-dup2")) is True
    finally:
        second.close()

    third = Database(path)
    try:
        assert third.get_stats()["total"] == 2
        assert third.key_exists("sk-dup2") is True
    finally:
        third.close()


def test_two_live_instances_share_same_schema(tmp_path):
    path = str(tmp_path / "shared.db")
    left = Database(path)
    right = Database(path)
    try:
        assert left.insert_key(make_key(api_key="sk-shared")) is True
        # right не имеет ключа в своём кэше -> идёт в БД и видит строку.
        assert right.key_exists("sk-shared") is True
        assert right.get_stats()["total"] == 1
    finally:
        left.close()
        right.close()


def test_legacy_schema_is_migrated_and_urls_normalized(tmp_path):
    path = str(tmp_path / "legacy.db")
    conn = sqlite3.connect(path)
    try:
        conn.execute(
            """
            CREATE TABLE leaked_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT NOT NULL,
                api_key TEXT NOT NULL UNIQUE,
                base_url TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                balance TEXT DEFAULT '',
                source_url TEXT DEFAULT '',
                found_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                verified_time DATETIME
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE key_models (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id INTEGER NOT NULL,
                model_name TEXT NOT NULL,
                platform TEXT NOT NULL DEFAULT '',
                base_url TEXT NOT NULL DEFAULT '',
                first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(key_id, model_name)
            )
            """
        )
        conn.execute(
            "INSERT INTO leaked_keys (platform, api_key, base_url) "
            "VALUES ('old', 'legacy-key', "
            "'https://api.groq.com/openai/v1/chat/completions')"
        )
        conn.execute(
            "INSERT INTO key_models (key_id, model_name, platform, base_url) "
            "VALUES (1, 'llama-3', 'old', "
            "'https://api.groq.com/openai/v1/chat/completions')"
        )
        conn.commit()
    finally:
        conn.close()

    legacy = Database(path)
    try:
        columns = {
            row[1] for row in query(legacy, "PRAGMA table_info(leaked_keys)")
        }
        assert {"tpd", "concurrency_limit", "confirm_attempts", "rate_headers"} <= columns

        keys = legacy.get_all_keys()
        assert [k.api_key for k in keys] == ["legacy-key"]
        # Старый endpoint приведён к API-корню при открытии базы.
        assert keys[0].base_url == "https://api.groq.com/openai/v1"
        assert query(legacy, "SELECT model_name, base_url FROM key_models") == [
            ("llama-3", "https://api.groq.com/openai/v1"),
        ]
        assert legacy.get_key_status("legacy-key") == "pending"
        assert legacy.update_key_meta("legacy-key", tpd=99) is True
        assert [k.api_key for k in legacy.get_failed_keys()] == ["legacy-key"]
    finally:
        legacy.close()


def test_close_is_idempotent_and_operations_reconnect(db):
    db.insert_key(make_key(api_key="sk-close"))
    db.close()
    assert db.close() is None  # повторное закрытие безопасно
    # Соединение пересоздаётся лениво — операции продолжают работать.
    assert db.get_stats()["total"] == 1
    assert db.insert_key(make_key(api_key="sk-after-close")) is True
    assert db.key_exists("sk-after-close") is True


# ============================================================================
# Вставка ключей, дедупликация, кэш существования
# ============================================================================

def test_insert_key_deduplicates_by_api_key(db):
    key = make_key(api_key="sk-one")
    assert db.insert_key(key) is True
    assert db.insert_key(key) is False
    # Тот же api_key с другой платформой — всё равно дубликат (UNIQUE api_key).
    assert db.insert_key(make_key(api_key="sk-one", platform="azure")) is False
    assert db.key_exists("sk-one") is True
    assert db.key_exists("sk-missing") is False
    assert db.get_stats()["total"] == 1

    row = query(
        db,
        "SELECT platform, status, is_high_value, verified_time "
        "FROM leaked_keys WHERE api_key = ?",
        ("sk-one",),
    )[0]
    assert row[0] == "openai"           # платформа первого вхождения сохранена
    assert row[1] == "pending"
    assert row[2] == 0
    assert row[3] is None


def test_insert_key_normalizes_base_url_and_maps_fields(db):
    found = datetime(2026, 1, 2, 3, 4, 5)
    key = make_key(
        api_key="sk-norm",
        base_url="https://api.perplexity.ai/chat/completions",
        balance="$5",
        source_url="https://github.com/x/y",
        model_tier="GPT-4",
        rpm=30,
        is_high_value=True,
        found_time=found,
    )
    assert db.insert_key(key) is True

    stored = scalar(db, "SELECT base_url FROM leaked_keys WHERE api_key='sk-norm'")
    assert stored == "https://api.perplexity.ai/v1"

    loaded = {k.api_key: k for k in db.get_all_keys()}["sk-norm"]
    assert loaded.base_url == "https://api.perplexity.ai/v1"
    assert loaded.balance == "$5"
    assert loaded.source_url == "https://github.com/x/y"
    assert loaded.model_tier == "GPT-4"
    assert loaded.rpm == 30
    assert loaded.is_high_value is True
    assert loaded.found_time == found
    assert loaded.id is not None

    assert db.insert_key(make_key(api_key="sk-empty-url", base_url="")) is True
    assert scalar(db, "SELECT base_url FROM leaked_keys WHERE api_key='sk-empty-url'") == ""


def test_insert_keys_batch_counts_only_new_rows(db):
    batch = [
        make_key(api_key="sk-b1"),
        make_key(api_key="sk-b2"),
        make_key(api_key="sk-b1"),  # дубликат внутри партии
    ]
    assert db.insert_keys_batch(batch) == 2
    assert db.insert_keys_batch(batch) == 0
    assert db.insert_keys_batch([]) == 0
    assert db.get_stats()["total"] == 2
    assert db.key_exists("sk-b2") is True


def test_exists_cache_overflow_keeps_answers_correct(db):
    db._exists_cache_max = 3
    for index in range(10):
        assert db.insert_key(make_key(api_key=f"sk-cache-{index}")) is True
    assert len(db._exists_cache) <= 3
    for index in range(10):
        assert db.key_exists(f"sk-cache-{index}") is True


# ============================================================================
# Дедупликация отсканированных blob SHA
# ============================================================================

def test_blob_scan_dedup_and_count(db):
    assert db.is_blob_scanned("sha-1") is False
    assert db.mark_blob_scanned("sha-1") is True
    assert db.is_blob_scanned("sha-1") is True
    # повторная отметка не вставляет строку
    assert db.mark_blob_scanned("sha-1") is False
    assert db.get_scanned_blob_count() == 1
    assert db.is_blob_scanned("") is False
    assert db.mark_blob_scanned("") is False
    assert db.get_scanned_blob_count() == 1


def test_blob_cache_is_warmed_on_reopen(tmp_path):
    path = str(tmp_path / "blob-warmup.db")
    first = Database(path)
    try:
        first.mark_blob_scanned("sha-warm")
    finally:
        first.close()

    again = Database(path)
    try:
        assert "sha-warm" in again._blob_cache
        assert again.is_blob_scanned("sha-warm") is True
        assert again.get_scanned_blob_count() == 1
    finally:
        again.close()


def test_mark_blobs_scanned_batch_counts_inserted(db):
    assert db.mark_blobs_scanned_batch(["sha-a", "sha-a", "sha-b", ""]) == 2
    assert db.mark_blobs_scanned_batch(["sha-a", "sha-c"]) == 1
    assert db.mark_blobs_scanned_batch([]) == 0
    assert db.mark_blobs_scanned_batch([""]) == 0
    assert db.get_scanned_blob_count() == 3
    assert db.is_blob_scanned("sha-c") is True


def test_cleanup_old_blobs_deletes_only_old_rows(db):
    db.mark_blob_scanned("sha-old")
    db.mark_blob_scanned("sha-new")
    execute(
        db,
        "UPDATE scanned_blobs SET scan_time = datetime('now', '-40 days') "
        "WHERE file_sha = 'sha-old'",
    )

    assert db.cleanup_old_blobs(max_age_days=30) == 1
    assert db.get_scanned_blob_count() == 1
    assert scalar(
        db, "SELECT file_sha FROM scanned_blobs"
    ) == "sha-new"
    assert db.cleanup_old_blobs(max_age_days=30) == 0


# ============================================================================
# Статусы ключей и выборки для ревалидации
# ============================================================================

@pytest.mark.parametrize("status", list(KeyStatus))
def test_update_key_status_roundtrip(db, status):
    api_key = f"sk-status-{status.value}"
    assert db.insert_key(make_key(api_key=api_key)) is True

    assert db.update_key_status(
        api_key,
        status,
        balance="bal",
        model_tier="tier-x",
        rpm=11,
        is_high_value=True,
    ) is True

    row = query(
        db,
        "SELECT status, balance, model_tier, rpm, is_high_value, verified_time "
        "FROM leaked_keys WHERE api_key = ?",
        (api_key,),
    )[0]
    assert row[0] == status.value
    assert row[1] == "bal"
    assert row[2] == "tier-x"
    assert row[3] == 11
    assert row[4] == 1
    assert row[5] is not None
    assert db.get_key_status(api_key) == status.value


def test_update_key_status_unknown_key_returns_false(db):
    assert db.update_key_status("sk-nowhere", KeyStatus.VALID) is False
    assert db.get_key_status("sk-nowhere") is None
    assert db.increment_confirm_attempts("sk-nowhere") == 0


def test_dead_status_resets_confirmed_models(db):
    assert db.insert_key(make_key(api_key="sk-models")) is True
    assert db.save_key_models("sk-models", ["gpt-4", "gpt-3.5"], confirmed=True) == 2

    db.update_key_status("sk-models", KeyStatus.VALID)
    confirmed = query(
        db, "SELECT is_confirmed FROM key_models ORDER BY model_name"
    )
    assert [row[0] for row in confirmed] == [1, 1]

    db.update_key_status("sk-models", KeyStatus.INVALID)
    confirmed = query(
        db, "SELECT is_confirmed FROM key_models ORDER BY model_name"
    )
    assert [row[0] for row in confirmed] == [0, 0]

    # Восстановили и снова убили уже через quota_exceeded.
    db.mark_models_confirmed_batch("sk-models", ["gpt-4", "gpt-3.5"])
    db.update_key_status("sk-models", KeyStatus.QUOTA_EXCEEDED)
    confirmed = query(
        db, "SELECT is_confirmed FROM key_models ORDER BY model_name"
    )
    assert [row[0] for row in confirmed] == [0, 0]


def test_update_keys_status_batch_counts_and_applies(db):
    assert db.insert_keys_batch(
        [make_key(api_key="sk-x1"), make_key(api_key="sk-x2"), make_key(api_key="sk-x3")]
    ) == 3
    assert db.save_key_models("sk-x1", ["gpt-4"], confirmed=True) == 1

    updated = db.update_keys_status_batch([
        ("sk-x1", KeyStatus.INVALID, "b1", "t1", 1, False),
        ("sk-x2", "valid", "b2", "t2", 2, True),
        ("sk-x-missing", KeyStatus.VALID, "", "", 0, False),
    ])
    assert updated == 2

    assert db.get_key_status("sk-x1") == "invalid"
    assert db.get_key_status("sk-x2") == "valid"
    assert db.get_key_status("sk-x3") == "pending"

    row = query(
        db,
        "SELECT balance, model_tier, rpm, is_high_value, verified_time "
        "FROM leaked_keys WHERE api_key = 'sk-x2'",
    )[0]
    assert row[:4] == ("b2", "t2", 2, 1)
    assert row[4] is not None

    # invalid в батче тоже сбрасывает подтверждение моделей
    assert scalar(
        db, "SELECT is_confirmed FROM key_models WHERE model_name='gpt-4'"
    ) == 0

    assert db.update_keys_status_batch([]) == 0


def test_update_key_meta_applies_only_provided_fields(db):
    assert db.insert_key(make_key(api_key="sk-meta")) is True
    assert db.update_key_meta("sk-meta") is False

    assert db.update_key_meta(
        "sk-meta",
        tpd=100,
        concurrency_limit=4,
        balance_usd=1.5,
        org_plan="team",
        rate_tier="tier1",
        rate_headers="x-ratelimit: 1",
    ) is True
    row = query(
        db,
        "SELECT tpd, concurrency_limit, balance_usd, org_plan, rate_tier, rate_headers "
        "FROM leaked_keys WHERE api_key='sk-meta'",
    )[0]
    assert row == (100, 4, 1.5, "team", "tier1", "x-ratelimit: 1")

    # balance_usd=0.0 — валидное значение (>= 0), остальные поля не сбрасываются.
    assert db.update_key_meta("sk-meta", balance_usd=0.0) is True
    row = query(
        db,
        "SELECT tpd, balance_usd FROM leaked_keys WHERE api_key='sk-meta'",
    )[0]
    assert row == (100, 0.0)

    # Пустые строки/дефолты не считаются изменением.
    assert db.update_key_meta("sk-meta", org_plan="", rate_tier="") is False
    assert db.update_key_meta("sk-missing", tpd=1) is False


def test_get_failed_keys_selection_rules(db):
    base = datetime(2026, 1, 1, 12, 0, 0)
    assert db.insert_keys_batch([
        make_key(api_key="sk-pending", found_time=base),
        make_key(api_key="sk-unverified", status=KeyStatus.UNVERIFIED.value,
                 found_time=base + timedelta(minutes=1)),
        make_key(api_key="sk-conn", found_time=base + timedelta(minutes=2)),
        make_key(api_key="sk-valid", status=KeyStatus.VALID.value,
                 found_time=base + timedelta(minutes=3)),
        make_key(api_key="sk-invalid", status=KeyStatus.INVALID.value,
                 found_time=base + timedelta(minutes=4)),
    ]) == 5

    db.update_key_status("sk-conn", KeyStatus.CONNECTION_ERROR)
    assert [k.api_key for k in db.get_failed_keys()] == [
        "sk-pending", "sk-unverified", "sk-conn",
    ]
    assert [k.api_key for k in db.get_failed_keys(limit=1)] == ["sk-pending"]

    # connection_error: не более 3 попыток подтверждения
    for expected in (1, 2, 3):
        assert db.increment_confirm_attempts("sk-conn") == expected
    assert [k.api_key for k in db.get_failed_keys()] == ["sk-pending", "sk-unverified"]

    # pending/unverified после реальной проверки (verified_time задан) не берутся
    db.update_key_status("sk-unverified", KeyStatus.UNVERIFIED)
    assert [k.api_key for k in db.get_failed_keys()] == ["sk-pending"]

    # statuses принимается, но логика фиксирована на три статуса
    assert [k.api_key for k in db.get_failed_keys(statuses=["valid"])] == ["sk-pending"]


def test_get_stats_groups_statuses_and_platforms(db):
    db.insert_keys_batch([
        make_key(api_key="sk-s1", platform="openai"),
        make_key(api_key="sk-s2", platform="openai"),
        make_key(api_key="sk-s3", platform="azure"),
        make_key(api_key="sk-s4", platform="azure"),
        make_key(api_key="sk-s5", platform="openai"),
        make_key(api_key="sk-s6", platform="openai"),
    ])
    db.update_key_status("sk-s1", KeyStatus.VALID)
    db.update_key_status("sk-s2", KeyStatus.QUOTA_EXCEEDED)
    db.update_key_status("sk-s3", KeyStatus.INVALID)
    db.update_key_status("sk-s5", KeyStatus.UNVERIFIED)
    db.update_key_status("sk-s6", KeyStatus.CONFIRMED)

    stats = db.get_stats()
    assert stats["total"] == 6
    assert stats["statuses"] == {
        "valid": 1,
        "quota_exceeded": 1,
        "invalid": 1,
        "pending": 1,
        "unverified": 1,
        "confirmed": 1,
    }
    assert stats["platforms"] == {"openai": 4, "azure": 2}
    # valid = valid + quota_exceeded; confirmed сюда не входит.
    assert stats["valid"] == 2
    assert db.get_valid_keys_count() == 2


def test_get_valid_keys_filters_by_platform(db):
    db.insert_keys_batch([
        make_key(api_key="sk-v1", platform="openai"),
        make_key(api_key="sk-v2", platform="openai"),
        make_key(api_key="sk-v3", platform="azure"),
        make_key(api_key="sk-v4", platform="openai"),
    ])
    db.update_key_status("sk-v1", KeyStatus.VALID)
    db.update_key_status("sk-v2", KeyStatus.QUOTA_EXCEEDED)
    db.update_key_status("sk-v3", KeyStatus.QUOTA_EXCEEDED)
    db.update_key_status("sk-v4", KeyStatus.INVALID)

    assert {k.api_key for k in db.get_valid_keys()} == {"sk-v1", "sk-v2", "sk-v3"}
    assert {k.api_key for k in db.get_valid_keys("openai")} == {"sk-v1", "sk-v2"}
    assert db.get_valid_keys("anthropic") == []
    assert db.get_valid_keys_count() == 3


def test_get_all_keys_orders_by_found_time_desc(db):
    base = datetime(2026, 2, 1, 10, 0, 0)
    db.insert_keys_batch([
        make_key(api_key="sk-old", found_time=base),
        make_key(api_key="sk-new", found_time=base + timedelta(days=2)),
        make_key(api_key="sk-mid", found_time=base + timedelta(days=1)),
    ])
    assert [k.api_key for k in db.get_all_keys()] == ["sk-new", "sk-mid", "sk-old"]


# ============================================================================
# source_state / scanned_source_items / scan_progress
# ============================================================================

def test_source_state_default_set_and_overwrite(db):
    assert db.get_source_state("cursor") == ""
    assert db.get_source_state("cursor", default="none") == "none"

    db.set_source_state("cursor", "page-2")
    assert db.get_source_state("cursor") == "page-2"
    db.set_source_state("cursor", "page-3")
    assert db.get_source_state("cursor") == "page-3"
    assert scalar(db, "SELECT COUNT(*) FROM source_state") == 1


def test_scanned_source_items_idempotent_and_scoped(db):
    assert db.is_source_item_scanned("github", "repo:1") is False
    db.mark_source_item_scanned("github", "repo:1")
    db.mark_source_item_scanned("github", "repo:1")  # идемпотентно
    assert db.is_source_item_scanned("github", "repo:1") is True
    assert db.is_source_item_scanned("github", "repo:2") is False
    assert db.is_source_item_scanned("gitlab", "repo:1") is False
    assert scalar(db, "SELECT COUNT(*) FROM scanned_source_items") == 1


def test_scanned_source_items_persist_after_reopen(tmp_path):
    path = str(tmp_path / "items.db")
    first = Database(path)
    try:
        first.mark_source_item_scanned("github", "repo:42")
        assert first.is_source_item_scanned("github", "repo:42") is True
    finally:
        first.close()

    again = Database(path)
    try:
        assert again.is_source_item_scanned("github", "repo:42") is True
        assert again.is_source_item_scanned("github", "repo:43") is False
    finally:
        again.close()


def test_scan_progress_save_load_reset(db):
    assert db.load_progress() == {
        "current_index": 0, "total": 0, "is_completed": False,
    }

    db.save_progress(3, 9)
    assert db.load_progress() == {
        "current_index": 3, "total": 9, "is_completed": False,
    }

    db.save_progress(9, 9, is_completed=True)
    assert db.load_progress() == {
        "current_index": 9, "total": 9, "is_completed": True,
    }

    db.reset_progress()
    assert db.load_progress() == {
        "current_index": 0, "total": 0, "is_completed": False,
    }


# ============================================================================
# source_progress: upsert, счётчики, heartbeat, stale/reap
# ============================================================================

def test_upsert_source_progress_inserts_full_row(db):
    db.upsert_source_progress(
        "github",
        status="running",
        phase="search",
        current=4,
        total=10,
        processed=4,
        found=1,
        errors=2,
        message="scanning",
    )
    rows = db.get_source_progress()
    assert len(rows) == 1
    row = rows[0]
    assert row["source"] == "github"
    assert row["status"] == "running"
    assert row["phase"] == "search"
    assert (row["current"], row["total"], row["processed"]) == (4, 10, 4)
    assert (row["found"], row["errors"], row["message"]) == (1, 2, "scanning")
    assert row["heartbeat"]
    assert row["stale"] is False


def test_upsert_source_progress_increments_accumulate(db):
    db.upsert_source_progress("gh", status="running")
    db.upsert_source_progress("gh", processed_increment=2, found_increment=1)
    db.upsert_source_progress("gh", processed_increment=3, errors_increment=4)
    db.upsert_source_progress("gh", errors_increment=1)

    row = db.get_source_progress()[0]
    assert row["processed"] == 5
    assert row["found"] == 1
    assert row["errors"] == 5
    assert row["status"] == "running"


def test_upsert_source_progress_field_plus_increment(db):
    db.upsert_source_progress("gh", status="running")
    db.upsert_source_progress("gh", processed=100, processed_increment=5)
    assert db.get_source_progress()[0]["processed"] == 105
    # повтор с новым значением перезаписывает, а не суммирует со старым
    db.upsert_source_progress("gh", processed=200, processed_increment=1)
    assert db.get_source_progress()[0]["processed"] == 201


def test_upsert_source_progress_keeps_message_until_replaced(db):
    db.upsert_source_progress("gh", status="running", message="hello")
    db.upsert_source_progress("gh", status="running", phase="p2")
    row = db.get_source_progress()[0]
    assert row["message"] == "hello"
    assert row["phase"] == "p2"

    db.upsert_source_progress("gh", message="")
    assert db.get_source_progress()[0]["message"] == ""


def test_upsert_source_progress_rejects_unknown_field(db):
    with pytest.raises(TypeError, match="typo_field"):
        db.upsert_source_progress("gh", typo_field=1)
    assert db.get_source_progress() == []


def test_increment_source_progress_shorthand(db):
    db.increment_source_progress("gh", processed=2, found=1, errors=1)
    row = db.get_source_progress()[0]
    assert (row["processed"], row["found"], row["errors"]) == (2, 1, 1)
    db.increment_source_progress("gh", processed=1)
    row = db.get_source_progress()[0]
    assert (row["processed"], row["found"], row["errors"]) == (3, 1, 1)


def test_safe_upsert_source_progress_returns_true_and_propagates_type_errors(db):
    assert db.safe_upsert_source_progress("gh", status="running") is True
    assert db.get_source_progress()[0]["status"] == "running"
    with pytest.raises(TypeError):
        db.safe_upsert_source_progress("gh", unknown=1)


def test_get_source_progress_stale_flag_only_for_active_statuses(db):
    db.upsert_source_progress("running-fresh", status="running")
    db.upsert_source_progress("starting-old", status="starting")
    db.upsert_source_progress("stopped-old", status="stopped")

    old = (datetime.now() - timedelta(minutes=10)).isoformat()
    execute(
        db,
        "UPDATE source_progress SET heartbeat = ? "
        "WHERE source IN ('starting-old', 'stopped-old')",
        (old,),
    )

    rows = {r["source"]: r for r in db.get_source_progress(stale_after_seconds=60)}
    assert rows["running-fresh"]["stale"] is False
    assert rows["starting-old"]["stale"] is True
    assert rows["stopped-old"]["stale"] is False

    # невалидный heartbeat у активного статуса считается протухшим
    execute(
        db,
        "UPDATE source_progress SET heartbeat = 'not-a-date' WHERE source = 'running-fresh'",
    )
    rows = {r["source"]: r for r in db.get_source_progress(stale_after_seconds=60)}
    assert rows["running-fresh"]["stale"] is True


def test_reap_stale_source_progress_stops_dead_active_rows(db):
    db.upsert_source_progress("gh-fresh", status="running", phase="search", message="live")
    for source, status in (
        ("gh-dead", "running"),
        ("gl-starting", "starting"),
        ("pb-waiting", "waiting"),
    ):
        db.upsert_source_progress(source, status=status, phase="p", message="m")
    db.upsert_source_progress("old-error", status="error", phase="e", message="keep")

    old = (datetime.now() - timedelta(minutes=30)).isoformat()
    execute(
        db,
        "UPDATE source_progress SET heartbeat = ? "
        "WHERE source IN ('gh-dead', 'gl-starting', 'pb-waiting', 'old-error')",
        (old,),
    )

    assert db.reap_stale_source_progress(stale_after_seconds=60) == 3
    rows = {r["source"]: r for r in db.get_source_progress()}
    for source in ("gh-dead", "gl-starting", "pb-waiting"):
        assert rows[source]["status"] == "stopped"
        assert rows[source]["phase"] == "stopped"
        assert rows[source]["message"] == ""
    assert rows["gh-fresh"]["status"] == "running"
    assert rows["gh-fresh"]["stale"] is False
    assert rows["old-error"]["status"] == "error"
    assert rows["old-error"]["message"] == "keep"
    assert db.reap_stale_source_progress(stale_after_seconds=60) == 0


# ============================================================================
# Дедупликация ключевых слов
# ============================================================================

def test_keyword_scanned_lifecycle(db):
    assert db.is_keyword_scanned("never-seen") is False

    db.mark_keyword_scanned("kw-partial", result_count=5, fully_scanned=False)
    assert db.is_keyword_scanned("kw-partial") is False

    db.mark_keyword_scanned("kw-full", result_count=2)
    assert db.is_keyword_scanned("kw-full") is True
    assert db.is_keyword_scanned("kw-full", max_age_hours=0) is False
    assert db.count_scanned_keywords() == 1

    execute(
        db,
        "UPDATE scanned_keywords SET scan_time = ? WHERE keyword = 'kw-full'",
        ((datetime.now() - timedelta(hours=48)).isoformat(),),
    )
    assert db.is_keyword_scanned("kw-full", max_age_hours=24) is False
    assert db.is_keyword_scanned("kw-full", max_age_hours=72) is True

    execute(
        db,
        "UPDATE scanned_keywords SET scan_time = 'garbage' WHERE keyword = 'kw-full'",
    )
    assert db.is_keyword_scanned("kw-full") is False

    # повторная отметка обновляет данные
    db.mark_keyword_scanned("kw-full", result_count=9)
    assert scalar(
        db, "SELECT result_count FROM scanned_keywords WHERE keyword='kw-full'"
    ) == 9

    assert db.clear_scanned_keywords() == 2
    assert db.count_scanned_keywords() == 0
    assert db.is_keyword_scanned("kw-full") is False


# ============================================================================
# Модели по ключам
# ============================================================================

def test_save_key_models_replaces_and_dedups(db):
    assert db.insert_key(make_key(api_key="sk-mod")) is True

    assert db.save_key_models("sk-mod", ["gpt-4", "GPT-4", "  ", "gpt-3.5"]) == 2
    assert db.get_models_by_key("sk-mod") == ["gpt-3.5", "gpt-4"]

    assert db.save_key_models("sk-mod", ["gpt-4o"]) == 1
    assert db.get_models_by_key("sk-mod") == ["gpt-4o"]

    row = query(
        db,
        "SELECT platform, base_url, is_confirmed FROM key_models "
        "WHERE model_name='gpt-4o'",
    )[0]
    assert row == ("openai", "https://api.openai.com/v1", 0)

    assert db.save_key_models("sk-missing", ["gpt-4"]) == 0
    assert db.save_key_models("sk-mod", []) == 0
    assert db.get_models_by_key("sk-mod") == ["gpt-4o"]


def test_mark_model_confirmed_and_batch(db):
    assert db.insert_key(make_key(api_key="sk-conf")) is True
    assert db.save_key_models("sk-conf", ["gpt-4", "gpt-3.5"]) == 2

    assert db.mark_model_confirmed("sk-conf", "gpt-4") is True
    assert db.mark_model_confirmed("sk-conf", "unknown-model") is False
    assert db.mark_models_confirmed_batch("sk-conf", ["gpt-3.5", "gpt-4"]) == 2
    assert db.mark_models_confirmed_batch("sk-conf", []) == 0
    assert db.mark_models_confirmed_batch("sk-missing", ["gpt-4"]) == 0

    row = query(db, "SELECT model_name, is_confirmed FROM key_models ORDER BY model_name")
    assert row == [("gpt-3.5", 1), ("gpt-4", 1)]


def test_get_all_models_with_counts_only_valid_keys(db):
    db.insert_keys_batch([
        make_key(api_key="sk-m1", platform="openai"),
        make_key(api_key="sk-m2", platform="azure", base_url="https://x.test"),
        make_key(api_key="sk-m3", platform="openai"),
    ])
    db.save_key_models("sk-m1", ["gpt-4", "gpt-3.5"])
    db.save_key_models("sk-m2", ["gpt-4"])
    db.save_key_models("sk-m3", ["claude-3"])
    db.update_key_status("sk-m1", KeyStatus.VALID)
    db.update_key_status("sk-m2", KeyStatus.VALID)
    # sk-m3 остаётся pending -> не попадает

    counts = {row["model_name"]: row for row in db.get_all_models_with_counts()}
    assert set(counts) == {"gpt-4", "gpt-3.5"}
    assert counts["gpt-4"]["key_count"] == 2
    assert sorted(counts["gpt-4"]["platforms"]) == ["azure", "openai"]
    assert sorted(counts["gpt-4"]["base_urls"]) == [
        "https://api.openai.com/v1", "https://x.test",
    ]
    assert counts["gpt-3.5"]["key_count"] == 1

    db.update_key_status("sk-m2", KeyStatus.INVALID)
    counts = {row["model_name"]: row for row in db.get_all_models_with_counts()}
    assert counts["gpt-4"]["key_count"] == 1
    assert counts["gpt-4"]["platforms"] == ["openai"]


def test_get_keys_for_model_returns_only_valid_keys(db):
    db.insert_keys_batch([
        make_key(api_key="sk-k1", platform="openai"),
        make_key(api_key="sk-k2", platform="openai"),
        make_key(api_key="sk-k3", platform="openai"),
    ])
    db.save_key_models("sk-k1", ["gpt-4"])
    db.save_key_models("sk-k2", ["gpt-4"])
    db.save_key_models("sk-k3", ["gpt-4"])
    db.update_key_status("sk-k1", KeyStatus.VALID)
    db.update_key_status("sk-k2", KeyStatus.QUOTA_EXCEEDED, is_high_value=True)
    db.update_key_status("sk-k3", KeyStatus.INVALID)

    keys = db.get_keys_for_model("gpt-4")
    assert [row["api_key"] for row in keys] == ["sk-k2", "sk-k1"]
    assert keys[0]["is_high_value"] is True
    assert keys[0]["status"] == "quota_exceeded"
    expected_fields = {
        "id", "platform", "api_key", "base_url", "status",
        "model_tier", "rpm", "is_high_value", "verified_time",
    }
    assert set(keys[0]) == expected_fields
    assert db.get_keys_for_model("unknown-model") == []


# ============================================================================
# Обслуживание и конкурентный доступ
# ============================================================================

def test_vacuum_keeps_data(db):
    assert db.insert_key(make_key(api_key="sk-vacuum")) is True
    assert db.mark_blob_scanned("sha-vacuum") is True
    assert db.vacuum() is None
    assert db.key_exists("sk-vacuum") is True
    assert db.get_scanned_blob_count() == 1
    assert db.get_stats()["total"] == 1


def test_concurrent_threads_insert_and_update_without_lock_errors(tmp_path):
    database = Database(str(tmp_path / "threads.db"))
    workers = 4
    per_worker = 25
    errors = []

    def worker(index):
        try:
            for step in range(per_worker):
                api_key = f"sk-{index}-{step}"
                assert database.insert_key(make_key(api_key=api_key)) is True
                assert database.key_exists(api_key) is True
                assert database.mark_blob_scanned(f"sha-{index}-{step}") is True
                assert database.update_key_status(api_key, KeyStatus.VALID) is True
        except Exception as exc:  # pragma: no cover - только при регрессе
            errors.append(f"worker {index}: {exc!r}")

    threads = [
        threading.Thread(target=worker, args=(index,), name=f"db-worker-{index}")
        for index in range(workers)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    try:
        assert [t for t in threads if t.is_alive()] == []
        assert errors == []
        assert database.get_stats()["total"] == workers * per_worker
        assert database.get_valid_keys_count() == workers * per_worker
        assert database.get_scanned_blob_count() == workers * per_worker
        for index in range(workers):
            assert database.key_exists(f"sk-{index}-0") is True
    finally:
        database.close()


# ============================================================================
#  Регрессия: get_keys_by_status (вызывается экспортом --status/--export-csv)
# ============================================================================

def test_get_keys_by_status_returns_only_matching_keys(db):
    """Метод был потерян при чистке perf-стека: экспорт падал AttributeError,
    а тело висело мёртвым блоком после return в update_key_meta."""
    assert hasattr(db, "get_keys_by_status")

    db.insert_key(make_key("sk-alpha-0001"))
    db.insert_key(make_key("sk-beta-0002"))
    db.insert_key(make_key("sk-gamma-0003"))
    db.update_key_status("sk-alpha-0001", KeyStatus.VALID)
    db.update_key_status("sk-beta-0002", KeyStatus.INVALID)

    valid = db.get_keys_by_status(KeyStatus.VALID)
    assert [k.api_key for k in valid] == ["sk-alpha-0001"]

    invalid = db.get_keys_by_status(KeyStatus.INVALID)
    assert [k.api_key for k in invalid] == ["sk-beta-0002"]

    # Непроверенные ключи не попадают в отфильтрованный статус
    assert [k.api_key for k in db.get_keys_by_status(KeyStatus.PENDING)] == ["sk-gamma-0003"]
    assert db.get_keys_by_status(KeyStatus.CONFIRMED) == []


def test_get_keys_by_status_returns_full_rows(db):
    db.insert_key(make_key("sk-full-row", base_url="https://relay.example/v1", source_url="u"))
    db.update_key_status("sk-full-row", KeyStatus.QUOTA_EXCEEDED)

    (key,) = db.get_keys_by_status(KeyStatus.QUOTA_EXCEEDED)
    assert key.platform == "openai"
    assert key.base_url == "https://relay.example/v1"
    assert key.source_url == "u"
    assert key.status == KeyStatus.QUOTA_EXCEEDED.value
