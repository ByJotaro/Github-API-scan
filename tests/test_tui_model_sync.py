"""Headless проверка кнопки «Обновить у провайдеров» во вкладке «Модели».

Синхронизация моделей идёт из вкладки: без кнопки обновить список после
смены моделей у провайдера можно было только перевалидацией ключей.
Тест монтирует TUI, убеждается, что кнопка есть, и что нажатие запускает
model_sync.refresh_models + пересборку пула (сеть подменена).
"""

import asyncio
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

import tui_app


def _make_db(path: str) -> None:
    with sqlite3.connect(path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS source_progress (
                source TEXT PRIMARY KEY,
                status TEXT DEFAULT 'disabled',
                phase TEXT,
                current INTEGER DEFAULT 0,
                total INTEGER DEFAULT 0,
                processed INTEGER DEFAULT 0,
                found INTEGER DEFAULT 0,
                errors INTEGER DEFAULT 0,
                message TEXT,
                heartbeat TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS leaked_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                platform TEXT NOT NULL,
                api_key TEXT NOT NULL UNIQUE,
                base_url TEXT DEFAULT '',
                status TEXT DEFAULT 'unverified',
                source_url TEXT DEFAULT '',
                is_high_value INTEGER DEFAULT 0,
                found_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                verified_time DATETIME,
                balance TEXT DEFAULT '',
                model_tier TEXT DEFAULT '',
                rpm INTEGER DEFAULT 0
            )
        """)
        conn.commit()


class ModelSyncButtonTests(unittest.TestCase):
    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        _make_db(self.db_path)
        self._old_db = tui_app.DB
        tui_app.DB = self.db_path
        tui_app._invalidate_caches()

    def tearDown(self):
        tui_app.DB = self._old_db
        tui_app._invalidate_caches()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.db_path + suffix)
            except (FileNotFoundError, PermissionError):
                pass

    def test_sync_button_exists_and_triggers_refresh(self):
        calls = {"refresh": 0, "resync": 0}

        async def fake_refresh(db, **kwargs):
            calls["refresh"] += 1
            return {"endpoints": 1, "ok": 1, "failed": 0, "added": 2,
                    "removed": 0, "demoted": 0, "keys": 1, "errors": []}

        class FakePool:
            def __init__(self, db):
                pass

            def resync_pool(self):
                calls["resync"] += 1
                return {"added": 1, "updated": 0, "removed": 0}

        async def _t():
            import model_sync
            app = tui_app.ScannerTUI()
            async with app.run_test(size=(140, 45)) as pilot:
                await pilot.pause()
                app.query_one("#tabs", tui_app.TabbedContent).active = "models"
                await pilot.pause()
                button = app.query_one("#m_sync", tui_app.Button)
                self.assertEqual(button.label.plain, "Обновить у провайдеров"
                                 if app._lang == "ru" else "Sync from providers")
                with mock.patch.object(model_sync, "refresh_models", fake_refresh), \
                     mock.patch("proxy_server.ActivePool", FakePool):
                    button.press()
                    for _ in range(60):
                        await pilot.pause(0.05)
                        if calls["resync"]:
                            break

        asyncio.run(_t())
        self.assertEqual(calls["refresh"], 1)
        self.assertEqual(calls["resync"], 1)


if __name__ == "__main__":
    unittest.main()


class PoolRebuildTests(unittest.TestCase):
    """Пересборка пула в TUI не должна воскрешать удалённые пары."""

    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        from database import Database
        db = Database(self.db_path)      # полная схема leaked_keys/key_models
        db.insert_keys_batch([__import__("database").LeakedKey(
            platform="openai", api_key="sk-1",
            base_url="https://relay.test/v1")])
        db.update_key_status("sk-1", __import__("database").KeyStatus.CONFIRMED)
        db.sync_key_models("sk-1", ["m1"], confirmed=["m1"])
        db.close()
        self._old_db = tui_app.DB
        tui_app.DB = self.db_path
        tui_app._invalidate_caches()

    def tearDown(self):
        tui_app.DB = self._old_db
        tui_app._invalidate_caches()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.db_path + suffix)
            except (FileNotFoundError, PermissionError):
                pass

    def _pool_rows(self):
        with sqlite3.connect(self.db_path) as conn:
            return conn.execute(
                "SELECT model_name, endpoint, enabled, priority "
                "FROM active_pool").fetchall()

    def test_removed_pair_stays_gone_after_tui_rebuild(self):
        tui_app._pool_add_model("m1")
        assert self._pool_rows() == [("m1", "https://relay.test/v1", 1, 0)]

        tui_app._pool_remove_row("m1", "https://relay.test/v1")
        assert self._pool_rows() == []

        # Любое изменение пула в TUI дергает пересборку
        tui_app._rebuild_active_pool()
        assert self._pool_rows() == []

    def test_rebuild_preserves_enabled_and_priority(self):
        tui_app._pool_add_model("m1")
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE active_pool SET enabled=0, priority=3")
            conn.commit()
        tui_app._rebuild_active_pool()
        assert self._pool_rows() == [("m1", "https://relay.test/v1", 0, 3)]

    def test_add_endpoint_then_rebuild_keeps_pair(self):
        assert "Добавлено" in tui_app._pool_add_endpoint("https://relay.test/v1")
        assert len(self._pool_rows()) == 1
        tui_app._rebuild_active_pool()
        assert len(self._pool_rows()) == 1
