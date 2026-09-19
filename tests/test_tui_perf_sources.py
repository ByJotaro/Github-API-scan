import os
import sqlite3
import tempfile
import time
import unittest

import tui_app


def _make_db(path: str) -> None:
    """Создать схему + таблицу source_progress (Stage 1) для тестов TUI."""
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
                base_url TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                balance TEXT DEFAULT '',
                source_url TEXT DEFAULT '',
                model_tier TEXT DEFAULT '',
                rpm INTEGER DEFAULT 0,
                is_high_value BOOLEAN DEFAULT 0,
                found_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                verified_time DATETIME,
                tpd INTEGER DEFAULT 0,
                concurrency_limit INTEGER DEFAULT 0,
                balance_usd REAL DEFAULT -1,
                org_plan TEXT DEFAULT '',
                rate_tier TEXT DEFAULT '',
                rate_headers TEXT DEFAULT ''
            )
        """)


def _insert_keys(conn: sqlite3.Connection, n: int) -> None:
    rows = []
    urls = [
        "https://github.com/foo/bar",
        "https://paster.sh/abc",
        "https://pastebin.com/xyz",
        "https://gist.github.com/u/g",
        "https://gitlab.com/p/r",
        "https://realtime.example.com/x",
        "https://raw.githubusercontent.com/user/repo/main/.env",
    ]
    for i in range(n):
        src = urls[i % len(urls)]
        rows.append((
            "openai", f"key_{i}", "https://api.openai.com", src,
            "unverified", i % 3 == 0,
        ))
    conn.executemany(
        "INSERT INTO leaked_keys (platform, api_key, base_url, source_url, status, is_high_value) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()


class TuiSourceProgressTests(unittest.TestCase):
    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        _make_db(self.db_path)
        # Перенаправить TUI на temp БД и сбросить кэши.
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

    def test_source_progress_exactly_eight_rows(self):
        """_source_progress всегда отдаёт ровно 8 строк (по _KNOWN_SOURCES)."""
        progress = tui_app._source_progress()
        self.assertEqual(len(progress), 8)
        self.assertEqual(
            [p["source"] for p in progress],
            list(tui_app._KNOWN_SOURCES),
        )

    def test_source_progress_derived_status_disabled_when_empty(self):
        """Нет записей в source_progress -> все disabled."""
        progress = tui_app._source_progress()
        for p in progress:
            self.assertEqual(p["derived_status"], "disabled")
            self.assertEqual(p["status"], "disabled")

    def test_derived_status_mapping(self):
        """idle-статус (не active, не error) -> derived 'idle', не 'disabled'."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO source_progress (source, status) VALUES ('pastebin', 'idle')")
        tui_app._invalidate_caches()
        progress = {p["source"]: p for p in tui_app._source_progress()}
        self.assertEqual(progress["pastebin"]["derived_status"], "idle")
        # Источники без строки остаются disabled.
        self.assertEqual(progress["github"]["derived_status"], "disabled")

    def test_source_progress_derived_status_running_and_error(self):
        """active+не stale -> running; error -> error; stale active -> stale;
        disabled/idle/stopped -> соответствующие метки."""
        now = __import__("datetime").datetime.now().isoformat()
        stale = (__import__("datetime").datetime.now()
                 - __import__("datetime").timedelta(seconds=300)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO source_progress (source, status, heartbeat) "
                "VALUES ('github', 'running', ?)", (now,))
            conn.execute(
                "INSERT INTO source_progress (source, status, heartbeat) "
                "VALUES ('gitlab', 'error', ?)", (now,))
            conn.execute(
                "INSERT INTO source_progress (source, status, heartbeat) "
                "VALUES ('paster', 'starting', ?)", (stale,))
            conn.execute(
                "INSERT INTO source_progress (source, status) "
                "VALUES ('pastebin', 'idle')")
            conn.execute(
                "INSERT INTO source_progress (source, status) "
                "VALUES ('realtime', 'disabled')")
            conn.execute(
                "INSERT INTO source_progress (source, status) "
                "VALUES ('codegraph', 'stopped')")
        tui_app._invalidate_caches()
        progress = {p["source"]: p for p in tui_app._source_progress()}
        self.assertEqual(progress["github"]["derived_status"], "running")
        self.assertFalse(progress["github"]["stale"])
        self.assertEqual(progress["gitlab"]["derived_status"], "error")
        self.assertEqual(progress["paster"]["derived_status"], "stale")
        self.assertTrue(progress["paster"]["stale"])
        self.assertEqual(progress["pastebin"]["derived_status"], "idle")
        self.assertEqual(progress["realtime"]["derived_status"], "disabled")
        self.assertEqual(progress["codegraph"]["derived_status"], "stopped")

    def test_source_progress_key_count_column(self):
        """key_count — число leaked_keys по источнику (из закэшированного подсчёта)."""
        with sqlite3.connect(self.db_path) as conn:
            _insert_keys(conn, 700)
        tui_app._invalidate_caches()
        progress = {p["source"]: p for p in tui_app._source_progress()}
        # 700 ключей, по 8 источникам → ~87-88 каждый.
        self.assertEqual(sum(p["key_count"] for p in progress.values()), 700)
        # Проверяем что распределение есть (ключи не в 0)
        self.assertGreater(progress["mcp"]["key_count"], 0)

    def test_stats_snapshot_latency_under_one_second(self):
        """Один _stats() на ~50k строк < 1.0s."""
        with sqlite3.connect(self.db_path) as conn:
            _insert_keys(conn, 50000)
        tui_app._invalidate_caches()
        start = time.perf_counter()
        st = tui_app._stats()
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, 1.0, f"_stats() занял {elapsed*1000:.1f}ms")
        self.assertEqual(st["total"], 50000)
        # source_progress строится из кэшированного подсчёта, без GROUP BY внутри _stats.
        sp_sources = [p["source"] for p in st["source_progress"]]
        self.assertIn("github", sp_sources)
        self.assertEqual(len(st["source_progress"]), 8)
        self.assertIn("Github", st["sources"])

    def test_stats_cache_returns_same_object_within_ttl(self):
        """Внутри TTL _stats() возвращает тот же объект (кэш)."""
        with sqlite3.connect(self.db_path) as conn:
            _insert_keys(conn, 1000)
        tui_app._invalidate_caches()
        first = tui_app._stats()
        second = tui_app._stats()
        self.assertIs(first, second)
        # Явный сброс кэша -> новый объект.
        tui_app._invalidate_caches()
        third = tui_app._stats()
        self.assertIsNot(first, third)


if __name__ == "__main__":
    unittest.main()
