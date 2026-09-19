"""Stage3+4: headless TUI tests for the dense operator-style redesign.

Проверяет дашборд (worker-матрица из 7 строк), рендер на узком/широком
терминале, переключение вкладок и обновление worker-матрицы из
_source_progress().

Запуск:  python -m unittest tests.test_tui_redesign
"""

import asyncio
import os
import sqlite3
import tempfile
import unittest

import tui_app


def _make_db(path: str) -> None:
    """Создать схему + source_progress (Stage 1) + leaked_keys для тестов TUI."""
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


def _seed_progress(conn: sqlite3.Connection) -> None:
    """Заполнить source_progress — разные статусы, чтобы матрица менялась."""
    import datetime as dt
    now = dt.datetime.now().isoformat()
    rows = [
        ("github", "running", "scanning", 120, 500, 120, 5, 0, now),
        ("paster", "running", "backfill", 80, 300, 80, 12, 1, now),
        ("pastebin", "idle", None, 0, 0, 0, 0, 0, None),
        ("gist", "error", "fetch", 10, 50, 10, 0, 3, now),
        ("gitlab", "disabled", None, 0, 0, 0, 0, 0, None),
        ("realtime", "running", "streaming", 200, 1000, 200, 40, 0, now),
    ]
    conn.executemany(
        "INSERT INTO source_progress "
        "(source, status, phase, current, total, processed, found, errors, heartbeat) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()


def _insert_keys(conn: sqlite3.Connection, n: int) -> None:
    urls = [
        "https://github.com/foo/bar",
        "https://paster.sh/abc",
        "https://pastebin.com/xyz",
        "https://gist.github.com/u/g",
        "https://gitlab.com/p/r",
        "https://realtime.example.com/x",
        "https://raw.githubusercontent.com/user/repo/main/.env",
    ]
    rows = []
    for i in range(n):
        src = urls[i % len(urls)]
        rows.append(
            ("openai", f"key_{i}", "https://api.openai.com", src,
             "unverified", i % 3 == 0))
    conn.executemany(
        "INSERT INTO leaked_keys "
        "(platform, api_key, base_url, source_url, status, is_high_value) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        rows,
    )
    conn.commit()


class TuiRedesignTests(unittest.TestCase):
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

    # --- 1) Дашборд отображает все 8 worker-строк -----------------------
    def test_dashboard_worker_matrix_eight_rows(self):
        with sqlite3.connect(self.db_path) as conn:
            _seed_progress(conn)
        tui_app._invalidate_caches()

        async def _t():
            app = tui_app.ScannerTUI()
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                # Mount defers full dashboard paint (async startup).
                app._update_dashboard()
                await pilot.pause()
                table = app.query_one("#d_workers", tui_app.DataTable)
                return (table.row_count,
                        [table.get_row_at(i)[0] for i in range(table.row_count)])

        count, sources = asyncio.run(_t())
        self.assertEqual(count, 8)
        self.assertEqual(
            sources,
            ["GitHub", "Paster.sh", "Pastebin", "Gist", "GitLab",
             "Realtime", "MCP", "CodeGraph"],
        )

    # --- 2) Render не падает на узком/широком терминале ----------------
    def test_render_wide_terminal(self):
        with sqlite3.connect(self.db_path) as conn:
            _seed_progress(conn)
            _insert_keys(conn, 500)
        tui_app._invalidate_caches()

        async def _t():
            app = tui_app.ScannerTUI()
            async with app.run_test(size=(200, 50)) as pilot:
                await pilot.pause()
                app._update_dashboard()
                app._update_statusbar()
                await pilot.pause()

        asyncio.run(_t())

    def test_render_narrow_terminal(self):
        with sqlite3.connect(self.db_path) as conn:
            _seed_progress(conn)
        tui_app._invalidate_caches()

        async def _t():
            app = tui_app.ScannerTUI()
            async with app.run_test(size=(60, 24)) as pilot:
                await pilot.pause()
                app._update_dashboard()
                app._update_statusbar()
                await pilot.pause()

        asyncio.run(_t())

    # --- 3) Переключение вкладок работает ------------------------------
    def test_tab_switching(self):
        async def _t():
            app = tui_app.ScannerTUI()
            async with app.run_test(size=(120, 40)) as pilot:
                for tid in ("dashboard", "keys", "models", "providers",
                             "endpoints", "settings", "logs"):
                    app.query_one("#tabs", tui_app.TabbedContent).active = tid
                    await pilot.pause()

        asyncio.run(_t())

    # --- 4) Worker-матрица обновляется из _source_progress ------------
    def test_worker_matrix_updates_from_source_progress(self):
        with sqlite3.connect(self.db_path) as conn:
            _seed_progress(conn)
        tui_app._invalidate_caches()

        async def _t():
            app = tui_app.ScannerTUI()
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                # Dashboard paint is deferred at mount (async startup);
                # drive an explicit refresh for the matrix assertion.
                app._update_dashboard()
                await pilot.pause()
                table = app.query_one("#d_workers", tui_app.DataTable)
                return (table.get_row_at(0), table.get_row_at(3))

        github_row, gist_row = asyncio.run(_t())
        self.assertEqual(github_row[0], "GitHub")
        self.assertIn("RUN", str(github_row[1]))
        self.assertEqual(str(github_row[5]), "5")    # found
        self.assertEqual(str(github_row[4]), "120")  # processed
        # col6 = Keys (key_count), col7 = Err
        self.assertEqual(gist_row[0], "Gist")
        self.assertIn("ERR", str(gist_row[1]))
        self.assertIn("3", str(gist_row[7]))  # errors

    def test_worker_matrix_reflects_disabled_when_empty(self):
        async def _t():
            app = tui_app.ScannerTUI()
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                app._update_dashboard()
                await pilot.pause()
                return app.query_one("#d_workers", tui_app.DataTable)

        table = asyncio.run(_t())
        self.assertEqual(table.row_count, 8)
        first = table.get_row_at(0)
        self.assertEqual(first[0], "GitHub")
        self.assertIn("OFF", str(first[1]))

    # --- 5) Validation funnel панель рендерится без падения -----------
    def test_validation_funnel_renders(self):
        async def _t():
            app = tui_app.ScannerTUI()
            async with app.run_test(size=(120, 40)) as pilot:
                await pilot.pause()
                app._update_dashboard()
                await pilot.pause()

        asyncio.run(_t())


if __name__ == "__main__":
    unittest.main()
