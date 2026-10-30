import os
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta
from unittest.mock import patch

from database import Database
from main_optimized import OptimizedSecretScanner


class _ConnectionProxy:
    def __init__(self, connection):
        self.connection = connection
        self.rollback_calls = 0

    def execute(self, *args, **kwargs):
        return self.connection.execute(*args, **kwargs)

    def commit(self):
        return self.connection.commit()

    def rollback(self):
        self.rollback_calls += 1
        return self.connection.rollback()


class SourceProgressDatabaseContractTests(unittest.TestCase):
    def setUp(self):
        handle, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.db = Database(self.db_path)

    def tearDown(self):
        self.db.close()
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(self.db_path + suffix)
            except (FileNotFoundError, PermissionError):
                pass

    def test_single_upsert_atomically_updates_fields_and_increments(self):
        statements = []
        self.db._conn.set_trace_callback(statements.append)

        self.db.upsert_source_progress(
            "github",
            status="running",
            phase="search",
            current=2,
            total=7,
            processed=3,
            found=4,
            errors=1,
            message="keyword 2/7",
            processed_increment=2,
            found_increment=3,
            errors_increment=4,
        )

        row = self.db.get_source_progress()[0]
        writes = [
            statement
            for statement in statements
            if statement.lstrip().upper().startswith("INSERT INTO SOURCE_PROGRESS")
        ]
        self.assertEqual(len(writes), 1)
        self.assertEqual(row["status"], "running")
        self.assertEqual(row["phase"], "search")
        self.assertEqual(row["current"], 2)
        self.assertEqual(row["total"], 7)
        self.assertEqual(row["processed"], 5)
        self.assertEqual(row["found"], 7)
        self.assertEqual(row["errors"], 5)
        self.assertEqual(row["message"], "keyword 2/7")
        self.assertTrue(row["heartbeat"])

    def test_unknown_telemetry_field_is_rejected(self):
        with self.assertRaises(TypeError):
            self.db.upsert_source_progress("github", typo_field=1)
        self.assertEqual(self.db.get_source_progress(), [])

    def test_sqlite_failure_rolls_back_the_telemetry_transaction(self):
        self.db.upsert_source_progress(
            "github", status="starting", processed=5, message="before"
        )
        self.db._conn.execute(
            "CREATE TRIGGER fail_progress_update BEFORE UPDATE ON source_progress "
            "BEGIN SELECT RAISE(FAIL, 'injected failure'); END"
        )
        self.db._conn.commit()
        proxy = _ConnectionProxy(self.db._conn)

        @contextmanager
        def connection():
            yield proxy

        with patch.object(self.db, "_get_connection", side_effect=connection):
            with self.assertRaises(sqlite3.DatabaseError):
                self.db.upsert_source_progress(
                    "github",
                    status="running",
                    processed_increment=1,
                    message="after",
                )

        self.assertEqual(proxy.rollback_calls, 1)
        self.db._conn.execute("DROP TRIGGER fail_progress_update")
        self.db._conn.commit()
        row = self.db.get_source_progress()[0]
        self.assertEqual(row["status"], "starting")
        self.assertEqual(row["processed"], 5)
        self.assertEqual(row["message"], "before")

    def test_only_active_statuses_can_be_stale(self):
        stale_heartbeat = (datetime.now() - timedelta(minutes=5)).isoformat()
        for status in ("starting", "running", "disabled", "stopped", "error"):
            self.db.upsert_source_progress(status, status=status)
        with self.db._get_connection() as conn:
            conn.execute(
                "UPDATE source_progress SET heartbeat = ?", (stale_heartbeat,)
            )
            conn.commit()

        rows = {row["source"]: row for row in self.db.get_source_progress(90)}
        self.assertTrue(rows["starting"]["stale"])
        self.assertTrue(rows["running"]["stale"])
        self.assertFalse(rows["disabled"]["stale"])
        self.assertFalse(rows["stopped"]["stale"])

    def test_reap_marks_dead_active_sources_as_stopped(self):
        # fresh heartbeat: не трогаем
        self.db.upsert_source_progress("github", status="running", phase="search")
        # stale active (starting/running/waiting): рейпим
        self.db.upsert_source_progress("gitlab", status="running", phase="fetch")
        self.db.upsert_source_progress("paster", status="starting", phase="startup")
        self.db.upsert_source_progress("gist", status="waiting", phase="retry")
        # не-active: никогда не рейпим
        self.db.upsert_source_progress("pastebin", status="disabled", phase="config")
        self.db.upsert_source_progress("realtime", status="stopped", phase="stopped")
        self.db.upsert_source_progress("mcp", status="error", phase="error")
        old = (datetime.now() - timedelta(minutes=20)).isoformat()
        with self.db._get_connection() as conn:
            conn.execute(
                "UPDATE source_progress SET heartbeat = ? "
                "WHERE source IN ('gitlab','paster','gist','pastebin','realtime','mcp')",
                (old,),
            )
            conn.commit()

        n = self.db.reap_stale_source_progress(stale_after_seconds=600)
        self.assertEqual(n, 3)  # gitlab, paster, gist
        rows = {row["source"]: row["status"] for row in self.db.get_source_progress()}
        self.assertEqual(rows["gitlab"], "stopped")
        self.assertEqual(rows["paster"], "stopped")
        self.assertEqual(rows["gist"], "stopped")
        # живой остался running, не-active не тронуты
        self.assertEqual(rows["github"], "running")
        self.assertEqual(rows["pastebin"], "disabled")
        self.assertEqual(rows["realtime"], "stopped")
        self.assertEqual(rows["mcp"], "error")

    def test_reap_returns_zero_when_nothing_stale(self):
        # свежие heartbeat у active + не-active статусы: рейп не трогает
        self.db.upsert_source_progress("github", status="running", phase="search")
        self.db.upsert_source_progress("gitlab", status="disabled", phase="config")
        self.assertEqual(self.db.reap_stale_source_progress(stale_after_seconds=3600), 0)
        rows = {row["source"]: row["status"] for row in self.db.get_source_progress()}
        self.assertEqual(rows["github"], "running")
        self.assertEqual(rows["gitlab"], "disabled")

class SourceRegistrationResetTests(unittest.TestCase):
    def test_new_run_resets_enabled_and_disabled_source_counters(self):
        handle, db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        try:
            with (
                patch("main_optimized.config.db_path", db_path),
                patch("main_optimized.Dashboard"),
                patch("main_optimized.signal.signal"),
            ):
                first = OptimizedSecretScanner(enable_gist=True)
                first.db.upsert_source_progress(
                    "github",
                    current=8,
                    total=9,
                    processed=7,
                    found=6,
                    errors=5,
                    message="old",
                )
                first.db.upsert_source_progress(
                    "gist",
                    current=4,
                    total=4,
                    processed=3,
                    found=2,
                    errors=1,
                    message="old",
                )
                first.db.upsert_source_progress(
                    "gitlab",
                    current=3,
                    total=3,
                    processed=3,
                    found=3,
                    errors=3,
                    message="old",
                )
                first.db.close()

                restarted = OptimizedSecretScanner(enable_gist=True)
                try:
                    rows = {
                        row["source"]: row
                        for row in restarted.db.get_source_progress()
                    }
                finally:
                    restarted.db.close()

            for source in ("github", "gist", "gitlab"):
                with self.subTest(source=source):
                    row = rows[source]
                    self.assertEqual(row["current"], 0)
                    self.assertEqual(row["total"], 0)
                    self.assertEqual(row["processed"], 0)
                    self.assertEqual(row["found"], 0)
                    self.assertEqual(row["errors"], 0)
                    self.assertEqual(row["message"], "")
            self.assertEqual(rows["github"]["status"], "starting")
            self.assertEqual(rows["gist"]["status"], "starting")
            self.assertEqual(rows["gitlab"]["status"], "disabled")
        finally:
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.remove(db_path + suffix)
                except (FileNotFoundError, PermissionError):
                    pass


if __name__ == "__main__":
    unittest.main()
