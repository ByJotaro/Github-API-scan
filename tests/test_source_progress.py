import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta
from queue import Queue
from threading import Event
from unittest.mock import patch

from database import Database
from main_optimized import OptimizedSecretScanner
import scanner
from scanner import GitHubScanner
from source_gist import GistScanner
from source_gitlab import GitLabScanner
from source_pastebin import PastebinScanner
from source_realtime import RealtimeScanner
from source_codegraph import CodeGraphScanner


SOURCES = {
    "github",
    "paster",
    "pastebin",
    "gist",
    "gitlab",
    "realtime",
    "mcp",
    "codegraph",
}


class SourceProgressDatabaseTests(unittest.TestCase):
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

    def test_source_progress_schema(self):
        with sqlite3.connect(self.db_path) as conn:
            columns = {
                row[1]: row[5]
                for row in conn.execute("PRAGMA table_info(source_progress)")
            }

        self.assertEqual(
            set(columns),
            {
                "source",
                "status",
                "phase",
                "current",
                "total",
                "processed",
                "found",
                "errors",
                "message",
                "heartbeat",
            },
        )
        self.assertEqual(columns["source"], 1)

    def test_upsert_preserves_counters_and_increment_is_atomic(self):
        self.db.upsert_source_progress(
            "github",
            status="starting",
            phase="startup",
            current=2,
            total=9,
            processed=3,
            found=1,
            errors=0,
            message="initializing",
        )
        first = self.db.get_source_progress()[0]

        self.db.upsert_source_progress("github", status="running", phase="search")
        self.db.increment_source_progress("github", processed=2, found=3, errors=1)
        row = self.db.get_source_progress()[0]

        self.assertEqual(row["status"], "running")
        self.assertEqual(row["phase"], "search")
        self.assertEqual(row["current"], 2)
        self.assertEqual(row["total"], 9)
        self.assertEqual(row["processed"], 5)
        self.assertEqual(row["found"], 4)
        self.assertEqual(row["errors"], 1)
        self.assertGreaterEqual(row["heartbeat"], first["heartbeat"])

    def test_progress_persists_across_database_instances(self):
        self.db.upsert_source_progress(
            "gitlab", status="error", errors=4, message="network failure"
        )
        self.db.close()

        reopened = Database(self.db_path)
        try:
            rows = reopened.get_source_progress()
        finally:
            reopened.close()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], "gitlab")
        self.assertEqual(rows[0]["status"], "error")
        self.assertEqual(rows[0]["errors"], 4)
        self.assertEqual(rows[0]["message"], "network failure")

    def test_stale_is_computed_from_heartbeat(self):
        self.db.upsert_source_progress("github", status="running")
        stale_heartbeat = (datetime.now() - timedelta(seconds=120)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE source_progress SET heartbeat = ? WHERE source = ?",
                (stale_heartbeat, "github"),
            )

        self.assertTrue(self.db.get_source_progress(stale_after_seconds=90)[0]["stale"])
        self.assertFalse(self.db.get_source_progress(stale_after_seconds=180)[0]["stale"])


class SourceRuntimeTelemetryTests(unittest.TestCase):
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

    def test_runtime_error_transitions_are_sanitized_and_recover(self):
        scanners = (
            ("gist", GistScanner(Queue(), Event(), db=self.db)),
            ("gitlab", GitLabScanner(Queue(), Event(), db=self.db)),
            ("pastebin", PastebinScanner(Queue(), Event(), db=self.db)),
            ("codegraph", CodeGraphScanner(Queue(), Event(), db=self.db)),
            ("realtime", RealtimeScanner(Queue(), Event(), db=self.db)),
        )

        for source, scanner in scanners:
            with self.subTest(source=source):
                scanner._telemetry_error("request failed (TimeoutError)")
                row = next(
                    item for item in self.db.get_source_progress()
                    if item["source"] == source
                )
                self.assertEqual(row["status"], "error")
                self.assertEqual(row["phase"], "error")
                self.assertEqual(row["errors"], 1)
                self.assertEqual(row["message"], "request failed (TimeoutError)")

                scanner._telemetry_running("fetch")
                row = next(
                    item for item in self.db.get_source_progress()
                    if item["source"] == source
                )
                self.assertEqual(row["status"], "running")
                self.assertEqual(row["phase"], "fetch")
                self.assertEqual(row["message"], "")
                self.assertEqual(row["errors"], 1)


class GitHubTelemetryTests(unittest.TestCase):
    def test_completed_keyword_increments_once(self):
        handle, db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        db = Database(db_path)
        try:
            db.safe_upsert_source_progress("github", status="running", phase="search",
                                           current=0, total=1, message="")
            # Один keyword завершён: processed +1, found +=3 за единственный вызов.
            db.safe_upsert_source_progress("github", status="running", phase="search",
                                           current=1, message="",
                                           processed_increment=1, found_increment=3)
            row = db.get_source_progress()[0]
        finally:
            db.close()
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.remove(db_path + suffix)
                except (FileNotFoundError, PermissionError):
                    pass

        self.assertEqual(row["processed"], 1)
        self.assertEqual(row["found"], 3)
        self.assertEqual(row["current"], 1)


class SourceRegistrationTests(unittest.TestCase):
    @patch("main_optimized.Dashboard")
    @patch("main_optimized.Database")
    def test_registers_all_seven_sources_with_enabled_states(self, database_cls, _dashboard):
        scanner = OptimizedSecretScanner(
            enable_paster=True,
            enable_pastebin=False,
            enable_gist=True,
            enable_gitlab=False,
            enable_realtime=False,
            enable_mcp=True,
            enable_codegraph=True,
        )

        calls = database_cls.return_value.upsert_source_progress.call_args_list
        statuses = {call.args[0]: call.kwargs["status"] for call in calls}

        self.assertEqual(set(statuses), SOURCES)
        self.assertEqual(len(calls), 8)
        self.assertEqual(statuses["github"], "starting")
        self.assertEqual(statuses["paster"], "starting")
        self.assertEqual(statuses["gist"], "starting")
        self.assertEqual(statuses["pastebin"], "disabled")
        self.assertEqual(statuses["gitlab"], "disabled")
        self.assertEqual(statuses["realtime"], "disabled")
        self.assertEqual(statuses["mcp"], "starting")
        self.assertEqual(statuses["codegraph"], "starting")


if __name__ == "__main__":
    unittest.main()
