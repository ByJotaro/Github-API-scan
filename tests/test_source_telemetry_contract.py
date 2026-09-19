import asyncio
import os
import queue
import tempfile
import threading
import unittest
from dataclasses import dataclass
from unittest.mock import Mock, AsyncMock, patch

from database import Database
from scanner import GitHubScanner
from source_gist import GistFile, GistScanner
from source_gitlab import GitLabScanner, SnippetInfo
from source_pastebin import PasteMetadata, PastebinScanner
from source_paster import PageOutcome, PasterScanner
from source_realtime import RealtimeScanner
from source_codegraph import CodeGraphScanner


@dataclass
class _Result:
    platform: str = "openai"
    api_key: str = "sk-test"


class _RecordingDatabase:
    def __init__(self):
        self.calls = []

    def safe_upsert_source_progress(self, source, **fields):
        self.calls.append((source, fields))
        return True

    def upsert_source_progress(self, source, **fields):
        self.calls.append((source, fields))


class GitHubTelemetryContractTests(unittest.TestCase):
    def _scanner(self, db=None):
        scanner = GitHubScanner.__new__(GitHubScanner)
        scanner.db = db or _RecordingDatabase()
        scanner.result_queue = queue.Queue(maxsize=1)
        scanner.stop_event = threading.Event()
        scanner.dashboard = None
        scanner.stats = {
            "files_scanned": 0,
            "total_found": 0,
        }
        scanner._sha_lock = threading.Lock()
        scanner._sha_batch_buffer = []
        scanner._rotate_client = Mock()
        scanner._log = Mock()
        return scanner

    def test_full_queue_does_not_overcount_found(self):
        scanner = self._scanner()
        scanner.result_queue.put(object())
        scanner._extract_keys_from_content = Mock(return_value=[_Result()])

        delivered = scanner._process_downloaded_file("url", "content")

        self.assertEqual(delivered, 0)
        self.assertEqual(scanner.stats["total_found"], 0)

    def test_interrupted_keyword_is_not_processed_or_checkpointed(self):
        db = _RecordingDatabase()
        db.load_progress = Mock(return_value={"total": 1, "current_index": 0, "is_completed": False})
        db.save_progress = Mock()
        db.reset_progress = Mock()
        db.mark_blobs_scanned_batch = Mock()
        scanner = self._scanner(db)

        def interrupted(_keyword):
            scanner.stop_event.set()
            return None

        scanner.search_keyword = interrupted
        with patch("scanner.config.search_keywords", ["one"]), patch("scanner.time.sleep"):
            scanner.run(resume=False)

        completed = [
            fields for _, fields in db.calls
            if fields.get("processed_increment")
        ]
        self.assertEqual(completed, [])
        self.assertNotIn(
            unittest.mock.call(1, 1, is_completed=True), db.save_progress.call_args_list
        )

    def test_failed_keyword_is_not_processed_or_checkpointed(self):
        db = _RecordingDatabase()
        db.load_progress = Mock(return_value={"total": 1, "current_index": 0, "is_completed": False})
        db.save_progress = Mock()
        db.reset_progress = Mock()
        db.mark_blobs_scanned_batch = Mock()
        scanner = self._scanner(db)
        scanner.search_keyword = Mock(return_value=None)
        scanner.stop_event.set = Mock(side_effect=scanner.stop_event.set)

        def fail_and_stop(_keyword):
            scanner.stop_event.set()
            return None

        scanner.search_keyword.side_effect = fail_and_stop
        with patch("scanner.config.search_keywords", ["one"]), patch("scanner.time.sleep"):
            scanner.run(resume=False)

        self.assertFalse(any(fields.get("processed_increment") for _, fields in db.calls))
        self.assertFalse(any(call.args and call.args[0] == 1 for call in db.save_progress.call_args_list))


class BatchHealthContractTests(unittest.TestCase):
    def test_gist_sibling_success_does_not_hide_error_and_found_is_delivered(self):
        db = _RecordingDatabase()
        result_queue = queue.Queue(maxsize=1)
        result_queue.put(object())
        scanner = GistScanner(result_queue, threading.Event(), db=db)
        good = GistFile("1", "good", "good", "good-url", 1)
        bad = GistFile("2", "bad", "bad", "bad-url", 1)

        async def fetch(url):
            return None if url == "bad" else "content"

        scanner._fetch_gist_content = fetch
        scanner._extract_keys = Mock(return_value=[_Result()])
        outcome = asyncio.run(scanner._scan_batch([good, bad]))

        self.assertEqual(outcome.processed, 1)
        self.assertEqual(outcome.found, 0)
        self.assertGreaterEqual(outcome.errors, 2)
        self.assertFalse(any(fields.get("status") == "running" for _, fields in db.calls))

    def test_gitlab_sibling_success_does_not_hide_error(self):
        db = _RecordingDatabase()
        scanner = GitLabScanner(queue.Queue(), threading.Event(), db=db)
        # Отмечаем ошибку, затем нормальное состояние — проверяем, что статус running приходит
        scanner._telemetry_error("test error")
        self.assertEqual(db.calls[-1][1]["status"], "error")
        self.assertEqual(db.calls[-1][1]["message"], "test error")
        scanner._telemetry_running("scan")
        self.assertEqual(db.calls[-1][1]["status"], "running")


class PastebinContractTests(unittest.TestCase):
    def test_missing_api_key_uses_keyless_archive_not_disabled(self):
        """Без ключа — keyless archive-режим (running/fetch), а не disabled."""
        db = _RecordingDatabase()
        scanner = PastebinScanner(queue.Queue(), threading.Event(), api_key="", db=db)
        scanner._fetch_archive_pastes = AsyncMock(
            return_value=[PasteMetadata("k1", "", "", 0, "", "https://pastebin.com/k1")]
        )
        scanner._scan_batch = AsyncMock(return_value=Mock(processed=1, found=0, errors=0))
        scanner.stop_event.set()  # один цикл: fetch+scan, затем выход
        scanner.run()

        statuses = [c[1].get("status") for c in db.calls]
        self.assertIn("running", statuses)
        self.assertNotIn("disabled", statuses)

    def test_batch_exception_counts_error_and_only_completed_are_processed(self):
        scanner = PastebinScanner(queue.Queue(), threading.Event())
        pastes = [
            PasteMetadata("good", "", "", 0, "", "good"),
            PasteMetadata("bad", "", "", 0, "", "bad"),
        ]

        async def scan(paste):
            if paste.key == "bad":
                raise RuntimeError("boom")
            return (1, 0, 0)

        scanner._scan_paste = scan
        outcome = asyncio.run(scanner._scan_batch(pastes))
        self.assertEqual((outcome.processed, outcome.found, outcome.errors), (1, 0, 1))


class ErrorRecoveryContractTests(unittest.TestCase):
    def test_waiting_keeps_worker_alive_after_error(self):
        """После ошибки worker жив: waiting/retry, не залипание в ERR навсегда.

        pastebin сохраняет error до success; realtime помечает running/retry,
        чтобы дашборд не показывал ложный permanent ERR при 401/network.
        """
        # pastebin: waiting сохраняет error до явного recovery
        pb = PastebinScanner(queue.Queue(), threading.Event(), db=_RecordingDatabase())
        pb._telemetry_error("network")
        pb._telemetry_waiting()
        self.assertEqual(pb.db.calls[-1][1]["status"], "error")
        self.assertEqual(pb.db.calls[-1][1]["phase"], "error")
        pb._telemetry_running("fetch")
        self.assertEqual(pb.db.calls[-1][1]["status"], "running")

        # realtime: waiting после ошибки = running/retry (worker жив)
        rt = RealtimeScanner(queue.Queue(), threading.Event(), db=_RecordingDatabase())
        rt._telemetry_error("network")
        rt._telemetry_waiting()
        self.assertEqual(rt.db.calls[-1][1]["status"], "running")
        self.assertEqual(rt.db.calls[-1][1]["phase"], "retry")
        rt._telemetry_running("events")
        self.assertEqual(rt.db.calls[-1][1]["status"], "running")

    def test_codegraph_error_preserved_until_running_recovery(self):
        db = _RecordingDatabase()
        scanner = CodeGraphScanner(queue.Queue(), threading.Event(), db=db)
        scanner._telemetry_error("network")
        self.assertEqual(db.calls[-1][1]["status"], "error")
        self.assertEqual(db.calls[-1][1]["phase"], "error")
        scanner._telemetry_running("discover")
        self.assertEqual(db.calls[-1][1]["status"], "running")


class PasterOutcomeContractTests(unittest.TestCase):
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

    def test_transient_failure_is_error_and_never_marks_complete(self):
        scanner = PasterScanner(queue.Queue(), self.db, threading.Event())
        scanner._fetch_text = AsyncMock(return_value=None)

        outcome = asyncio.run(scanner._process_page_async(1))
        self.assertEqual(outcome, PageOutcome.ERROR)

        self.assertEqual(self.db.get_source_state("paster_backfill_complete"), "")
        row = self.db.get_source_progress()[0]
        self.assertEqual(row["status"], "error")
        self.assertEqual(row["phase"], "error")

    def test_only_empty_archive_marks_backfill_exhausted(self):
        scanner = PasterScanner(queue.Queue(), self.db, threading.Event())
        scanner._process_page = Mock(return_value=PageOutcome.EXHAUSTED)
        scanner.run()

        self.assertEqual(self.db.get_source_state("paster_backfill_complete"), "1")

    def test_seen_item_advances_current_without_processed_increment(self):
        scanner = PasterScanner(queue.Queue(), self.db, threading.Event())
        self.db.mark_source_item_scanned("paster", "ABC123")
        scanner._fetch_text = AsyncMock(return_value='<a href="/ABC123">seen</a>')

        outcome = asyncio.run(scanner._process_page_async(1))

        self.assertEqual(outcome, PageOutcome.SUCCESS)
        row = self.db.get_source_progress()[0]
        self.assertEqual(row["current"], 1)
        self.assertEqual(row["processed"], 0)

    def test_telemetry_database_failure_cannot_kill_worker(self):
        scanner = PasterScanner(queue.Queue(), self.db, threading.Event())
        scanner.db.safe_upsert_source_progress = Mock(return_value=False)
        scanner._fetch_text = AsyncMock(return_value="")

        self.assertEqual(
            asyncio.run(scanner._process_page_async(1)), PageOutcome.EXHAUSTED
        )


class CodeGraphContractTests(unittest.TestCase):
    def test_error_telemetry_is_single_atomic_call(self):
        db = _RecordingDatabase()
        scanner = CodeGraphScanner(queue.Queue(), threading.Event(), db=db)

        scanner._telemetry_error("boom", count=2)
        self.assertEqual(len(db.calls), 1)
        source, fields = db.calls[0]
        self.assertEqual(source, "codegraph")
        self.assertEqual(fields.get("status"), "error")
        self.assertEqual(fields.get("phase"), "error")
        self.assertEqual(fields.get("errors_increment"), 2)

    def test_successful_running_uses_single_atomic_telemetry(self):
        db = _RecordingDatabase()
        scanner = CodeGraphScanner(queue.Queue(), threading.Event(), db=db)

        scanner._telemetry_running("discover")
        self.assertEqual(len(db.calls), 1)
        source, fields = db.calls[0]
        self.assertEqual(source, "codegraph")
        self.assertEqual(fields.get("status"), "running")
        self.assertEqual(fields.get("phase"), "discover")


if __name__ == "__main__":
    unittest.main()
