import inspect
import queue
import tempfile
import threading
import unittest
from pathlib import Path

from database import Database
from main_optimized import OptimizedSecretScanner
from source_paster import PasterScanner, PageOutcome, parse_archive


ARCHIVE_HTML = """
<a href="/ABC123">Newest paste</a>
<a href="https://paster.sh/DEF456">Older paste</a>
<a href="/archive?page=2">Next</a>
<a href="/ABC123">View</a>
"""


class PasterSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db = Database(str(Path(self.temp_dir.name) / "test.db"))

    def tearDown(self):
        self.db.close()
        self.temp_dir.cleanup()

    def test_parse_archive_returns_unique_paste_codes_in_order(self):
        self.assertEqual(parse_archive(ARCHIVE_HTML), ["ABC123", "DEF456"])

    def test_optimized_scanner_exposes_paster_source_switch(self):
        parameters = inspect.signature(OptimizedSecretScanner.__init__).parameters
        self.assertIn("enable_paster", parameters)

    def test_completed_page_advances_backfill_cursor(self):
        scanner = PasterScanner(queue.Queue(), self.db, threading.Event())
        scanner._process_page = lambda page: PageOutcome.SUCCESS

        self.assertTrue(scanner.run_backfill_page())
        self.assertEqual(self.db.get_source_state("paster_backfill_page"), "2")

    def test_each_sync_page_closes_its_event_loop_session(self):
        scanner = PasterScanner(queue.Queue(), self.db, threading.Event())

        async def fake_page(page):
            await scanner._get_session()
            return True

        scanner._process_page_async = fake_page
        self.assertTrue(scanner._process_page(1))
        self.assertTrue(scanner._session.closed)
        self.assertTrue(scanner._process_page(2))
        self.assertTrue(scanner._session.closed)

    def test_failed_page_does_not_advance_backfill_cursor(self):
        self.db.set_source_state("paster_backfill_page", "4")
        scanner = PasterScanner(queue.Queue(), self.db, threading.Event())
        scanner._process_page = lambda page: PageOutcome.ERROR

        self.assertNotEqual(scanner.run_backfill_page(), PageOutcome.SUCCESS)
        self.assertEqual(self.db.get_source_state("paster_backfill_page"), "4")

    def test_first_page_exhaustion_sets_complete_flag(self):
        self.db.set_source_state("paster_backfill_page", "9")
        scanner = PasterScanner(queue.Queue(), self.db, threading.Event())
        scanner._process_page = lambda page: PageOutcome.EXHAUSTED

        scanner.run()
        self.assertEqual(self.db.get_source_state("paster_backfill_complete"), "1")

    def test_seen_pastes_survive_database_reopen(self):
        self.db.mark_source_item_scanned("paster", "ABC123")
        self.db.close()
        reopened = Database(str(Path(self.temp_dir.name) / "test.db"))
        try:
            self.assertTrue(reopened.is_source_item_scanned("paster", "ABC123"))
        finally:
            reopened.close()

    def test_extracts_key_with_nearby_relay_base_url(self):
        scanner = PasterScanner(queue.Queue(), self.db, threading.Event())
        key = "sk-proj-" + "A7b9C2d4E6f8G1h3J5k7L9m2N4p6Q8r1S3t5U7v9W2x4Y6z8"
        content = (
            '"$schema": "https://opencode.ai/config.json",\n'
            f'"baseURL": "https://relay.example.com/v1",\n'
            f'"apiKey": "{key}"'
        )

        results = scanner._extract_keys(content, "https://paster.sh/ABC123")

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].api_key, key)
        self.assertEqual(results[0].base_url, "https://relay.example.com/v1")
        self.assertTrue(results[0].is_relay)


if __name__ == "__main__":
    unittest.main()
