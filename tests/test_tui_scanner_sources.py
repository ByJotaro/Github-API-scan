import sys
import unittest

import tui_app


class TuiScannerSourcesTests(unittest.TestCase):
    def test_tui_scanner_command_enables_all_sources(self):
        self.assertEqual(
            tui_app._scanner_command(),
            [sys.executable, tui_app.MAIN, "--all-sources"],
        )


if __name__ == "__main__":
    unittest.main()
