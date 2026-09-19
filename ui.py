"""
Headless dashboard stub for scanner workers.

The old Rich Live TUI was removed. Operator UI is Textual (`tui_app.py` /
`start_tui.bat`). Workers still call dashboard.add_log / update_stats /
add_valid_key — those write to scanner.log (and optionally stderr).
"""

from __future__ import annotations

import os
import sys
import threading
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional
from collections import deque


@dataclass
class DashboardStats:
    total_scanned: int = 0
    total_keys_found: int = 0
    valid_keys: int = 0
    invalid_keys: int = 0
    quota_exceeded: int = 0
    connection_errors: int = 0
    queue_size: int = 0
    skipped_low_entropy: int = 0
    skipped_blacklist: int = 0
    skipped_duplicate: int = 0
    current_keyword: str = ""
    current_token_index: int = 0
    total_tokens: int = 0
    is_running: bool = True


@dataclass
class ValidKeyRecord:
    platform: str
    masked_key: str
    balance: str
    source: str
    found_time: str
    is_high_value: bool = False


class Dashboard:
    """Headless dashboard: log-to-file, no terminal Live UI."""

    def __init__(self, echo_stderr: bool = False) -> None:
        self.stats = DashboardStats()
        self.valid_keys: List[ValidKeyRecord] = []
        self.logs: Deque[str] = deque(maxlen=50)
        self._lock = threading.Lock()
        self._echo = echo_stderr or os.environ.get("SCANNER_ECHO", "").lower() in (
            "1", "true", "yes",
        )
        self._log_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "scanner.log"
        )

    def add_log(self, message: str, level: str = "INFO") -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"{timestamp} [{level}] {message}"
        with self._lock:
            self.logs.append(formatted)
        try:
            line = (
                f"{datetime.now():%Y-%m-%d %H:%M:%S} | {level: <8} | {message}\n"
            )
            with open(self._log_path, "a", encoding="utf-8") as fh:
                fh.write(line)
        except OSError:
            pass
        if self._echo:
            try:
                print(formatted, file=sys.stderr, flush=True)
            except Exception:
                pass

    def add_valid_key(
        self,
        platform: str,
        masked_key: str,
        balance: str,
        source: str,
        is_high_value: bool = False,
    ) -> None:
        record = ValidKeyRecord(
            platform=platform,
            masked_key=masked_key,
            balance=balance,
            source=source,
            found_time=datetime.now().strftime("%H:%M:%S"),
            is_high_value=is_high_value,
        )
        with self._lock:
            self.valid_keys.append(record)
            self.stats.valid_keys += 1
        tag = "HIGH" if is_high_value else "VALID"
        self.add_log(
            f"{tag} {platform} {masked_key} balance={balance} src={source}",
            tag,
        )

    def update_stats(self, **kwargs: Any) -> None:
        """Same semantics as the old Rich dashboard (int fields accumulate)."""
        with self._lock:
            for key, value in kwargs.items():
                if not hasattr(self.stats, key):
                    continue
                if isinstance(value, bool) or key == "is_running":
                    setattr(self.stats, key, value)
                elif (
                    isinstance(value, int)
                    and key
                    not in ("current_token_index", "total_tokens", "queue_size")
                ):
                    setattr(self.stats, key, getattr(self.stats, key) + value)
                else:
                    setattr(self.stats, key, value)

    def increment_stat(self, stat_name: str, amount: int = 1) -> None:
        with self._lock:
            if hasattr(self.stats, stat_name):
                cur = getattr(self.stats, stat_name)
                if isinstance(cur, int):
                    setattr(self.stats, stat_name, cur + amount)

    @contextmanager
    def start(self):
        """Context manager replacing Rich Live — no terminal UI."""
        self.stats.is_running = True
        self.add_log("Headless scanner UI (use start_tui.bat / tui_app.py for TUI)", "INFO")
        try:
            yield self
        finally:
            self.stop()

    def refresh(self) -> None:
        return

    def stop(self) -> None:
        with self._lock:
            self.stats.is_running = False


dashboard = Dashboard()
