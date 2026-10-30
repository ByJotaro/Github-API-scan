"""Telegram: публичные веб-превью каналов (t.me/s/<channel>).

Telegram-каналы с дампами и «free keys» — заметная часть утечек, но Bot API
и клиентский API требуют авторизации. Публичное превью t.me/s/<channel>
отдаёт последние сообщения обычным HTML без токенов и аккаунта — этого
достаточно, чтобы вытаскивать ключи из текста постов.
"""

import html as html_lib
import re
from typing import List, Tuple

from config import config
from database import Database
from source_common import BaseSourceScanner, start_source_thread
from source_search import load_discovered_channels

PREVIEW_URL = "https://t.me/s/{channel}"
MESSAGE_SPLIT_RE = re.compile(r'data-post="[^"/]+/(\d+)"')
TEXT_START_RE = re.compile(
    r'class="[^"]*js-message_text[^"]*"[^>]*>', re.IGNORECASE)
TAG_RE = re.compile(r"<[^>]+>")


def _balanced_div_end(html: str, start: int) -> int:
    """Индекс закрывающего </div> для блока, начатого после start."""
    depth = 1
    pos = start
    while pos < len(html):
        next_open = html.find("<div", pos)
        next_close = html.find("</div>", pos)
        if next_close == -1:
            return len(html)
        if next_open != -1 and next_open < next_close:
            depth += 1
            pos = next_open + 4
            continue
        depth -= 1
        if depth == 0:
            return next_close
        pos = next_close + 6
    return len(html)


def extract_messages(page: str) -> List[Tuple[int, str]]:
    """[(message_id, text)] из HTML-превью канала."""
    marks = [(int(m.group(1)), m.start()) for m in MESSAGE_SPLIT_RE.finditer(page)]
    messages: List[Tuple[int, str]] = []
    for index, (message_id, pos) in enumerate(marks):
        end = marks[index + 1][1] if index + 1 < len(marks) else len(page)
        block = page[pos:end]
        text_start = TEXT_START_RE.search(block)
        if not text_start:
            continue
        body_start = pos + text_start.end()
        body_end = _balanced_div_end(page, body_start)
        raw = page[body_start:body_end]
        raw = raw.replace("<br/>", "\n").replace("<br>", "\n")
        text = html_lib.unescape(TAG_RE.sub("", raw))
        if text.strip():
            messages.append((message_id, text))
    return messages


class TelegramScanner(BaseSourceScanner):
    name = "telegram"
    poll_interval = 180.0

    def __init__(self, result_queue, db: Database, stop_event,
                 dashboard=None, channels=None):
        super().__init__(result_queue, db, stop_event, dashboard)
        self.channels = list(channels or getattr(config, "telegram_channels", []) or [])

    def _cursor_key(self, channel: str) -> str:
        return f"telegram_last_{channel}"

    def _active_channels(self) -> list:
        """Настроенные каналы + найденные веб-поиском (без дублей, с лимитом)."""
        cap = getattr(config, "telegram_discovered_cap", 30)
        merged = list(self.channels)
        for channel in load_discovered_channels(self.db):
            if len(merged) >= len(self.channels) + cap:
                break
            if channel not in merged:
                merged.append(channel)
        return merged

    async def _cycle(self, session) -> None:
        for channel in self._active_channels():
            if self.stop_event.is_set():
                return
            page = await self._fetch_text(
                PREVIEW_URL.format(channel=channel), session=session)
            if page is None:
                self.stats["errors"] += 1
                self._log(f"{channel}: превью недоступно", "WARN")
                continue
            messages = extract_messages(page)
            if not messages:
                continue
            raw_cursor = self.db.get_source_state(self._cursor_key(channel))
            cursor = int(raw_cursor) if raw_cursor and raw_cursor.isdigit() else 0
            fresh = [(mid, text) for mid, text in messages if mid > cursor]
            for message_id, text in fresh:
                item_id = f"{channel}/{message_id}"
                self.stats["items"] += 1
                if self._item_seen(item_id):
                    continue
                from source_common import extract_key_results
                results = extract_key_results(
                    text, f"https://t.me/{channel}/{message_id}", db=self.db)
                self._emit(results)
                self._mark_item(item_id)
            if fresh:
                newest = max(mid for mid, _ in fresh)
                self.db.set_source_state(self._cursor_key(channel), str(newest))
                self._log(f"{channel}: новых сообщений {len(fresh)}")


def start_telegram_scanner(result_queue, db: Database, stop_event,
                           dashboard=None, channels=None):
    scanner = TelegramScanner(result_queue, db, stop_event, dashboard,
                              channels=channels)
    return start_source_thread(scanner)
