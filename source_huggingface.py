"""HuggingFace: полнотекстовый поиск по коду датасетов, Spaces и моделей.

Публичный индекс HuggingFace (/api/search/full-text) ищет прямо по
содержимому файлов репозиториев и отдаёт имя репозитория, файл и сниппет
вокруг совпадения — без токена. Это точнее, чем поиск по названиям:
демо-Spaces регулярно содержат захардкоженные ключи (GitGuardian 2025:
утечки давно вышли за GitHub).
"""

from urllib.parse import quote

from config import config
from database import Database
from source_common import BaseSourceScanner, extract_key_results, start_source_thread

HF_API = "https://huggingface.co/api"
# Алфавит расширения запроса: индексируются только top-N хитов на запрос.
QUERY_SUFFIXES = "abcdefghijklmnopqrstuvwxyz0123456789_-."
RAW_BASE = {
    "space": "https://huggingface.co/spaces/{repo}/raw/main/{path}",
    "dataset": "https://huggingface.co/datasets/{repo}/raw/main/{path}",
    "model": "https://huggingface.co/{repo}/raw/main/{path}",
}
BLOB_BASE = {
    "space": "https://huggingface.co/spaces/{repo}/blob/main/{path}",
    "dataset": "https://huggingface.co/datasets/{repo}/blob/main/{path}",
    "model": "https://huggingface.co/{repo}/blob/main/{path}",
}


class HuggingFaceScanner(BaseSourceScanner):
    name = "huggingface"
    poll_interval = 600.0
    # Space/dataset дописывают файлы после нашего визита; без окна каждый
    # hit помечался навсегда и полный обход слайсов «выбирал» индекс за час.
    rescan_hours = 7 * 24

    def __init__(self, result_queue, db: Database, stop_event, dashboard=None,
                 queries=None, per_query: int = 10, subs_per_cycle: int = 6):
        super().__init__(result_queue, db, stop_event, dashboard)
        self.queries = list(queries or getattr(
            config, "huggingface_queries", []) or [])
        self.per_query = per_query
        self.subs_per_cycle = subs_per_cycle
        self._cursor_key = "huggingface_sub_idx"

    def _subqueries(self):
        """Плоский список подзапросов: префикс ключа + символ алфавита.

        HF-индекс отдаёт только top-N и игнорирует offset (проверено:
        offset=0/50/200 -> байт-идентичная выдача), поэтому глубина
        достигается разбиением запроса, а не страницами.
        """
        return [q + s for q in self.queries for s in QUERY_SUFFIXES]

    def _next_slice(self):
        """Круговая нарезка подзапросов: каждый цикл — следующие N."""
        subs = self._subqueries()
        if not subs:
            return []
        raw = self.db.get_source_state(self._cursor_key)
        idx = int(raw) if raw and raw.isdigit() else 0
        idx %= len(subs)
        take = min(self.subs_per_cycle, len(subs))
        chunk = [subs[(idx + i) % len(subs)] for i in range(take)]
        self.db.set_source_state(self._cursor_key,
                                 str((idx + take) % len(subs)))
        return chunk

    async def _scan_hit(self, session, hit: dict) -> None:
        kind = hit.get("type") or ""
        repo = hit.get("name") or ""
        path = hit.get("fileName") or ""
        if kind not in RAW_BASE or not repo or not path:
            return
        item_id = f"{kind}/{repo}/{path}@{hit.get('repoId', '')}"
        if self._item_seen(item_id):
            return
        content = await self._fetch_text(
            RAW_BASE[kind].format(repo=repo, path=quote(path)), session=session)
        self._mark_item(item_id)
        if not content:
            return
        self.stats["items"] += 1
        results = extract_key_results(
            content, BLOB_BASE[kind].format(repo=repo, path=path), db=self.db)
        if results:
            self._log(f"{repo}/{path}: ключей {len(results)}")
        self._emit(results)

    async def _cycle(self, session) -> None:
        for query in self._next_slice():
            payload = await self._fetch_json(
                f"{HF_API}/search/full-text?q={quote(query)}"
                f"&limit={self.per_query}", session=session)
            if not isinstance(payload, dict):
                continue
            for hit in payload.get("hits") or []:
                if self.stop_event.is_set():
                    return
                await self._scan_hit(session, hit)


def start_huggingface_scanner(result_queue, db: Database, stop_event,
                              dashboard=None, **kwargs):
    scanner = HuggingFaceScanner(result_queue, db, stop_event, dashboard,
                                 **kwargs)
    return start_source_thread(scanner)
