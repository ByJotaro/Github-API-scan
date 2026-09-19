#!/usr/bin/env python3
"""GitHub Secret Scanner Pro - TUI v2.

Полная переработка интерфейса: фиксированная панель статуса, дашборд с
прогрессом сканирования и разбивкой по платформам/статусам, таблица ключей с
фильтрами/поиском/сортировкой/детальной панелью, управление сканером и БД,
экспорт (TXT/CSV/JSON), просмотр конфигурации и живой лог.

Запуск:
    python tui_app.py
Переменные окружения:
    TUI_AUTOSTART=0   не запускать сканер автоматически при старте TUI
    TUI_INTERVAL=2    частота авто-обновления (сек)
"""

import csv
import json
import os
import threading
import time
import sqlite3
import subprocess
import sys
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from textual import on
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.theme import Theme
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

# Тёмная тема по умолчанию: нейтральный slate, акцент только на active/focus
_SCANNER_DARK = Theme(
    name="scanner-dark",
    primary="#94a3b8",       # slate-400 — нейтральный, не cyan
    secondary="#64748b",     # slate-500
    accent="#38bdf8",        # sky-400 — только для focus/active
    warning="#fbbf24",
    error="#f87171",
    success="#4ade80",
    foreground="#f1f5f9",    # slate-100 — высокий контраст текста
    background="#0a0a0b",    # почти чёрный
    surface="#141416",       # card bg
    panel="#1c1c1f",         # elevated
    boost="#0f0f12",
    dark=True,
    luminosity_spread=0.12,
    text_alpha=0.95,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE_DIR, os.environ.get("TUI_DB", "leaked_keys.db"))
LOG = os.path.join(BASE_DIR, "scanner.log")
MAIN = os.path.join(BASE_DIR, "main_optimized.py")
CONFIG_LOCAL_PATH = os.path.abspath(os.path.join(BASE_DIR, "config_local.py"))
CONFIG_LOCAL_EXAMPLE = os.path.abspath(
    os.path.join(BASE_DIR, "config_local.py.example")
)

try:
    from tui_i18n import (
        t as _t,
        tf as _tf,
        resolve_lang as _resolve_lang,
        load_lang_pref as _load_lang_pref,
        save_lang_pref as _save_lang_pref,
        detect_system_lang as _detect_system_lang,
    )
except Exception:
    def _t(key: str, lang=None) -> str:
        return key
    def _tf(key: str, lang=None, **kwargs) -> str:
        try:
            return key.format(**kwargs)
        except Exception:
            return key
    def _resolve_lang(pref=None) -> str:
        return "en"
    def _load_lang_pref() -> str:
        return "auto"
    def _save_lang_pref(pref: str) -> None:
        return None
    def _detect_system_lang() -> str:
        return "en"


def _scanner_command() -> List[str]:
    return [sys.executable, MAIN, "--all-sources"]


def _configured_github_tokens() -> List[str]:
    """Список непустых GitHub-токенов из config / config_local / env."""
    try:
        import config as _cfg_mod
        cfg = getattr(_cfg_mod, "config", None)
        raw = list(getattr(cfg, "github_tokens", None) or [])
    except Exception:
        raw = []
    env = os.environ.get("GITHUB_TOKENS", "")
    if env:
        raw.extend(t.strip() for t in env.split(","))
    out: List[str] = []
    seen = set()
    for t in raw:
        s = (t or "").strip()
        if not s or s.startswith("#") or s in seen:
            continue
        # placeholders from example
        if "xxxx" in s.lower() or s.endswith("xxxx"):
            continue
        seen.add(s)
        out.append(s)
    return out


def _probe_github_token(token: str, timeout: float = 2.0) -> bool:
    """True если token отвечает 200 на /rate_limit (не 401/403)."""
    try:
        import urllib.request
        req = urllib.request.Request(
            "https://api.github.com/rate_limit",
            headers={
                "Authorization": f"token {token}",
                "User-Agent": "SecretScannerPro-token-check",
                "Accept": "application/vnd.github+json",
            },
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= int(resp.status) < 300
    except Exception:
        return False


def _github_token_health(max_probe: int = 3) -> Dict[str, Any]:
    """Сводка: configured / working / paths (без утечки самих токенов).

    Fail-fast: stop probing after first working token. Short timeout.
    Call ONLY from a worker thread — never on the Textual UI loop.
    """
    toks = _configured_github_tokens()
    working = 0
    probed = 0
    for t in toks[:max_probe]:
        probed += 1
        if _probe_github_token(t, timeout=2.0):
            working += 1
            break  # one live token is enough
    return {
        "configured": len(toks),
        "probed": probed,
        "working": working,
        "config_local_path": CONFIG_LOCAL_PATH,
        "config_local_exists": os.path.isfile(CONFIG_LOCAL_PATH),
        "example_path": CONFIG_LOCAL_EXAMPLE,
        "env_set": bool(os.environ.get("GITHUB_TOKENS", "").strip()),
    }


class GitHubTokenNotice(ModalScreen[None]):
    """Модалка: нет рабочих GitHub-токенов — язык UI, OK, клик по фону закрывает."""

    BINDINGS = [
        Binding("escape", "dismiss_notice", "OK", show=False),
        Binding("enter", "dismiss_notice", "OK", show=False),
    ]

    CSS = """
    GitHubTokenNotice {
        align: center middle;
    }
    #gh_notice {
        width: 88;
        max-width: 96;
        height: auto;
        max-height: 28;
        background: $surface;
        border: tall $error;
        padding: 1 2;
    }
    #gh_notice_title {
        text-style: bold;
        color: $error;
        padding: 0 0 1 0;
        height: auto;
    }
    #gh_notice_body {
        color: $foreground;
        height: auto;
        padding: 0 0 1 0;
    }
    #gh_notice_path {
        color: $accent;
        text-style: bold;
        padding: 0 0 1 0;
        height: auto;
    }
    #gh_notice_help {
        height: auto;
        color: $text-muted;
    }
    #gh_notice_btns {
        height: 3;
        width: 100%;
        align: center middle;
        padding: 1 0 0 0;
    }
    #gh_ok {
        min-width: 18;
        width: auto;
        height: 3;
        min-height: 3;
        background: $success;
        color: $foreground;
        border: tall $success;
        content-align: center middle;
    }
    #gh_ok:hover {
        background: $success 80%;
    }
    #gh_ok:focus {
        border: tall $accent;
    }
    """

    def __init__(self, health: Dict[str, Any], lang: str | None = None) -> None:
        super().__init__()
        self._health = health
        self._lang = lang or _resolve_lang()

    def compose(self) -> ComposeResult:
        h = self._health
        conf = int(h.get("configured") or 0)
        work = int(h.get("working") or 0)
        path = h.get("config_local_path") or CONFIG_LOCAL_PATH
        exists = bool(h.get("config_local_exists"))
        ru = self._lang == "ru"

        if ru:
            title = "⚠  Нужны рабочие GitHub-токены"
            if conf == 0:
                status = "[bold red]GitHub-токены не заданы[/]"
            else:
                status = (
                    f"[bold yellow]Задано токенов: {conf}, рабочих: {work}[/]"
                )
            body = (
                f"{status}\n\n"
                "Для GitHub Code Search / Gist нужен рабочий Personal Access Token.\n"
                "Без него GitHub-источники деградируют (только public / 401).\n"
                "Остальные источники (Paster, Pastebin, GitLab, MCP, CodeGraph) работают.\n\n"
                "[bold]Положите токены сюда:[/]"
            )
            file_s = "файл есть" if exists else "файла нет — создайте"
            help_s = (
                f"{file_s}\n\n"
                "[dim]# config_local.py\n"
                "GITHUB_TOKENS = [\n"
                '    "ghp_ВАШ_ТОКЕН",\n'
                "]\n\n"
                "Или env:  set GITHUB_TOKENS=ghp_xxx,ghp_yyy\n"
                "Создать токен: https://github.com/settings/tokens\n"
                f"(classic · public_repo)\nШаблон: {CONFIG_LOCAL_EXAMPLE}[/]"
            )
            ok_label = "OK"
        else:
            title = "⚠  Working GitHub tokens required"
            if conf == 0:
                status = "[bold red]No GitHub tokens configured[/]"
            else:
                status = (
                    f"[bold yellow]{conf} token(s) configured, {work} working[/]"
                )
            body = (
                f"{status}\n\n"
                "GitHub Code Search / Gist need a valid Personal Access Token.\n"
                "Without it, GitHub-backed sources stay degraded (public-only / 401).\n"
                "Other sources (Paster, Pastebin, GitLab, MCP, CodeGraph) still run.\n\n"
                "[bold]Put tokens here:[/]"
            )
            file_s = "file exists" if exists else "file missing — create it"
            help_s = (
                f"{file_s}\n\n"
                "[dim]# config_local.py\n"
                "GITHUB_TOKENS = [\n"
                '    "ghp_YOUR_TOKEN_HERE",\n'
                "]\n\n"
                "Or env:  set GITHUB_TOKENS=ghp_xxx,ghp_yyy\n"
                "Create token: https://github.com/settings/tokens\n"
                f"(classic · public_repo)\nTemplate: {CONFIG_LOCAL_EXAMPLE}[/]"
            )
            ok_label = "OK"

        with Vertical(id="gh_notice"):
            yield Static(title, id="gh_notice_title")
            yield Static(body, id="gh_notice_body", markup=True)
            yield Static(str(path), id="gh_notice_path")
            yield Static(help_s, id="gh_notice_help", markup=True)
            with Horizontal(id="gh_notice_btns"):
                yield Button(ok_label, id="gh_ok", variant="success")

    def on_mount(self) -> None:
        try:
            self.query_one("#gh_ok", Button).focus()
        except Exception:
            pass

    def action_dismiss_notice(self) -> None:
        self.dismiss(None)

    @on(Button.Pressed, "#gh_ok")
    def _on_ok_pressed(self) -> None:
        self.dismiss(None)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        # Fallback if @on decorator path misses the event
        if event.button.id == "gh_ok":
            event.stop()
            self.dismiss(None)

    def on_click(self, event) -> None:
        """Клик по затемнённому фону (вне #gh_notice) — закрыть."""
        try:
            widget = event.widget
            if widget is None:
                return
            # Click on the modal screen itself (backdrop) or outside the panel
            if widget is self:
                event.stop()
                self.dismiss(None)
                return
            # Walk up: if click is not inside #gh_notice, dismiss
            node = widget
            while node is not None and node is not self:
                if getattr(node, "id", None) == "gh_notice":
                    return  # inside panel — keep open
                node = getattr(node, "parent", None)
            # Not inside panel
            if node is self or widget is self:
                event.stop()
                self.dismiss(None)
        except Exception:
            pass


sys.path.insert(0, BASE_DIR)
try:
    from model_registry import (lookup as _model_lookup, sort_key as _model_sort_key,
                                 capability_sort_key as _cap_sort_key,
                                 capability_label as _cap_label,
                                 capability_rank as _cap_rank)
except Exception:
    _model_lookup = None
    _model_sort_key = None
    _cap_sort_key = None
    _cap_label = None
    _cap_rank = None

try:
    from database import DEFAULT_SOURCE_PROGRESS_STALE_SECONDS
except Exception:
    DEFAULT_SOURCE_PROGRESS_STALE_SECONDS = 90
try:
    from database import SOURCE_PROGRESS_REAP_SECONDS
except Exception:
    SOURCE_PROGRESS_REAP_SECONDS = 600

AUTOSTART = os.environ.get("TUI_AUTOSTART", "1") not in ("0", "false", "no")
AUTODRAIN = os.environ.get("TUI_AUTODRAIN", "1") not in ("0", "false", "no")
TICK = float(os.environ.get("TUI_INTERVAL", "2"))

# Палитра статусов -> (метка, цвет markup)
STATUS_STYLE: Dict[str, Tuple[str, str]] = {
    "confirmed": ("CONFIRMED", "bold green"),
    "valid": ("VALID", "green"),
    "invalid": ("INVALID", "red"),
    "quota_exceeded": ("QUOTA", "yellow"),
    "connection_error": ("ERROR", "magenta"),
    "pending": ("PENDING", "blue"),
    "unverified": ("UNVERIFIED", "grey62"),
}
HIGH_VALUE_PLATFORMS = {
    "openai", "anthropic", "gemini", "azure", "groq", "xai", "deepseek",
    "mistral", "perplexity", "cohere", "together", "replicate", "fireworks",
    "anyscale", "huggingface", "openrouter", "cerebras",
    # Расширенный каталог (Voice/Image/RAG/Browser/LLMOps/Vector/Code)
    "elevenlabs", "stability", "heygen", "runway", "tavily",
    "firecrawl", "langfuse", "astra", "llamacloud",
}


# ============================================================================
#                          Слой доступа к данным
# ============================================================================

_tui_conn: Optional[sqlite3.Connection] = None
# RLock: _stats_uncached() holds the conn while calling _source_progress() /
# _source_key_counts(), which also enter _conn() — plain Lock deadlocks.
_tui_conn_lock = threading.RLock()


@contextmanager
def _conn():
    """Read-only shared connection; RLock so nested _conn() is safe."""
    global _tui_conn
    with _tui_conn_lock:
        if _tui_conn is None:
            _tui_conn = sqlite3.connect(DB, timeout=3, check_same_thread=False)
            _tui_conn.row_factory = sqlite3.Row
            _tui_conn.execute("PRAGMA journal_mode=WAL")
            _tui_conn.execute("PRAGMA query_only=1")
        yield _tui_conn


def _db(sql: str, p: Tuple = ()) -> List[Dict[str, Any]]:
    try:
        with _conn() as c:
            return [dict(r) for r in c.execute(sql, p).fetchall()]
    except sqlite3.Error:
        return []


def _one(sql: str, p: Tuple = ()) -> Any:
    try:
        with _conn() as c:
            row = c.execute(sql, p).fetchone()
            return row[0] if row else None
    except sqlite3.Error:
        return None


_tui_write_conn: Optional[sqlite3.Connection] = None


def _exec(sql: str, p: Tuple = ()) -> Optional[str]:
    """Выполнить запись. Возвращает None при успехе или текст ошибки."""
    global _tui_write_conn
    try:
        if _tui_write_conn is None:
            _tui_write_conn = sqlite3.connect(DB, timeout=3, check_same_thread=False)
        _tui_write_conn.execute(sql, p)
        _tui_write_conn.commit()
    except sqlite3.Error as e:
        return str(e)
    # Сбросить кэши сводки/прогресса - данные изменились этой же TUI-сессией.
    _invalidate_caches()
    return None


def _mask(k: Optional[str]) -> str:
    if not k:
        return ""
    if len(k) <= 12:
        return k
    return f"{k[:6]}…{k[-4:]}"


def _fmt_time(ts: Any, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    if not ts:
        return "—"
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "")).strftime(fmt)
    except (ValueError, TypeError):
        return str(ts)[:19]


def _cfg() -> Dict[str, Any]:
    """Безопасно прочитать конфигурацию проекта."""
    out: Dict[str, Any] = {"tokens": 0, "proxy": "", "threads": 0,
                           "timeout": 0, "circuit": False, "keywords": 0,
                           "base_urls": 0, "pastebin": False}
    try:
        sys.path.insert(0, BASE_DIR)
        from config import config  # type: ignore
        out["tokens"] = len([t for t in config.github_tokens if t])
        out["proxy"] = bool(config.proxy_url)
        out["threads"] = getattr(config, "consumer_threads", 0)
        out["timeout"] = getattr(config, "request_timeout", 0)
        out["circuit"] = getattr(config, "circuit_breaker_enabled", False)
        out["keywords"] = len(getattr(config, "search_keywords", []) or [])
        out["base_urls"] = len(getattr(config, "default_base_urls", {}) or {})
        out["pastebin"] = bool(getattr(config, "pastebin_api_key", ""))
    except Exception:
        pass
    return out


_stats_cache: Optional[Dict[str, Any]] = None
_stats_cache_time: float = 0


_STATS_TTL = 5.0  # сек - кэш тяжёлой сводки (БД ~70k строк, частые тики)

# Async refresh: тяжёлые COUNT/GROUP BY на большой БД не должны блокировать
# UI-поток. _stats() возвращает последний известный snapshot (stale-while-
# revalidate) и запускает фоновое обновление, если кэш протух.
_stats_refreshing = False
# True, когда первый реальный snapshot уже в кэше. _tick не делает тяжёлые
# UI-обновления до этого момента (иначе UI фризился бы на холодном скане БД).
_primed = False


def _stats_uncached_into_cache() -> Dict[str, Any]:
    """Принудительно вычислить сводку и положить в кэш (для фонового прогрева)."""
    global _stats_cache, _stats_cache_time, _primed
    import time as _t
    result = _stats_uncached()
    _stats_cache = result
    _stats_cache_time = _t.time()
    _primed = True
    return result


def _stats() -> Dict[str, Any]:
    """Полная сводка состояния БД + конфига (неблокирующий stale-while-revalidate).

    Свежий кэш -> вернуть. Протух -> вернуть СТАРЫЙ snapshot сразу (UI не
    фризится) и обновить в фоновом потоке. Первый вызов без кэша идёт
    синхронно (иначе вернуть нечего).
    """
    global _stats_cache, _stats_cache_time, _stats_refreshing, _primed
    import time as _t
    now = _t.time()
    if _stats_cache is not None and (now - _stats_cache_time) < _STATS_TTL:
        return _stats_cache

    if _stats_cache is not None:
        # есть старый snapshot — вернуть его и обновить в фоне
        if not _stats_refreshing:
            _stats_refreshing = True
            def _bg():
                global _stats_cache, _stats_cache_time, _stats_refreshing
                try:
                    result = _stats_uncached()
                    _stats_cache = result
                    _stats_cache_time = _t.time()
                except Exception:
                    pass
                finally:
                    _stats_refreshing = False
            threading.Thread(target=_bg, daemon=True, name="tui-stats").start()
        return _stats_cache

    # Нет ни одного snapshot — синхронно (реальные данные). UI-фриз при этом
    # избегается тем, что _prime_caches() в потоке заполняет кэш ДО первого
    # paint, а _tick пропускает тяжёлые обновления до _primed.
    result = _stats_uncached()
    _stats_cache = result
    _stats_cache_time = now
    _primed = True
    return result


def _invalidate_caches() -> None:
    """Сбросить кэши сводки/прогресса валидации после TUI-записи в БД."""
    global _stats_cache, _stats_cache_time, _vp_cache, _vp_cache_time
    global _skc_cache, _skc_cache_time, _sp_cache, _sp_cache_time
    global _tui_conn
    _stats_cache = None
    _stats_cache_time = 0
    _vp_cache = None
    _vp_cache_time = 0.0
    _skc_cache = None
    _skc_cache_time = 0.0
    _sp_cache = None
    _sp_cache_time = 0.0
    # Сброс read-соединения: DB могла смениться (тесты/переключение файла).
    _tui_conn = None


# Кэш метрик прогресса валидации (5 COUNT-запросов по большой таблице -
# не выполнять каждый тик, кэшируем 4с).
_vp_cache: Optional[Dict[str, Any]] = None
_vp_cache_time: float = 0.0
_vp_refreshing = False

_BULK_PLATFORMS = (
    "'aws_secret_key','aws_access_key','shadeform','modal',"
    "'google_api_key','firebase','heroku','figma_token',"
    "'runpod','lambdalabs','coreweave','digitalocean','linode',"
    "'vultr','hetzner','scaleway'")


def _validation_progress() -> Dict[str, int]:
    """Метрики прогресса валидации (неблокирующий stale-while-revalidate)."""
    global _vp_cache, _vp_cache_time, _vp_refreshing
    import time as _t
    now = _t.time()
    if _vp_cache is not None and (now - _vp_cache_time) < _STATS_TTL:
        return _vp_cache

    if _vp_cache is not None:
        if not _vp_refreshing:
            _vp_refreshing = True
            def _bg():
                global _vp_cache, _vp_cache_time, _vp_refreshing
                try:
                    result = _validation_progress_uncached()
                    _vp_cache = result
                    _vp_cache_time = _t.time()
                except Exception:
                    pass
                finally:
                    _vp_refreshing = False
            threading.Thread(target=_bg, daemon=True, name="tui-vp").start()
        return _vp_cache

    # Нет snapshot — синхронно (реальные данные).
    result = _validation_progress_uncached()
    _vp_cache = result
    _vp_cache_time = now
    return result


def _validation_progress_uncached() -> Dict[str, int]:
    """Синхронные метрики валидации (5 COUNT по большой таблице)."""
    empty = {"valid_attempts": 0, "valid_done": 0, "unv_to_check": 0,
             "unv_total": 0, "net_total": 0, "resolved": 0}
    try:
        with _conn() as c:
            valid_attempts = c.execute(
                "SELECT COUNT(*) FROM leaked_keys "
                "WHERE status='valid' AND confirm_attempts < 10").fetchone()[0]
            valid_done = c.execute(
                "SELECT COUNT(*) FROM leaked_keys "
                "WHERE status='valid' AND confirm_attempts > 0").fetchone()[0]
            unv_to_check = c.execute(
                f"SELECT COUNT(*) FROM leaked_keys "
                f"WHERE status='unverified' AND platform NOT IN ({_BULK_PLATFORMS}) "
                f"AND ((platform='gemini' AND confirm_attempts < 15) "
                f"     OR (platform!='gemini' AND confirm_attempts < 7))"
            ).fetchone()[0]
            unv_total = c.execute(
                f"SELECT COUNT(*) FROM leaked_keys "
                f"WHERE status='unverified' "
                f"AND platform NOT IN ({_BULK_PLATFORMS})").fetchone()[0]
            net_total = c.execute(
                f"SELECT COUNT(*) FROM leaked_keys "
                f"WHERE platform NOT IN ({_BULK_PLATFORMS})").fetchone()[0]
            resolved = c.execute(
                f"SELECT COUNT(*) FROM leaked_keys "
                f"WHERE status IN ('confirmed','valid','quota_exceeded',"
                f"'invalid','connection_error') "
                f"AND platform NOT IN ({_BULK_PLATFORMS})").fetchone()[0]
        return {"valid_attempts": valid_attempts, "valid_done": valid_done,
                "unv_to_check": unv_to_check, "unv_total": unv_total,
                "net_total": net_total, "resolved": resolved}
    except Exception:
        return empty


# Кэш discovery/confirmed моделей (лёгкие COUNT(DISTINCT) по key_models -
# не делаем каждый тик дашборда).
_md_cache: Optional[Dict[str, int]] = None
_md_cache_time: float = 0.0
_md_refreshing = False


def _model_discovery_counts() -> Dict[str, int]:
    """Число discovery / confirmed моделей (неблокирующий stale-while-revalidate)."""
    global _md_cache, _md_cache_time, _md_refreshing
    import time as _t
    now = _t.time()
    if _md_cache is not None and (now - _md_cache_time) < _STATS_TTL:
        return _md_cache

    if _md_cache is not None:
        if not _md_refreshing:
            _md_refreshing = True
            def _bg():
                global _md_cache, _md_cache_time, _md_refreshing
                try:
                    _md_cache = _model_discovery_counts_uncached()
                    _md_cache_time = _t.time()
                except Exception:
                    pass
                finally:
                    _md_refreshing = False
            threading.Thread(target=_bg, daemon=True, name="tui-md").start()
        return _md_cache

    # Холодный старт — синхронно (реальные данные).
    _md_cache = _model_discovery_counts_uncached()
    _md_cache_time = now
    return _md_cache


def _model_discovery_counts_uncached() -> Dict[str, int]:
    """Синхронный COUNT(DISTINCT) по key_models (для фонового обновления)."""
    discovered = conf = 0
    if os.path.exists(DB):
        try:
            with _conn() as c:
                discovered = c.execute(
                    "SELECT COUNT(DISTINCT model_name) FROM key_models"
                ).fetchone()[0] or 0
                conf = c.execute(
                    "SELECT COUNT(DISTINCT model_name) FROM key_models "
                    "WHERE is_confirmed=1"
                ).fetchone()[0] or 0
        except sqlite3.Error:
            pass
    return {"discovered": discovered, "confirmed": conf}


# Модульный прогресс фоновых задач: task_type -> {"done": int, "total": int}.
# Фоновые задачи (в других потоках) пишут сюда, _update_dashboard читает.
# Thread-safe через GIL (dict-операции атомарны).
TASK_PROGRESS: Dict[str, Dict[str, int]] = {}


def _set_task_progress(task_type: str, done: int, total: int) -> None:
    """Обновить прогресс фоновой задачи (для прогресс-бара в дашборде)."""
    TASK_PROGRESS[task_type] = {"done": done, "total": total}


def _clear_task_progress(task_type: str) -> None:
    TASK_PROGRESS.pop(task_type, None)


# Известные источники (source_progress). Фиксированный набор = ровно N строк в матрице.
_KNOWN_SOURCES = (
    "github", "paster", "pastebin", "gist", "gitlab", "realtime", "mcp", "codegraph",
)
# Короткие human-readable имена для UI
_SOURCE_LABELS = {
    "github": "GitHub",
    "paster": "Paster.sh",
    "pastebin": "Pastebin",
    "gist": "Gist",
    "gitlab": "GitLab",
    "realtime": "Realtime",
    "mcp": "MCP",
    "codegraph": "CodeGraph",
}
_ACTIVE_STATUSES = {"starting", "running", "waiting"}


def _derive_source_status(row: Optional[dict], stale: bool = False) -> str:
    """Производный статус источника: disabled/stopped/error/stale/idle/running/waiting."""
    if row is None:
        return "disabled"
    status = row.get("status")
    if status == "disabled":
        return "disabled"
    if status == "stopped":
        return "stopped"
    if status == "error":
        return "error"
    if status in _ACTIVE_STATUSES:
        if stale:
            return "stale"
        # phase "waiting"/"retry" — это тоже живая работа (пауза/backoff),
        # НЕ "зависание": показываем как running, чтобы матрица не висела на "waiting".
        return "running"
    if status == "done":
        return "done"
    return "idle"


# Кэш подсчёта ключей по источникам (тяжёлый GROUP BY - не делаем каждый тик).
_skc_cache: Optional[Dict[str, int]] = None
_skc_cache_time: float = 0.0


def _source_key_counts() -> Dict[str, int]:
    """Число leaked_keys по источнику (по source_url), закэшировано на _STATS_TTL."""
    global _skc_cache, _skc_cache_time
    import time as _t
    now = _t.time()
    if _skc_cache is not None and (now - _skc_cache_time) < _STATS_TTL:
        return _skc_cache
    counts: Dict[str, int] = {s: 0 for s in _KNOWN_SOURCES}
    if os.path.exists(DB):
        try:
            with _conn() as c:
                for name, cnt in c.execute("""
                    SELECT CASE
                        WHEN source_url LIKE '%raw.githubusercontent.com/%' THEN 'MCP'
                        WHEN source_url LIKE '%sourcegraph.com/%' THEN 'CodeGraph'
                        WHEN source_url LIKE '%paster.sh/%' THEN 'Paster'
                        WHEN source_url LIKE '%pastebin.com/%' THEN 'Pastebin'
                        WHEN source_url LIKE '%gist.github.com/%' THEN 'Gist'
                        WHEN source_url LIKE '%gitlab.com/%' THEN 'GitLab'
                        WHEN source_url LIKE '%github.com/%' THEN 'GitHub'
                        ELSE 'Realtime/Other'
                    END, COUNT(*) FROM leaked_keys GROUP BY 1
                """):
                    key = name.lower().split("/")[0]
                    if key in counts:
                        counts[key] = cnt
        except sqlite3.Error:
            pass
    _skc_cache = counts
    _skc_cache_time = now
    return counts


# Кэш сводки source_progress (читается из таблицы Stage 1, не из GROUP BY).
_sp_cache: Optional[List[dict]] = None
_sp_cache_time: float = 0.0
_sp_refreshing = False


def _source_progress() -> List[dict]:
    """Сводка по источникам (неблокирующий stale-while-revalidate).

    Свежий кэш -> вернуть. Протух -> вернуть СТАРЫЙ snapshot сразу (UI не
    фризится) и обновить в фоновом потоке. Первый вызов без кэша — синхронно.
    """
    global _sp_cache, _sp_cache_time, _sp_refreshing
    import time as _t
    now = _t.time()
    if _sp_cache is not None and (now - _sp_cache_time) < _STATS_TTL:
        return _sp_cache

    if _sp_cache is not None:
        if not _sp_refreshing:
            _sp_refreshing = True
            def _bg():
                global _sp_cache, _sp_cache_time, _sp_refreshing
                try:
                    result = _source_progress_uncached()
                    _sp_cache = result
                    _sp_cache_time = _t.time()
                except Exception:
                    pass
                finally:
                    _sp_refreshing = False
            threading.Thread(target=_bg, daemon=True, name="tui-sp").start()
        return _sp_cache

    # Нет snapshot — синхронно (реальные данные; тесты/прогрев зависят от этого).
    result = _source_progress_uncached()
    _sp_cache = result
    _sp_cache_time = now
    return result


def _source_progress_uncached() -> List[dict]:
    """Синхронная сводка по источникам (используется фоновым обновлением).

    Всегда ровно len(_KNOWN_SOURCES) строк; каждая содержит производный
    статус (disabled/error/running/idle) и число ключей по источнику.
    """
    import time as _t
    now = _t.time()
    counts = _source_key_counts()
    rows: Dict[str, dict] = {}
    if os.path.exists(DB):
        try:
            with _conn() as c:
                for r in c.execute("SELECT * FROM source_progress"):
                    rows[r["source"]] = dict(r)
        except sqlite3.Error:
            pass
    progress = []
    for source in _KNOWN_SOURCES:
        row = rows.get(source)
        item = {
            "source": source,
            "status": (row or {}).get("status", "disabled"),
            "phase": (row or {}).get("phase"),
            "current": (row or {}).get("current", 0),
            "total": (row or {}).get("total", 0),
            "processed": (row or {}).get("processed", 0),
            "found": (row or {}).get("found", 0),
            "errors": (row or {}).get("errors", 0),
            "message": (row or {}).get("message"),
            "stale": False,
            "key_count": counts.get(source, 0),
        }
        if row and row.get("status") in _ACTIVE_STATUSES:
            try:
                hb = datetime.fromisoformat(row["heartbeat"])
                item["stale"] = (
                    now - hb.timestamp()
                ) > DEFAULT_SOURCE_PROGRESS_STALE_SECONDS
            except (TypeError, ValueError, KeyError):
                item["stale"] = True
        item["derived_status"] = _derive_source_status(row, item["stale"])
        progress.append(item)
    return progress


def _reap_stale_sources(reap_seconds: Optional[float] = None) -> int:
    """Пометить мёртвые active-источники как stopped (воркер умер).

    Сканер/TUI может быть убит (kill, краш, _kill_stale_*): строка
    source_progress остаётся running/waiting/starting со старым heartbeat, и
    дашборд вечно показывает STALE, хотя воркеров нет. Рейпим их в stopped,
    чтобы UI отражал реальность. Живые (свежий heartbeat) не трогаются.

    Возвращает число зарейпленных строк. Безопасен: 0 при любой ошибке.
    """
    global _sp_cache, _sp_cache_time
    if not os.path.exists(DB):
        return 0
    try:
        from database import Database

        db = Database(DB)
        try:
            n = db.reap_stale_source_progress(
                stale_after_seconds=reap_seconds or SOURCE_PROGRESS_REAP_SECONDS
            )
        finally:
            db.close()
    except Exception:
        return 0
    if n:
        # Инвалидация сводки: следующий тик покажет stopped вместо STALE.
        _sp_cache = None
        _sp_cache_time = 0.0
    return n


def _stats_uncached() -> Dict[str, Any]:
    """Полная сводка состояния БД + конфига."""
    empty: Dict[str, Any] = {
        "total": 0, "statuses": {}, "platforms": {}, "platforms_valid": {},
        "high_value": 0,
        "blobs": 0, "prog_cur": 0, "prog_total": 0, "prog_done": False,
        "prog_updated": None, "last_found": None, "valid_value": 0,
        "sources": {}, "paster_page": 1, "paster_seen": 0,
    }
    if not os.path.exists(DB):
        return {**empty, **_cfg()}
    try:
        with _conn() as c:
            # Один агрегирующий запрос вместо 2 COUNT + 3 GROUP BY:
            # суммируем total/is_high_value/валидные/last_found за один проход.
            row = c.execute("""
                SELECT
                    COUNT(*),
                    SUM(CASE WHEN is_high_value=1 THEN 1 ELSE 0 END),
                    SUM(CASE WHEN status IN
                        ('valid','confirmed','quota_exceeded') THEN 1 ELSE 0 END),
                    MAX(found_time)
                FROM leaked_keys
            """).fetchone()
            total = row[0] or 0
            high_value = row[1] or 0
            valid_count = row[2] or 0
            last_found = row[3]
            # Статусы и платформы - лёгкие агрегаты (индексы по status/platform).
            statuses = {r[0]: r[1] for r in c.execute(
                "SELECT status, COUNT(*) FROM leaked_keys GROUP BY status")}
            platforms = {r[0]: r[1] for r in c.execute(
                "SELECT platform, COUNT(*) FROM leaked_keys GROUP BY platform")}
            platforms_valid = {r[0]: r[1] for r in c.execute(
                "SELECT platform, COUNT(*) FROM leaked_keys "
                "WHERE status IN ('valid','confirmed','quota_exceeded') GROUP BY platform")}
            try:
                blobs = c.execute(
                    "SELECT COUNT(*) FROM scanned_blobs").fetchone()[0]
            except sqlite3.Error:
                blobs = 0
            prog_cur = prog_total = 0
            prog_done = False
            prog_updated = None
            try:
                prow = c.execute(
                    "SELECT current_index, total, is_completed, update_time "
                    "FROM scan_progress ORDER BY id DESC LIMIT 1"
                ).fetchone()
                if prow:
                    prog_cur, prog_total, prog_done, prog_updated = prow
            except sqlite3.Error:
                pass
            # Ключи по источникам - из кэшированного подсчёта (без GROUP BY каждый тик).
            counts = _source_key_counts()
            sources = {s.title(): counts.get(s, 0) for s in _KNOWN_SOURCES}
            source_progress = _source_progress()
            paster_page = 1
            paster_seen = 0
            try:
                row = c.execute(
                    "SELECT value FROM source_state WHERE name='paster_backfill_page'"
                ).fetchone()
                paster_page = int(row[0]) if row else 1
                paster_seen = c.execute(
                    "SELECT COUNT(*) FROM scanned_source_items WHERE source='paster'"
                ).fetchone()[0]
            except (sqlite3.Error, ValueError, TypeError):
                pass
    except sqlite3.Error:
        return {**empty, **_cfg()}
    return {
        "total": total, "statuses": statuses, "platforms": platforms,
        "platforms_valid": platforms_valid,
        "high_value": high_value, "blobs": blobs,
        "prog_cur": prog_cur or 0, "prog_total": prog_total or 0,
        "prog_done": bool(prog_done), "prog_updated": prog_updated,
        "last_found": last_found, "valid_value": valid_count,
        "sources": sources, "source_progress": source_progress,
        "paster_page": paster_page,
        "paster_seen": paster_seen, **_cfg(),
    }


def _keys(status: Optional[str] = None, platform: Optional[str] = None,
          search: str = "", limit: int = 500, offset: int = 0,
          high_value_only: bool = False) -> List[Dict[str, Any]]:
    sql = "SELECT * FROM leaked_keys WHERE 1=1"
    p: List[Any] = []
    if status and status != "all":
        sql += " AND status=?"
        p.append(status)
    if platform and platform != "all":
        sql += " AND platform=?"
        p.append(platform)
    if high_value_only:
        sql += " AND is_high_value=1"
    if search:
        sql += (" AND (api_key LIKE ? OR source_url LIKE ? "
                "OR base_url LIKE ? OR balance LIKE ?)")
        like = f"%{search}%"
        p += [like, like, like, like]
    sql += " ORDER BY found_time DESC LIMIT ? OFFSET ?"
    p += [limit, offset]
    return _db(sql, tuple(p))


def _count_keys(status=None, platform=None, search="",
                high_value_only=False) -> int:
    sql = "SELECT COUNT(*) FROM leaked_keys WHERE 1=1"
    p: List[Any] = []
    if status and status != "all":
        sql += " AND status=?"; p.append(status)
    if platform and platform != "all":
        sql += " AND platform=?"; p.append(platform)
    if high_value_only:
        sql += " AND is_high_value=1"
    if search:
        sql += (" AND (api_key LIKE ? OR source_url LIKE ? "
                "OR base_url LIKE ? OR balance LIKE ?)")
        like = f"%{search}%"; p += [like, like, like, like]
    v = _one(sql, tuple(p))
    return int(v) if v else 0


def _platforms() -> List[str]:
    rows = _db("SELECT DISTINCT platform FROM leaked_keys ORDER BY platform")
    return [r["platform"] for r in rows if r["platform"]]


_models_data_cache: Dict[bool, List[Dict[str, Any]]] = {}
_models_data_time: Dict[bool, float] = {True: 0.0, False: 0.0}
_models_data_refreshing = False


def _models_data(confirmed_only: bool = False, _refresh: bool = False) -> List[Dict[str, Any]]:
    """Все модели с количеством ключей (кэшировано; тяжёлый GROUP BY на 449k).

    confirmed_only=True - только модели с is_confirmed=1 (реально ответили).
    """
    if _refresh or confirmed_only not in _models_data_cache:
        import time as _time
        result = _models_data_uncached(confirmed_only)
        _models_data_cache[confirmed_only] = result
        _models_data_time[confirmed_only] = _time.time()
        return result
    return _models_data_cache[confirmed_only]


def _models_data_uncached(confirmed_only: bool = False) -> List[Dict[str, Any]]:
    """Синхронный тяжёлый запрос моделей (JOIN+GROUP BY)."""
    if confirmed_only:
        sql = (
            "SELECT km.model_name AS model_name, "
            "  COUNT(DISTINCT km.key_id) AS key_count, "
            "  GROUP_CONCAT(DISTINCT km.platform) AS platforms, "
            "  GROUP_CONCAT(DISTINCT km.base_url) AS base_urls "
            "FROM key_models km "
            "JOIN leaked_keys lk ON lk.id = km.key_id "
            "WHERE km.is_confirmed = 1 "
            "  AND lk.status IN ('valid','confirmed','quota_exceeded') "
            "GROUP BY km.model_name"
        )
    else:
        sql = (
            "SELECT km.model_name AS model_name, "
            "  COUNT(DISTINCT km.key_id) AS key_count, "
            "  GROUP_CONCAT(DISTINCT km.platform) AS platforms, "
            "  GROUP_CONCAT(DISTINCT km.base_url) AS base_urls "
            "FROM key_models km "
            "JOIN leaked_keys lk ON lk.id = km.key_id "
            "WHERE lk.status IN ('valid','confirmed','quota_exceeded') "
            "GROUP BY km.model_name"
        )
    return _db(sql)


def _keys_for_model(model_name: str, confirmed_only: bool = False) -> List[Dict[str, Any]]:
    """Получить ключи, поддерживающие модель.

    Если confirmed_only - только ключи где эта конкретная модель is_confirmed=1.
    """
    if confirmed_only:
        sql = (
            "SELECT lk.id, lk.platform, lk.api_key, lk.base_url, "
            "  lk.status, lk.model_tier, lk.rpm, lk.tpd, "
            "  lk.concurrency_limit, lk.balance_usd, lk.org_plan, "
            "  lk.rate_tier, lk.rate_headers, lk.is_high_value, "
            "  lk.verified_time, lk.balance "
            "FROM key_models km "
            "JOIN leaked_keys lk ON lk.id = km.key_id "
            "WHERE km.model_name = ? "
            "  AND km.is_confirmed = 1 "
            "  AND lk.status IN ('valid','confirmed','quota_exceeded') "
            "ORDER BY lk.status='confirmed' DESC, lk.is_high_value DESC, lk.verified_time DESC"
        )
    else:
        sql = (
            "SELECT lk.id, lk.platform, lk.api_key, lk.base_url, "
            "  lk.status, lk.model_tier, lk.rpm, lk.tpd, "
            "  lk.concurrency_limit, lk.balance_usd, lk.org_plan, "
            "  lk.rate_tier, lk.rate_headers, lk.is_high_value, "
            "  lk.verified_time, lk.balance "
            "FROM key_models km "
            "JOIN leaked_keys lk ON lk.id = km.key_id "
            "WHERE km.model_name = ? "
            "  AND lk.status IN ('valid','confirmed','quota_exceeded') "
            "ORDER BY lk.status='confirmed' DESC, lk.is_high_value DESC, lk.verified_time DESC"
        )
    return _db(sql, (model_name,))


def _providers_data() -> List[Dict[str, Any]]:
    """Получить агрегированные данные по провайдерам (endpoint).

    Группировка по нормализованному base_url, подсчёт валидных/подтверждённых
    ключей и топ моделей для каждого провайдера.
    """
    sql = (
        "SELECT lk.base_url, "
        "  COUNT(DISTINCT CASE WHEN lk.status IN ('valid','confirmed') "
        "      THEN lk.id END) AS key_count, "
        "  COUNT(DISTINCT CASE WHEN lk.status = 'confirmed' "
        "      THEN lk.id END) AS confirmed_count, "
        "  GROUP_CONCAT(DISTINCT lk.platform) AS platforms, "
        "  GROUP_CONCAT(DISTINCT km.model_name) AS models "
        "FROM leaked_keys lk "
        "LEFT JOIN key_models km ON km.key_id = lk.id "
        "WHERE lk.status IN ('valid','confirmed','quota_exceeded') "
        "GROUP BY lk.base_url "
        "ORDER BY key_count DESC"
    )
    return _db(sql)


def _provider_name(base_url: str) -> str:
    """Извлечь понятное имя провайдера из base_url."""
    if not base_url:
        return "Unknown"
    try:
        from urllib.parse import urlparse
        host = urlparse(base_url).netloc
        if not host:
            return base_url
        # Удалить www и api-поддомен, но оставить хост
        host = host.lower()
        if host.startswith("api."):
            host = host[4:]
        return host
    except Exception:
        return base_url


def _top_models(models_str: Optional[str], limit: int = 10) -> List[str]:
    """Выбрать топ моделей по приоритету (лучшие/новейшие первыми).

    Использует model_registry для сортировки по новизне релиза.
    Приоритет префиксов для топ-моделей 2026:
    GPT-5.x > Opus 4.x > GLM-5 > Kimi k2.x > Gemini 3.x > DeepSeek v4 >
    Claude 3.5 > GPT-4o > Sonar > Nemotron > Llama > Qwen > остальное.
    """
    if not models_str:
        return []
    models = list(dict.fromkeys(m.strip() for m in models_str.split(",") if m.strip()))

    # Жёсткие приоритеты топ-моделей (нормализованные, без префиксов)
    priority = [
        "gpt-5", "gpt5", "gpt-5.5", "gpt-5.4", "gpt-5.2", "gpt-5.1",
        "opus-4", "opus4", "claude-opus-4", "claude-4",
        "glm-5", "glm5", "glm-5.2", "glm-5.1",
        "kimi-k2", "kimi", "moonshot-v2",
        "gemini-3", "gemini3",
        "deepseek-v4", "deepseek-r1",
        "o3", "o1",
        "gpt-4o", "gpt-4.1",
        "claude-3.5", "claude-3-5",
        "sonar", "perplexity",
        "nemotron",
        "llama-3.3", "llama3.3", "llama-3.1",
        "qwen-2.5", "qwen2.5", "qwen-plus",
        "mistral-large", "mixtral",
        "gpt-4", "gpt4",
        "gemini-2.5", "gemini-2.0",
        "deepseek-chat",
        "gpt-3.5",
    ]

    def norm(name: str) -> str:
        low = name.lower()
        # Удалить префикс провайдера: openai/gpt-5 -> gpt-5
        bare = low.split("/")[-1] if "/" in low else low
        # Удалить даты и суффиксы: gpt-4o-2024-05-13 -> gpt-4o
        import re
        bare = re.sub(r'-\d{4}-\d{2}-\d{2}.*$', '', bare)
        bare = re.sub(r'-preview.*$', '', bare)
        return bare.strip()

    def priority_rank(model: str) -> int:
        n = norm(model)
        for i, pref in enumerate(priority):
            p = pref.replace("-", "").replace(".", "")
            n_norm = n.replace("-", "").replace(".", "")
            if p in n_norm:
                return i
        return len(priority)

    # Сортировка: сначала по приоритету, затем по новизне через registry
    ranked = sorted(models, key=lambda m: (priority_rank(m), m.lower()))
    if _model_sort_key:
        # Внутри каждого приоритета - по новизне
        top_cut = []
        prev_rank = -1
        bucket = []
        for m in ranked:
            r = priority_rank(m)
            if r != prev_rank and bucket:
                bucket.sort(key=lambda x: _model_sort_key(x))
                top_cut.extend(bucket)
                bucket = []
            bucket.append(m)
            prev_rank = r
        if bucket:
            bucket.sort(key=lambda x: _model_sort_key(x))
            top_cut.extend(bucket)
        ranked = top_cut

    return ranked[:limit]


def _log_lines(n: int = 300) -> List[str]:
    """Прочитать последние n строк scanner.log (через seek - без загрузки всего файла)."""
    if not os.path.exists(LOG):
        return []
    try:
        with open(LOG, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            f.seek(max(0, size - 32768))  # последние ~32КБ
            if size > 32768:
                f.readline()  # отбросить неполную первую строку
            return f.read().decode("utf-8", "ignore").splitlines()[-n:]
    except OSError:
        return []


def _bar(count: int, total: int, width: int = 24) -> str:
    if total <= 0:
        return "░" * width
    filled = int(round(width * count / total))
    return "█" * filled + "░" * (width - filled)


def _ensure_active_pool():
    """Создать таблицы пула.

    Три таблицы:
      pool_models    - модели, добавленные пользователем явно (левая колонка)
      pool_endpoints - провайдеры (эндпоинты), добавленные явно (правая колонка)
      active_pool    - materialized cache (model+endpoint+keys) для прокси,
                       перестраивается из двух верхних через _rebuild_active_pool
    """
    try:
        _exec(
            "CREATE TABLE IF NOT EXISTS active_pool "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "model_name TEXT NOT NULL, endpoint TEXT NOT NULL, "
            "platform TEXT DEFAULT '', api_keys TEXT DEFAULT '[]', "
            "added_time DATETIME DEFAULT CURRENT_TIMESTAMP, "
            "enabled BOOLEAN DEFAULT 1, "
            "source TEXT DEFAULT 'model', "
            "UNIQUE(model_name, endpoint))")
        # Миграция: добавить недостающие колонки к старой active_pool
        try:
            cols = _db("PRAGMA table_info(active_pool)")
            col_names = {c["name"] for c in cols}
            for col, ddl in (
                ("source", "ALTER TABLE active_pool ADD COLUMN source "
                 "TEXT DEFAULT 'model'"),
                ("priority", "ALTER TABLE active_pool ADD COLUMN priority "
                 "INTEGER DEFAULT 0"),
                ("zone", "ALTER TABLE active_pool ADD COLUMN zone "
                 "TEXT DEFAULT 'model'"),
            ):
                if col not in col_names:
                    _exec(ddl)
        except Exception:
            pass
        _exec(
            "CREATE TABLE IF NOT EXISTS pool_models "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "model_name TEXT NOT NULL UNIQUE, "
            "added_time DATETIME DEFAULT CURRENT_TIMESTAMP)")
        _exec(
            "CREATE TABLE IF NOT EXISTS pool_endpoints "
            "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "endpoint TEXT NOT NULL UNIQUE, "
            "added_time DATETIME DEFAULT CURRENT_TIMESTAMP)")
    except Exception:
        pass


def _rebuild_active_pool():
    """Перестроить active_pool (cache для прокси) из pool_models +
    pool_endpoints. Модели -> все их эндпоинты; эндпоинты -> все confirmed модели.
    Вызывать после любого изменения pool_models/pool_endpoints."""
    from proxy_server import ActivePool
    from database import Database
    _ensure_active_pool()
    # Очистить cache
    _exec("DELETE FROM active_pool")
    pool = ActivePool(Database(DB))
    # 1) Явно добавленные модели (source='model' - ПРИОРИТЕТ при маршрутизации)
    added_models = [r["model_name"] for r in _db("SELECT model_name FROM pool_models")]
    for m in added_models:
        try:
            pool.add_model(m)
        except Exception:
            pass
    # 2) Явно добавленные провайдеры (source='endpoint' - fallback)
    for r in _db("SELECT endpoint FROM pool_endpoints"):
        try:
            pool.add_endpoint(r["endpoint"])
        except Exception:
            pass
    # Маркировка source: модели, добавленные явно слева, ВСЕ их строки = 'model'
    # (приоритет при маршрутизации); прочие = 'endpoint'.
    if added_models:
        _exec("UPDATE active_pool SET source='endpoint'")  # все сначала fallback
        ph = ",".join("?" * len(added_models))
        _exec(
            f"UPDATE active_pool SET source='model' "
            f"WHERE model_name IN ({ph})",
            tuple(added_models))


def _pool_models_set() -> set:
    """Множество имён моделей, добавленных явно (левая колонка)."""
    _ensure_active_pool()
    try:
        rows = _db("SELECT model_name FROM pool_models")
        return {r["model_name"] for r in rows}
    except Exception:
        return set()


def _pool_endpoints_set() -> set:
    """Множество base_url, добавленных явно (правая колонка)."""
    _ensure_active_pool()
    try:
        rows = _db("SELECT endpoint FROM pool_endpoints")
        return {r["endpoint"] for r in rows}
    except Exception:
        return set()


def _pool_msg(key: str, **kw) -> str:
    """Pool action message in current UI language."""
    try:
        from tui_i18n import tf as _i18n_tf, resolve_lang as _i18n_lang
        return _i18n_tf(key, _i18n_lang(), **kw)
    except Exception:
        return key


def _pool_add_model(model_name: str) -> str:
    """Add model to pool (left column)."""
    _ensure_active_pool()
    _exec("INSERT OR IGNORE INTO pool_models (model_name) VALUES (?)",
          (model_name,))
    _rebuild_active_pool()
    return _pool_msg("pool_added_model", name=model_name)


def _pool_add_endpoint(base_url: str) -> str:
    """Add provider endpoint to pool (right column)."""
    _ensure_active_pool()
    _exec("INSERT OR IGNORE INTO pool_endpoints (endpoint) VALUES (?)",
          (base_url,))
    _rebuild_active_pool()
    return _pool_msg("pool_added_provider", name=base_url)


def _pool_remove_model(model_name: str) -> str:
    """Remove model from pool (left column)."""
    _ensure_active_pool()
    _exec("DELETE FROM pool_models WHERE model_name=?", (model_name,))
    _rebuild_active_pool()
    return _pool_msg("pool_removed", name=model_name)


def _pool_remove_endpoint(base_url: str) -> str:
    """Remove provider endpoint from pool (right column)."""
    _ensure_active_pool()
    _exec("DELETE FROM pool_endpoints WHERE endpoint=?", (base_url,))
    _rebuild_active_pool()
    return _pool_msg("pool_removed", name=base_url)


def _pool_remove_row(model_name: str, endpoint: str) -> str:
    """Remove (model, endpoint) pair from active_pool cache."""
    _ensure_active_pool()
    _exec("DELETE FROM active_pool WHERE model_name=? AND endpoint=?",
          (model_name, endpoint))
    return _pool_msg("pool_removed_pair", name=model_name, endpoint=endpoint)


def _pool_clear() -> str:
    _ensure_active_pool()
    _exec("DELETE FROM pool_models")
    _exec("DELETE FROM pool_endpoints")
    _exec("DELETE FROM active_pool")
    return "Пул очищен"


async def _recheck_confirmed_keys(db) -> str:
    """Перепроверить CONFIRMED ключи - все модели, обновить статусы.

    Standalone async функция (не метод класса) - вызывается из фонового потока.
    Возвращает строку-результат для отображения в slog.
    """
    import asyncio
    from validator import AsyncValidator, KeyStatus
    validator = AsyncValidator(db)
    validator._circuit_breaker.reset()

    keys = _db(
        "SELECT id, api_key, base_url, platform FROM leaked_keys "
        "WHERE status='confirmed' AND base_url != '' ORDER BY id"
    )
    if not keys:
        await validator.close()
        return "[dim]Нет CONFIRMED ключей для перепроверки[/]"

    # Число моделей каждого ключа - для плавного прогресса по моделям
    # (а не по ключам: один ключ может перебирать 50 моделей = долго,
    # прогресс «по ключам» стоял бы). total = суммарно моделей.
    models_per_key = {}
    total_models = 0
    try:
        for r in _db(
            "SELECT key_id, COUNT(*) AS c FROM key_models "
            "WHERE key_id IN (%s) GROUP BY key_id"
            % ",".join("?" * len(keys)),
            tuple(k["id"] for k in keys)):
            models_per_key[r["key_id"]] = r["c"]
            total_models += r["c"]
    except Exception:
        pass
    # Если моделей нет - fallback на число ключей
    total_for_progress = total_models or len(keys)

    sem = asyncio.Semaphore(8)
    stats = {"confirmed": 0, "valid": 0, "quota": 0, "invalid": 0,
             "models_confirmed": 0, "done": 0}
    models_done = [0]  # суммарно обработано моделей (для прогресса)
    _set_task_progress("confirm_models", 0, total_for_progress)

    async def check_one(key):
        async with sem:
            try:
                # Сбросить is_confirmed=0 для ВСЕХ моделей ключа
                with db._lock:
                    with db._get_connection() as conn:
                        conn.execute(
                            "UPDATE key_models SET is_confirmed=0 "
                            "WHERE key_id=?", (key["id"],))
                        conn.commit()

                # confirm_key проверит все модели и пометит рабочие через batch
                ck = await validator.confirm_key(
                    key["api_key"], key["base_url"], None,
                    platform=key["platform"])

                if ck.status == KeyStatus.VALID and "Подтверждён" in ck.info:
                    working = len(ck.models) if ck.models else 0
                    stats["models_confirmed"] += working
                    stats["confirmed"] += 1
                elif ck.status == KeyStatus.QUOTA_EXCEEDED:
                    db.update_key_status(
                        key["api_key"], KeyStatus.QUOTA_EXCEEDED,
                        balance="Квота исчерпана при перепроверке")
                    stats["quota"] += 1
                elif ck.status == KeyStatus.INVALID:
                    db.update_key_status(
                        key["api_key"], KeyStatus.INVALID,
                        balance="Ключ отозван при перепроверке")
                    stats["invalid"] += 1
                else:
                    db.update_key_status(
                        key["api_key"], KeyStatus.VALID,
                        balance=ck.info or "VALID (модели не отвечают)")
                    stats["valid"] += 1
            except Exception as e:
                import logging
                logging.debug(f"_recheck_confirmed error: {e}")
            finally:
                stats["done"] += 1
                # Прогресс по моделям (плавнее): +модели этого ключа
                models_done[0] += models_per_key.get(key["id"], 1) \
                    if total_models else 1
                _set_task_progress("confirm_models", models_done[0],
                                   total_for_progress)

    await asyncio.gather(*[check_one(k) for k in keys],
                         return_exceptions=True)
    _clear_task_progress("confirm_models")
    try:
        await validator.close()
    except Exception:
        pass
    return (
        f"[green]Готово: {stats['done']}/{len(keys)} ключей - "
        f"CONFIRMED:{stats['confirmed']} QUOTA:{stats['quota']} "
        f"INVALID:{stats['invalid']} понижен до VALID:{stats['valid']} "
        f"| моделей подтверждено: {stats['models_confirmed']}[/]")


def _colorize_log(line: str) -> str:
    up = line.upper()
    if "ERROR" in up or "TRACEBACK" in up:
        return f"[red]{line}[/]"
    if "WARN" in up:
        return f"[yellow]{line}[/]"
    if "FOUND" in up or "VALID" in up or "SUCCESS" in up:
        return f"[green]{line}[/]"
    if "SCAN" in up or "START" in up:
        return f"[white]{line}[/]"
    if "QUOTA" in up or "RATE" in up:
        return f"[magenta]{line}[/]"
    return line


# ============================================================================
#                                  Приложение
# ============================================================================

class ScannerTUI(App):
    TITLE = "Secret Scanner Pro"
    SUB_TITLE = "8 sources"

    # Filled in __init__ after language resolve (compose reads self._lang / _t)
    # Class defaults: English so screenshots/docs are EN without locale.
    # Тёмная тема — default, не opt-in
    CSS = """
    /* ─── Base (neutral dark, no cyan wash) ────────────── */
    Screen { background: $background; color: $foreground; }
    Header {
        background: $surface;
        color: $foreground;
        text-style: bold;
        dock: top;
        border-bottom: solid $panel;
    }
    Footer {
        background: $surface;
        color: $text-muted;
        dock: bottom;
        border-top: solid $panel;
    }

    /* ─── Status bar ───────────────────────────────────── */
    #statusbar {
        dock: top; height: 3; padding: 0 2;
        background: $surface;
        border-bottom: solid $panel;
        color: $foreground;
        content-align: left middle;
    }

    /* ─── Tabs: high contrast active ───────────────────── */
    TabbedContent { height: 1fr; background: $background; }
    Tabs {
        dock: top;
        background: $surface;
        height: 3;
        border-bottom: solid $panel;
    }
    Tab {
        color: #94a3b8;
        background: transparent;
        padding: 0 3;
        height: 3;
        content-align: center middle;
    }
    Tab.-active {
        color: #ffffff;
        text-style: bold;
        background: $panel;
        border-bottom: heavy $accent;
    }
    Tab:hover {
        color: #e2e8f0;
        background: $panel 60%;
    }
    Underline { background: transparent; }
    Underline > .underline--bar { color: $accent; background: $accent; }
    TabPane { padding: 1 1; background: $background; }

    /* ─── Toolbar / buttons (readable height) ──────────── */
    .toolbar {
        height: auto;
        min-height: 3;
        padding: 0 0 1 0;
        align-vertical: middle;
    }
    Button {
        min-height: 3;
        height: 3;
        min-width: 8;
        padding: 0 2;
        margin: 0 1 1 0;
        background: $panel;
        color: $foreground;
        border: tall $panel;
        content-align: center middle;
    }
    Button:hover {
        background: #2a2a30;
        color: #ffffff;
        border: tall #3f3f46;
    }
    Button:focus {
        border: tall $accent;
    }
    Button.-primary {
        background: #1e3a5f;
        color: #e0f2fe;
        border: tall #2563eb;
    }
    Button.-primary:hover { background: #1d4ed8; color: #ffffff; }
    Button.-success {
        background: #14532d;
        color: #bbf7d0;
        border: tall #16a34a;
    }
    Button.-success:hover { background: #166534; }
    Button.-error {
        background: #450a0a;
        color: #fecaca;
        border: tall #dc2626;
    }
    Button.-error:hover { background: #7f1d1d; }
    Button.-warning {
        background: #422006;
        color: #fde68a;
        border: tall #d97706;
    }
    .toolbar Button { margin: 0 1 0 0; }
    .toolbar Input {
        width: 1fr; max-width: 40; height: 3; margin: 0 1 0 1;
        background: $panel; border: tall $panel; color: $foreground;
        padding: 0 1;
    }
    .toolbar Input:focus { border: tall $accent; }
    /* Select: text vertically centered, left pad, not glued to edge */
    Select {
        width: 22;
        height: 3;
        min-height: 3;
        margin: 0 1 0 0;
        background: $panel;
        color: $foreground;
        border: tall $panel;
        padding: 0;
    }
    Select:focus { border: tall $accent; }
    SelectCurrent {
        height: 3;
        min-height: 3;
        padding: 0 2;
        content-align: left middle;
        color: $foreground;
        background: $panel;
        border: none;
    }
    SelectCurrent > .select-current--label {
        color: $foreground;
        content-align: left middle;
    }
    SelectOverlay {
        background: $surface;
        border: tall $panel;
        color: $foreground;
        max-height: 16;
    }
    SelectOverlay > .option-list--option {
        padding: 0 2;
        color: $foreground;
    }
    SelectOverlay > .option-list--option-highlighted {
        background: $panel;
        color: $foreground;
        text-style: bold;
    }
    .toolbar Select {
        width: 22;
        height: 3;
        margin: 0 1 0 0;
    }
    #k_platform { width: 24; }
    #m_family { width: 20; }
    #m_sort { width: 18; }
    #p_sort { width: 22; }

    /* API: gap between pool tables and selection method */
    #e_sel_mode_row {
        height: auto;
        min-height: 3;
        margin: 1 0 1 0;
        padding: 1 0 0 0;
        border-top: solid $panel;
    }
    #e_sel_mode_btn {
        margin: 0 1 0 0;
        min-width: 28;
        height: 3;
    }
    #e_sel_mode_label {
        color: $text-muted;
        content-align: left middle;
        height: 3;
        padding: 0 1;
    }

    /* ─── Panels: solid edges + surface fill (no black under round corners) ─ */
    .panel {
        border: solid $panel;
        background: $surface;
        padding: 0 1 1 1;
        margin: 0 1 1 0;
        height: auto;
        min-width: 16;
    }
    .panel:focus-within {
        border: solid $panel;
        background: $surface;
    }
    .panel-title {
        color: #e2e8f0;
        text-style: bold;
        padding: 0 0 0 0;
        height: 1;
        background: transparent;
    }
    .dim { color: $text-muted; }
    .hint {
        color: $text-muted;
        text-style: italic;
        padding: 0 0 1 0;
        margin: 0 0 1 0;
    }
    .danger { color: $error; }

    /* ─── Dashboard: flush tiles, no gaps between panels ─ */
    TabPane#dashboard { height: 1fr; padding: 0; background: $background; }
    #d_root {
        height: 1fr;
        width: 100%;
        layout: vertical;
        background: $background;
        padding: 0;
    }
    #d_main {
        height: 1fr;
        min-height: 12;
        width: 100%;
        background: $background;
    }
    /* zero .panel margins inside dashboard so squares sit edge-to-edge */
    #d_root .panel {
        margin: 0;
        padding: 0 1 0 1;
    }
    #d_workers_wrap {
        width: 3fr;
        min-width: 36;
        height: 1fr;
        min-height: 8;
        margin: 0;
    }
    #d_side_stack {
        width: 2fr;
        min-width: 24;
        height: 1fr;
    }
    #d_workers {
        height: 1fr;
        background: $surface;
        color: $foreground;
    }
    #d_funnel_wrap, #d_statuses_wrap, #d_confirm_wrap {
        width: 100%;
        height: 1fr;
        min-height: 4;
        margin: 0;
    }
    #d_funnel, #d_statuses, #d_confirm {
        height: 1fr;
        color: $foreground;
        overflow-y: auto;
    }
    #d_prog_wrap {
        width: 100%;
        height: auto;
        min-height: 3;
        max-height: 5;
        margin: 0;
    }
    #d_progress {
        height: auto;
        min-height: 2;
        max-height: 4;
        padding: 0 1;
        color: $foreground;
    }
    #d_bottom {
        height: auto;
        min-height: 0;
        max-height: 10;
        width: 100%;
        margin: 0;
        padding: 0;
        align-vertical: top;
    }
    /* equal tile height for bottom strip; no inner empty band under short content */
    #d_plat_wrap, #d_keys_wrap, #d_models_wrap {
        width: 1fr;
        min-width: 16;
        height: 1fr;
        max-height: 10;
        margin: 0;
        padding: 0 1 0 1;
    }
    #d_platforms, #d_keys, #d_confmodels {
        height: 1fr;
        max-height: 8;
        color: $foreground;
        overflow-y: auto;
        padding: 0;
        margin: 0;
    }
    #d_log_wrap {
        width: 100%;
        height: 8;
        min-height: 5;
        max-height: 12;
        margin: 0;
        padding: 0 1 0 1;
    }

    #dlog {
        height: 1fr;
        min-height: 4;
        background: $boost;
        color: $foreground;
        border: none;
    }

    /* ─── Tables: restore surface/zebra palette ─────────────────────────
       Only override Textual's :focus background-tint that greys the WHOLE
       table when clicked (leftover from light/old theme focus wash).
       Row cursor/hover stay subtle; not a full-table recolor. */
    DataTable {
        background: $surface;
        color: $foreground;
        scrollbar-background: $boost;
        scrollbar-color: $panel;
    }
    /* KEY FIX: do not wash entire table grey/blue on focus/click */
    DataTable:focus {
        background: $surface;
        background-tint: transparent;
    }
    DataTable > .datatable--header {
        background: $panel;
        color: #cbd5e1;
        text-style: bold;
    }
    DataTable:focus > .datatable--header {
        background: $panel;
        background-tint: transparent;
    }
    DataTable > .datatable--cursor {
        background: $panel;
        color: $foreground;
        text-style: bold;
    }
    DataTable:focus > .datatable--cursor {
        background: $panel;
        color: $foreground;
        text-style: bold;
        background-tint: transparent;
    }
    DataTable > .datatable--fixed-cursor {
        background: $panel;
        color: $foreground;
    }
    DataTable:focus > .datatable--fixed-cursor {
        background: $panel;
        color: $foreground;
        background-tint: transparent;
    }
    DataTable > .datatable--hover {
        background: $panel 60%;
        color: $foreground;
    }
    DataTable > .datatable--header-cursor {
        background: $panel;
        color: $accent;
        text-style: bold;
    }
    DataTable > .datatable--header-hover {
        background: $panel;
        color: $foreground;
    }
    /* Zebra: clear alternate row shades (even darker / odd slightly lighter) */
    DataTable > .datatable--even-row {
        background: #101012;
    }
    DataTable > .datatable--odd-row {
        background: #1e1e22;
    }
    DataTable:dark > .datatable--even-row {
        background: #101012;
    }
    DataTable:dark > .datatable--odd-row {
        background: #1e1e22;
    }
    DataTable:focus > .datatable--even-row {
        background: #101012;
        background-tint: transparent;
    }
    DataTable:focus > .datatable--odd-row {
        background: #1e1e22;
        background-tint: transparent;
    }
    /* workers: display-only, no selection chrome */
    #d_workers,
    #d_workers:focus {
        background: $surface;
        background-tint: transparent;
    }
    #d_workers > .datatable--cursor,
    #d_workers > .datatable--hover,
    #d_workers > .datatable--fixed-cursor,
    #d_workers:focus > .datatable--cursor {
        background: transparent;
        color: $foreground;
        text-style: none;
    }
    #tbl, #m_tbl, #p_tbl, #e_models_tbl, #e_providers_tbl {
        height: 1fr;
        background: $surface;
    }
    #tbl:focus, #m_tbl:focus, #p_tbl:focus,
    #e_models_tbl:focus, #e_providers_tbl:focus {
        background: $surface;
        background-tint: transparent;
    }
    #detail {
        border: solid $panel;
        background: $surface;
        padding: 0 1; margin: 1 0 0 0;
        height: auto; min-height: 5; color: $foreground;
    }
    #keyscount { color: $text-muted; padding: 0 1; height: 1; }

    #m_detail_wrap, #p_detail_wrap {
        border: solid $panel;
        background: $surface;
        padding: 0 1; margin: 1 0 0 0;
        height: 40%; min-height: 6;
        overflow-y: auto; overflow-x: hidden; width: 100%;
    }
    #m_detail, #p_detail { width: 100%; color: $foreground; background: $surface; }
    #m_count, #p_count { color: $text-muted; padding: 0 1; height: 1; }

    /* ─── Endpoints / logs ─────────────────────────────── */
    TabPane#endpoints { height: 1fr; background: $background; }
    #endpoints > Vertical { height: 1fr; background: $background; }
    #e_tables_row { height: 1fr; width: 100%; background: $background; }
    #e_tables_row > Vertical {
        height: 1fr; width: 1fr;
        border: solid $panel;
        background: $surface;
        padding: 0 1; margin: 1 1 0 0;
    }
    #e_tables_row > Vertical:focus-within {
        border: solid $panel;
        background: $surface;
    }
    #e_models_tbl, #e_providers_tbl { height: 1fr; background: $surface; }
    #e_models_count, #e_providers_count {
        color: $text-muted; padding: 0 1 1 0; height: auto; margin: 0 0 1 0;
    }
    #e_trace {
        height: 8;
        border: solid $panel;
        background: $boost;
        color: $foreground;
    }

    #slog, #mlog {
        height: 1fr;
        background: $boost;
        color: $foreground;
        border: solid $panel;
    }
    """

    # Binding labels stay English (footer); full UI strings come from tui_i18n.
    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
        Binding("1", "go('dashboard')", "Dashboard", show=True),
        Binding("2", "go('keys')", "Keys", show=True),
        Binding("3", "go('models')", "Models", show=True),
        Binding("4", "go('providers')", "Providers", show=True),
        Binding("5", "go('endpoints')", "API", show=True),
        Binding("6", "go('settings')", "Settings", show=True),
        Binding("7", "go('logs')", "Logs", show=True),
        Binding("r", "refresh", "Refresh", show=True),
        Binding("s", "toggle_scanner", "Start/Stop", show=True),
        Binding("R", "revalidate", "Re-validate", show=True),
        Binding("d", "drain", "Drain UNVERIFIED", show=True),
        Binding("p", "toggle_proxy", "Proxy ON/OFF", show=True),
        Binding("c", "copy_selected", "Copy key", show=True),
        Binding("slash", "focus_search", "Search", show=True),
        Binding("question_mark", "help", "Help", show=True),
    ]

    STATUS_FILTERS = [
        ("all", "All", "primary"),
        ("confirmed", "Confirmed", "success"),
        ("valid", "Valid", "success"),
        ("invalid", "Invalid", "error"),
        ("quota_exceeded", "Quota", "warning"),
        ("connection_error", "Errors", ""),
        ("unverified", "Unverified", ""),
        ("pending", "Pending", ""),
    ]

    SORT_COLS = {
        "platform": "platform", "key": "api_key", "status": "status",
        "balance": "balance", "base_url": "base_url",
        "source_url": "source_url", "found_time": "found_time",
        "high_value": "is_high_value",
    }

    def __init__(self) -> None:
        super().__init__()
        self._lang_pref = _load_lang_pref()  # auto | en | ru
        self._lang = _resolve_lang(self._lang_pref)  # en | ru (effective)
        self.TITLE = _t("app_title", self._lang)
        self.SUB_TITLE = _t("app_subtitle", self._lang)
        self._proc: Optional[subprocess.Popen] = None
        # Watchdog перезапуска сканера: отслеживаем смерть _proc и перезапускаем
        # с бэкоффом. Сбрасывается при ручном stop/успешном долгом ране.
        self._wd_restarts: int = 0          # перезапусков в текущем окне
        self._wd_window_start: float = 0.0  # начало окна бэкоффа
        self._wd_not_before: float = 0.0    # не перезапускать раньше этого времени
        self._wd_gave_up: bool = False      # сдаться после лавины падений
        self._wd_respawn_armed: bool = False  # pending watchdog-respawn timer
        self._drain_thread = None  # фоновый поток дрейна UNVERIFIED
        # Реестр активных фоновых задач: type -> {label, start, done, total}
        self._active_tasks: Dict[str, Dict[str, Any]] = {}
        self._trace_last_id: int = 0  # последний показанный req_id трейса
        # Async рендер моделей: поток для тяжёлого GROUP BY + генерация запросов
        import concurrent.futures as _cf
        self._models_exec = _cf.ThreadPoolExecutor(max_workers=1, thread_name_prefix="tui-models")
        self._models_gen = 0
        self._log_pos = 0  # byte offset в scanner.log для инкрементального чтения
        self._rows: List[Dict[str, Any]] = []
        self._k_selected: Optional[Dict[str, Any]] = None
        self._filter: str = "all"
        self._platform: str = "all"
        self._search: str = ""
        self._reveal: bool = False
        self._high_value: bool = False
        self._sort_key: str = "found_time"
        self._sort_desc: bool = True
        self._autoscroll: bool = True
        self._stats_cache: Optional[Dict[str, Any]] = None
        self._stats_time: float = 0
        # вкладка «Модели»
        self._m_rows: List[Dict[str, Any]] = []
        self._m_selected: Optional[Dict[str, Any]] = None
        self._m_search: str = ""
        self._m_family: str = "all"
        self._m_sort: str = "caps"
        self._m_confirmed_only: bool = False
        # вкладка «Провайдеры»
        self._p_rows: List[Dict[str, Any]] = []
        self._p_selected: Optional[Dict[str, Any]] = None
        self._p_search: str = ""
        self._p_sort: str = "keys"
        # вкладка «API» (эндпоинты)
        self._e_endpoint: str = "all"
        self._e_model: str = "none"
        self._e_temp: float = 0.0
        self._e_keypool: List[Dict[str, Any]] = []
        self._e_keypool_idx: int = 0
        self._proxy_proc: Optional[subprocess.Popen] = None
        self._proxy_external: bool = False  # 0.0.0.0 (внешний доступ через IP)
        # Трекинг двойного клика для добавления/удаления из пула
        self._m_last_click: float = 0.0
        self._p_last_click: float = 0.0
        self._e_last_click: float = 0.0
        self._e_selected_model: str = ""
        self._e_models_rows: List[Dict[str, Any]] = []
        self._e_providers_rows: List[Dict[str, Any]] = []
        self._e_selected_endpoint: str = ""  # выбран добавленный провайдер
        # Paint signature cache: skip dashboard repaint when data unchanged.
        self._dash_sig: Optional[str] = None

    def tr(self, key: str) -> str:
        return _t(key, self._lang)

    def trf(self, key: str, **kwargs) -> str:
        return _tf(key, self._lang, **kwargs)


    # ---------------------------- композиция -----------------------------

    def compose(self) -> ComposeResult:
        tr = self.tr
        yield Header()
        yield Static(tr("loading"), id="statusbar")
        with TabbedContent("dashboard", "keys", "models", "providers", "endpoints", "settings", "logs", id="tabs"):
            with TabPane(tr("tab_dashboard"), id="dashboard"):
                yield from self._compose_dashboard()
            with TabPane(tr("tab_keys"), id="keys"):
                yield from self._compose_keys()
            with TabPane(tr("tab_models"), id="models"):
                yield from self._compose_models()
            with TabPane(tr("tab_providers"), id="providers"):
                yield from self._compose_providers()
            with TabPane(tr("tab_api"), id="endpoints"):
                yield from self._compose_endpoints()
            with TabPane(tr("tab_settings"), id="settings"):
                yield from self._compose_settings()
            with TabPane(tr("tab_logs"), id="logs"):
                yield from self._compose_logs()
        yield Footer()

    def _compose_dashboard(self) -> ComposeResult:
        """Dense stretch layout: workers | stats stack; bottom strip; log.

        Uses fr heights (not nested 1fr-in-scroll) so resize fills the pane.
        """
        tr = self.tr
        with Vertical(id="d_root"):
            with Container(classes="panel", id="d_prog_wrap"):
                yield Static(tr("panel_progress"), classes="panel-title")
                yield Static("", id="d_progress")
            with Horizontal(id="d_main"):
                with Container(classes="panel", id="d_workers_wrap"):
                    yield Static(tr("panel_workers"), classes="panel-title")
                    yield DataTable(
                        id="d_workers",
                        cursor_type="none",
                        show_cursor=False,
                        zebra_stripes=True,
                        show_header=True,
                    )
                with Vertical(id="d_side_stack"):
                    with Container(classes="panel", id="d_funnel_wrap"):
                        yield Static(tr("panel_funnel"), classes="panel-title")
                        yield Static("", id="d_funnel")
                    with Container(classes="panel", id="d_statuses_wrap"):
                        yield Static(tr("panel_statuses"), classes="panel-title")
                        yield Static("", id="d_statuses")
                    with Container(classes="panel", id="d_confirm_wrap"):
                        yield Static(tr("panel_tasks"), classes="panel-title")
                        yield Static("", id="d_confirm")
            with Horizontal(id="d_bottom"):
                with Container(classes="panel", id="d_plat_wrap"):
                    yield Static(tr("panel_platforms"), classes="panel-title")
                    yield Static("", id="d_platforms")
                with Container(classes="panel", id="d_keys_wrap"):
                    yield Static(tr("panel_recent_keys"), classes="panel-title")
                    yield Static("", id="d_keys")
                with Container(classes="panel", id="d_models_wrap"):
                    yield Static(tr("panel_top_models"), classes="panel-title")
                    yield Static("", id="d_confmodels")
            with Container(classes="panel", id="d_log_wrap"):
                yield Static(tr("panel_live_log"), classes="panel-title")
                yield RichLog(
                    id="dlog", max_lines=80, markup=True,
                    highlight=True, auto_scroll=True,
                )

    def _status_filters(self):
        tr = self.tr
        return [
            ("all", tr("filter_all"), "primary"),
            ("confirmed", "Confirmed", "success"),
            ("valid", "Valid", "success"),
            ("invalid", "Invalid", "error"),
            ("quota_exceeded", "Quota", "warning"),
            ("connection_error", "Errors", ""),
            ("unverified", "Unverified", ""),
            ("pending", "Pending", ""),
        ]

    def _compose_keys(self) -> ComposeResult:
        tr = self.tr
        with Vertical():
            with Horizontal(classes="toolbar", id="k_filterbar"):
                for key, label, variant in self._status_filters():
                    yield Button(label, id=f"kf_{key}", variant=variant or "default")
                yield Button(tr("btn_high_value"), id="k_hv", variant="default")
                yield Button(tr("btn_reveal"), id="k_reveal", variant="default")
            with Horizontal(classes="toolbar"):
                yield Select(
                    [(tr("filter_all_platforms"), "all")] +
                    [(p, p) for p in _platforms()],
                    id="k_platform", value="all", allow_blank=False)
                yield Input(placeholder=tr("search_keys"), id="k_search")
                yield Button(tr("btn_refresh"), id="k_refresh", variant="primary")
            yield DataTable(
                id="tbl", cursor_type="row", show_cursor=True,
                zebra_stripes=True,
                cursor_background_priority="css",
            )
            yield Static("—", id="keyscount")
            yield Static(f"[dim]{tr('hint_keys')}[/]", classes="hint")
            yield Static(tr("hint_keys_detail"), id="detail", classes="dim")

    def _compose_models(self) -> ComposeResult:
        tr = self.tr
        with Vertical():
            with Horizontal(classes="toolbar"):
                yield Select(
                    [(tr("family_all"), "all"),
                     ("GPT", "GPT"), ("Claude", "Claude"), ("Gemini", "Gemini"),
                     ("Llama", "Llama"), ("Mistral", "Mistral"),
                     ("Mixtral", "Mixtral"), ("Command", "Command"),
                     ("Grok", "Grok"), ("DeepSeek", "DeepSeek"),
                     ("Qwen", "Qwen"), ("Gemma", "Gemma"), ("Phi", "Phi"),
                     ("o-series", "o-series"), ("Sonar", "Sonar"),
                     ("Embedding", "Embedding"), ("Image", "Image"),
                     ("Other", "Other")],
                    id="m_family", value="all", allow_blank=False)
                yield Input(placeholder=tr("search_model"), id="m_search")
                yield Select(
                    [(tr("sort_caps"), "caps"), (tr("sort_newest"), "newest"),
                     (tr("sort_keys"), "keys"),
                     (tr("sort_name"), "name"), (tr("sort_family"), "family")],
                    id="m_sort", value="caps", allow_blank=False)
                yield Button(tr("btn_refresh"), id="m_refresh", variant="primary")
                yield Button(tr("btn_confirmed_only"), id="m_confirmed", variant="default")
            yield DataTable(
                id="m_tbl", cursor_type="row", zebra_stripes=True,
                cursor_background_priority="css",
            )
            yield Static("—", id="m_count")
            yield Static(tr("hint_models"), classes="hint")
            with VerticalScroll(id="m_detail_wrap"):
                yield Static(tr("hint_models_detail"), id="m_detail", classes="dim")

    def _compose_providers(self) -> ComposeResult:
        tr = self.tr
        with Vertical():
            with Horizontal(classes="toolbar"):
                yield Input(placeholder=tr("search_provider"), id="p_search")
                yield Select(
                    [(tr("sort_keys"), "keys"), (tr("sort_confirmed"), "confirmed"),
                     (tr("sort_name"), "name"), (tr("sort_models"), "models")],
                    id="p_sort", value="keys", allow_blank=False)
                yield Button(tr("btn_refresh"), id="p_refresh", variant="primary")
                yield Button(tr("btn_reveal"), id="p_reveal", variant="default")
            yield DataTable(
                id="p_tbl", cursor_type="row", zebra_stripes=True,
                cursor_background_priority="css",
            )
            yield Static("—", id="p_count")
            with VerticalScroll(id="p_detail_wrap"):
                yield Static(tr("hint_providers_detail"), id="p_detail", classes="dim")

    def _compose_endpoints(self) -> ComposeResult:
        tr = self.tr
        with Vertical():
            with Horizontal(classes="toolbar"):
                yield Button(tr("btn_proxy_on"), id="e_proxy", variant="success")
                yield Button(tr("btn_external_ip"), id="e_external", variant="default")
                yield Button(tr("btn_test_url"), id="e_test_url", variant="default")
                yield Button(tr("btn_refresh"), id="e_refresh", variant="primary")
                yield Button(tr("btn_check_all"), id="e_check_all", variant="warning")
                yield Button(tr("btn_clear_pool"), id="e_clear", variant="error")
            yield Static(
                f"[dim]{tr('hint_api')}[/]",
                classes="hint", id="e_hint")
            with Horizontal(id="e_tables_row"):
                with Vertical():
                    yield Static(f"[bold]{tr('pool_models')}[/]", classes="panel-title")
                    yield DataTable(
                        id="e_models_tbl", cursor_type="row",
                        zebra_stripes=True,
                        cursor_background_priority="css",
                    )
                    yield Static("—", id="e_models_count")
                with Vertical():
                    yield Static(
                        f"[bold]{tr('pool_providers')}[/] "
                        f"[dim]{tr('pool_providers_hint')}[/]",
                        classes="panel-title", id="e_providers_title")
                    yield DataTable(
                        id="e_providers_tbl", cursor_type="row",
                        zebra_stripes=True,
                        cursor_background_priority="css",
                    )
                    with Horizontal(classes="toolbar"):
                        yield Button("▲", id="e_p_up", variant="default")
                        yield Button("▼", id="e_p_down", variant="default")
                        yield Button(tr("btn_toggle"), id="e_p_toggle", variant="success")
                        yield Button(tr("btn_delete"), id="e_p_del", variant="error")
                    yield Static("—", id="e_providers_count")
            with Horizontal(classes="toolbar", id="e_sel_mode_row"):
                yield Static(tr("key_selection"), id="e_sel_mode_label")
                yield Button(tr("method_rr"), id="e_sel_mode_btn",
                             variant="default")
            yield Static(tr("trace_title"), classes="panel-title")
            yield RichLog(id="e_trace", max_lines=100, markup=True,
                          highlight=False, auto_scroll=True)

    def _compose_settings(self) -> ComposeResult:
        tr = self.tr
        with VerticalScroll():
            with Container(classes="panel"):
                yield Static(tr("settings_language"), classes="panel-title")
                with Horizontal(classes="toolbar"):
                    yield Select(
                        [
                            (f"{tr('lang_auto')} ({_detect_system_lang().upper()})", "auto"),
                            (tr("lang_en"), "en"),
                            (tr("lang_ru"), "ru"),
                        ],
                        id="s_lang",
                        value=self._lang_pref if self._lang_pref in ("auto", "en", "ru") else "auto",
                        allow_blank=False,
                    )
                    yield Button("Apply", id="s_lang_apply", variant="primary")
                yield Label(tr("lang_hint"), classes="hint")
            with Container(classes="panel"):
                yield Static(tr("settings_scanner"), classes="panel-title")
                with Horizontal(classes="toolbar"):
                    yield Button(tr("btn_start"), id="s_start", variant="success")
                    yield Button(tr("btn_stop"), id="s_stop", variant="error")
                    yield Button(tr("btn_restart"), id="s_restart")
                    yield Button("Autostart: ON" if AUTOSTART else "Autostart: OFF",
                                 id="s_autostart", variant="warning")
            with Container(classes="panel"):
                yield Static(tr("settings_db"), classes="panel-title")
                with Horizontal(classes="toolbar"):
                    yield Button(tr("btn_clear_sha"), id="s_clearsha",
                                 variant="warning")
                    yield Button(tr("btn_clear_prog"), id="s_clearprog")
                    yield Button(tr("btn_vacuum"), id="s_vacuum")
                    yield Button(tr("btn_del_invalid"), id="s_delinvalid",
                                 variant="error")
                    yield Button(tr("btn_reset_attempts"), id="s_resetattempts",
                                 variant="warning")
                    yield Button(tr("btn_mark_hv"), id="s_markhv",
                                 variant="success")
            with Container(classes="panel"):
                yield Static(tr("settings_revalidate"), classes="panel-title")
                with Horizontal(classes="toolbar"):
                    yield Button(tr("btn_revalidate_all"), id="s_revalidate_all",
                                 variant="primary")
                    yield Button(tr("btn_revalidate_failed"), id="s_revalidate_failed",
                                 variant="warning")
                    yield Button(tr("btn_confirm_all"), id="s_confirm_all",
                                 variant="success")
                    yield Button(tr("btn_drain"), id="s_drain_unverified",
                                 variant="warning")
                    yield Button(tr("btn_confirm_models"), id="s_confirm_models",
                                 variant="primary")
                yield Label(tr("hint_revalidate"), classes="hint")
            with Container(classes="panel"):
                yield Static(tr("settings_export"), classes="panel-title")
                with Horizontal(classes="toolbar"):
                    yield Button("TXT (valid)", id="s_txt", variant="primary")
                    yield Button("CSV (valid)", id="s_csv", variant="primary")
                    yield Button("JSON (all)", id="s_json", variant="primary")
                    yield Button("Models JSON", id="s_models_export", variant="success")
                yield Label(tr("hint_export"), classes="hint")
            with Container(classes="panel"):
                yield Static(tr("settings_config"), classes="panel-title")
                yield Static("", id="s_config")
            with Container(classes="panel"):
                yield Static(tr("settings_log"), classes="panel-title")
                yield RichLog(id="slog", max_lines=200, markup=True,
                              highlight=True)

    def _compose_logs(self) -> ComposeResult:
        tr = self.tr
        with Vertical():
            with Horizontal(classes="toolbar"):
                yield Button(tr("btn_load"), id="l_load", variant="primary")
                yield Button(tr("btn_clear"), id="l_clear")
                yield Button("Autoscroll: ON", id="l_autoscroll",
                             variant="warning")
                yield Input(placeholder=tr("search_log"), id="l_filter")
                yield Button(tr("btn_copy"), id="l_copy", variant="default")
            yield RichLog(id="mlog", max_lines=1000, markup=True,
                          highlight=True)

    # ----------------------------- mount --------------------------------

    def on_mount(self) -> None:
        # Тёмная современная тема
        try:
            self.register_theme(_SCANNER_DARK)
            self.theme = "scanner-dark"
            self.dark = True
        except Exception:
            pass
        # Убить зомби от прошлых запусков (держат порт 8818/спамят) - в потоке,
        # PowerShell медленный. Иначе новый прокси/сканер не стартуют.
        import threading as _th
        _th.Thread(target=self._kill_zombie_processes, daemon=True).start()
        tr = self.tr
        tbl = self.query_one("#tbl", DataTable)
        tbl.add_columns(
            "#", tr("col_platform"), tr("col_status"), tr("col_key"), tr("col_balance"),
            tr("col_base"), tr("col_src"), tr("col_high"), tr("col_found_time"),
        )
        m_tbl = self.query_one("#m_tbl", DataTable)
        m_tbl.add_columns(
            "*", "#", tr("col_model"), tr("col_family"), tr("col_cap"), tr("col_provider"),
            tr("col_release"), tr("col_tier"), tr("col_access"), tr("col_platforms"),
        )
        p_tbl = self.query_one("#p_tbl", DataTable)
        p_tbl.add_columns(
            "*", "#", tr("col_provider"), tr("col_endpoint"), tr("col_keys"),
            tr("col_confirmed"), tr("col_platforms"), tr("col_top_models"),
        )
        workers = self.query_one("#d_workers", DataTable)
        workers.add_columns(
            tr("col_source"), tr("col_status"), tr("col_phase"), tr("col_progress"),
            tr("col_proc"), tr("col_found"), tr("col_keys"), tr("col_err"), tr("col_age"),
        )
        self.set_interval(TICK, self._tick)
        # Restore lightweight UI prefs only (disk/env, no network)
        try:
            mode = self._get_proxy_mode()
            if mode == "external":
                self._proxy_external = True
                try:
                    self.query_one("#e_external", Button).variant = "success"
                except Exception:
                    pass
        except Exception:
            pass
        try:
            sm = self._get_selection_mode()
            btn = self.query_one("#e_sel_mode_btn", Button)
            btn.label = (self.tr("method_sticky") if sm == "sticky"
                         else self.tr("method_rr"))
        except Exception:
            pass
        # Defer heavy work: first paint is free, then background refresh/probes.
        # TUI must not block on DB/network/other scripts at startup.
        self.set_timer(0.05, self._deferred_startup)

    def _deferred_startup(self) -> None:
        """Non-blocking startup: first paint free, heavy work deferred.

        Token probe runs in a daemon thread (network). Full table/DB paint
        is scheduled on a short timer so the event loop is never blocked by
        mount-time network/DB — menu stays responsive independently of
        scanner/proxy scripts.
        """
        import threading as _th

        # Прогреть тяжёлые кэши (_stats/_source_progress/_validation_progress)
        # и собрать мёртвых воркеров — всё в фоновом потоке, чтобы первый paint
        # не ждал 2с+ полного скана БД (508k строк). _refresh_all на таймере
        # 0.2с прочитает уже тёплый кэш.
        def _prime_caches() -> None:
            try:
                # Сбор мёртвых воркеров: старые active-статусы -> stopped, чтобы
                # дашборд не показывал вечный STALE после убийства/падения сканера.
                _reap_stale_sources()
            except Exception:
                pass
            try:
                _stats_uncached_into_cache()
                _source_progress()
                _validation_progress()
                _model_discovery_counts()
            except Exception:
                pass
            # Первый полный paint — только когда кэш тёплый (не по слепому
            # таймеру 0.2с, который гонялся бы с прогревом и фризил UI).
            try:
                self.call_from_thread(self._refresh_all)
            except Exception:
                pass

        _th.Thread(target=_prime_caches, daemon=True, name="tui-prime").start()

        def _bg_token_check() -> None:
            if os.environ.get("TUI_SKIP_TOKEN_CHECK", "").lower() in (
                "1", "true", "yes",
            ):
                return
            try:
                health = _github_token_health()
            except Exception:
                return
            if int(health.get("working") or 0) > 0:
                return
            try:
                self.call_from_thread(
                    self.push_screen,
                    GitHubTokenNotice(health, lang=self._lang),
                )
            except Exception:
                try:
                    path = health.get("config_local_path") or CONFIG_LOCAL_PATH
                    self.call_from_thread(
                        self._slog,
                        f"[yellow]{self.trf('log_no_tokens', path=path)}[/]",
                    )
                except Exception:
                    pass

        # Не форсируем холодный _stats() на старте (это 2-4с полного скана БД).
        # Первый paint (статусбар + дашборд + таблицы) делает _prime_caches
        # через call_from_thread, когда кэш прогрет. Статусбар покажет данные
        # сразу после прогрева; до этого панель просто пустая — UI отзывчив.
        _th.Thread(target=_bg_token_check, daemon=True, name="tui-token").start()

        if AUTOSTART:
            self.set_timer(0.5, lambda: self._start_scanner(silent=True))
        if AUTODRAIN:
            self.set_timer(15, self._maybe_start_drain)
        self.set_timer(5, self._maybe_notice_update)
        AUTOPROXY = os.environ.get("TUI_AUTOPROXY", "1") not in ("0", "false", "no")
        if AUTOPROXY:
            self.set_timer(3, self._maybe_start_proxy)

    def _maybe_warn_github_tokens(self) -> None:
        """Legacy entry: schedule async token check (never block UI thread)."""
        import threading as _th

        def _run() -> None:
            if os.environ.get("TUI_SKIP_TOKEN_CHECK", "").lower() in (
                "1", "true", "yes",
            ):
                return
            try:
                health = _github_token_health()
            except Exception:
                return
            if int(health.get("working") or 0) > 0:
                return
            try:
                self.call_from_thread(
                    self.push_screen,
                    GitHubTokenNotice(health, lang=self._lang),
                )
            except Exception as e:
                path = CONFIG_LOCAL_PATH
                try:
                    self.call_from_thread(
                        self._slog,
                        f"[yellow]{self.trf('log_no_tokens', path=path)}[/] ({e})",
                    )
                except Exception:
                    pass

        _th.Thread(target=_run, daemon=True, name="tui-token-warn").start()

    def _maybe_start_proxy(self) -> None:
        """Запустить локальный прокси, если он ещё не активен."""
        if not self._is_proxy_running():
            self._on_e_proxy()
            self._slog(f"[green]{self.tr('log_proxy_autostart')}[/]")

    def _maybe_start_drain(self) -> None:
        """Запустить дрейн, если он ещё не активен (guard от двойного запуска)."""
        if not self._is_draining():
            self._run_bg_task("drain_unverified")

    def _maybe_notice_update(self) -> None:
        """Разовая проверка обновлений при старте TUI (фон, без блока UI).

        Сравнивает локальный HEAD с upstream. При отставании — одна строка
        в лог: обновиться через `ascan upgrade` (ключи/БД не трогает).
        """
        import threading as _th

        def _run() -> None:
            if os.environ.get("ASCAN_SKIP_UPDATE_CHECK", "").lower() in ("1", "true", "yes"):
                return
            try:
                import subprocess as _sp
                _sp.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=BASE_DIR,
                        capture_output=True, timeout=10,
                        creationflags=getattr(_sp, "CREATE_NO_WINDOW", 0)).check_returncode()
                _sp.run(["git", "fetch", "origin"], cwd=BASE_DIR,
                        capture_output=True, timeout=30,
                        creationflags=getattr(_sp, "CREATE_NO_WINDOW", 0))
                local = _sp.run(["git", "rev-parse", "HEAD"], cwd=BASE_DIR,
                                capture_output=True, text=True, timeout=10,
                                creationflags=getattr(_sp, "CREATE_NO_WINDOW", 0)).stdout.strip()
                remote = _sp.run(["git", "rev-parse", "@{u}"], cwd=BASE_DIR,
                                 capture_output=True, text=True, timeout=10,
                                 creationflags=getattr(_sp, "CREATE_NO_WINDOW", 0)).stdout.strip()
                if local and remote and local != remote:
                    self.call_from_thread(
                        self._slog,
                        "[yellow]Update available — run: ascan upgrade[/] "
                        "(config_local.py + *.db untouched)",
                    )
            except Exception:
                pass

        _th.Thread(target=_run, daemon=True, name="tui-update-check").start()

    # ----------------------------- тикер --------------------------------

    def _tick(self) -> None:
        # Пока первый snapshot не загружен (_prime_caches в потоке) — не делаем
        # тяжёлые UI-обновления (_update_statusbar/_update_dashboard дергают
        # _stats(), который на холодном кэше делает 2-4с скан БД). Прогрев сам
        # вызовет _refresh_all через call_from_thread, когда будет готов.
        if not _primed:
            return
        try:
            self._update_statusbar()
        except Exception:
            pass
        # Периодический сбор мёртвых воркеров: active-статус без heartbeat
        # дольше порога -> stopped (вечный STALE после убийства сканера).
        try:
            if time.time() - getattr(self, "_last_reap", 0.0) >= 30.0:
                self._last_reap = time.time()
                _reap_stale_sources()
        except Exception:
            pass
        # Watchdog: если сканер-субпроцесс умер — перезапустить с бэкоффом.
        try:
            self._watchdog_scanner()
        except Exception:
            pass
        try:
            active = self.query_one("#tabs", TabbedContent).active
        except Exception:
            return
        try:
            if active == "dashboard":
                self._write_mini_log()  # лог обновляем всегда, независимо от _dash_sig
                self._update_dashboard()
            elif active == "logs":
                self._stream_logs()
            elif active == "endpoints":
                self._render_trace()
        except Exception:
            pass

    def _render_trace(self) -> None:
        """Показать трейс запросов прокси (попытки ключей со статусами).

        Читает /trace от локального прокси (если запущен). Новые события
        дописываются в RichLog, старые не дублируются (по req_id).
        HTTP-запрос выполняется в потоке, чтобы не блокировать UI.
        """
        if not self._is_proxy_running():
            return

        def _fetch():
            try:
                import urllib.request as _u
                import json as _j
                with _u.urlopen("http://127.0.0.1:8818/trace?n=50", timeout=1) as _r:
                    events = _j.loads(_r.read()).get("events", [])
                self.call_from_thread(self._apply_trace, events)
            except Exception:
                pass

        import threading as _th
        _th.Thread(target=_fetch, daemon=True).start()

    def _apply_trace(self, events: list) -> None:
        """Применить результаты трейса (вызывается из главного потока)."""
        try:
            lg = self.query_one("#e_trace", RichLog)
        except Exception:
            return
        last = getattr(self, "_trace_last_id", 0)
        new = [e for e in events if e.get("req_id", 0) > last]
        if not new:
            return
        for e in new:
            t = e.get("time", "")
            mdl = (e.get("model") or "")[:18]
            detail = e.get("detail", "")
            if e.get("summary"):
                color = "green" if "OK" in detail else "red"
                tag = "SUM" if self._lang != "ru" else "ИТОГ"
                lg.write(f"[{color}]{t} {tag} {mdl}: {detail}[/]")
            else:
                st = e.get("status")
                sc = ("green" if st == 200 else "yellow" if st in (429, 402)
                      else "red")
                mk = e.get("key", "")
                ep = (e.get("endpoint") or "")[:28]
                a = e.get("attempt", "?")
                lg.write(f"[dim]{t}[/] [white]{mdl:18s}[/] #{a} "
                         f"[{sc}]{mk}@{ep} {detail}[/]")
        self._trace_last_id = new[-1].get("req_id", last)

    # ------------------------- статусбар --------------------------------

    def _is_running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def _is_draining(self) -> bool:
        return (self._drain_thread is not None
                and self._drain_thread.is_alive())

    def _update_statusbar(self) -> None:
        """Синхронный fallback (ручной refresh)."""
        try:
            self._paint_statusbar(_stats())
        except Exception:
            pass

    def _paint_statusbar(self, st: Dict[str, Any]) -> None:
        s = st["statuses"]
        run = "[bold green]● RUN[/]" if self._is_running() else "[bold red]○ STOP[/]"
        pid = f"#{self._proc.pid}" if self._is_running() else ""
        drain = "[white]DRAIN[/] " if self._is_draining() else ""
        proxy = "[white]PROXY[/] " if self._is_proxy_running() else ""
        if st["prog_total"]:
            pct = int(round(100 * st["prog_cur"] / st["prog_total"]))
            bar = _bar(st["prog_cur"], st["prog_total"], 10)
            prog = f"[white]{bar}[/] {pct}% {st['prog_cur']}/{st['prog_total']}"
        else:
            prog = "[dim]—[/]"
        # rate keys/min (smoothed)
        now_t = time.time()
        delta_keys = st["total"] - getattr(self, "_last_keys_count", st["total"])
        delta_t = now_t - getattr(self, "_last_keys_time", now_t)
        if delta_t >= 1.0 and delta_keys >= 0:
            rate = int(delta_keys / delta_t * 60)
            rate_str = f"[dim]↑[/][white]{rate}/m[/]  " if rate else ""
        else:
            rate_str = ""
        self._last_keys_count = st["total"]
        self._last_keys_time = now_t
        # живые источники
        try:
            alive = sum(
                1 for p in (st.get("source_progress") or [])
                if p.get("derived_status") in ("running", "waiting")
            )
            src_str = f"[dim]src[/][white]{alive}/{len(_KNOWN_SOURCES)}[/]"
        except Exception:
            src_str = ""
        line = (
            f"{run} [dim]{pid}[/]  {drain}{proxy}{rate_str}"
            f"[dim]scan[/] {prog}  "
            f"[dim]keys[/] [bold white]{st['total']}[/]  "
            f"[dim]ok[/][bold green]{s.get('confirmed',0)}[/] "
            f"[dim]v[/][green]{s.get('valid',0)}[/] "
            f"[dim]q[/][yellow]{s.get('quota_exceeded',0)}[/] "
            f"[dim]unv[/]{s.get('unverified',0)} "
            f"[dim]inv[/][red]{s.get('invalid',0)}[/]  "
            f"[dim]★[/][bold yellow]{st['high_value']}[/]  "
            f"{src_str}"
        )
        self.query_one("#statusbar", Static).update(line)

    # ------------------------- дашборд ----------------------------------

    def _update_dashboard(self) -> None:
        """Синхронный fallback (ручной refresh). Тяжёлые SQL на UI-потоке."""
        try:
            st = _stats()
            progress = _source_progress()
            self._paint_dashboard(st, progress)
        except Exception:
            return

    def _paint_dashboard(self, st: Dict[str, Any], progress: list) -> None:
        """Только UI-update: данные уже загружены в worker-потоке."""
        # skip identical paint (avoid flicker / wasted work)
        try:
            sig = (
                st.get("total"), st.get("prog_cur"), st.get("prog_total"),
                st.get("high_value"),
                tuple(sorted((k, v) for k, v in (st.get("statuses") or {}).items())),
                tuple(
                    (p.get("source"), p.get("derived_status"), p.get("phase"),
                     p.get("current"), p.get("total"), p.get("processed"),
                     p.get("found"), p.get("errors"), p.get("message"))
                    for p in (progress or [])
                ),
                tuple(sorted(self._active_tasks.keys())),
            )
            if sig == getattr(self, "_dash_sig", None):
                return
            self._dash_sig = sig
        except Exception:
            pass

        # --- Scan progress (compact one/two lines for dense dashboard) ---
        try:
            if self._lang == "ru":
                done_s, run_s = "готово", "в работе"
                kw_s, no_prog = "kw", "нет прогресса"
                workers_s, no_data = "ворк", "—"
            else:
                done_s, run_s = "done", "run"
                kw_s, no_prog = "kw", "no progress"
                workers_s, no_data = "wrk", "—"
            if st["prog_total"]:
                pct = int(round(100 * st["prog_cur"] / st["prog_total"]))
                bar = _bar(st["prog_cur"], st["prog_total"], 24)
                status = done_s if st["prog_done"] else run_s
                upd = _fmt_time(st["prog_updated"], "%H:%M:%S")
                progress_text = (
                    f"[white]{bar}[/] {pct}% "
                    f"[bold]{st['prog_cur']}/{st['prog_total']}[/]{kw_s} "
                    f"[dim]{status} {upd}[/]  "
                    f"blobs [white]{st['blobs']}[/]  "
                    f"keys [bold]{st['total']}[/]  "
                    f"HV [bold yellow]{st['high_value']}[/]  "
                    f"last {_fmt_time(st['last_found'])}"
                )
            else:
                progress_text = (
                    f"[dim]{no_prog}[/]  "
                    f"blobs [white]{st['blobs']}[/]  "
                    f"keys [bold]{st['total']}[/]  "
                    f"HV [bold yellow]{st['high_value']}[/]"
                )
            sp = st.get("source_progress") or []
            alive = sum(
                1 for p in sp
                if p.get("derived_status") in ("running", "waiting")
            )
            progress_text += (
                f"  [dim]{workers_s}[/][green]{alive}[/]/"
                f"[dim]{len(_KNOWN_SOURCES)}[/]"
                f"  paster:{st['paster_page']}/{st['paster_seen']}"
            )
            self.query_one("#d_progress", Static).update(progress_text)
        except Exception:
            pass

        # --- Worker-матрица (источники) ---
        try:
            self._render_worker_matrix(progress)
        except Exception:
            pass

        # --- Воронка валидации ---
        try:
            self._render_validation_funnel(st)
        except Exception:
            pass

        # --- Статусы ключей ---
        try:
            order = ["confirmed", "valid", "quota_exceeded", "invalid",
                     "connection_error", "unverified", "pending"]
            total = st["total"] or 1
            lines = []
            for st_key in order:
                cnt = st["statuses"].get(st_key, 0)
                if not cnt and st_key not in st["statuses"]:
                    continue
                label, color = STATUS_STYLE.get(st_key, (st_key, "white"))
                bar = _bar(cnt, total, 14)
                lines.append(
                    f"  [{color}]{label:12s}[/] {cnt:5d} [{color}]{bar}[/]"
                )
            no_data = self.tr("no_data")
            self.query_one("#d_statuses", Static).update(
                "\n".join(lines) if lines else f"  [dim]{no_data}[/]")
        except Exception:
            pass

        # --- Active tasks (right column) ---
        try:
            # Pull progress for each active task from TASK_PROGRESS
            # (drain uses CURRENT_PROGRESS). Universal for all task types.
            for ttype in list(self._active_tasks.keys()):
                prog = TASK_PROGRESS.get(ttype)
                if prog:
                    self._active_tasks[ttype]["done"] = prog.get("done", 0)
                    self._active_tasks[ttype]["total"] = prog.get("total", 0)
                elif ttype == "drain_unverified":
                    try:
                        from unverified_drainer import CURRENT_PROGRESS
                        self._active_tasks[ttype]["done"] = \
                            CURRENT_PROGRESS.get("done", 0)
                        self._active_tasks[ttype]["total"] = \
                            CURRENT_PROGRESS.get("total", 0)
                    except Exception:
                        pass
            lines = []
            tasks = dict(self._active_tasks)
            if not tasks:
                lines.append(f"  [dim]{self.tr('task_none')}[/]")
            else:
                for ttype, info in tasks.items():
                    elapsed = _t.time() - (info.get("start", _t.time()))
                    em, es = int(elapsed) // 60, int(elapsed) % 60
                    done = info.get("done", 0)
                    total = info.get("total", 0)
                    if total > 0:
                        pct = min(100, int(round(100 * done / total)))
                        bar = _bar(done, total, 16)
                        lines.append(f"  [white]{info['label']}[/]")
                        lines.append(f"  [green]{bar}[/] {pct}%  "
                                     f"[dim]{done}/{total} | {em}:{es:02d}[/]")
                    else:
                        lines.append(f"  [white]{info['label']}[/]")
                        lines.append(
                            f"  [yellow]{self.trf('task_running', m=em, s=es)}[/]")
            # Compact status totals (one line)
            s = st["statuses"]
            lines.append("")
            lines.append(
                f"  [dim]OK[/][green]{s.get('confirmed',0)}[/] "
                f"[dim]V[/][green]{s.get('valid',0)}[/] "
                f"[dim]Q[/][yellow]{s.get('quota_exceeded',0)}[/] "
                f"[dim]Unv[/]{s.get('unverified',0)} "
                f"[dim]Inv[/][red]{s.get('invalid',0)}[/]")
            # When idle: show validation progress (cached)
            if not tasks:
                vp = _validation_progress()
                if vp["net_total"] > 0:
                    resolved = vp["resolved"]
                    net = vp["net_total"]
                    rpct = min(100, int(round(100 * resolved / max(net, 1))))
                    rbar = _bar(resolved, net, 16)
                    lines.append("")
                    lines.append(
                        f"  [bold]{self.tr('validation_label')}[/] "
                        f"{resolved}/{net} ({rpct}%)")
                    lines.append(f"  [green]{rbar}[/]")
                    lines.append(
                        f"  [dim]{self.trf('validation_queue', q=vp['unv_to_check'], u=vp['unv_total'])}[/]")
            self.query_one("#d_confirm", Static).update(
                "\n".join(lines))
        except Exception:
            pass

        # --- Platforms top-8 ---
        try:
            pl_valid: Dict[str, int] = st.get("platforms_valid") or {}
            plats_all = sorted(
                st["platforms"].items(),
                key=lambda x: (pl_valid.get(x[0], 0), x[1]),
                reverse=True,
            )[:8]
            max_cnt = max((v for v in st["platforms"].values()), default=1)
            plines = []
            for pl, cnt in plats_all:
                vcnt = pl_valid.get(pl, 0)
                mark = "[yellow]★[/]" if pl in HIGH_VALUE_PLATFORMS else " "
                bar = _bar(cnt, max_cnt, 18)
                vstr = (f"[green bold]{vcnt:3d}[/]/[dim]{cnt:4d}[/]"
                        if vcnt else f"[dim]  0/{cnt:4d}[/]")
                plines.append(f"  {mark} {pl:14s} {vstr} [white]{bar}[/]")
            empty = self.tr("no_data")
            self.query_one("#d_platforms", Static).update(
                "\n".join(plines) if plines else f"  [dim]{empty}[/]")
        except Exception:
            pass

        # --- Recent valid keys ---
        try:
            ks = _db(
                "SELECT * FROM leaked_keys "
                "WHERE status IN ('confirmed','valid','quota_exceeded') "
                "ORDER BY found_time DESC LIMIT 5"
            )
            klines = []
            for k in ks:
                tag = ("[bold green]OK[/]" if k["status"] == "confirmed"
                       else "[green]OK[/]" if k["status"] == "valid"
                       else "[yellow]Q[/]")
                hv = "[yellow]★[/]" if k.get("is_high_value") else " "
                bal = (k.get("balance") or "-")[:14]
                plat = k["platform"][:12]
                klines.append(
                    f"  {hv}{tag} {plat:12s} {_mask(k['api_key']):14s} "
                    f"{bal:14s} [dim]{_fmt_time(k.get('found_time'), '%H:%M')}[/]")
            empty = self.tr("no_valid_keys_yet")
            self.query_one("#d_keys", Static).update(
                "\n".join(klines) if klines else f"  [dim]{empty}[/]")
        except Exception:
            pass

        # --- Top confirmed models ---
        try:
            conf_models = _db(
                "SELECT model_name, COUNT(DISTINCT key_id) AS cnt "
                "FROM key_models WHERE is_confirmed=1 "
                "GROUP BY model_name ORDER BY cnt DESC LIMIT 5")
            if conf_models:
                mlines = []
                for m in conf_models:
                    name = m.get("model_name", "")[:32]
                    cnt = m.get("cnt", 0)
                    mlines.append(f"  [green]{cnt:3d}[/] {name}")
                self.query_one("#d_confmodels", Static).update("\n".join(mlines))
            else:
                self.query_one("#d_confmodels", Static).update(
                    f"  [dim]{self.tr('no_confirmed_models')}[/]")
        except Exception:
            pass

        # --- Активные эндпоинты убраны с дашборда (дублируют вкладку API) ---
        # Примечание: мини-лог (#dlog) обновляется в _tick отдельно от _dash_sig,
        # чтобы не "замерзать" при живом сканировании (см. _write_mini_log).

    # ------------------- worker-матрица (Stage 1) --------------------

    def _worker_age(self, row: dict) -> str:
        """Возраст heartbeat источника (м->сек, ч->мин) или '-'."""
        hb = row.get("heartbeat")
        if not hb:
            return "—"
        try:
            dt = datetime.fromisoformat(hb)
        except (TypeError, ValueError):
            return "—"
        secs = max(0, int((datetime.now() - dt).total_seconds()))
        if secs < 60:
            return f"{secs}s"
        if secs < 3600:
            return f"{secs // 60}m"
        return f"{secs // 3600}h"

    def _render_worker_matrix(self, progress: list = None) -> None:
        """Матрица источников: status / phase / progress / keys / age.

        Кол-во строк = len(_KNOWN_SOURCES). Перерисовываем только при
        изменении сигнатуры (без дёрганья scroll).
        """
        if progress is None:
            progress = _source_progress()
        sig = tuple(
            (p["source"], p["derived_status"], p.get("status"), p.get("phase"),
             p.get("current", 0), p.get("total", 0),
             p.get("processed", 0), p.get("found", 0),
             p.get("errors", 0), p.get("key_count", 0), p.get("stale"))
            for p in progress
        )
        if getattr(self, "_d_workers_sig", None) == sig:
            return
        self._d_workers_sig = sig
        tbl = self.query_one("#d_workers", DataTable)
        tbl.clear()
        _STATUS_UI = {
            "running":  ("● RUN",   "bold green"),
            "waiting":  ("… WAIT",  "yellow"),
            "stale":    ("! STALE", "bold yellow"),
            "error":    ("✕ ERR",   "bold red"),
            "disabled": ("○ OFF",   "dim"),
            "stopped":  ("■ STOP",  "dim"),
            "done":     ("✓ DONE",  "dim"),
            "idle":     ("· IDLE",  "blue"),
        }
        for p in progress:
            dstatus = p["derived_status"]
            st_label, st_color = _STATUS_UI.get(dstatus, ("?", "white"))
            total = p.get("total", 0) or 0
            cur = p.get("current", 0) or 0
            if total > 0:
                progress_str = f"{cur}/{total}"
            elif p.get("processed"):
                progress_str = f"{p.get('processed')}"
            else:
                progress_str = "—"
            phase = (p.get("phase") or "—")[:18]
            if dstatus == "error" and p.get("message"):
                phase = str(p["message"])[:18]
            age = self._worker_age({"heartbeat": p.get("heartbeat")})
            src_label = _SOURCE_LABELS.get(p["source"], p["source"])
            keys = p.get("key_count", 0) or 0
            found = p.get("found", 0) or 0
            errs = p.get("errors", 0) or 0
            tbl.add_row(
                src_label,
                f"[{st_color}]{st_label}[/]",
                phase,
                progress_str,
                str(p.get("processed", 0) or 0),
                str(found),
                f"[white]{keys}[/]" if keys else "0",
                f"[red]{errs}[/]" if errs else "0",
                age,
            )

    def _render_validation_funnel(self, st: dict) -> None:
        """Воронка: found -> pending -> valid -> confirmed -> quota + модели.

        Берёт лёгкие агрегаты из кэшированного _stats() (без тяжёлого SQL
        в тике) и добавляет discovery/confirmed моделей.
        """
        s = st["statuses"]
        found = st["total"]
        pending = s.get("pending", 0)
        unv = s.get("unverified", 0)
        valid = s.get("valid", 0)
        confirmed = s.get("confirmed", 0)
        quota = s.get("quota_exceeded", 0)
        invalid = s.get("invalid", 0)
        # Модели (discovery / confirmed) - закэшированный лёгкий подсчёт.
        mc = _model_discovery_counts()
        discovered, conf_models = mc["discovered"], mc["confirmed"]
        lines = [
            f"  [dim]found[/] [bold]{found}[/]  "
            f"[dim]pending[/] {pending}  [dim]unv[/] {unv}",
            f"  [dim]valid[/] [green]{valid}[/]  "
            f"[dim]conf[/] [bold green]{confirmed}[/]  "
            f"[dim]quota[/] [yellow]{quota}[/]  "
            f"[dim]inv[/] [red]{invalid}[/]",
            f"  [dim]models:[/] discovered [white]{discovered}[/]  "
            f"confirmed [bold green]{conf_models}[/]",
        ]
        self.query_one("#d_funnel", Static).update("\n".join(lines))

    def _write_mini_log(self) -> None:
        """Обновить мини-лог дашборда из scanner.log.

        Читаем последние строки файла, фильтруем DEBUG-шум (оставляем только
        важные уровни: INFO/SCAN/FOUND/VALID/WARN/ERROR), и перерисовываем.
        Вызывается каждый тик независимо от _dash_sig — иначе лог "замерзает"
        при живом сканировании. Чтобы не дёргать файл каждые 2с без необходимости,
        сравниваем размер файла (дешёвая проверка) и перерисовываем только при
        изменении.
        """
        try:
            size = os.path.getsize(LOG)
        except OSError:
            return
        if size == getattr(self, "_dlog_size", -1):
            return
        self._dlog_size = size
        lg = self.query_one("#dlog", RichLog)
        lines = _log_lines(120)
        # DEBUG приплюсовывает шум — показываем только содержательные уровни
        # (INFO/SCAN/FOUND/VALID/WARN/ERROR/SKIP). Важные события сканера теперь
        # пишутся в scanner.log через dashboard.add_log, поэтому они здесь есть.
        keep = []
        for ln in lines:
            if "| DEBUG " in ln:
                continue
            keep.append(ln)
        if not keep:
            # На случай, если всё DEBUG — покажем последние 10 сырых строк.
            keep = lines[-10:]
        lg.clear()
        for ln in keep[-30:]:
            lg.write(_colorize_log(ln.rstrip()[-160:]))
        if self._autoscroll:
            lg.scroll_end(animate=False)

    # --------------------------- ключи ----------------------------------

    def _render_keys(self) -> None:
        tbl = self.query_one("#tbl", DataTable)
        # Подсветить активный фильтр (primary), остальные - default
        for key, _, _ in self._status_filters():
            try:
                self.query_one(f"#kf_{key}", Button).variant = (
                    "primary" if key == self._filter else "default")
            except Exception:
                pass
        # Полная очистка с пересозданием колонок - иначе ширина
        # колонок не сжимается обратно после Reveal
        tbl.clear(columns=True)
        tr = self.tr
        tbl.add_columns(
            "#", tr("col_platform"), tr("col_status"), tr("col_key"), tr("col_balance"),
            tr("col_base"), tr("col_src"), tr("col_high"), tr("col_found_time"),
        )
        rows = _keys(self._filter, self._platform, self._search,
                      limit=1000, high_value_only=self._high_value)
        # сортировка на стороне клиента
        reverse = self._sort_desc
        sk = self._sort_key
        rows.sort(key=lambda r: (str(r.get(sk) or "")), reverse=reverse)
        self._rows = rows
        for i, k in enumerate(rows, 1):
            label, color = STATUS_STYLE.get(
                k.get("status"), (k.get("status", ""), "white"))
            key_str = (k.get("api_key", "")[:48] if self._reveal
                       else _mask(k.get("api_key")))
            hv = "[yellow]★[/]" if k.get("is_high_value") else ""
            tbl.add_row(
                str(i),
                k.get("platform", ""),
                f"[{color}]{label}[/]",
                key_str,
                f"{(k.get('balance') or '-')[:14]} | {(k.get('model_tier') or '')[:12]}",
                (k.get("base_url") or "-")[:36],
                (k.get("source_url") or "-")[:40],
                hv,
                _fmt_time(k.get("found_time"), "%Y-%m-%d %H:%M"),
            )
        total = _count_keys(self._filter, self._platform, self._search,
                            self._high_value)
        shown = len(rows)
        if self._lang == "ru":
            cnt = (
                f"Показано [bold]{shown}[/] из [bold]{total}[/]  "
                f"[dim]| сортировка: {self._sort_key} "
                f"({'↓' if self._sort_desc else '↑'})[/]"
            )
        else:
            cnt = (
                f"Showing [bold]{shown}[/] of [bold]{total}[/]  "
                f"[dim]| sort: {self._sort_key} "
                f"({'↓' if self._sort_desc else '↑'})[/]"
            )
        cnt += (
            f"{'  [yellow]reveal[/]' if self._reveal else ''}"
            f"{'  [yellow]high-value[/]' if self._high_value else ''}"
        )
        self.query_one("#keyscount", Static).update(cnt)
        self._render_detail(None)

    def _render_detail(self, row: Optional[Dict[str, Any]]) -> None:
        if not row:
            msg = (
                "Выберите строку для просмотра деталей."
                if self._lang == "ru"
                else "Select a row to view details."
            )
            self.query_one("#detail", Static).update(msg)
            self.query_one("#detail", Static).set_classes("dim")
            return
        label, color = STATUS_STYLE.get(row.get("status"), ("", "white"))
        hv = "  [yellow]* HIGH-VALUE[/]" if row.get("is_high_value") else ""
        if self._lang == "ru":
            lines = [
                f"[bold]{row.get('platform','')}[/]  "
                f"[{color}]{label}[/]{hv}",
                f"Ключ:     [bold]{row.get('api_key','')}[/]",
                f"Base URL: {row.get('base_url') or '-'}",
                f"Источник: {row.get('source_url') or '-'}",
                f"Баланс:   {row.get('balance') or '-'}    "
                f"Model: {row.get('model_tier') or '-'}    "
                f"RPM: {row.get('rpm') or '-'}",
                f"Найден:   {_fmt_time(row.get('found_time'))}    "
                f"Проверен: {_fmt_time(row.get('verified_time'))}    "
                f"ID: {row.get('id')}",
            ]
        else:
            lines = [
                f"[bold]{row.get('platform','')}[/]  "
                f"[{color}]{label}[/]{hv}",
                f"Key:      [bold]{row.get('api_key','')}[/]",
                f"Base URL: {row.get('base_url') or '-'}",
                f"Source:   {row.get('source_url') or '-'}",
                f"Balance:  {row.get('balance') or '-'}    "
                f"Model: {row.get('model_tier') or '-'}    "
                f"RPM: {row.get('rpm') or '-'}",
                f"Found:    {_fmt_time(row.get('found_time'))}    "
                f"Verified: {_fmt_time(row.get('verified_time'))}    "
                f"ID: {row.get('id')}",
            ]
        self.query_one("#detail", Static).update("\n".join(lines))

    # --------------------------- модели ----------------------------------

    def _render_models(self) -> None:
        """Асинхронный рендер моделей: тяжёлый GROUP BY (449k строк) в потоке,
        таблица рисуется по готовности. Показывает 'loading', не фризит UI."""
        # Мгновенно: показать loading, не блокируя
        try:
            if self._lang == "ru":
                self.query_one("#m_count", Static).update("[dim]загрузка…[/]")
            else:
                self.query_one("#m_count", Static).update("[dim]loading…[/]")
        except Exception:
            pass
        # Отменить предыдущий запуск (частые refresh/переключения)
        self._models_gen = getattr(self, "_models_gen", 0) + 1
        gen = self._models_gen

        confirmed_only = self._m_confirmed_only
        family = self._m_family
        search = self._m_search
        sort = self._m_sort

        def _load():
            try:
                # pool_models_set тоже в потоке (DB open / active_pool init).
                pool_models = _pool_models_set()
                raw = _models_data(confirmed_only=confirmed_only, _refresh=True)
                enriched = []
                for r in raw:
                    name = r.get("model_name") or ""
                    info = _model_lookup(name) if _model_lookup else None
                    family_ = info.family if info else "Other"
                    provider = info.provider if info else ""
                    release = info.release if info else ""
                    tier = info.tier if info else ""
                    caps = info.capabilities if info else "text"
                    cap_label = _cap_label(caps) if _cap_label else "text"
                    cap_rank = (_cap_rank(r.get("model_name", ""), family_, tier, caps)
                                if _cap_rank else 0)
                    r.update({
                        "family": family_, "provider": provider, "release": release,
                        "tier": tier, "caps": caps, "cap_label": cap_label,
                        "cap_rank": cap_rank,
                        "context_window": info.context_window if info else 0,
                        "max_output": info.max_output if info else 0,
                        "input_price": info.input_price if info else 0.0,
                        "output_price": info.output_price if info else 0.0,
                    })
                    enriched.append(r)
                if family != "all":
                    enriched = [r for r in enriched if r["family"] == family]
                if search:
                    q = search.lower()
                    enriched = [r for r in enriched
                                if q in (r.get("model_name") or "").lower()
                                or q in (r.get("family") or "").lower()
                                or q in (r.get("caps") or "").lower()]
                if sort == "caps" and _cap_sort_key:
                    enriched.sort(key=lambda r: _cap_sort_key(r.get("model_name", "")))
                elif sort == "newest" and _model_sort_key:
                    enriched.sort(key=lambda r: _model_sort_key(r.get("model_name", "")))
                elif sort == "keys":
                    enriched.sort(key=lambda r: r.get("key_count", 0), reverse=True)
                elif sort == "name":
                    enriched.sort(key=lambda r: (r.get("model_name") or "").lower())
                elif sort == "family":
                    enriched.sort(key=lambda r: (r.get("family") or "",
                                                 -(r.get("key_count") or 0)))
                return enriched, pool_models
            except Exception:
                return [], set()

        def _done(fut):
            # Только если это последний запрос (не устарел)
            if gen != getattr(self, "_models_gen", 0):
                return
            try:
                rows, pool_models = fut.result()
            except Exception:
                rows, pool_models = [], set()
            self.call_from_thread(self._paint_models, rows, pool_models)

        import concurrent.futures as _cf
        fut = self._models_exec.submit(_load)
        fut.add_done_callback(_done)

    def _paint_models(self, enriched, pool_models) -> None:
        """UI-часть рендера моделей (данные уже загружены в потоке)."""
        tbl = self.query_one("#m_tbl", DataTable)
        try:
            saved_cursor = tbl.cursor_row
        except Exception:
            saved_cursor = 0
        tbl.clear(columns=True)
        tr = self.tr
        tbl.add_columns(
            "*", "#", tr("col_model"), tr("col_family"), tr("col_cap"),
            tr("col_provider"), tr("col_release"), tr("col_tier"),
            tr("col_access"), tr("col_platforms"),
        )
        self._m_selected = None
        self._m_rows = enriched
        for i, r in enumerate(enriched, 1):
            plats = (r.get("platforms") or "")
            plats_short = ",".join(sorted(set(p for p in plats.split(",") if p)))[:24]
            tier_color = {"frontier": "green", "standard": "cyan",
                          "legacy": "dim", "embedding": "yellow",
                          "image": "magenta"}.get(r.get("tier", ""), "white")
            cap_c = r.get("cap_label", "text")
            cap_color = {"text": "white", "vision": "cyan", "audio": "yellow",
                         "multi": "magenta", "think": "blue", "think+vis": "blue",
                         "embed": "dim", "image": "green",
                         "search": "green"}.get(cap_c, "white")
            in_pool = r.get("model_name") in pool_models
            model_cell = (f"[bold yellow]{r.get('model_name', '')}[/]"
                          if in_pool else r.get("model_name", ""))
            tbl.add_row(
                "[yellow]*[/]" if in_pool else "",
                str(i),
                model_cell,
                r.get("family", ""),
                f"[{cap_color}]{cap_c}[/]",
                r.get("provider", "") or "-",
                r.get("release", "") or "-",
                f"[{tier_color}]{r.get('tier') or '-'}[/]",
                str(r.get("key_count", 0)),
                plats_short or "-",
            )
        total_models = len(enriched)
        total_keys = sum(r.get("key_count", 0) for r in enriched)
        if self._lang == "ru":
            self.query_one("#m_count", Static).update(
                f"Моделей: [bold]{total_models}[/]  "
                f"Гарантированный доступ: [bold green]{total_keys}[/] ключей"
            )
        else:
            self.query_one("#m_count", Static).update(
                f"Models: [bold]{total_models}[/]  "
                f"Guaranteed access: [bold green]{total_keys}[/] keys"
            )
        try:
            if saved_cursor < len(enriched):
                tbl.move_cursor(row=saved_cursor)
        except Exception:
            pass
        self._render_model_detail(None)
        self._render_model_detail(None)

    def _render_model_detail(self, row: Optional[Dict[str, Any]]) -> None:
        if not row:
            self.query_one("#m_detail", Static).update(
                "Выберите модель для просмотра провайдеров и ключей."
                if self._lang == "ru"
                else "Select a model to view providers and keys."
            )
            self.query_one("#m_detail", Static).set_classes("dim")
            return
        model_name = row.get("model_name", "")
        keys = _keys_for_model(model_name, confirmed_only=self._m_confirmed_only)
        caps = row.get("caps", "text")
        ctx = row.get("context_window", 0)
        mo = row.get("max_output", 0)
        ip = row.get("input_price", 0.0)
        op = row.get("output_price", 0.0)

        # --- Model header ---
        if self._lang == "ru":
            meta = (
                f"Релиз: {row.get('release','') or '-'}  "
                f"Tier: {row.get('tier','') or '-'}  "
                f"Контекст: {self._fmt_ctx(ctx)}  "
                f"Макс.вывод: {self._fmt_ctx(mo)}"
            )
            price_s = f"Цена: ${ip}/1M in  ${op}/1M out"
            access_s = (
                f"Гарантированный доступ: [bold green]{len(keys)}[/] "
                f"валидных ключей"
            )
            endpoints_s = f"[bold]Эндпоинты ({0}):[/]"  # filled below
            keys_s = f"[bold]Ключи ({0}):[/]"
            more_s = "... ещё {n} (см. блок копирования)"
            hdr_plat, hdr_key = "Платф", "Ключ"
        else:
            meta = (
                f"Release: {row.get('release','') or '-'}  "
                f"Tier: {row.get('tier','') or '-'}  "
                f"Context: {self._fmt_ctx(ctx)}  "
                f"Max out: {self._fmt_ctx(mo)}"
            )
            price_s = f"Price: ${ip}/1M in  ${op}/1M out"
            access_s = (
                f"Guaranteed access: [bold green]{len(keys)}[/] valid keys"
            )
            endpoints_s = f"[bold]Endpoints ({0}):[/]"
            keys_s = f"[bold]Keys ({0}):[/]"
            more_s = "... +{n} more (see copy block)"
            hdr_plat, hdr_key = "Plat", "Key"
        lines = [
            f"[bold]{model_name}[/]  "
            f"[white]{row.get('family','')}[/]  "
            f"[{self._cap_color(row.get('cap_label',''))}]{row.get('cap_label','text')}[/]  "
            f"[dim]{row.get('provider','') or '-'}[/]",
            meta,
        ]
        if ip or op:
            lines.append(price_s)
        lines.append(f"Capabilities: [dim]{caps}[/]")
        lines.append("")
        lines.append(access_s)

        if keys:
            by_url: Dict[str, List[Dict[str, Any]]] = {}
            for k in keys:
                url = k.get("base_url") or "(default)"
                by_url.setdefault(url, []).append(k)

            lines.append("")
            if self._lang == "ru":
                lines.append(f"[bold]Эндпоинты ({len(by_url)}):[/]")
            else:
                lines.append(f"[bold]Endpoints ({len(by_url)}):[/]")
            for url, ks in sorted(by_url.items(), key=lambda x: -len(x[1])):
                plats = sorted(set(k.get("platform", "") for k in ks))
                hv = sum(1 for k in ks if k.get("is_high_value"))
                max_rpm = max((k.get("rpm") or 0) for k in ks)
                max_tpd = max((k.get("tpd") or 0) for k in ks)
                max_conc = max((k.get("concurrency_limit") or 0) for k in ks)
                lim = []
                if max_rpm: lim.append(f"RPM={max_rpm}")
                if max_tpd: lim.append(f"TPD={max_tpd}")
                if max_conc: lim.append(f"conc={max_conc}")
                lim_s = f"  [dim]{' '.join(lim)}[/]" if lim else ""
                lines.append(
                    f"  [white]{url}[/]  "
                    f"[dim]({len(ks)}, {', '.join(plats)}"
                    f"{', *'+str(hv) if hv else ''}{lim_s})[/]"
                )

            lines.append("")
            if self._lang == "ru":
                lines.append(f"[bold]Ключи ({len(keys)}):[/]")
            else:
                lines.append(f"[bold]Keys ({len(keys)}):[/]")
            lines.append(
                f"[dim]{'#':4s} {hdr_plat:7s} {hdr_key:30s} "
                f"{'RPM':5s} {'$':7s} {'Plan':8s} {'*':1s}[/]"
            )
            for i, k in enumerate(keys[:60], 1):
                hv = "[yellow]★[/]" if k.get("is_high_value") else " "
                key_str = (k.get("api_key", "")
                           if self._reveal else _mask(k.get("api_key")))
                key_str = key_str[:30]
                plat = (k.get("platform") or "")[:7]
                rpm = str(k.get("rpm") or "-")[:5]
                bal = k.get("balance_usd")
                if bal is not None and bal >= 0:
                    bc = "green" if bal > 1 else "yellow" if bal > 0 else "red"
                    bal_s = f"[{bc}]${bal:.2f}[/]"
                else:
                    bal_s = "-"
                bal_s = bal_s[:7]
                plan = (k.get("org_plan") or "-")[:8]
                lines.append(f"  {i:3d}  {plat:7s} {key_str:30s} "
                             f"{rpm:5s} {bal_s:7s} {plan:8s} {hv:1s}")
            if len(keys) > 60:
                n_more = len(keys) - 60
                if self._lang == "ru":
                    lines.append(
                        f"[dim]... ещё {n_more} (см. блок копирования)[/]")
                else:
                    lines.append(
                        f"[dim]... +{n_more} more (see copy block)[/]")

            # --- Блок для копирования: endpoint + ключи через энтер ---
            if self._reveal:
                lines.append("")
                lines.append("[bold green]═══ Блок копирования ═══[/]")
                lines.append("[dim](endpoint -> ключи, разделённые переносом строки)[/]")
                lines.append("")
                for url, ks in sorted(by_url.items(), key=lambda x: -len(x[1])):
                    lines.append(f"[white]{url}[/]")
                    for k in ks:
                        lines.append(k.get("api_key", ""))
                    lines.append("")
            else:
                lines.append("")
                lines.append("[dim]Reveal - показать полные ключи для копирования[/]")
        else:
            lines.append("[dim]Нет валидных ключей для этой модели.[/]")
        self.query_one("#m_detail", Static).update("\n".join(lines))
        self.query_one("#m_detail", Static).set_classes("")

    @staticmethod
    def _cap_color(label: str) -> str:
        return {"text": "white", "vision": "cyan", "audio": "yellow",
                "multi": "magenta", "think": "blue", "think+vis": "blue",
                "embed": "dim", "image": "green",
                "search": "green"}.get(label, "white")

    @staticmethod
    def _fmt_ctx(n: int) -> str:
        if not n:
            return "—"
        if n >= 1_000_000:
            return f"{n // 1_000_000}M"
        if n >= 1000:
            return f"{n // 1000}K"
        return str(n)

    # --------------------------- логи -----------------------------------

    def _stream_logs(self) -> None:
        lg = self.query_one("#mlog", RichLog)
        flt = self.query_one("#l_filter", Input).value.strip().lower()
        if not os.path.exists(LOG):
            return
        try:
            with open(LOG, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
                if size < self._log_pos:
                    # Файл был обнулён/ротирован - начать с начала
                    self._log_pos = 0
                # Первый заход на вкладку логов: НЕ читать весь (мульти-МБ) файл
                # с нуля — это фризит UI на десятки секунд (каждая строка через
                # _colorize_log в RichLog). Прыгаем к хвосту (~последние 64 КБ).
                if self._log_pos == 0 and size > 65536:
                    self._log_pos = size - 65536
                f.seek(self._log_pos)
                chunk = f.read().decode("utf-8", "ignore")
                self._log_pos = f.tell()
            # На первом чтении с хвоста — отбросить возможную обрезанную 1-ю строку
            lines = chunk.splitlines()
            for ln in lines:
                text = ln.rstrip()
                if not text:
                    continue
                if flt and flt not in text.lower():
                    continue
                lg.write(_colorize_log(text[-200:]))
        except OSError:
            pass
        if self._autoscroll:
            lg.scroll_end(animate=False)

    def _reload_logs(self) -> None:
        self.query_one("#mlog", RichLog).clear()
        self._log_pos = 0
        self._stream_logs()

    # ----------------------- управление сканером ------------------------

    def _start_scanner(self, silent: bool = False) -> None:
        if self._is_running():
            if not silent:
                self._slog(f"[yellow]{self.tr('log_scanner_already')}[/]")
            return
        try:
            # CREATE_NEW_PROCESS_GROUP + CREATE_NO_WINDOW: сканер в отдельной
            # группе, чтобы при выходе из TUI (вкл. Ctrl+C) убивать всё дерево
            # через taskkill /T, а не оставлять зомби-субпроцесс со спамом.
            flags = 0
            if sys.platform == "win32":
                flags = (subprocess.CREATE_NO_WINDOW
                         | subprocess.CREATE_NEW_PROCESS_GROUP)
            self._proc = subprocess.Popen(
                _scanner_command(),
                cwd=BASE_DIR,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=flags,
            )
            self._proc_started_at = time.time()  # для watchdog-бэкоффа
            if not silent:
                self._slog(
                    f"[green]{self.trf('log_scanner_started', pid=self._proc.pid)}[/]"
                )
        except OSError as e:
            self._slog(f"[red]{self.trf('log_scanner_start_fail', err=e)}[/]")

    def _kill_zombie_processes(self) -> None:
        """Убить зомби-процессы от прошлых запусков: proxy_server.py и
        main_optimized.py (сканер). Иначе они держат порт 8818/спамят,
        а новый прокси не может стартовать.

        Windows: PowerShell Get-CimInstance -> Stop-Process. Исключает текущий
        PID (этот TUI) и процесс-родитель. Запускать в потоке (PowerShell медленный).
        """
        if sys.platform != "win32":
            return
        import subprocess as _sp
        import os as _os
        my_pid = _os.getpid()
        # Имена скриптов, которые мы запускаем как subprocess
        targets = ("proxy_server.py", "main_optimized.py", "ngrok")
        try:
            ps = (
                "$my = " + str(my_pid) + "; "
                "Get-CimInstance Win32_Process -Filter \"name='python.exe'\" | "
                "Where-Object { $_.ProcessId -ne $my -and $_.ParentProcessId -ne $my -and ("
                "$_.CommandLine -like '*proxy_server.py*' -or "
                "$_.CommandLine -like '*main_optimized.py*') } | "
                "ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue } catch {} }"
            )
            _sp.run(
                ["powershell.exe", "-NoProfile", "-Command", ps],
                capture_output=True, timeout=15,
                creationflags=getattr(_sp, "CREATE_NO_WINDOW", 0))
        except Exception:
            pass

    def _kill_scanner_tree(self) -> bool:
        """Надёжно убить процесс сканера со всем деревом (Windows: taskkill /T).
        Возвращает True если процесс был и убит."""
        if not self._proc:
            return False
        pid = self._proc.pid
        # Windows: taskkill /T /F убивает процесс + всех потомков надёжно
        # (terminate() только главный, может оставить зомби при Ctrl+C).
        if sys.platform == "win32":
            try:
                subprocess.run(
                    ["taskkill", "/PID", str(pid), "/T", "/F"],
                    capture_output=True, timeout=8,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                return True
            except Exception:
                pass
        # Fallback: обычный terminate/kill
        try:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            return True
        except OSError:
            return False

    def _stop_scanner(self) -> None:
        if not self._is_running() and not self._proc:
            self._slog(f"[dim]{self.tr('log_scanner_not_running')}[/]")
            return
        # Ручная остановка — watchdog не должен тут же перезапускать.
        self._reset_scanner_watchdog()
        try:
            self._kill_scanner_tree()
            self._slog(f"[yellow]{self.tr('log_scanner_stopped')}[/]")
        except OSError as e:
            self._slog(f"[red]{self.trf('log_scanner_stop_fail', err=e)}[/]")
        finally:
            self._proc = None

    def _reset_scanner_watchdog(self) -> None:
        """Сбросить состояние watchdog (ручной стоп/рестарт, «gave up» → reset)."""
        self._wd_restarts = 0
        self._wd_window_start = 0.0
        self._wd_not_before = 0.0
        self._wd_gave_up = False
        self._wd_respawn_armed = False  # отменить pending watchdog-респаун

    def _restart_scanner(self) -> None:
        self._reset_scanner_watchdog()  # ручной рестарт — чистое окно бэкоффа
        self._stop_scanner()
        self._start_scanner()

    # --------------------------- watchdog -------------------------------

    def _watchdog_scanner(self) -> None:
        """Перезапустить сканер, если его субпроцесс умер.

        Сканер живёт отдельным процессом (main_optimized.py --all-sources).
        Рабочие ПОТОКИ внутри него сами перезапускаются по петле, но если весь
        процесс умирает (fatal/OOM/unhandled в main-thread) — воркеры гаснут,
        heartbeat замирает и дашборд уходит в STALE. Здесь ловим смерть процесса
        и перезапускаем с экспоненциальным бэкоффом (анти-краш-луп), с пределом.

        Бэкофф: 5s → 10 → 20 → 40 (max 60) per restart в окне 300s; >5 за окно
        → сдаёмся (юзер может Restart). Успешный долгий ран (>300s) сбрасывает.
        """
        if self._wd_gave_up:
            return
        proc = self._proc
        if proc is None:
            return  # сканер никогда не запускали (или только что стопнули)
        rc = proc.poll()
        if rc is None:
            return  # жив

        # Процесс умер. Если прожил достаточно долго — это разовый краш,
        # сбрасываем окно (не штрафуем). Иначе — краш-луп, копим штраф.
        now = time.time()
        started = getattr(self, "_proc_started_at", 0.0)
        if now - started > 300.0:
            self._reset_scanner_watchdog()
        else:
            if self._wd_window_start == 0.0:
                self._wd_window_start = now
            self._wd_restarts += 1
            if self._wd_restarts > 5:
                self._wd_gave_up = True
                self._slog(f"[red]{self.tr('log_scanner_watchdog_max')}[/]")
                self._proc = None
                return

        delay = min(5 * (2 ** max(self._wd_restarts, 0)), 60)
        if now < self._wd_not_before:
            return  # ещё ждём бэкофф
        self._wd_not_before = now + delay

        self._slog(f"[yellow]{self.trf('log_scanner_died', rc=rc, delay=delay)}[/]")
        self._proc = None
        # Перезапуск через бэкофф (таймер, не блокируя UI).
        # _wd_respawn_armed — защита от ручного Stop между крахом и респауном:
        # если юзер стопнул сканер, pending-таймер не должен его оживлять.
        self._wd_respawn_armed = True
        def _respawn():
            if not self._wd_respawn_armed:
                return  # юзер успел стопнуть вручную — не трогаем
            self._wd_respawn_armed = False
            if not self._is_running() and not self._wd_gave_up:
                self._start_scanner(silent=True)
                if self._is_running():
                    self._proc_started_at = time.time()
                    self._slog(
                        f"[green]{self.trf('log_scanner_watchdog_restart', pid=self._proc.pid, n=self._wd_restarts)}[/]"
                    )
        self.set_timer(delay, _respawn)

    # ----------------------------- helpers -------------------------------

    def _slog(self, msg: str) -> None:
        try:
            self.query_one("#slog", RichLog).write(
                f"[dim]{datetime.now():%H:%M:%S}[/] {msg}")
        except Exception:
            pass

    def _refresh_all(self) -> None:
        self._update_statusbar()
        self._update_dashboard()
        self._render_keys()
        try:
            self._render_models()
        except Exception:
            pass
        try:
            self._render_providers()
        except Exception:
            pass
        try:
            self._render_endpoints()
        except Exception:
            pass
        self._update_config_panel()

    def _update_config_panel(self) -> None:
        st = _stats()
        if self._lang == "ru":
            proxy = "включён" if st["proxy"] else "выключен (прямой)"
            circuit = "включён" if st["circuit"] else "выключен"
            pastebin = "да" if st["pastebin"] else "нет"
            lines = [
                f"  GitHub токенов:  [white]{st['tokens']}[/]",
                f"  Прокси:          {'[green]' if st['proxy'] else '[dim]'}{proxy}[/]",
                f"  Потоков валидатора: [white]{st['threads']}[/]",
                f"  Таймаут HTTP:    [white]{st['timeout']}s[/]",
                f"  Circuit breaker: {'[green]' if st['circuit'] else '[dim]'}{circuit}[/]",
                f"  Pastebin API:    {pastebin}",
                f"  Поисковых dorks: [white]{st['keywords']}[/]",
                f"  Base URL платформ: [white]{st['base_urls']}[/]",
                f"  База данных:     [dim]{DB}[/]",
                f"  Сканер:          [bold]{MAIN}[/]",
            ]
        else:
            proxy = "on" if st["proxy"] else "off (direct)"
            circuit = "on" if st["circuit"] else "off"
            pastebin = "yes" if st["pastebin"] else "no"
            lines = [
                f"  GitHub tokens:   [white]{st['tokens']}[/]",
                f"  Proxy:           {'[green]' if st['proxy'] else '[dim]'}{proxy}[/]",
                f"  Validator threads: [white]{st['threads']}[/]",
                f"  HTTP timeout:    [white]{st['timeout']}s[/]",
                f"  Circuit breaker: {'[green]' if st['circuit'] else '[dim]'}{circuit}[/]",
                f"  Pastebin API:    {pastebin}",
                f"  Search dorks:    [white]{st['keywords']}[/]",
                f"  Platform base URLs: [white]{st['base_urls']}[/]",
                f"  Database:        [dim]{DB}[/]",
                f"  Scanner:         [bold]{MAIN}[/]",
            ]
        self.query_one("#s_config", Static).update("\n".join(lines))

    # ----------------------------- экшены -------------------------------

    def action_go(self, tab: str) -> None:
        self.query_one("#tabs", TabbedContent).active = tab

    def action_refresh(self) -> None:
        self._refresh_all()

    def action_toggle_scanner(self) -> None:
        if self._is_running():
            self._stop_scanner()
        else:
            self._start_scanner()
        self._update_statusbar()

    def action_revalidate(self) -> None:
        """Re-check connection_error/pending keys in background."""
        import threading
        self._slog(f"[yellow]{self.tr('log_revalidate_start')}[/]")

        def _worker():
            import asyncio as _aio
            from database import Database
            from validator import AsyncValidator
            try:
                db = Database(config.db_path)
                validator = AsyncValidator(db)
                stats = _aio.run(validator.revalidate_failed_keys())
                msg = self.trf(
                    "log_revalidate_done",
                    valid=stats["valid"],
                    invalid=stats["invalid"],
                    quota=stats["quota"],
                    conn=stats["connection_error"],
                )
                self.call_after_refresh(self._slog, f"[green]{msg}[/]")
                self.call_after_refresh(self._refresh_all)
            except Exception as e:
                self.call_after_refresh(
                    self._slog, f"[red]{self.trf('task_error', err=e)}[/]")

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    def action_drain(self) -> None:
        """Горячая клавиша d: запустить дрейн UNVERIFIED."""
        self._b_drain_unverified()

    def action_toggle_proxy(self) -> None:
        """Горячая клавиша p: вкл/выкл локальный прокси."""
        try:
            self._on_e_proxy()
        except Exception:
            pass

    def action_copy_selected(self) -> None:
        """Горячая клавиша c: копировать ключ выбранной строки в буфер."""
        sel = getattr(self, "_k_selected", None)
        if not (sel and isinstance(sel, dict) and sel.get("api_key")):
            self._slog(f"[dim]{self.tr('log_copy_need_row')}[/]")
            return
        key = sel["api_key"]
        try:
            import pyperclip
            pyperclip.copy(key)
            self._slog(
                f"[green]{self.trf('log_key_copied', key=_mask(key))}[/]")
        except Exception:
            # Fallback: clip (Windows) without deps
            try:
                import subprocess as _sp
                _sp.run(["clip"], input=key.encode(),
                        creationflags=getattr(_sp, "CREATE_NO_WINDOW", 0))
                self._slog(
                    f"[green]{self.trf('log_key_copied', key=_mask(key))} (clip)[/]")
            except Exception as e:
                self._slog(
                    f"[red]{self.trf('log_clipboard_err', err=e, key=key)}[/]")

    def action_focus_search(self) -> None:
        """Горячая клавиша /: фокус на поле поиска текущей вкладки."""
        active = self.query_one("#tabs", TabbedContent).active
        search_map = {"keys": "#k_search", "models": "#m_search",
                      "providers": "#p_search"}
        sid = search_map.get(active)
        if sid:
            try:
                self.query_one(sid, Input).focus()
            except Exception:
                pass

    def action_help(self) -> None:
        """Горячая клавиша ?: список команд."""
        lines = [
            "[bold]Горячие клавиши[/]",
            "  [white]1–7[/]   вкладки: Дашборд · Ключи · Модели · Провайдеры · API · Настр · Логи",
            "  [white]r[/]     обновить экран",
            "  [white]s[/]     старт / стоп сканера",
            "  [white]d[/]     дрейн UNVERIFIED",
            "  [white]p[/]     прокси ON/OFF (:8818)",
            "  [white]R[/]     re-validate failed",
            "  [white]c[/]     копировать выбранный ключ",
            "  [white]/[/]     фокус на поиск",
            "  [white]q[/]     выход",
            "",
            "[bold]Источники[/]  GitHub · Paster · Pastebin · Gist · GitLab · Realtime · MCP · CodeGraph",
            "[dim]Модели/Провайдеры: двойной клик → в пул. API: двойной клик → убрать из пула.[/]",
        ]
        self._slog("\n".join(lines))

    def on_unmount(self) -> None:
        # Обязательное убиение сканера-субпроцесса при выходе (вкл. Ctrl+C),
        # иначе он остаётся жить как зомби и продолжает спамить логи /
        # крутить дрейнеры старым кодом. taskkill /T убивает всё дерево.
        try:
            self._kill_scanner_tree()
        except Exception:
            pass
        finally:
            self._proc = None
        # Убить прокси (не оставлять зомби)
        for proc_attr in ("_proxy_proc",):
            proc = getattr(self, proc_attr, None)
            if proc and proc.poll() is None:
                try:
                    import subprocess as _sp
                    if sys.platform == "win32":
                        _sp.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                                 capture_output=True, timeout=5,
                                 creationflags=getattr(_sp, "CREATE_NO_WINDOW", 0))
                    else:
                        proc.terminate()
                except Exception:
                    pass
            setattr(self, proc_attr, None)
        # Страховка: добить любые зомби proxy/scanner/ngrok (могли остаться)
        try:
            self._kill_zombie_processes()
        except Exception:
            pass

    # ----------------------- события: ключи -----------------------------

    @on(Button.Pressed)
    def _on_any_button(self, event: Button.Pressed) -> None:
        bid = event.button.id
        # фильтры статусов
        if bid and bid.startswith("kf_"):
            self._filter = bid[3:]
            self._render_keys()
            return
        mapping = {
            "k_hv": self._toggle_hv,
            "k_reveal": self._toggle_reveal,
            "k_refresh": self._render_keys,
        }
        if bid in mapping:
            mapping[bid]()

    def _toggle_hv(self) -> None:
        self._high_value = not self._high_value
        btn = self.query_one("#k_hv", Button)
        btn.variant = "warning" if self._high_value else "default"
        self._render_keys()

    def _toggle_reveal(self) -> None:
        self._reveal = not self._reveal
        btn = self.query_one("#k_reveal", Button)
        btn.variant = "error" if self._reveal else "default"
        self._render_keys()
        # Перерисовать детали модели если выбрана
        if self._m_selected:
            self._render_model_detail(self._m_selected)

    @on(Input.Changed, "#k_search")
    def _on_search(self, event: Input.Changed) -> None:
        self._search = event.value.strip()
        self._render_keys()

    @on(Select.Changed, "#k_platform")
    def _on_platform(self, event: Select.Changed) -> None:
        self._platform = str(event.value)
        self._render_keys()

    @on(DataTable.HeaderSelected, "#tbl")
    def _on_header(self, event: DataTable.HeaderSelected) -> None:
        names = ["idx", "platform", "status", "key", "balance",
                 "base_url", "source_url", "high", "found_time"]
        key = names[event.column_index] if event.column_index < len(names) else None
        if not key or key == "idx":
            return
        col = {"key": "api_key", "high": "is_high_value"}.get(key, key)
        if col not in self.SORT_COLS.values() and col not in self.SORT_COLS:
            col = key
        if self._sort_key == col:
            self._sort_desc = not self._sort_desc
        else:
            self._sort_key = col
            self._sort_desc = True
        self._render_keys()

    @on(DataTable.RowSelected, "#tbl")
    def _on_row(self, event: DataTable.RowSelected) -> None:
        try:
            row_data = event.data_table.get_row_at(event.cursor_row)
            idx = int(row_data[0]) - 1
        except Exception:
            return
        if 0 <= idx < len(self._rows):
            self._k_selected = self._rows[idx]
            self._render_detail(self._rows[idx])

    # ----------------------- события: модели -----------------------------

    @on(Input.Changed, "#m_search")
    def _on_m_search(self, event: Input.Changed) -> None:
        self._m_search = event.value.strip()
        self._render_models()

    @on(Select.Changed, "#m_family")
    def _on_m_family(self, event: Select.Changed) -> None:
        self._m_family = str(event.value)
        self._render_models()

    @on(Select.Changed, "#m_sort")
    def _on_m_sort(self, event: Select.Changed) -> None:
        self._m_sort = str(event.value)
        self._render_models()

    @on(Button.Pressed, "#m_refresh")
    def _on_m_refresh(self) -> None:
        self._render_models()

    @on(Button.Pressed, "#m_confirmed")
    def _on_m_confirmed(self) -> None:
        self._m_confirmed_only = not self._m_confirmed_only
        btn = self.query_one("#m_confirmed", Button)
        btn.variant = "success" if self._m_confirmed_only else "default"
        self._render_models()

    @on(DataTable.RowSelected, "#m_tbl")
    def _on_m_row(self, event: DataTable.RowSelected) -> None:
        try:
            row_data = event.data_table.get_row_at(event.cursor_row)
            idx = int(row_data[1]) - 1  # col[1]=№ (col[0]=*)
        except Exception:
            return
        if not (0 <= idx < len(self._m_rows)):
            return
        self._m_selected = self._m_rows[idx]
        self._render_model_detail(self._m_selected)
        # Двойной клик по модели -> добавить/убрать из пула
        import time as _t
        now = _t.time()
        if now - self._m_last_click < 0.45:
            self._toggle_pool_model(self._m_selected)
        self._m_last_click = now

    def _toggle_pool_model(self, row: Dict[str, Any]) -> None:
        """Добавить модель в пул или убрать (toggle по двойному клику)."""
        name = row.get("model_name") or ""
        if not name:
            return
        if name in _pool_models_set():
            self._slog(f"[yellow]{self.trf('log_pool_remove', name=name)}[/]")
            self._slog(_pool_remove_model(name))
        else:
            self._slog(f"[green]{self.trf('log_pool_add', name=name)}[/]")
            self._slog(_pool_add_model(name))
        self._render_models()
        self._render_endpoints()

    # ------------------------- провайдеры -------------------------------
    def _render_providers(self) -> None:
        tbl = self.query_one("#p_tbl", DataTable)
        try:
            saved_cursor = tbl.cursor_row
        except Exception:
            saved_cursor = 0
        tbl.clear(columns=True)
        tr = self.tr
        tbl.add_columns(
            "*", "#", tr("col_provider"), tr("col_endpoint"), tr("col_keys"),
            tr("col_confirmed"), tr("col_platforms"), tr("col_top_models"),
        )
        self._p_selected = None
        raw = _providers_data()
        # фильтрация по поиску
        if self._p_search:
            s = self._p_search.lower()
            raw = [r for r in raw if s in (r.get("base_url") or "").lower()
                   or s in (r.get("platforms") or "").lower()]
        # сортировка
        if self._p_sort == "keys":
            raw.sort(key=lambda r: -(r.get("key_count") or 0))
        elif self._p_sort == "confirmed":
            raw.sort(key=lambda r: -(r.get("confirmed_count") or 0))
        elif self._p_sort == "name":
            raw.sort(key=lambda r: _provider_name(r.get("base_url") or ""))
        elif self._p_sort == "models":
            raw.sort(key=lambda r: -(len((r.get("models") or "").split(",")) if r.get("models") else 0))
        self._p_rows = raw
        pool_eps = _pool_endpoints_set()
        for i, r in enumerate(raw, 1):
            base_url = r.get("base_url") or "-"
            name = _provider_name(base_url)
            models = _top_models(r.get("models"), limit=5)
            models_str = ", ".join(models) if models else "-"
            plats = r.get("platforms") or "-"
            in_pool = base_url in pool_eps
            name_cell = f"[bold yellow]{name[:28]}[/]" if in_pool else name[:28]
            tbl.add_row(
                "[yellow]*[/]" if in_pool else "",
                str(i),
                name_cell,
                base_url[:50],
                str(r.get("key_count") or 0),
                str(r.get("confirmed_count") or 0),
                plats[:30],
                models_str[:55],
            )
        if self._lang == "ru":
            self.query_one("#p_count", Static).update(
                f"Провайдеров: {len(raw)}"
            )
        else:
            self.query_one("#p_count", Static).update(
                f"Providers: {len(raw)}"
            )
        # Восстановить позицию курсора (не сбрасывать в начало при rerender)
        if saved_cursor and saved_cursor < len(self._p_rows):
            try:
                tbl.move_cursor(row=saved_cursor)
            except Exception:
                pass

    def _render_provider_detail(self, row: Optional[Dict[str, Any]]) -> None:
        detail = self.query_one("#p_detail", Static)
        if not row:
            detail.update(
                "Выберите провайдера для просмотра моделей и ключей."
                if self._lang == "ru"
                else "Select a provider to view models and keys."
            )
            return
        base_url = row.get("base_url", "")
        name = _provider_name(base_url)
        models = _top_models(row.get("models"), limit=50)
        plats = row.get("platforms") or "-"
        # Все ключи этого провайдера
        sql = (
            "SELECT lk.id, lk.platform, lk.api_key, lk.status, lk.is_high_value, "
            "  lk.verified_time, lk.balance_usd "
            "FROM leaked_keys lk "
            "WHERE lk.base_url = ? AND lk.status IN ('valid','confirmed','quota_exceeded') "
            "ORDER BY lk.status = 'confirmed' DESC, lk.is_high_value DESC, lk.verified_time DESC"
        )
        keys = _db(sql, (base_url,))
        confirmed_keys = [k for k in keys if k["status"] == "confirmed"]
        valid_keys = [k for k in keys if k["status"] == "valid"]
        quota_keys = [k for k in keys if k["status"] == "quota_exceeded"]
        hv = sum(1 for k in keys if k.get("is_high_value"))
        if self._lang == "ru":
            lines = [
                f"[bold]{name}[/]",
                f"[white]{base_url}[/]",
                f"Платформы: {plats}",
                "",
                f"Ключей: [bold]{len(keys)}[/]  "
                f"[bold green]Подтверждённых: {len(confirmed_keys)}[/]  "
                f"[green]Valid: {len(valid_keys)}[/]  "
                f"[yellow]Quota: {len(quota_keys)}[/]  "
                f"[yellow]* High-value: {hv}[/]",
                "",
            ]
            top_models_s = f"[bold]Топ модели ({len(models)}):[/]"
            no_models_s = "[dim]Модели не найдены[/]"
            conf_hdr = f"[bold green]--- Подтверждённые ключи ({len(confirmed_keys)}) ---[/]"
            valid_hdr = f"[bold]--- Валидные ключи ({len(valid_keys)}) ---[/]"
        else:
            lines = [
                f"[bold]{name}[/]",
                f"[white]{base_url}[/]",
                f"Platforms: {plats}",
                "",
                f"Keys: [bold]{len(keys)}[/]  "
                f"[bold green]Confirmed: {len(confirmed_keys)}[/]  "
                f"[green]Valid: {len(valid_keys)}[/]  "
                f"[yellow]Quota: {len(quota_keys)}[/]  "
                f"[yellow]* High-value: {hv}[/]",
                "",
            ]
            top_models_s = f"[bold]Top models ({len(models)}):[/]"
            no_models_s = "[dim]No models found[/]"
            conf_hdr = f"[bold green]--- Confirmed keys ({len(confirmed_keys)}) ---[/]"
            valid_hdr = f"[bold]--- Valid keys ({len(valid_keys)}) ---[/]"
        if models:
            lines.append(top_models_s)
            lines.append("  " + ", ".join(models))
        else:
            lines.append(no_models_s)

        if confirmed_keys:
            lines.append("")
            lines.append(conf_hdr)
            for k in confirmed_keys[:50]:
                star = " *" if k.get("is_high_value") else ""
                key_str = k['api_key'] if self._reveal else _mask(k['api_key'])
                lines.append(f"  {key_str}{star}")

        if valid_keys:
            lines.append("")
            lines.append(valid_hdr)
            for k in valid_keys[:50]:
                star = " *" if k.get("is_high_value") else ""
                key_str = k['api_key'] if self._reveal else _mask(k['api_key'])
                lines.append(f"  {key_str}{star}")

        if quota_keys:
            lines.append("")
            lines.append(f"[yellow]--- Quota exceeded ({len(quota_keys)}) ---[/]")
            for k in quota_keys[:20]:
                star = " *" if k.get("is_high_value") else ""
                key_str = k['api_key'] if self._reveal else _mask(k['api_key'])
                lines.append(f"  {key_str}{star}")

        if self._reveal and keys:
            lines.append("")
            lines.append("[bold green]═══ Блок копирования ═══[/]")
            lines.append(f"[white]{base_url}[/]")
            for k in keys:
                lines.append(k['api_key'])
        elif not self._reveal:
            lines.append("")
            lines.append("[dim]Reveal - показать полные ключи для копирования[/]")
        
        detail.update("\n".join(lines))

    # ------------------------- эндпоинты (API) ---------------------------
    def _is_proxy_running(self) -> bool:
        return self._proxy_proc is not None and self._proxy_proc.poll() is None

    def _pool_model_health(self, model_name: str) -> Tuple[int, int]:
        """Confirmed/всего ключей для модели (ТОЛЬКО confirmed, valid не считаем)."""
        try:
            rows = _db(
                "SELECT DISTINCT lk.api_key, lk.status FROM key_models km "
                "JOIN leaked_keys lk ON lk.id = km.key_id "
                "WHERE km.model_name=?", (model_name,))
        except Exception:
            return (0, 0)
        total = len(rows)
        confirmed = sum(1 for r in rows if r.get("status") == "confirmed")
        return (confirmed, total)

    def _pool_models_health_batch(self, models: List[str]
                                  ) -> Dict[str, Tuple[int, int]]:
        """Живые/всего ключей для списка моделей одним запросом (вместо N+1)."""
        if not models:
            return {}
        out = {m: (0, 0) for m in models}
        try:
            ph = ",".join("?" * len(models))
            rows = _db(
                f"SELECT km.model_name AS m, lk.api_key AS k, lk.status AS s "
                f"FROM key_models km JOIN leaked_keys lk ON lk.id = km.key_id "
                f"WHERE km.model_name IN ({ph})", tuple(models))
        except Exception:
            return out
        # Группировать: модель -> {ключ: статус} (DISTINCT по ключу)
        seen: Dict[str, Dict[str, str]] = {}
        for r in rows:
            seen.setdefault(r["m"], {})[r["k"]] = r["s"]
        for m, kmap in seen.items():
            # ТОЛЬКО confirmed (valid не крутим - не подтверждены)
            confirmed = sum(1 for st in kmap.values()
                            if st == "confirmed")
            total = len(kmap)
            out[m] = (confirmed, total)
        return out

    def _pool_endpoints_health_batch(self, endpoints: List[str]
                                     ) -> Dict[str, Tuple[int, int, int]]:
        """Эндпоинт -> (live, total, n_models) одним запросом (вместо N+1)."""
        if not endpoints:
            return {}
        out = {e: (0, 0, 0) for e in endpoints}
        try:
            ph = ",".join("?" * len(endpoints))
            # Ключи по статусам (ТОЛЬКО confirmed - valid не крутим)
            krows = _db(
                f"SELECT base_url AS u, "
                f"SUM(status='confirmed') AS l, "
                f"COUNT(*) AS t FROM leaked_keys "
                f"WHERE base_url IN ({ph}) GROUP BY base_url", tuple(endpoints))
            for r in krows:
                out[r["u"]] = (r["l"] or 0, r["t"] or 0, out.get(r["u"], (0,0,0))[2])
            # Число confirmed моделей
            mrows = _db(
                f"SELECT lk.base_url AS u, COUNT(DISTINCT km.model_name) AS c "
                f"FROM key_models km JOIN leaked_keys lk ON lk.id = km.key_id "
                f"WHERE lk.base_url IN ({ph}) AND lk.status='confirmed' "
                f"AND km.is_confirmed=1 "
                f"GROUP BY lk.base_url", tuple(endpoints))
            for r in mrows:
                l, t, _ = out.get(r["u"], (0, 0, 0))
                out[r["u"]] = (l, t, r["c"])
        except Exception:
            pass
        return out


    def _render_endpoints(self) -> None:
        """Две таблицы пула: модели и провайдеры, с состоянием (health)."""
        # Убедиться что active_pool существует
        try:
            _exec("CREATE TABLE IF NOT EXISTS active_pool "
                  "(id INTEGER PRIMARY KEY AUTOINCREMENT, "
                  "model_name TEXT NOT NULL, endpoint TEXT NOT NULL, "
                  "platform TEXT DEFAULT '', api_keys TEXT DEFAULT '[]', "
                  "added_time DATETIME DEFAULT CURRENT_TIMESTAMP, "
                  "enabled BOOLEAN DEFAULT 1, "
                  "UNIQUE(model_name, endpoint))")
        except Exception:
            pass

        try:
            pool = _db(
                "SELECT model_name, endpoint, platform, api_keys, enabled "
                "FROM active_pool ORDER BY model_name")
        except Exception:
            pool = []

        proxy = ("[green]ON[/]" if self._is_proxy_running() else "[red]OFF[/]")
        # Статистика прокси (если запущен): запросы/успех
        proxy_stat = ""
        if self._is_proxy_running():
            # Non-blocking: very short timeout; never stall UI refresh
            try:
                import urllib.request as _u, json as _j
                with _u.urlopen("http://127.0.0.1:8818/health", timeout=0.25) as _r:
                    hs = _j.loads(_r.read())
                if self._lang == "ru":
                    proxy_stat = (
                        f" | {hs.get('total_calls', 0)} запр. "
                        f"[green]{hs.get('success_rate', 0)}%[/]"
                    )
                else:
                    proxy_stat = (
                        f" | {hs.get('total_calls', 0)} calls "
                        f"[green]{hs.get('success_rate', 0)}%[/]"
                    )
            except Exception:
                pass
        m_tbl = self.query_one("#e_models_tbl", DataTable)
        m_tbl.clear(columns=True)
        tr = self.tr
        if self._lang == "ru":
            m_tbl.add_columns("*", "#", "Имя", "Тип", "Ключей", "Состояние")
        else:
            m_tbl.add_columns("*", "#", "Name", "Type", "Keys", "State")
        # (headers localized above)
        self._e_models_rows = []
        # Модели (zone=model) - из pool_models (только confirmed ключи)
        pool_models_list = sorted(_pool_models_set())
        health = self._pool_models_health_batch(pool_models_list)
        idx = 0
        for model in pool_models_list:
            idx += 1
            confirmed, _ = health.get(model, (0, 0))
            live = confirmed  # только confirmed, valid не крутим
            if live == 0:
                state, sc = (
                    ("X нет confirmed", "red") if self._lang == "ru"
                    else ("X no confirmed", "red")
                )
            else:
                state, sc = f"{live}", "green"
            type_lbl = "[white]модель[/]" if self._lang == "ru" else "[white]model[/]"
            m_tbl.add_row(
                "[yellow]*[/]", str(idx),
                f"[bold yellow]{model}[/]" if live else model,
                type_lbl, str(live), f"[{sc}]{state}[/]")
            self._e_models_rows.append({"model": model, "type": "model"})
        # Providers (zone=endpoint) from pool_endpoints (confirmed only)
        pool_eps_list = sorted(_pool_endpoints_set())
        ep_health = self._pool_endpoints_health_batch(pool_eps_list)
        for ep in pool_eps_list:
            idx += 1
            name = _provider_name(ep)
            live, _, n_models = ep_health.get(ep, (0, 0, 0))
            if live == 0:
                state, sc = (
                    ("X нет confirmed", "red") if self._lang == "ru"
                    else ("X no confirmed", "red")
                )
            else:
                state, sc = f"{live}", "green"
            m_tbl.add_row(
                "[yellow]*[/]", str(idx),
                f"[bold white]{name[:24]}[/]" if live else name[:24],
                "[magenta]provider[/]" if self._lang != "ru" else "[magenta]провайдер[/]",
                str(live), f"[{sc}]{state}[/]")
            self._e_models_rows.append(
                {"endpoint": ep, "name": name, "type": "provider"})
        n_models = len(pool_models_list)
        n_provs = len(pool_eps_list)
        if self._lang == "ru":
            self.query_one("#e_models_count", Static).update(
                f"Моделей: {n_models} | Провайдеров: {n_provs} | "
                f"Прокси: {proxy} :8818{proxy_stat}")
        else:
            self.query_one("#e_models_count", Static).update(
                f"Models: {n_models} | Providers: {n_provs} | "
                f"Proxy: {proxy} :8818{proxy_stat}")

        # ---- Правая таблица: детали выбранного слева ----
        p_tbl = self.query_one("#e_providers_tbl", DataTable)
        p_tbl.clear(columns=True)
        if self._lang == "ru":
            p_tbl.add_columns(
                "#", "Имя", "Эндпоинт/Модель", "Ключей", "Статус", "Приор.", "Вкл",
            )
        else:
            p_tbl.add_columns(
                "#", "Name", "Endpoint/Model", "Keys", "Status", "Prio", "On",
            )
        self._e_providers_rows = []
        sel_model = getattr(self, "_e_selected_model", "")
        sel_endpoint = getattr(self, "_e_selected_endpoint", "")
        title = self.query_one("#e_providers_title", Static)

        if not sel_model and not sel_endpoint:
            if self._lang == "ru":
                title.update("[bold]Детали[/] [dim](выберите модель или провайдера слева)[/]")
            else:
                title.update("[bold]Details[/] [dim](select a model or provider on the left)[/]")
            self.query_one("#e_providers_count", Static).update("-")
        elif sel_model:
            # Model -> its providers (zone=model) with keys
            if self._lang == "ru":
                title.update(f"[bold]Провайдеры модели:[/] [yellow]{sel_model}[/]")
            else:
                title.update(f"[bold]Providers for model:[/] [yellow]{sel_model}[/]")
            # Только эндпоинты с confirmed ключами (а не все из active_pool).
            # n_keys/n_conf считаем ТОЛЬКО по confirmed/valid - мёртвые не в счёт.
            try:
                eps = _db(
                    "SELECT ap.endpoint, ap.platform, ap.priority, ap.enabled "
                    "FROM active_pool ap "
                    "WHERE ap.model_name=? AND EXISTS("
                    "  SELECT 1 FROM key_models km "
                    "  JOIN leaked_keys lk ON lk.id=km.key_id "
                    "  WHERE km.model_name=ap.model_name "
                    "    AND lk.base_url=ap.endpoint "
                    "    AND lk.status='confirmed' AND km.is_confirmed=1) "
                    "ORDER BY ap.priority DESC",
                    (sel_model,))
            except Exception:
                eps = []
            for i, r in enumerate(eps, 1):
                ep = r["endpoint"]
                name = _provider_name(ep)
                try:
                    # Актуальные ключи: только confirmed (живые, подтверждали)
                    n_conf = _db(
                        "SELECT COUNT(DISTINCT lk.api_key) AS c FROM key_models km "
                        "JOIN leaked_keys lk ON lk.id=km.key_id "
                        "WHERE km.model_name=? AND lk.base_url=? "
                        "AND lk.status='confirmed' AND km.is_confirmed=1",
                        (sel_model, ep))[0]["c"]
                    n_conf = _db(
                        "SELECT COUNT(DISTINCT lk.api_key) AS c FROM key_models km "
                        "JOIN leaked_keys lk ON lk.id=km.key_id "
                        "WHERE km.model_name=? AND lk.base_url=? "
                        "AND lk.status='confirmed' AND km.is_confirmed=1",
                        (sel_model, ep))[0]["c"]
                except Exception:
                    n_conf = 0
                n_keys = n_conf  # крутимо ТІЛЬКИ confirmed (valid не працюють)
                if n_conf == 0:
                    state, sc = "-", "dim"
                else:
                    state, sc = f"OK{n_conf}", "green"
                prio = r.get("priority", 0) or 0
                prio_str = f"[white]{prio}[/]" if prio else "[dim]0[/]"
                enabled = r.get("enabled", 1)
                en_mark = "[green]*[/]" if enabled else "[dim]o[/]"
                p_tbl.add_row(
                    str(i),
                    f"[bold yellow]{name[:20]}[/]" if n_conf else name[:20],
                    ep[:26], str(n_keys), f"[{sc}]{state}[/]",
                    prio_str, en_mark)
                self._e_providers_rows.append(
                    {"endpoint": ep, "name": name, "model": sel_model,
                     "enabled": enabled})
            if self._lang == "ru":
                self.query_one("#e_providers_count", Static).update(
                    f"Эндпоинтов: {len(eps)}")
            else:
                self.query_one("#e_providers_count", Static).update(
                    f"Endpoints: {len(eps)}")
        else:
            # Provider -> its models with keys
            name = _provider_name(sel_endpoint)
            if self._lang == "ru":
                title.update(f"[bold]Модели провайдера:[/] [white]{name}[/]")
            else:
                title.update(f"[bold]Models for provider:[/] [white]{name}[/]")
            try:
                mrows = _db(
                    "SELECT DISTINCT km.model_name AS m FROM key_models km "
                    "JOIN leaked_keys lk ON lk.id = km.key_id "
                    "WHERE lk.base_url=? AND lk.status='confirmed' "
                    "AND km.is_confirmed=1 ORDER BY km.model_name",
                    (sel_endpoint,))
            except Exception:
                mrows = []
            for i, r in enumerate(mrows, 1):
                mdl = r["m"]
                try:
                    krows = _db(
                        "SELECT lk.api_key, lk.status FROM key_models km "
                        "JOIN leaked_keys lk ON lk.id = km.key_id "
                        "WHERE km.model_name=? AND lk.base_url=?",
                        (mdl, sel_endpoint))
                    n_keys = len(krows)
                    n_conf = sum(1 for k in krows
                                 if k["status"] == "confirmed")
                except Exception:
                    n_keys, n_conf = 0, 0
                state = (f"OK{n_conf}" if n_conf == n_keys and n_keys
                         else f"{n_conf}/{n_keys}" if n_conf
                         else "0" if n_keys else "-")
                p_tbl.add_row(
                    str(i), f"[bold white]{mdl[:24]}[/]",
                    sel_endpoint[:26], str(n_keys), state,
                    "[dim]-[/]", "[green]*[/]")
                self._e_providers_rows.append(
                    {"endpoint": sel_endpoint, "name": mdl,
                     "model": mdl, "enabled": 1})
            if self._lang == "ru":
                self.query_one("#e_providers_count", Static).update(
                    f"Моделей: {len(mrows)}")
            else:
                self.query_one("#e_providers_count", Static).update(
                    f"Models: {len(mrows)}")

    @on(Button.Pressed, "#e_proxy")
    def _on_e_proxy(self) -> None:
        """Запуск/стоп локального прокси. Хост 0.0.0.0 если _proxy_external."""
        if self._is_proxy_running():
            self._proxy_proc.terminate()
            self._proxy_proc = None
            self._slog(f"[red]{self.tr('log_proxy_stopped')}[/]")
        else:
            import subprocess as _sp
            host = "0.0.0.0" if self._proxy_external else "127.0.0.1"
            self._proxy_proc = _sp.Popen(
                [sys.executable, os.path.join(BASE_DIR, "proxy_server.py"),
                 "--port", "8818", "--host", host],
                stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
                creationflags=getattr(_sp, "CREATE_NO_WINDOW", 0))
            if self._proxy_external:
                self._slog(f"[green]{self.tr('log_proxy_external')}[/]")
            else:
                self._slog(f"[green]{self.tr('log_proxy_started')}[/]")
        btn = self.query_one("#e_proxy", Button)
        btn.label = "■ Прокси OFF" if self._is_proxy_running() else "Прокси ON"
        btn.variant = "error" if self._is_proxy_running() else "success"
        self._render_endpoints()

    @on(Button.Pressed, "#e_external")
    def _on_e_external(self) -> None:
        """Внешний IP: переключить режим 0.0.0.0 + инструкция port-forward.

        OmniRouter стучит на публичный IP (http://ВАШ_IP:8818/v1). Нужен
        port-forwarding 8818 на роутере. Альтернатива ngrok - без регистрации,
        но IP может меняться провайдером."""
        self._proxy_external = not self._proxy_external
        btn = self.query_one("#e_external", Button)
        btn.variant = "success" if self._proxy_external else "default"
        self._save_proxy_mode("external" if self._proxy_external else "local")
        if self._proxy_external:
            # Авто-открыть порт в брандмауэре Windows (иначе внешние запросы
            # блокируются, даже если прокси слушает 0.0.0.0). Требует админ-прав.
            fw_ok = self._open_firewall_port(8818)
            # Получить публичный IP
            pub_ip = ""
            try:
                import urllib.request as _u
                with _u.urlopen("https://api.ipify.org", timeout=5) as _r:
                    pub_ip = _r.read().decode().strip()
            except Exception:
                pass
            self._slog(
                "[bold white]=== Внешний доступ через IP ===[/]\n"
                "[yellow]Прокси будет слушать 0.0.0.0 (все интерфейсы).[/]\n"
                f"  [1] Брандмауэр 8818: {'[green]открытOK[/]' if fw_ok else '[red]НЕ открыт - запусти TUI от админа или добавь вручную[/]'}\n"
                "  [2] На роутере: Port Forwarding TCP 8818 -> "
                "192.168.0.101:8818\n"
                "  [3] OmniRouter Base URL: " +
                (f"http://{pub_ip}:8818/v1" if pub_ip else
                 "http://ВАШ_ПУБЛИЧНЫЙ_IP:8818/v1") + "\n"
                "[dim]Внимание: IP может меняться провайдером.[/]")
            if pub_ip:
                self.query_one("#e_hint", Static).update(
                    f"[bold green]Внешний URL: http://{pub_ip}:8818/v1[/]\n"
                    f"[dim]Port-forward 8818 на роутере -> 192.168.0.101[/]")
            # Авто-перезапуск прокси на 0.0.0.0 (если был на 127.0.0.1)
            self._restart_proxy_for_mode()
        else:
            self._slog(f"[yellow]{self.tr('log_proxy_local_only')}[/]")
            self._restart_proxy_for_mode()
        self._render_endpoints()

    def _restart_proxy_for_mode(self) -> None:
        """Перезапустить прокси под текущий режим (external=0.0.0.0 / local).
        Чтобы изменение режима применилось без ручного OFF->ON."""
        was_running = self._is_proxy_running()
        if was_running:
            # Остановить старый (на другом хосте)
            try:
                self._proxy_proc.terminate()
            except Exception:
                pass
            self._proxy_proc = None
        # Запустить заново с текущим _proxy_external
        if was_running or self._is_proxy_running() is False:
            import subprocess as _sp
            host = "0.0.0.0" if self._proxy_external else "127.0.0.1"
            try:
                self._proxy_proc = _sp.Popen(
                    [sys.executable, os.path.join(BASE_DIR, "proxy_server.py"),
                     "--port", "8818", "--host", host],
                    stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
                    creationflags=getattr(_sp, "CREATE_NO_WINDOW", 0))
                self._slog(f"[green]{self.trf('log_proxy_restarted', host=host)}[/]")
            except Exception as e:
                self._slog(f"[red]{self.trf('log_proxy_restart_fail', err=e)}[/]")
        # Обновить кнопку
        try:
            btn = self.query_one("#e_proxy", Button)
            btn.label = "■ Прокси OFF" if self._is_proxy_running() else "Прокси ON"
            btn.variant = "error" if self._is_proxy_running() else "success"
        except Exception:
            pass

    def _open_firewall_port(self, port: int) -> bool:
        """Открыть TCP-порт в брандмауэре Windows (netsh). Требует админ-права.

        Без этого внешние запросы блокируются, даже если прокси слушает 0.0.0.0
        (loopback-запросы с этой же машины проходят, внешние - нет).
        Возвращает True если правило создано/есть.
        """
        if sys.platform != "win32":
            return True
        import subprocess as _sp
        name = f"SecretScanner Proxy {port}"
        try:
            # Проверить есть ли уже правило
            r = _sp.run(
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 f"name={name}"],
                capture_output=True, timeout=8,
                creationflags=getattr(_sp, "CREATE_NO_WINDOW", 0))
            if r.returncode == 0 and name.encode() in r.stdout:
                return True  # уже есть
            # Создать inbound-правило
            _sp.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={name}", "dir=in", "action=allow",
                 "protocol=TCP", f"localport={port}"],
                capture_output=True, timeout=8,
                creationflags=getattr(_sp, "CREATE_NO_WINDOW", 0))
            # Проверить что создалось
            r = _sp.run(
                ["netsh", "advfirewall", "firewall", "show", "rule",
                 f"name={name}"],
                capture_output=True, timeout=8,
                creationflags=getattr(_sp, "CREATE_NO_WINDOW", 0))
            return r.returncode == 0 and name.encode() in r.stdout
        except Exception:
            return False

    @on(Button.Pressed, "#e_test_url")
    def _on_e_test_url(self) -> None:
        """Тест URL: проверить что OmniRouter-подобный клиент увидит.
        Тестирует /v1/models на локальном и публичном URL. В фоне (поток),
        результат в #e_hint + slog, чтобы не блокировать TUI."""
        self._slog(f"[yellow]{self.tr('log_test_url_start')}[/]")
        import threading

        def _worker():
            import urllib.request as _u
            import json as _j

            def _test(url: str) -> str:
                try:
                    req = _u.Request(f"{url}/models",
                                     headers={"Authorization": "Bearer test"})
                    with _u.urlopen(req, timeout=8) as r:
                        d = _j.loads(r.read())
                        n = len(d.get("data", []))
                        return f"{url} -> 200, {n} моделей"
                except Exception as e:
                    return f"X {url} -> {type(e).__name__}: {str(e)[:50]}"

            lines = ["=== Тест доступности (как OmniRouter) ==="]
            local = _test("http://127.0.0.1:8818/v1")
            lines.append("  " + local)
            hint = local
            try:
                with _u.urlopen("https://api.ipify.org", timeout=5) as _r:
                    pub = _r.read().decode().strip()
                pub_r = _test(f"http://{pub}:8818/v1")
                lines.append("  " + pub_r)
                hint = f"{local}\n{pub_r}"
                if "OK" in pub_r:
                    lines.append("  Публичный доступен, но OmniRouter пишет "
                                 "unavailable? -> он требует HTTPS. Используй ngrok.")
            except Exception as e:
                lines.append(f"  X Публичный IP: {e}")
            msg = "\n".join(lines)
            self.call_after_refresh(self._slog, msg)
            # Также в e_hint (видно в API вкладке)
            def _upd():
                try:
                    self.query_one("#e_hint", Static).update(
                        msg.replace("OK", "[green]OK[/]")
                           .replace("X", "[red]X[/]"))
                except Exception:
                    pass
            self.call_after_refresh(_upd)

        threading.Thread(target=_worker, daemon=True).start()

    @on(Button.Pressed, "#e_sel_mode_btn")
    def _on_e_sel_mode_btn(self) -> None:
        """Метод: кнопка-переключатель round_robin ↔ sticky."""
        cur = self._get_selection_mode()
        mode = "sticky" if cur == "round_robin" else "round_robin"
        self._save_selection_mode(mode)
        btn = self.query_one("#e_sel_mode_btn", Button)
        btn.label = (self.tr("method_sticky") if mode == "sticky"
                     else self.tr("method_rr"))
        if self._is_proxy_running():
            try:
                import urllib.request as _u
                import json as _j
                req = _u.Request(
                    "http://127.0.0.1:8818/pool/selection_mode",
                    data=_j.dumps({"mode": mode}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST")
                _u.urlopen(req, timeout=3).read()
                self._slog(f"[green]{self.trf('log_method_set', mode=mode)}[/]")
            except Exception as e:
                self._slog(f"[red]{self.trf('log_method_fail', err=e)}[/]")

    def _get_proxy_mode(self) -> str:
        """Режим доступа: 'local' | 'external'."""
        try:
            import config_local
            return (getattr(config_local, "PROXY_MODE", "") or "local").strip()
        except Exception:
            return "local"

    def _save_proxy_mode(self, mode: str) -> None:
        """Сохранить режим доступа в config_local.PROXY_MODE."""
        try:
            path = os.path.join(BASE_DIR, "config_local.py")
            try:
                content = open(path, encoding="utf-8").read()
            except OSError:
                content = ""
            line = f'PROXY_MODE = "{mode}"'
            if "PROXY_MODE" in content:
                import re
                content = re.sub(r'PROXY_MODE\s*=\s*["\'][^"\']*["\']', line, content)
            else:
                content = (content.rstrip() + "\n" if content.strip() else "") + line + "\n"
            open(path, "w", encoding="utf-8").write(content)
            import config_local
            config_local.PROXY_MODE = mode
        except Exception:
            pass

    def _save_selection_mode(self, mode: str) -> None:
        try:
            path = os.path.join(BASE_DIR, "config_local.py")
            try:
                content = open(path, encoding="utf-8").read()
            except OSError:
                content = ""
            line = f'SELECTION_MODE = "{mode}"'
            if "SELECTION_MODE" in content:
                import re
                content = re.sub(r'SELECTION_MODE\s*=\s*["\'][^"\']*["\']', line, content)
            else:
                content = (content.rstrip() + "\n" if content.strip() else "") + line + "\n"
            open(path, "w", encoding="utf-8").write(content)
            # Обновить импортированный модуль (иначе _get_selection_mode
            # вернёт старое значение из кеша импорта)
            import config_local
            config_local.SELECTION_MODE = mode
        except Exception:
            pass

    def _get_selection_mode(self) -> str:
        try:
            import config_local
            return (getattr(config_local, "SELECTION_MODE", "")
                    or "round_robin").strip()
        except Exception:
            return "round_robin"

    @on(Button.Pressed, "#e_p_up")
    def _on_e_p_up(self) -> None:
        self._reorder_selected("up")

    @on(Button.Pressed, "#e_p_down")
    def _on_e_p_down(self) -> None:
        self._reorder_selected("down")

    def _reorder_selected(self, direction: str) -> None:
        """Поднять/опустить выбранный провайдер в таблице провайдеров модели.

        Запрос /pool/reorder к прокси; active_pool.priority меняется.
        Кнопки ^v под правой таблицей."""
        try:
            tbl = self.query_one("#e_providers_tbl", DataTable)
            row = tbl.get_row_at(tbl.cursor_row)
            idx = int(row[0]) - 1  # col[0]=№ (правая таблица без *)
        except Exception:
            self._slog(f"[dim]{self.tr('log_pick_provider')}[/]")
            return
        if not (0 <= idx < len(self._e_providers_rows)):
            return
        entry = self._e_providers_rows[idx]
        endpoint = entry["endpoint"]
        name = entry.get("name", "")
        if self._is_proxy_running() and endpoint:
            try:
                import urllib.request as _u
                import json as _j
                req = _u.Request(
                    "http://127.0.0.1:8818/pool/reorder",
                    data=_j.dumps(
                        {"endpoint": endpoint, "direction": direction}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST")
                _u.urlopen(req, timeout=3).read()
                self._slog(f"[green]{('^' if direction=='up' else 'v')} {name}[/]")
            except Exception as e:
                self._slog(f"[red]reorder: {e}[/]")
        elif not self._is_proxy_running():
            self._slog(f"[dim]{self.tr('log_proxy_for_reorder')}[/]")
        self._render_endpoints()

    def _toggle_selected_source(self) -> None:
        """Вкл/выкл выбранного провайдера модели (POST /pool/toggle)."""
        try:
            tbl = self.query_one("#e_providers_tbl", DataTable)
            row = tbl.get_row_at(tbl.cursor_row)
            idx = int(row[0]) - 1
        except Exception:
            self._slog(f"[dim]{self.tr('log_pick_provider')}[/]")
            return
        if not (0 <= idx < len(self._e_providers_rows)):
            return
        entry = self._e_providers_rows[idx]
        model = entry.get("model", self._e_selected_model)
        ep = entry["endpoint"]
        if self._is_proxy_running():
            try:
                import urllib.request as _u
                import json as _j
                req = _u.Request(
                    "http://127.0.0.1:8818/pool/toggle",
                    data=_j.dumps({"model": model, "endpoint": ep}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST")
                _u.urlopen(req, timeout=3).read()
                self._slog(f"[green]{self.trf('log_toggled', name=entry.get('name',''))}[/]")
            except Exception as e:
                self._slog(f"[red]toggle: {e}[/]")
        self._render_endpoints()

    def _delete_selected_source(self) -> None:
        """Удалить связь модель↔провайдер (POST /pool/remove_source)."""
        try:
            tbl = self.query_one("#e_providers_tbl", DataTable)
            row = tbl.get_row_at(tbl.cursor_row)
            idx = int(row[0]) - 1
        except Exception:
            self._slog(f"[dim]{self.tr('log_pick_provider')}[/]")
            return
        if not (0 <= idx < len(self._e_providers_rows)):
            return
        entry = self._e_providers_rows[idx]
        model = entry.get("model", self._e_selected_model)
        ep = entry["endpoint"]
        name = entry.get("name", "")
        if self._is_proxy_running():
            try:
                import urllib.request as _u
                import json as _j
                req = _u.Request(
                    "http://127.0.0.1:8818/pool/remove_source",
                    data=_j.dumps({"model": model, "endpoint": ep}).encode(),
                    headers={"Content-Type": "application/json"},
                    method="POST")
                _u.urlopen(req, timeout=3).read()
                self._slog(f"[red]{self.trf('log_removed_from_model', name=name, model=model)}[/]")
            except Exception as e:
                self._slog(f"[red]remove: {e}[/]")
        self._render_endpoints()

    @on(Button.Pressed, "#e_p_toggle")
    def _on_e_p_toggle(self) -> None:
        self._toggle_selected_source()

    @on(Button.Pressed, "#e_p_del")
    def _on_e_p_del(self) -> None:
        self._delete_selected_source()

    @on(DataTable.RowSelected, "#e_models_tbl")
    def _on_e_model_row(self, event: DataTable.RowSelected) -> None:
        """Клик слева -> справа детали. Модель -> её провайдеры; провайдер -> его
        модели/ключи. Двойной клик -> убрать из пула."""
        try:
            row_data = event.data_table.get_row_at(event.cursor_row)
            idx = int(row_data[1]) - 1  # col[1]=№
        except Exception:
            return
        if not (0 <= idx < len(self._e_models_rows)):
            return
        entry = self._e_models_rows[idx]
        is_provider = entry.get("type") == "provider"
        import time as _t
        now = _t.time()
        if now - self._m_last_click < 0.45:
            # Двойной клик -> убрать из пула
            if is_provider:
                ep = entry["endpoint"]
                self._slog(f"[red]{self.trf('log_pool_remove', name=entry.get('name',''))}[/]")
                self._slog(_pool_remove_endpoint(ep))
            else:
                model = entry.get("model", "")
                self._slog(f"[red]{self.trf('log_pool_remove', name=model)}[/]")
                self._slog(_pool_remove_model(model))
            self._e_selected_model = ""
            self._e_selected_endpoint = ""
            self._render_models()
        else:
            # Одиночный клик -> выбрать, правая таблица обновится
            if is_provider:
                self._e_selected_endpoint = entry["endpoint"]
                self._e_selected_model = ""
            else:
                self._e_selected_model = entry.get("model", "")
                self._e_selected_endpoint = ""
        self._render_endpoints()
        self._m_last_click = now

    @on(DataTable.RowSelected, "#e_providers_tbl")
    def _on_e_provider_row(self, event: DataTable.RowSelected) -> None:
        """Двойной клик по провайдеру модели -> вкл/выкл (toggle enabled)."""
        import time as _t
        now = _t.time()
        if now - self._p_last_click < 0.45:
            self._toggle_selected_source()
        self._p_last_click = now

    @on(Button.Pressed, "#e_refresh")
    def _on_e_refresh(self) -> None:
        self._render_endpoints()

    @on(Button.Pressed, "#e_clear")
    def _on_e_clear(self) -> None:
        """Очистить весь пул."""
        self._slog(f"[red]{_pool_clear()}[/]")
        self._render_endpoints()
        self._render_models()
        self._render_providers()

    @on(Button.Pressed, "#e_check_all")
    def _on_e_check_all(self) -> None:
        """Перепроверить все модели в пуле."""
        import threading
        self._slog(f"[yellow]{self.tr('log_check_all_models')}[/]")

        def _worker():
            import asyncio as _aio
            from database import Database
            try:
                result = _aio.run(_recheck_confirmed_keys(Database(DB)))
                self.call_after_refresh(self._slog, result)
            except Exception as e:
                self.call_after_refresh(self._slog, f"[red]{self.trf('task_error', err=e)}[/]")

        threading.Thread(target=_worker, daemon=True).start()

    @on(Input.Changed, "#p_search")
    def _on_p_search(self, event: Input.Changed) -> None:
        self._p_search = event.value.strip()
        self._render_providers()

    @on(Select.Changed, "#p_sort")
    def _on_p_sort(self, event: Select.Changed) -> None:
        self._p_sort = str(event.value)
        self._render_providers()

    @on(Button.Pressed, "#p_refresh")
    def _on_p_refresh(self) -> None:
        self._render_providers()

    @on(Button.Pressed, "#p_reveal")
    def _on_p_reveal(self) -> None:
        self._reveal = not self._reveal
        btn = self.query_one("#p_reveal", Button)
        btn.variant = "error" if self._reveal else "default"
        if self._p_selected:
            self._render_provider_detail(self._p_selected)

    @on(DataTable.RowSelected, "#p_tbl")
    def _on_p_row(self, event: DataTable.RowSelected) -> None:
        try:
            row_data = event.data_table.get_row_at(event.cursor_row)
            idx = int(row_data[1]) - 1  # col[1]=№ (col[0]=*)
        except Exception:
            return
        if not (0 <= idx < len(self._p_rows)):
            return
        self._p_selected = self._p_rows[idx]
        self._render_provider_detail(self._p_selected)
        # Двойной клик по провайдеру -> добавить/убрать все его модели из пула
        import time as _t
        now = _t.time()
        if now - self._p_last_click < 0.45:
            self._toggle_pool_endpoint(self._p_selected)
        self._p_last_click = now

    def _toggle_pool_endpoint(self, row: Dict[str, Any]) -> None:
        """Добавить все модели эндпоинта в пул или убрать (toggle)."""
        base_url = row.get("base_url") or ""
        if not base_url:
            return
        name = _provider_name(base_url)
        if base_url in _pool_endpoints_set():
            self._slog(f"[yellow]{self.trf('log_pool_remove', name=name)}[/]")
            self._slog(_pool_remove_endpoint(base_url))
        else:
            self._slog(f"[green]{self.trf('log_pool_add', name=name)} (all)[/]")
            self._slog(_pool_add_endpoint(base_url))
        self._render_providers()
        self._render_endpoints()

    @on(Button.Pressed, "#s_lang_apply")
    def _on_s_lang_apply(self) -> None:
        """Persist UI language pref and re-apply labels that can change live."""
        try:
            sel = self.query_one("#s_lang", Select)
            pref = str(sel.value or "auto").strip().lower()
        except Exception:
            pref = "auto"
        if pref not in ("auto", "en", "ru"):
            pref = "auto"
        self._lang_pref = pref
        self._lang = _resolve_lang(pref)  # type: ignore[arg-type]
        try:
            _save_lang_pref(pref)  # type: ignore[arg-type]
        except Exception:
            pass
        self.TITLE = self.tr("app_title")
        self.SUB_TITLE = self.tr("app_subtitle")
        # Update tab labels if TabbedContent exposes them
        try:
            tabs = self.query_one("#tabs", TabbedContent)
            mapping = {
                "dashboard": "tab_dashboard",
                "keys": "tab_keys",
                "models": "tab_models",
                "providers": "tab_providers",
                "endpoints": "tab_api",
                "settings": "tab_settings",
                "logs": "tab_logs",
            }
            for pane in tabs.query(TabPane):
                key = mapping.get(pane.id or "")
                if key:
                    pane.set_class(False, "-disabled")  # no-op keep alive
                    try:
                        pane.label = self.tr(key)
                    except Exception:
                        pass
        except Exception:
            pass
        self._slog(
            f"[green]Language:[/] pref={pref} → {self._lang} "
            f"(restart TUI for full re-compose if some labels stay old)"
        )
        self.notify(
            f"Language: {pref} → {self._lang}. Restart TUI for full UI refresh.",
            severity="information",
        )

    @on(Button.Pressed, "#s_start")
    def _b_start(self) -> None:
        self._start_scanner()
        self._update_statusbar()

    @on(Button.Pressed, "#s_stop")
    def _b_stop(self) -> None:
        self._stop_scanner()
        self._update_statusbar()

    @on(Button.Pressed, "#s_restart")
    def _b_restart(self) -> None:
        self._restart_scanner()
        self._update_statusbar()

    @on(Button.Pressed, "#s_autostart")
    def _b_autostart(self) -> None:
        global AUTOSTART
        AUTOSTART = not AUTOSTART
        btn = self.query_one("#s_autostart", Button)
        btn.label = "Autostart: ON" if AUTOSTART else "Autostart: OFF"

    @on(Button.Pressed, "#s_clearsha")
    def _b_clearsha(self) -> None:
        err = _exec("DELETE FROM scanned_blobs")
        self._slog(f"[green]{self.tr('log_sha_cleared')}[/]"
                   if not err else f"[red]{err}[/]")

    @on(Button.Pressed, "#s_clearprog")
    def _b_clearprog(self) -> None:
        err = _exec("DELETE FROM scan_progress")
        self._slog(f"[green]{self.tr('log_progress_reset')}[/]"
                   if not err else f"[red]{err}[/]")

    @on(Button.Pressed, "#s_vacuum")
    def _b_vacuum(self) -> None:
        import threading
        self._slog(f"[yellow]{self.tr('log_vacuum_start')}[/]")
        def _worker():
            err = _exec("VACUUM")
            if err:
                self.call_after_refresh(self._slog, f"[red]VACUUM: {err}[/]")
            else:
                self.call_after_refresh(self._slog, f"[green]{self.tr('log_vacuum_done')}[/]")
        threading.Thread(target=_worker, daemon=True).start()

    @on(Button.Pressed, "#s_delinvalid")
    def _b_delinvalid(self) -> None:
        n = _count_keys("invalid")
        err = _exec("DELETE FROM leaked_keys WHERE status='invalid'")
        if err:
            self._slog(f"[red]{err}[/]")
        else:
            self._slog(f"[red]{self.trf('log_invalid_deleted', n=n)}[/]")
        self._refresh_all()

    @on(Button.Pressed, "#s_resetattempts")
    def _b_resetattempts(self) -> None:
        """Сброс confirm_attempts=0 для всех ключей -> перепроверка."""
        err = _exec("UPDATE leaked_keys SET confirm_attempts=0")
        if err:
            self._slog(f"[red]{err}[/]")
        else:
            n = _db("SELECT COUNT(*) AS c FROM leaked_keys")
            self._slog(f"[yellow]{self.tr('log_attempts_reset')}: {n[0]['c'] if n else 0}[/]")
        self._refresh_all()

    @on(Button.Pressed, "#s_markhv")
    def _b_markhv(self) -> None:
        """Пометить все CONFIRMED ключи как high-value."""
        err = _exec("UPDATE leaked_keys SET is_high_value=1 WHERE status='confirmed'")
        if err:
            self._slog(f"[red]{err}[/]")
        else:
            n = _count_keys("confirmed")
            self._slog(f"[green]{self.trf('log_hv_marked', n=n)}[/]")
        self._refresh_all()

    @on(Button.Pressed, "#s_revalidate_all")
    def _b_revalidate_all(self) -> None:
        """Полная перепроверка: нормализация + валидация + подтверждение + модели"""
        self._run_bg_task("full_revalidate")

    @on(Button.Pressed, "#s_revalidate_failed")
    def _b_revalidate_failed(self) -> None:
        """Перепроверка только pending/unverified/connection_error"""
        self._run_bg_task("failed_revalidate")

    @on(Button.Pressed, "#s_confirm_all")
    def _b_confirm_all(self) -> None:
        """Подтверждение VALID ключей -> CONFIRMED"""
        self._run_bg_task("confirm_all")

    @on(Button.Pressed, "#s_confirm_models")
    def _b_confirm_models(self) -> None:
        """Перепроверить ВСЕ модели CONFIRMED-ключей на доступ"""
        self._run_bg_task("confirm_models")

    @on(Button.Pressed, "#s_drain_unverified")
    def _b_drain_unverified(self) -> None:
        """Фоновый дрейн UNVERIFIED ключей через реальную генерацию"""
        if self._is_draining():
            self._slog(f"[dim]{self.tr('log_drain_already')}[/]")
            return
        self._run_bg_task("drain_unverified")

    def _run_bg_task(self, task_type: str) -> None:
        """Start a background revalidation task; show in Tasks panel."""
        import threading
        import time as _t
        label_keys = {
            "full_revalidate": "task_full_revalidate",
            "failed_revalidate": "task_failed_revalidate",
            "confirm_all": "task_confirm_all",
            "drain_unverified": "task_drain_unverified",
            "confirm_models": "task_confirm_models",
        }
        label = self.tr(label_keys.get(task_type, task_type))
        if label == label_keys.get(task_type, task_type):
            label = task_type
        self._active_tasks[task_type] = {
            "label": label, "start": _t.time(), "done": 0, "total": 0}
        self._slog(f"[yellow]{self.trf('task_started', label=label)}[/]")
        self._refresh_all()

        def _worker():
            import asyncio as _aio
            try:
                from revalidate_all import revalidate_all
                from database import Database
                db = Database(DB)

                if task_type == "full_revalidate":
                    _aio.run(revalidate_all(db, limit=0, workers=40,
                                            task_type="full_revalidate"))
                elif task_type == "failed_revalidate":
                    _aio.run(revalidate_all(db, limit=0, workers=40,
                                            task_type="failed_revalidate"))
                elif task_type == "confirm_all":
                    _aio.run(self._confirm_all_bg(db))
                elif task_type == "drain_unverified":
                    from unverified_drainer import drain_unverified
                    _aio.run(drain_unverified(db, limit=0, workers=8,
                                              max_attempts=7, batch_size=100))
                elif task_type == "confirm_models":
                    result = _aio.run(_recheck_confirmed_keys(db))
                    self.call_after_refresh(self._slog, result)

                msg = f"[green]{self.trf('task_done', label=label)}[/]"
                self.call_after_refresh(self._slog, msg)
            except Exception as e:
                self.call_after_refresh(
                    self._slog, f"[red]{self.trf('task_error', err=e)}[/]")
            finally:
                def _unreg():
                    self._active_tasks.pop(task_type, None)
                    self._refresh_all()
                self.call_after_refresh(_unreg)

        t = threading.Thread(target=_worker, daemon=True)
        if task_type == "drain_unverified":
            self._drain_thread = t
        t.start()

    async def _confirm_all_bg(self, db) -> None:
        """Подтвердить все VALID ключи (без полной перепроверки)."""
        import asyncio
        from validator import AsyncValidator, KeyStatus
        from types import SimpleNamespace
        validator = AsyncValidator(db)
        validator._circuit_breaker.reset()

        confirm_platforms = {
            'openai', 'relay', 'xai', 'openrouter', 'cerebras', 'groq',
            'deepseek', 'perplexity', 'together', 'mistral', 'fireworks',
            'moonshot', 'siliconflow', 'dashscope', 'anthropic',
            'gemini', 'huggingface', 'replicate', 'cohere', 'anyscale',
            'lepton', 'jina', 'voyage', 'zhipu', 'yi', 'baichuan',
            'stepfun', 'minimax', 'internlm', 'volcengine',
        }

        # VALID ключи, не CONFIRMED. Явное действие пользователя (кнопка) -
        # перепроверяем ВСЕ valid (без порога attempts, который блокировал
        # ключи после нескольких неудачных confirm - они все на attempts=10).
        keys = _db(
            "SELECT * FROM leaked_keys WHERE status='valid' "
            "ORDER BY id"
        )
        if not keys:
            self._slog(f"[dim]{self.tr('log_no_valid_confirm')}[/]")
            return

        # Подгрузить модели ключей из key_models (confirm_key переберёт реальные
        # модели вместо дефолтных 2-3). Берём все модели ключа (вкл.
        # неподтверждённые) - confirm_key сам определит рабочие.
        try:
            models_map = {}
            with _conn() as c:
                for r in c.execute(
                    "SELECT key_id, model_name FROM key_models"
                ):
                    # мапа key_id -> [models]
                    models_map.setdefault(r["key_id"], []).append(
                        r["model_name"])
        except Exception:
            models_map = {}

        self._slog(f"[white]{self.trf('log_confirm_start', n=len(keys))}[/]")
        sem = asyncio.Semaphore(30)
        confirmed = 0
        done_cnt = 0
        _set_task_progress("confirm_all", 0, len(keys))

        async def confirm_one(key):
            nonlocal confirmed, done_cnt
            async with sem:
                if key["platform"].lower() not in confirm_platforms:
                    done_cnt += 1
                    _set_task_progress("confirm_all", done_cnt, len(keys))
                    return
                result = SimpleNamespace(
                    platform=key["platform"], api_key=key["api_key"],
                    base_url=key["base_url"], source_url="",
                    is_azure=(key["platform"] == "azure"),
                )
                try:
                    models = models_map.get(key["id"])
                    vr = await validator.confirm_key(
                        key["api_key"], key["base_url"], models,
                        platform=key.get("platform", ""))
                    if vr.status.name == "VALID" and "Подтверждён" in vr.info:
                        db.update_key_status(
                            key["api_key"], KeyStatus.CONFIRMED,
                            balance=vr.info or "", model_tier=vr.model_tier,
                            rpm=vr.rpm, is_high_value=vr.is_high_value)
                        confirmed += 1
                except Exception:
                    pass
                finally:
                    done_cnt += 1
                    _set_task_progress("confirm_all", done_cnt, len(keys))

        try:
            tasks = [confirm_one(k) for k in keys]
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            _clear_task_progress("confirm_all")
            try:
                await validator.close()
            except Exception:
                pass
        self._slog(f"[green]{self.trf('log_confirm_done', n=confirmed, total=len(keys))}[/]")

    @on(Button.Pressed, "#s_txt")
    def _b_txt(self) -> None:
        self._export(("confirmed", "valid", "quota_exceeded"), "txt")

    @on(Button.Pressed, "#s_csv")
    def _b_csv(self) -> None:
        self._export(("confirmed", "valid", "quota_exceeded"), "csv")

    @on(Button.Pressed, "#s_json")
    def _b_json(self) -> None:
        self._export(None, "json")

    @on(Button.Pressed, "#s_models_export")
    def _b_models_export(self) -> None:
        """Экспорт подтверждённых моделей с ключами и эндпоинтами."""
        import json
        models = _db(
            "SELECT km.model_name, km.is_confirmed, "
            "  lk.base_url, lk.api_key, lk.platform, lk.status "
            "FROM key_models km "
            "JOIN leaked_keys lk ON lk.id = km.key_id "
            "WHERE km.is_confirmed = 1 "
            "AND lk.status IN ('valid','confirmed') "
            "ORDER BY km.model_name")
        if not models:
            self._slog(f"[yellow]{self.tr('log_no_models_export')}[/]")
            return
        # Группировать по model_name
        grouped: Dict[str, list] = {}
        for m in models:
            name = m.get("model_name", "")
            grouped.setdefault(name, []).append({
                "endpoint": m.get("base_url", ""),
                "key": m.get("api_key", ""),
                "platform": m.get("platform", ""),
                "status": m.get("status", ""),
            })
        path = os.path.join(BASE_DIR, "exported_models.json")
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(grouped, f, ensure_ascii=False, indent=2)
        except OSError as e:
            self._slog(f"[red]{self.trf('task_error', err=e)}[/]")
            return
        self._slog(f"[green]{self.trf('log_export_models', n=len(grouped), path=os.path.basename(path))}[/]")

    def _export(self, statuses: Optional[Tuple[str, ...]], fmt: str) -> None:
        if statuses:
            ph = ",".join("?" for _ in statuses)
            rows = _db(f"SELECT * FROM leaked_keys "
                       f"WHERE status IN ({ph}) ORDER BY found_time DESC",
                       statuses)
        else:
            rows = _db("SELECT * FROM leaked_keys ORDER BY found_time DESC")
        if not rows:
            self._slog(f"[yellow]{self.tr('log_no_keys_export')}[/]")
            return
        path = os.path.join(BASE_DIR, f"exported_keys.{fmt}")
        try:
            if fmt == "txt":
                with open(path, "w", encoding="utf-8") as f:
                    for k in rows:
                        f.write(f"{k['platform']}|{k['api_key']}|"
                                f"{k.get('base_url','')}|{k['status']}|"
                                f"{k.get('balance','')}\n")
            elif fmt == "csv":
                cols = ["platform", "api_key", "status", "balance",
                        "base_url", "source_url", "model_tier", "rpm",
                        "is_high_value", "found_time", "verified_time"]
                with open(path, "w", encoding="utf-8", newline="") as f:
                    w = csv.DictWriter(f, fieldnames=cols)
                    w.writeheader()
                    for k in rows:
                        w.writerow({c: k.get(c, "") for c in cols})
            elif fmt == "json":
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(rows, f, ensure_ascii=False, indent=2,
                              default=str)
        except OSError as e:
            self._slog(f"[red]{self.trf('log_export_err', err=e)}[/]")
            return
        self._slog(f"[green]{self.trf('log_export_ok', fmt=fmt.upper(), n=len(rows), path=os.path.basename(path))}[/]")

    # -------------------------- события: логи ---------------------------

    @on(Button.Pressed, "#l_load")
    def _b_lload(self) -> None:
        self._reload_logs()

    @on(Button.Pressed, "#l_clear")
    def _b_lclear(self) -> None:
        self.query_one("#mlog", RichLog).clear()
        if os.path.exists(LOG):
            self._log_pos = os.path.getsize(LOG)
        else:
            self._log_pos = 0

    @on(Button.Pressed, "#l_autoscroll")
    def _b_lauto(self) -> None:
        self._autoscroll = not self._autoscroll
        btn = self.query_one("#l_autoscroll", Button)
        btn.label = "Autoscroll: ON" if self._autoscroll else "Autoscroll: OFF"
        btn.variant = "warning" if self._autoscroll else "default"

    @on(Button.Pressed, "#l_copy")
    def _b_lcopy(self) -> None:
        """Скопировать лог в буфер обмена (без Rich markup)."""
        try:
            lines = _log_lines(100)
            text = "\n".join(lines)
            import re as _re
            # Убрать Rich markup [green]...[/] и т.п.
            text = _re.sub(r'\[/?\w+\]', '', text)
            if text.strip():
                self.copy_to_clipboard(text)
                self._slog(f"[green]{self.tr('log_log_copied')}[/]")
            else:
                self._slog(f"[dim]{self.tr('log_log_empty')}[/]")
        except Exception as e:
            self._slog(f"[red]{self.trf('log_copy_err', err=e)}[/]")


def _kill_stale_tui_processes() -> int:
    """Завершить старые копии TUI перед запуском новой.

    БЕЗОПАСНО: не трогает саму себя и своих потомков (сканер, запущенный
    этой TUI как subprocess). Убивает только процессы, стартовавшие РАНЬШЕ
    текущей TUI (по create_time) — т.е. реально «старые» копии.
    """
    try:
        import psutil
    except Exception:
        return 0
    my_pid = os.getpid()
    try:
        me = psutil.Process(my_pid)
        my_create = me.create_time()
        my_children = {c.pid for c in me.children()}
    except Exception:
        my_create = None
        my_children = set()
    killed = 0
    markers = ("tui_app.py",)
    for proc in psutil.process_iter(["pid", "name", "cmdline", "create_time", "ppid"]):
        try:
            info = proc.info
            name = (info.get("name") or "").lower()
            if name not in ("python.exe", "pythonw.exe", "python", "pythonw"):
                continue
            cmd = " ".join(info.get("cmdline") or [])
        except Exception:
            continue
        low = cmd.lower()
        if "tui_app.py" not in low:
            continue
        pid = info.get("pid")
        if pid is None or pid == my_pid:
            continue
        # Не убиваем своего потомка (сканер-subprocess этой TUI).
        if pid in my_children:
            continue
        # Не убиваем процесс, стартовавший позже/одновременно с нами.
        if my_create is not None:
            try:
                if info.get("create_time", 0) >= my_create:
                    continue
            except Exception:
                pass
        try:
            proc.kill()
            killed += 1
        except Exception:
            pass
    return killed


def run_tui() -> None:
    # Завершить старые копии TUI/сканера, чтобы не дублировались процессы.
    try:
        n = _kill_stale_tui_processes()
        if n:
            print(_tf("log_stale_killed", None, n=n))
    except Exception:
        pass
    # Логирование: убрать дефолтный loguru stderr-sink (иначе логи дрейна/
    # validator'а, запускаемых в потоках TUI, пишутся ПОВЕРХ TUI в терминал).
    # Оставить только file-sink в scanner.log (живой лог TUI читает оттуда).
    try:
        from loguru import logger
        logger.remove()  # убрать дефолтный stderr-sink
        logger.add(LOG, level="INFO",
                   format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}",
                   rotation="10 MB", retention="3 days",
                   enqueue=True, backtrace=False, diagnose=False)
    except Exception:
        pass
    app = ScannerTUI()
    try:
        app.run()
    except KeyboardInterrupt:
        # Ctrl+C: чистый выход - убить сканер-субпроцесс (иначе зомби со спамом).
        try:
            app._kill_scanner_tree()
        except Exception:
            pass
        try:
            app._kill_zombie_processes()
        except Exception:
            pass


if __name__ == "__main__":
    run_tui()
