"""CLI / entry-point tests: ascan, main_optimized, revalidate_all,
unverified_drainer, ui.Dashboard.

Правила:
- никакой сети: все валидаторы/сессии — фейки;
- БД только во временном каталоге (никогда leaked_keys.db);
- потоки не запускаются: start_* в main_optimized подменены рекордерами;
- сигналы не трогаются (signal.signal подменён), loguru-синк в scanner.log
  снят, чтобы прогон не писал в файл проекта.
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import csv
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import types
from pathlib import Path
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import ascan  # noqa: E402
import revalidate_all  # noqa: E402
import unverified_drainer  # noqa: E402
import ui  # noqa: E402
import validator as validator_module  # noqa: E402
import main_optimized  # noqa: E402  (последним: он делает logger.remove())
from config import config  # noqa: E402
from database import Database, KeyStatus, LeakedKey  # noqa: E402
from validator import ValidationResult  # noqa: E402

MAIN_STARTERS = (
    "start_scanner",
    "start_validators",
    "start_pastebin_scanner",
    "start_paster_scanner",
    "start_gist_scanner",
    "start_gitlab_scanner",
    "start_realtime_scanner",
    "start_mcp_scanner",
    "start_codegraph_scanner",
)


def _drop_scanner_log_sinks() -> None:
    """Снять loguru-синки, пишущие в scanner.log проекта.

    main_optimized при импорте добавляет FileSink на scanner.log и loguru
    пишет туда каждую строку — тесты не должны трогать файл в репозитории.
    """
    from loguru import logger

    target = os.path.abspath(os.path.join(str(PROJECT_ROOT), "scanner.log"))
    for handler_id, handler in list(logger._core.handlers.items()):
        sink = handler._sink
        path = getattr(sink, "_path", None) or getattr(sink, "_file", None)
        if path and os.path.abspath(str(path)) == target:
            logger.remove(handler_id)


_drop_scanner_log_sinks()


# ===========================================================================
#                            Общие фейки / хелперы
# ===========================================================================

class FakeThread:
    def __init__(self, alive: bool = False):
        self.alive = alive
        self.joins: list = []

    def is_alive(self) -> bool:
        return self.alive

    def join(self, timeout=None):
        self.joins.append(timeout)
        self.alive = False


class FakeDashboard:
    instances: list = []

    def __init__(self, *a, **kw):
        self.logs: list = []
        self.stats_updates: list = []
        self.started = 0
        self.stopped = 0
        FakeDashboard.instances.append(self)

    def add_log(self, message, level="INFO"):
        self.logs.append((level, message))

    def update_stats(self, **kwargs):
        self.stats_updates.append(kwargs)

    @contextlib.contextmanager
    def start(self):
        self.started += 1
        try:
            yield self
        finally:
            self.stop()

    def stop(self):
        self.stopped += 1


class FakeDB:
    def __init__(self, path):
        self.path = path
        self.source_progress: list = []
        self.closed = 0

    def upsert_source_progress(self, source, **kwargs):
        self.source_progress.append((source, kwargs))

    def get_stats(self):
        return {"total": 0, "statuses": {}}

    def get_scanned_blob_count(self):
        return 0

    def close(self):
        self.closed += 1


class FakeAsyncDB:
    instances: list = []

    def __init__(self, path):
        self.path = path
        self.inited = 0
        self.closed = 0
        FakeAsyncDB.instances.append(self)

    async def init(self):
        self.inited += 1

    async def close(self):
        self.closed += 1


class FakeCircuitBreaker:
    def __init__(self):
        self.resets = 0

    def reset(self):
        self.resets += 1


class RecordingLogger:
    """Замена loguru-logger внутри конкретного модуля."""

    def __init__(self):
        self.messages: list = []

    def _add(self, msg, *a, **k):
        self.messages.append(str(msg))

    info = debug = warning = error = success = _add

    def text(self) -> str:
        return "\n".join(self.messages)


@pytest.fixture
def db(tmp_path):
    database = Database(str(tmp_path / "scan.db"))
    try:
        yield database
    finally:
        database.close()


def _insert_key(db, *, platform="openai", api_key="sk-test",
                base_url="https://relay.example.com/v1",
                status="unverified", attempts=0):
    with db._lock, db._get_connection() as conn:
        conn.execute(
            "INSERT INTO leaked_keys "
            "(platform, api_key, base_url, status, found_time, confirm_attempts) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (platform, api_key, base_url, status, "2026-01-01T00:00:00", attempts),
        )
        conn.commit()


def _fetchall(db, sql, params=()):
    with db._lock, db._get_connection() as conn:
        return conn.execute(sql, params).fetchall()


def _key_row(db, api_key):
    rows = _fetchall(db, "SELECT * FROM leaked_keys WHERE api_key = ?", (api_key,))
    assert len(rows) == 1
    return dict(rows[0])


def _models_of(db, api_key):
    rows = _fetchall(
        db,
        "SELECT km.model_name FROM key_models km "
        "JOIN leaked_keys lk ON lk.id = km.key_id WHERE lk.api_key = ?",
        (api_key,),
    )
    return sorted(r[0] for r in rows)


@pytest.fixture
def fake_tui(monkeypatch):
    """Подменить tui_app: прогресс-хуки ревалидации/дрейна + run_tui."""
    module = types.ModuleType("tui_app")
    calls: list = []
    module._set_task_progress = lambda *a: calls.append(("set",) + a)
    module._clear_task_progress = lambda *a: calls.append(("clear",) + a)
    module.run_tui = lambda *a, **k: calls.append(("run_tui",))
    monkeypatch.setitem(sys.modules, "tui_app", module)
    return calls


# ===========================================================================
#                              A. ascan.py
# ===========================================================================

def _ok(stdout: str = "", stderr: str = ""):
    return SimpleNamespace(returncode=0, stdout=stdout, stderr=stderr)


def _fail(stderr: str = "boom", returncode: int = 1):
    return SimpleNamespace(returncode=returncode, stdout="", stderr=stderr)


class FakeSubprocess:
    """subprocess.run-заменитель: очередь результатов (или исключений)."""

    def __init__(self, results):
        self.results = list(results)
        self.calls: list = []

    def run(self, cmd, **kwargs):
        self.calls.append((list(cmd), dict(kwargs)))
        result = self.results.pop(0) if self.results else _ok()
        if isinstance(result, BaseException):
            raise result
        return result


def _use_subprocess(monkeypatch, results) -> FakeSubprocess:
    fake = FakeSubprocess(results)
    monkeypatch.setattr(ascan, "subprocess", SimpleNamespace(run=fake.run))
    return fake


def _fake_execv(monkeypatch):
    calls: list = []

    def execv(executable, args):
        calls.append((executable, list(args)))
        return None

    monkeypatch.setattr(os, "execv", execv)
    return calls


def test_ascan_run_git_returns_error_on_exception(monkeypatch):
    _use_subprocess(monkeypatch, [subprocess.TimeoutExpired("git", 60)])

    code, out, err = ascan._run_git("pull")

    assert (code, out) == (1, "")
    assert "timed out" in err.lower()


def test_ascan_run_git_passes_cwd_and_timeout(monkeypatch):
    fake = _use_subprocess(monkeypatch, [_ok("true\n")])

    assert ascan._run_git("rev-parse", "--is-inside-work-tree") == (0, "true", "")
    cmd, kwargs = fake.calls[0]
    assert cmd[:2] == ["git", "rev-parse"]
    assert kwargs["cwd"] == ascan.BASE_DIR
    assert kwargs["timeout"] == 60


def test_ascan_upgrade_not_a_git_checkout(monkeypatch, capsys):
    fake = _use_subprocess(monkeypatch, [_fail("fatal: not a git repository")])

    assert ascan.main(["upgrade"]) == 1

    assert len(fake.calls) == 1  # дальше git не дёргаем
    assert "not a git checkout" in capsys.readouterr().out


def test_ascan_upgrade_already_up_to_date(monkeypatch, capsys):
    fake = _use_subprocess(
        monkeypatch, [_ok("true"), _ok(), _ok("abc123"), _ok("abc123")]
    )

    assert ascan.main(["upgrade"]) == 0

    assert [c[0] for c in fake.calls] == [
        ["git", "rev-parse", "--is-inside-work-tree"],
        ["git", "fetch", "origin"],
        ["git", "rev-parse", "HEAD"],
        ["git", "rev-parse", "@{u}"],
    ]
    out = capsys.readouterr().out
    assert "already up to date" in out
    assert "[OK]" in out


def test_ascan_upgrade_stashes_dirty_tree_then_pulls(monkeypatch, capsys):
    fake = _use_subprocess(
        monkeypatch,
        [
            _ok("true"),          # is-inside-work-tree
            _ok(),                # fetch
            _ok("aaaa"),          # HEAD
            _ok("bbbb"),          # @{u}
            _ok(" M config.py"),  # status --porcelain
            _ok(""),              # stash push
            _ok("Fast-forward"),  # pull
        ],
    )

    assert ascan.main(["upgrade"]) == 0

    commands = [c[0] for c in fake.calls]
    assert ["git", "stash", "push", "-m", "ascan-upgrade-autostash"] in commands
    assert ["git", "pull", "--ff-only"] in commands
    out = capsys.readouterr().out
    assert "local modifications present" in out
    assert "upgraded" in out


def test_ascan_upgrade_clean_tree_skips_stash(monkeypatch):
    fake = _use_subprocess(
        monkeypatch,
        [_ok("true"), _ok(), _ok("aaaa"), _ok("bbbb"), _ok(""), _ok("done")],
    )

    assert ascan.main(["upgrade"]) == 0

    commands = [c[0] for c in fake.calls]
    assert not any("stash" in " ".join(c) for c in commands)
    assert commands[-1] == ["git", "pull", "--ff-only"]


def test_ascan_upgrade_unresolvable_revisions(monkeypatch, capsys):
    _use_subprocess(
        monkeypatch, [_ok("true"), _ok(), _fail("bad revision"), _fail()]
    )

    assert ascan.main(["upgrade"]) == 1
    assert "cannot resolve revisions" in capsys.readouterr().out


def test_ascan_upgrade_pull_failure_is_reported(monkeypatch, capsys):
    _use_subprocess(
        monkeypatch,
        [_ok("true"), _ok(), _ok("aaaa"), _ok("bbbb"), _ok(""), _fail("diverged")],
    )

    assert ascan.main(["upgrade"]) == 1
    assert "pull failed" in capsys.readouterr().out


def test_ascan_upgrade_stash_failure_is_reported(monkeypatch, capsys):
    _use_subprocess(
        monkeypatch,
        [
            _ok("true"), _ok(), _ok("aaaa"), _ok("bbbb"),
            _ok("M x.py"), _fail("stash exploded"),
        ],
    )

    assert ascan.main(["upgrade"]) == 1
    assert "stash failed" in capsys.readouterr().out


def test_ascan_version_prints_rev_and_tip(monkeypatch, capsys):
    _use_subprocess(monkeypatch, [_ok("v2.3.0-4-gabc123\n"), _ok("abc123 init")])

    assert ascan.main(["version"]) == 0

    out = capsys.readouterr().out
    assert "ascan @" in out
    assert "rev: v2.3.0-4-gabc123" in out
    assert "tip: abc123 init" in out


def test_ascan_version_survives_git_errors(monkeypatch, capsys):
    _use_subprocess(monkeypatch, [_fail("no tags"), _fail("no repo")])

    assert ascan.main(["version"]) == 0

    out = capsys.readouterr().out
    assert "ascan @" in out
    assert "rev:" not in out and "tip:" not in out


@pytest.mark.parametrize("alias", ["version", "--version", "-V"])
def test_ascan_version_aliases(monkeypatch, alias):
    _use_subprocess(monkeypatch, [_ok("v1"), _ok("tip")])
    assert ascan.main([alias]) == 0


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--stats"],
        ["--all-sources", "--gist"],
        ["--db", "C:/tmp/x.db", "--stats"],
        ["--tui"],
    ],
)
def test_ascan_default_dispatch_execs_main(monkeypatch, argv):
    execs = _fake_execv(monkeypatch)

    assert ascan.main(list(argv)) is None

    assert execs == [(sys.executable, [sys.executable, ascan.MAIN, *argv])]
    assert ascan.MAIN.endswith("main_optimized.py")
    assert os.path.isfile(ascan.MAIN)


def test_ascan_stats_passthrough_keeps_tmp_db(monkeypatch, tmp_path):
    execs = _fake_execv(monkeypatch)
    db_path = str(tmp_path / "tmp-stats.db")

    ascan.main(["--stats", "--db", db_path])

    _, args = execs[0]
    assert args[-2:] == ["--db", db_path]
    assert "--stats" in args


def test_ascan_upgrade_does_not_exec(monkeypatch):
    execs = _fake_execv(monkeypatch)
    _use_subprocess(monkeypatch, [_fail()])

    assert ascan.main(["upgrade"]) == 1
    assert execs == []


# ===========================================================================
#                          B. main_optimized.py
# ===========================================================================

@pytest.fixture
def main_env(monkeypatch, tmp_path):
    """Изоляция main_optimized: БД, сигналы, дашборд, стартеры потоков."""
    monkeypatch.setattr(signal, "signal", lambda *a, **k: None)
    monkeypatch.setattr(main_optimized, "Database", FakeDB)
    monkeypatch.setattr(main_optimized, "Dashboard", FakeDashboard)
    monkeypatch.setattr(main_optimized, "AsyncDatabase", FakeAsyncDB)
    monkeypatch.setattr(main_optimized, "try_enable_uvloop", lambda: False)
    monkeypatch.setattr(config, "db_path", str(tmp_path / "main.db"))
    monkeypatch.setattr(config, "github_tokens", ["ghp_unit_test"])
    monkeypatch.setattr(config, "proxy_url", "")
    monkeypatch.setattr(config, "pastebin_api_key", "")

    FakeDashboard.instances.clear()
    FakeAsyncDB.instances.clear()

    started: dict = {}
    threads: dict = {}
    for name in MAIN_STARTERS:
        thread = ([FakeThread(alive=False)] if name == "start_validators"
                  else FakeThread(alive=False))
        threads[name] = thread

        def _starter(*args, _name=name, _thread=thread, **kwargs):
            started[_name] = {"args": args, "kwargs": kwargs}
            return _thread

        monkeypatch.setattr(main_optimized, name, _starter)

    return SimpleNamespace(started=started, threads=threads,
                           db_path=tmp_path / "main.db", tmp_path=tmp_path)


def _new_loop():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    return loop


def _dispose_loop(loop):
    if loop is not None and not loop.is_closed():
        loop.close()
    asyncio.set_event_loop(None)


# --- ConfigValidator / PerformanceMetrics ---

def test_config_validator_accepts_good_config(monkeypatch):
    monkeypatch.setattr(config, "github_tokens", ["ghp_x"])
    monkeypatch.setattr(config, "db_path", "leaked_keys.db")
    monkeypatch.setattr(config, "proxy_url", "socks5://127.0.0.1:1080")

    ok, errors = main_optimized.ConfigValidator.validate()

    assert ok is True
    assert errors == []


@pytest.mark.parametrize("proxy", ["http://p:1", "https://p:2", "socks5://p:3"])
def test_config_validator_proxy_schemes(monkeypatch, proxy):
    monkeypatch.setattr(config, "github_tokens", ["ghp_x"])
    monkeypatch.setattr(config, "db_path", "x.db")
    monkeypatch.setattr(config, "proxy_url", proxy)

    ok, errors = main_optimized.ConfigValidator.validate()
    assert ok is True and errors == []


def test_config_validator_reports_all_problems(monkeypatch):
    monkeypatch.setattr(config, "github_tokens", [])
    monkeypatch.setattr(config, "db_path", "")
    monkeypatch.setattr(config, "proxy_url", "ftp://bad-host:21")

    ok, errors = main_optimized.ConfigValidator.validate()

    assert ok is False
    assert len(errors) == 3
    assert all(isinstance(e, str) and e for e in errors)
    # Сообщение о прокси содержит сам URL (язык интерфейса не важен).
    assert any("ftp://bad-host:21" in e for e in errors)


def test_config_validator_github_tokens_counts(monkeypatch):
    monkeypatch.setattr(config, "github_tokens", ["a", "b", "c"])
    assert main_optimized.ConfigValidator.validate_github_tokens() == (3, 3)


def test_performance_metrics(monkeypatch):
    metrics = main_optimized.PerformanceMetrics()
    metrics.increment_found()
    metrics.increment_found()
    metrics.increment_valid()
    metrics.increment_invalid()
    metrics.increment_errors()

    stats = metrics.get_stats()

    assert stats["keys_found"] == 2
    assert stats["keys_valid"] == 1
    assert stats["keys_invalid"] == 1
    assert stats["scan_errors"] == 1
    assert stats["runtime_seconds"] >= 0
    assert stats["keys_per_minute"] >= 0

    # runtime == 0 не должен делить на ноль.
    frozen = main_optimized.PerformanceMetrics()
    frozen.start_time = 0
    monkeypatch.setattr(main_optimized, "time", SimpleNamespace(time=lambda: 0.0))
    assert frozen.get_stats()["keys_per_minute"] == 0


# --- orchestrator: инициализация ---

def test_orchestrator_init_mounts_state(main_env):
    scanner = main_optimized.OptimizedSecretScanner(
        enable_pastebin=True, enable_gist=True, enable_gitlab=True,
        enable_realtime=True, pastebin_api_key="PB-KEY",
        enable_paster=True, enable_mcp=True, enable_codegraph=True,
        enable_telegram=True, enable_huggingface=True, enable_search=True,
    )

    assert isinstance(scanner.stop_event, threading.Event)
    assert scanner.stop_event.is_set() is False
    assert isinstance(scanner.result_queue, queue.Queue)
    assert scanner.result_queue.maxsize == 10000
    assert scanner.async_db is None  # инициализируется только в start()
    assert isinstance(scanner.db, FakeDB)
    assert scanner.pastebin_api_key == "PB-KEY"
    for flag in ("enable_pastebin", "enable_paster", "enable_gist",
                 "enable_gitlab", "enable_realtime", "enable_mcp",
                 "enable_codegraph", "enable_telegram", "enable_huggingface",
                 "enable_search"):
        assert getattr(scanner, flag) is True
    assert scanner.validator_threads == []
    for attr in ("scanner_thread", "pastebin_thread", "paster_thread",
                 "gist_thread", "gitlab_thread", "realtime_thread",
                 "mcp_thread", "codegraph_thread", "telegram_thread",
                 "huggingface_thread", "search_thread"):
        assert getattr(scanner, attr) is None

    sources = [name for name, _ in scanner.db.source_progress]
    assert sources == ["github", "paster", "pastebin", "gist", "gitlab",
                       "realtime", "mcp", "codegraph", "telegram",
                       "huggingface", "search"]
    assert all(kw["status"] == "starting" for _, kw in scanner.db.source_progress)
    assert all(kw["phase"] == "startup" for _, kw in scanner.db.source_progress)


def test_orchestrator_disabled_sources_marked(main_env):
    scanner = main_optimized.OptimizedSecretScanner()

    by_source = dict(scanner.db.source_progress)
    assert by_source["github"]["status"] == "starting"
    for source in ("paster", "pastebin", "gist", "gitlab", "realtime",
                   "mcp", "codegraph"):
        assert by_source[source]["status"] == "disabled"
        assert by_source[source]["phase"] == "disabled"


def test_orchestrator_start_mounts_all_sources(main_env, monkeypatch):
    scanner = main_optimized.OptimizedSecretScanner(
        enable_pastebin=True, enable_paster=True, enable_gist=True,
        enable_gitlab=True, enable_realtime=True, enable_mcp=True,
        enable_codegraph=True, pastebin_api_key="PB-KEY",
    )
    # stop_event выставляем из «sleep» — цикл headless-сканера завершится.
    monkeypatch.setattr(
        main_optimized,
        "time",
        SimpleNamespace(sleep=lambda _s: scanner.stop_event.set(),
                        time=lambda: 0.0),
    )

    scanner.start()

    started = main_env.started
    assert started["start_scanner"]["args"] == (
        scanner.result_queue, scanner.db, scanner.stop_event)
    assert started["start_scanner"]["kwargs"]["dashboard"] is scanner.dashboard
    assert started["start_validators"]["args"] == (
        scanner.result_queue, scanner.db, scanner.stop_event)
    assert started["start_validators"]["kwargs"]["num_workers"] == 1

    for name in ("start_pastebin_scanner", "start_gist_scanner",
                 "start_gitlab_scanner", "start_realtime_scanner",
                 "start_mcp_scanner", "start_codegraph_scanner"):
        args = started[name]["args"]
        kwargs = started[name]["kwargs"]
        assert args[0] is scanner.result_queue
        assert args[1] is scanner.stop_event
        assert kwargs["db"] is scanner.db
        assert kwargs["dashboard"] is scanner.dashboard
    assert started["start_pastebin_scanner"]["kwargs"]["api_key"] == "PB-KEY"

    # paster принимает db позиционно (отличие от остальных источников)
    assert started["start_paster_scanner"]["args"] == (
        scanner.result_queue, scanner.db, scanner.stop_event)

    async_db = FakeAsyncDB.instances[-1]
    assert async_db.path == config.db_path
    assert async_db.inited == 1
    # start() вышел из цикла по внешнему stop_event: stop() внутри finally
    # видит уже установленное событие и штатно завершается рано (не закрывает
    # async_db) — это проверяется отдельным тестом ниже.

    assert scanner.stop_event.is_set() is True
    assert scanner.dashboard.started == 1
    assert scanner.dashboard.stopped >= 1
    assert any("queue_size" in update for update in scanner.dashboard.stats_updates)
    assert len(scanner.dashboard.logs) == 7  # по одному на включённый источник

    _dispose_loop(asyncio.get_event_loop())


def test_orchestrator_stop_closes_async_db_and_joins_threads(main_env):
    scanner = main_optimized.OptimizedSecretScanner()
    async_db = FakeAsyncDB("ignored")
    scanner.async_db = async_db

    names = ("scanner_thread", "pastebin_thread", "paster_thread",
             "gist_thread", "gitlab_thread", "realtime_thread",
             "mcp_thread", "telegram_thread", "huggingface_thread",
             "search_thread")
    alive_threads = []
    for name in names:
        thread = FakeThread(alive=True)
        setattr(scanner, name, thread)
        alive_threads.append(thread)
    alive_threads.extend([FakeThread(alive=True), FakeThread(alive=True)])
    scanner.validator_threads = alive_threads[-2:]
    dead = FakeThread(alive=False)
    scanner.codegraph_thread = dead  # мёртвый поток не джойним

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        scanner.stop()
        # Повторный stop() идемпотентен: ничего не закрывает второй раз.
        scanner.stop()
    finally:
        _dispose_loop(loop)

    assert scanner.stop_event.is_set() is True
    assert scanner.dashboard.stopped == 1
    assert async_db.closed == 1
    assert dead.joins == []
    for thread in alive_threads:
        assert thread.joins == [5]


def test_orchestrator_start_requires_valid_config(main_env, monkeypatch):
    monkeypatch.setattr(config, "github_tokens", [])
    scanner = main_optimized.OptimizedSecretScanner()

    with pytest.raises(SystemExit) as excinfo:
        scanner.start()

    assert excinfo.value.code == 1
    assert main_env.started == {}  # ни один источник не стартовал


def test_orchestrator_start_only_selected_sources(main_env, monkeypatch):
    scanner = main_optimized.OptimizedSecretScanner(enable_gist=True)
    monkeypatch.setattr(
        main_optimized,
        "time",
        SimpleNamespace(sleep=lambda _s: scanner.stop_event.set(),
                        time=lambda: 0.0),
    )

    scanner.start()

    assert "start_gist_scanner" in main_env.started
    for name in ("start_pastebin_scanner", "start_paster_scanner",
                 "start_gitlab_scanner", "start_realtime_scanner",
                 "start_mcp_scanner", "start_codegraph_scanner"):
        assert name not in main_env.started

    _dispose_loop(asyncio.get_event_loop())


# --- orchestrator: stop() без async_db ---

def test_stop_without_async_db_and_threads(main_env):
    scanner = main_optimized.OptimizedSecretScanner()

    loop = _new_loop()
    try:
        scanner.stop()
        assert scanner.stop_event.is_set() is True
        assert scanner.dashboard.stopped == 1
        assert scanner.async_db is None
    finally:
        _dispose_loop(loop)


def test_signal_handler_calls_stop(main_env):
    scanner = main_optimized.OptimizedSecretScanner()
    loop = _new_loop()
    try:
        scanner._signal_handler(signal.SIGINT, None)
        assert scanner.stop_event.is_set() is True
    finally:
        _dispose_loop(loop)


# --- argparse: дефолты и все флаги ---

@pytest.fixture
def parser_shim(monkeypatch):
    """Перехватить Namespace, который строит main()."""
    holder: dict = {}

    class RecordingParser(argparse.ArgumentParser):
        def parse_args(self, *a, **kw):
            ns = super().parse_args(*a, **kw)
            holder["ns"] = ns
            return ns

    monkeypatch.setattr(
        main_optimized,
        "argparse",
        SimpleNamespace(
            ArgumentParser=RecordingParser,
            RawDescriptionHelpFormatter=argparse.RawDescriptionHelpFormatter,
        ),
    )
    return holder


EXPECTED_DEFAULTS = {
    "export": None, "export_csv": None, "export_encrypted": None,
    "decrypt": None, "key_file": None, "status": None, "stats": False,
    "db": None, "proxy": None, "fresh": False, "reset_db": False,
    "tui": False, "revalidate": False, "pastebin": False, "paster": False,
    "pastebin_key": "", "gist": False, "gitlab": False, "realtime": False,
    "mcp": False, "codegraph": False, "all_sources": False,
}


def test_cli_defaults(parser_shim, fake_tui, main_env, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["main_optimized.py"])

    main_optimized.main()

    ns = parser_shim["ns"]
    for name, value in EXPECTED_DEFAULTS.items():
        assert getattr(ns, name) == value, name

    # Без headless-флагов запускается операторский TUI.
    assert fake_tui == [("run_tui",)]
    assert main_env.started == {}


def test_cli_parses_every_flag(parser_shim, fake_tui, main_env, monkeypatch,
                               tmp_path):
    db_path = str(tmp_path / "cli.db")
    argv = [
        "main_optimized.py",
        "--export", "e.txt", "--export-csv", "e.csv",
        "--export-encrypted", "e.enc", "--decrypt", "d.enc",
        "--key-file", "k.key", "--status", "valid", "--stats",
        "--db", db_path, "--proxy", "http://127.0.0.1:9",
        "--fresh", "--tui", "--revalidate",
        "--pastebin", "--paster", "--pastebin-key", "PBK",
        "--gist", "--gitlab", "--realtime", "--mcp", "--codegraph",
        "--all-sources",
    ]
    monkeypatch.setattr(sys, "argv", argv)

    main_optimized.main()

    ns = parser_shim["ns"]
    assert (ns.export, ns.export_csv, ns.export_encrypted) == (
        "e.txt", "e.csv", "e.enc")
    assert (ns.decrypt, ns.key_file, ns.status) == ("d.enc", "k.key", "valid")
    assert ns.stats is True
    assert ns.db == db_path
    assert ns.proxy == "http://127.0.0.1:9"
    for flag in ("fresh", "tui", "revalidate", "pastebin", "paster", "gist",
                 "gitlab", "realtime", "mcp", "codegraph", "all_sources"):
        assert getattr(ns, flag) is True, flag
    assert ns.pastebin_key == "PBK"
    # --tui обрабатывается раньше сканирования.
    assert fake_tui == [("run_tui",)]
    assert main_env.started == {}


def _scanner_recorder(monkeypatch):
    created: list = []

    class RecorderScanner:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self.started = 0
            created.append(self)

        def start(self):
            self.started += 1

    monkeypatch.setattr(main_optimized, "OptimizedSecretScanner", RecorderScanner)
    return created


def test_cli_all_sources_enables_every_source(main_env, monkeypatch):
    created = _scanner_recorder(monkeypatch)
    monkeypatch.setattr(config, "pastebin_api_key", "CFG-PB")
    monkeypatch.setattr(sys, "argv", ["main_optimized.py", "--all-sources"])

    main_optimized.main()

    kwargs = created[0].kwargs
    for name in ("enable_pastebin", "enable_paster", "enable_gist",
                 "enable_gitlab", "enable_realtime", "enable_mcp",
                 "enable_codegraph"):
        assert kwargs[name] is True, name
    # --pastebin-key не задан -> берём значение из config.
    assert kwargs["pastebin_api_key"] == "CFG-PB"
    assert created[0].started == 1


def test_cli_single_source_flag_does_not_enable_others(main_env, monkeypatch):
    created = _scanner_recorder(monkeypatch)
    monkeypatch.setattr(
        sys, "argv", ["main_optimized.py", "--gist", "--pastebin-key", "PK"])

    main_optimized.main()

    kwargs = created[0].kwargs
    assert kwargs["enable_gist"] is True
    assert kwargs["enable_pastebin"] is False
    assert kwargs["enable_paster"] is False
    assert kwargs["enable_gitlab"] is False
    assert kwargs["enable_realtime"] is False
    assert kwargs["enable_mcp"] is False
    assert kwargs["enable_codegraph"] is False
    assert kwargs["pastebin_api_key"] == "PK"


def test_cli_proxy_and_db_override_config(main_env, monkeypatch, tmp_path):
    _scanner_recorder(monkeypatch)
    db_path = str(tmp_path / "override.db")
    monkeypatch.setattr(sys, "argv", [
        "main_optimized.py", "--gist", "--db", db_path,
        "--proxy", "socks5://1.2.3.4:9050",
    ])

    main_optimized.main()

    assert config.db_path == db_path
    assert config.proxy_url == "socks5://1.2.3.4:9050"


def test_cli_fresh_clears_sha_cache(main_env, monkeypatch):
    real = Database(str(main_env.db_path))
    with real._lock, real._get_connection() as conn:
        conn.execute("INSERT INTO scanned_blobs (file_sha) VALUES ('deadbeef')")
        # scan_progress создаётся лениво (save_scan_progress) — на живой БД,
        # где скан уже запускался, таблица есть. Воспроизводим это состояние.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS scan_progress ("
            "id INTEGER PRIMARY KEY, current_index INTEGER, total INTEGER, "
            "is_completed BOOLEAN, update_time DATETIME)")
        conn.execute("INSERT OR REPLACE INTO scan_progress "
                     "(id, current_index, total, is_completed) "
                     "VALUES (1, 5, 10, 0)")
        conn.commit()
    real.close()
    created = _scanner_recorder(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["main_optimized.py", "--fresh", "--gist"])

    main_optimized.main()

    check = Database(str(main_env.db_path))
    try:
        assert _fetchall(check, "SELECT * FROM scanned_blobs") == []
        assert _fetchall(check, "SELECT * FROM scan_progress") == []
    finally:
        check.close()
    assert created[0].kwargs["enable_gist"] is True


def test_cli_reset_db_missing_file(main_env, monkeypatch, capsys):
    created = _scanner_recorder(monkeypatch)
    missing = str(main_env.tmp_path / "nope.db")
    monkeypatch.setattr(
        sys, "argv", ["main_optimized.py", "--reset-db", "--db", missing])

    main_optimized.main()

    assert "не найдена" in capsys.readouterr().out
    assert created == []  # сканер не стартует


def test_cli_decrypt_without_key_file_logs_error(main_env, monkeypatch):
    recorder = RecordingLogger()
    monkeypatch.setattr(main_optimized, "logger", recorder)
    monkeypatch.setattr(sys, "argv", ["main_optimized.py", "--decrypt", "x.enc"])

    main_optimized.main()

    assert "key-file" in recorder.text()


def test_cli_tui_flag_runs_tui(fake_tui, main_env, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["main_optimized.py", "--tui"])

    main_optimized.main()

    assert fake_tui == [("run_tui",)]


def test_cli_stats_route_uses_config_db(main_env, monkeypatch, tmp_path):
    seen: list = []
    monkeypatch.setattr(main_optimized, "show_stats", seen.append)
    db_path = str(tmp_path / "stats.db")
    monkeypatch.setattr(
        sys, "argv", ["main_optimized.py", "--stats", "--db", db_path])

    main_optimized.main()

    assert seen == [db_path]


def test_cli_revalidate_route(main_env, monkeypatch, capsys):
    calls: list = []

    class FakeValidator:
        def __init__(self, db, dashboard=None):
            calls.append(db)
            self.runs = 0

        async def revalidate_failed_keys(self):
            self.runs += 1
            return {"revalidated": 4, "valid": 2, "invalid": 1,
                    "quota": 1, "connection_error": 0, "unverified": 0}

    monkeypatch.setattr(validator_module, "AsyncValidator", FakeValidator)
    monkeypatch.setattr(sys, "argv", ["main_optimized.py", "--revalidate"])

    main_optimized.main()

    out = capsys.readouterr().out
    assert "Повторная проверка завершена" in out
    assert "Всего перепроверено: 4" in out
    assert "Валидных:            2" in out
    assert len(calls) == 1 and isinstance(calls[0], FakeDB)


# --- show_stats / export на временной БД ---

def _use_real_database(monkeypatch):
    """main_optimized.Database -> настоящий Database.

    Вызывать ВНУТРИ теста: main_env подменяет Database на FakeDB, и порядок
    фикстур (real_database раньше main_env) иначе вернул бы FakeDB.
    """
    monkeypatch.setattr(main_optimized, "Database", Database)


def test_show_stats_on_tmp_db(monkeypatch, db, capsys):
    _use_real_database(monkeypatch)
    _insert_key(db, api_key="sk-valid-1", status="valid")
    _insert_key(db, api_key="sk-invalid-1", status="invalid", platform="gemini")

    main_optimized.show_stats(str(db.db_path))

    out = capsys.readouterr().out
    assert "Всего ключей" in out
    assert "Действительные" in out
    assert "Распределение по платформам" in out


def test_cli_stats_runs_on_tmp_db(main_env, db, monkeypatch, capsys):
    _use_real_database(monkeypatch)
    _insert_key(db, api_key="sk-valid-2", status="valid")
    monkeypatch.setattr(
        sys, "argv", ["main_optimized.py", "--stats", "--db", str(db.db_path)])

    main_optimized.main()

    assert "Всего ключей" in capsys.readouterr().out


def test_export_txt_via_cli(main_env, db, monkeypatch, tmp_path):
    _use_real_database(monkeypatch)
    _insert_key(db, api_key="sk-export-me", status="valid",
                platform="openai", base_url="https://api.openai.com/v1")
    out_file = tmp_path / "keys.txt"
    monkeypatch.setattr(sys, "argv", [
        "main_optimized.py", "--export", str(out_file), "--db", str(db.db_path),
    ])

    main_optimized.main()

    text = out_file.read_text(encoding="utf-8")
    assert "Платформа: openai" in text
    assert "Ключ: sk-export-me" in text
    assert "Статус: valid" in text


def test_export_csv_via_cli(main_env, db, monkeypatch, tmp_path):
    _use_real_database(monkeypatch)
    _insert_key(db, api_key="sk-csv-me", status="valid")
    out_file = tmp_path / "keys.csv"
    monkeypatch.setattr(sys, "argv", [
        "main_optimized.py", "--export-csv", str(out_file),
        "--db", str(db.db_path),
    ])

    main_optimized.main()

    with out_file.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 1
    assert rows[0]["api_key"] == "sk-csv-me"
    assert rows[0]["status"] == "valid"
    assert rows[0]["is_high_value"] == "0"


def test_export_encrypted_roundtrip(main_env, db, monkeypatch, tmp_path):
    _use_real_database(monkeypatch)
    fernet_mod = pytest.importorskip("cryptography.fernet")
    _insert_key(db, api_key="sk-secret-me", status="valid")
    out_file = tmp_path / "keys.enc"
    monkeypatch.setattr(sys, "argv", [
        "main_optimized.py", "--export-encrypted", str(out_file),
        "--db", str(db.db_path),
    ])

    main_optimized.main()

    key_file = Path(str(out_file) + ".key")
    assert out_file.is_file() and key_file.is_file()

    cipher = fernet_mod.Fernet(key_file.read_bytes())
    payload = json.loads(cipher.decrypt(out_file.read_bytes()).decode())
    assert payload[0]["api_key"] == "sk-secret-me"
    assert payload[0]["platform"] == "openai"


def test_export_without_matching_keys_prints_notice(monkeypatch, db, capsys, tmp_path):
    _use_real_database(monkeypatch)
    _insert_key(db, api_key="sk-only-invalid", status="invalid")
    out_file = tmp_path / "none.txt"

    main_optimized.export_keys(str(db.db_path), str(out_file))

    assert not out_file.exists()
    assert "Нет ключей" in capsys.readouterr().out


# ===========================================================================
#                                 C. ui.py
# ===========================================================================

def test_dashboard_add_log_writes_ring_buffer_and_file(tmp_path):
    dashboard = ui.Dashboard()
    dashboard._log_path = str(tmp_path / "ui.log")

    dashboard.add_log("hello world", "INFO")

    assert len(dashboard.logs) == 1
    assert dashboard.logs[0].endswith("[INFO] hello world")
    text = (tmp_path / "ui.log").read_text(encoding="utf-8")
    assert "| INFO" in text and "hello world" in text


def test_dashboard_ring_buffer_is_bounded(tmp_path):
    dashboard = ui.Dashboard()
    dashboard._log_path = str(tmp_path / "ui.log")

    for index in range(dashboard.logs.maxlen + 20):
        dashboard.add_log(f"line {index}")

    assert len(dashboard.logs) == dashboard.logs.maxlen
    assert dashboard.logs[-1].endswith(f"line {dashboard.logs.maxlen + 19}")


def test_dashboard_add_log_swallows_os_error(tmp_path):
    dashboard = ui.Dashboard()
    dashboard._log_path = str(tmp_path / "missing-dir" / "ui.log")

    dashboard.add_log("still recorded")

    assert dashboard.logs  # запись в память осталась


def test_dashboard_add_valid_key_updates_stats(tmp_path):
    dashboard = ui.Dashboard()
    dashboard._log_path = str(tmp_path / "ui.log")
    before = dashboard.stats.valid_keys

    dashboard.add_valid_key("openai", "sk-ab...cdef", "$1.00", "github",
                            is_high_value=True)

    assert dashboard.stats.valid_keys == before + 1
    record = dashboard.valid_keys[-1]
    assert record.platform == "openai"
    assert record.masked_key == "sk-ab...cdef"
    assert record.is_high_value is True
    assert any("HIGH openai" in line for line in dashboard.logs)


def test_dashboard_update_stats_semantics(tmp_path):
    dashboard = ui.Dashboard()
    dashboard._log_path = str(tmp_path / "ui.log")

    dashboard.update_stats(total_scanned=5, current_token_index=3,
                           total_tokens=10, queue_size=7, is_running=True)
    assert dashboard.stats.total_scanned == 5
    # эти счётчики ПЕРЕЗАПИСЫВАЮТСЯ, а не накапливаются
    assert dashboard.stats.current_token_index == 3
    assert dashboard.stats.total_tokens == 10
    assert dashboard.stats.queue_size == 7
    assert dashboard.stats.is_running is True

    dashboard.update_stats(total_scanned=2)
    assert dashboard.stats.total_scanned == 7

    dashboard.update_stats(is_running=False)
    assert dashboard.stats.is_running is False

    dashboard.update_stats(unknown_field=123)
    assert not hasattr(dashboard.stats, "unknown_field")


def test_dashboard_increment_stat(tmp_path):
    dashboard = ui.Dashboard()
    dashboard._log_path = str(tmp_path / "ui.log")

    dashboard.increment_stat("skipped_blacklist", 3)
    assert dashboard.stats.skipped_blacklist == 3
    dashboard.increment_stat("unknown_stat")  # без падения
    assert not hasattr(dashboard.stats, "unknown_stat")


def test_dashboard_start_context_manager(tmp_path):
    dashboard = ui.Dashboard()
    dashboard._log_path = str(tmp_path / "ui.log")

    with dashboard.start() as inner:
        assert inner is dashboard
        assert dashboard.stats.is_running is True

    assert dashboard.stats.is_running is False
    assert any("Headless" in line for line in dashboard.logs)


def test_dashboard_echo_to_stderr(tmp_path, capsys):
    dashboard = ui.Dashboard(echo_stderr=True)
    dashboard._log_path = str(tmp_path / "ui.log")

    dashboard.add_log("loud message", "ERROR")

    assert "loud message" in capsys.readouterr().err
    assert "loud message" in (tmp_path / "ui.log").read_text(encoding="utf-8")


def test_dashboard_echo_from_env(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("SCANNER_ECHO", "1")
    dashboard = ui.Dashboard()
    dashboard._log_path = str(tmp_path / "ui.log")

    assert dashboard._echo is True
    dashboard.add_log("via env")
    assert "via env" in capsys.readouterr().err


def test_dashboard_refresh_and_stop(tmp_path):
    dashboard = ui.Dashboard()
    dashboard._log_path = str(tmp_path / "ui.log")
    assert dashboard.refresh() is None
    dashboard.stop()
    assert dashboard.stats.is_running is False


# ===========================================================================
#                            D. revalidate_all.py
# ===========================================================================

class FakeValidatorBase:
    """Общий фейк AsyncValidator (без сети)."""

    created: list = []
    single_default = None
    confirm_default = None
    gemini_default = None

    def __init__(self, db, dashboard=None):
        self.db = db
        self.dashboard = dashboard
        self._circuit_breaker = FakeCircuitBreaker()
        self.validate_calls: list = []
        self.confirm_calls: list = []
        self.gemini_calls: list = []
        self.closed = 0
        self.single = type(self).single_default
        self.confirm = type(self).confirm_default
        self.gemini = type(self).gemini_default
        type(self).created.append(self)

    async def validate_single(self, result):
        self.validate_calls.append((result.api_key, result.base_url))
        if self.single is None:
            raise AssertionError("fake validate_single not configured")
        return self.single(result)

    async def validate_gemini_deep(self, api_key, base_url, models):
        self.gemini_calls.append((api_key, base_url, list(models or [])))
        if self.gemini is None:
            raise AssertionError("fake validate_gemini_deep not configured")
        return self.gemini(api_key, base_url)

    async def confirm_key(self, api_key, base_url, models, platform=""):
        self.confirm_calls.append((api_key, base_url, list(models or []), platform))
        if self.confirm is None:
            return ValidationResult(KeyStatus.VALID, "ok")
        return self.confirm(api_key, base_url)

    async def close(self):
        self.closed += 1


@pytest.fixture
def fake_validator(monkeypatch):
    class FakeValidator(FakeValidatorBase):
        created: list = []
        single_default = None
        confirm_default = None
        gemini_default = None

    monkeypatch.setattr(revalidate_all, "AsyncValidator", FakeValidator)
    monkeypatch.setattr(unverified_drainer, "AsyncValidator", FakeValidator)
    return FakeValidator


def test_status_rank_ordering():
    ranks = {
        KeyStatus.CONFIRMED: 6,
        KeyStatus.VALID: 5,
        KeyStatus.QUOTA_EXCEEDED: 4,
        KeyStatus.UNVERIFIED: 3,
        KeyStatus.CONNECTION_ERROR: 2,
        KeyStatus.INVALID: 1,
        KeyStatus.PENDING: 0,
    }
    for status, expected in ranks.items():
        assert revalidate_all._status_rank(status) == expected
        assert unverified_drainer._status_rank(status) == expected
    assert revalidate_all._status_rank("not-a-status") == 0


def test_build_scan_result_fields():
    row = {
        "platform": "AzUrE", "api_key": "k1",
        "base_url": "https://x.openai.azure.com", "source_url": "https://gh/1",
    }
    result = revalidate_all._build_scan_result(row)
    assert result.platform == "AzUrE"
    assert result.api_key == "k1"
    assert result.base_url == "https://x.openai.azure.com"
    assert result.source_url == "https://gh/1"
    assert result.is_azure is True

    assert revalidate_all._build_scan_result({"platform": "openai"}).is_azure is False
    assert unverified_drainer._build_scan_result({"platform": "Azure"}).is_azure is True


def test_revalidate_empty_db_returns_early(fake_validator, db, monkeypatch):
    recorder = RecordingLogger()
    monkeypatch.setattr(revalidate_all, "logger", recorder)

    assert asyncio.run(revalidate_all.revalidate_all(db)) is None

    instance = fake_validator.created[0]
    assert instance.validate_calls == []
    assert instance._circuit_breaker.resets == 1
    assert "Ключей для перепроверки: 0" in recorder.text()


def test_revalidate_skips_invalid_keys(fake_validator, db):
    _insert_key(db, api_key="k-invalid", status="invalid")

    asyncio.run(revalidate_all.revalidate_all(db))

    assert fake_validator.created[0].validate_calls == []


def test_revalidate_limit(fake_validator, db):
    for index in range(5):
        _insert_key(db, api_key=f"k{index}",
                    base_url="https://relay.example.com/v1")
    fake_validator.single_default = staticmethod(
        lambda result: ValidationResult(KeyStatus.UNVERIFIED, "?"))

    asyncio.run(revalidate_all.revalidate_all(db, limit=2, workers=2))

    processed = [call[0] for call in fake_validator.created[0].validate_calls]
    assert processed == ["k0", "k1"]


def test_revalidate_writes_statuses(fake_validator, db):
    base = "https://relay.example.com/v1"
    for api_key in ("k-valid", "k-quota", "k-invalid", "k-conn"):
        _insert_key(db, api_key=api_key, base_url=base)

    scripted = {
        "k-valid": ValidationResult(KeyStatus.VALID, "", models=["m1"]),
        "k-quota": ValidationResult(KeyStatus.QUOTA_EXCEEDED, "Квота"),
        "k-invalid": ValidationResult(KeyStatus.INVALID, "отозван"),
        "k-conn": ValidationResult(KeyStatus.CONNECTION_ERROR, "таймаут"),
    }
    fake_validator.single_default = staticmethod(
        lambda result: scripted[result.api_key])

    asyncio.run(revalidate_all.revalidate_all(db, workers=2))

    row_valid = _key_row(db, "k-valid")
    assert row_valid["status"] == "valid"
    assert _models_of(db, "k-valid") == ["m1"]
    assert row_valid["verified_time"] is not None
    assert _key_row(db, "k-quota")["status"] == "quota_exceeded"
    assert _key_row(db, "k-invalid")["status"] == "invalid"
    assert _key_row(db, "k-conn")["status"] == "connection_error"


def test_revalidate_confirms_valid_keys(fake_validator, db):
    base = "https://relay.example.com/v1"
    _insert_key(db, api_key="k-confirm", base_url=base, status="valid")

    fake_validator.single_default = staticmethod(
        lambda result: ValidationResult(KeyStatus.VALID, "", models=["gpt-4o"]))
    fake_validator.confirm_default = staticmethod(
        lambda api_key, url: ValidationResult(KeyStatus.VALID, "Подтверждён 2+32"))

    asyncio.run(revalidate_all.revalidate_all(db))

    instance = fake_validator.created[0]
    assert instance.confirm_calls == [("k-confirm", base, ["gpt-4o"], "openai")]
    assert _key_row(db, "k-confirm")["status"] == "confirmed"


def test_revalidate_falls_back_to_original_url(fake_validator, db):
    from database import normalize_base_url

    original = "https://relay.example.com/v1/chat/completions"
    canonical = normalize_base_url(original)
    assert canonical != original  # предусловие теста
    _insert_key(db, api_key="k-fallback", base_url=original)

    def single(result):
        if result.base_url == canonical:
            return ValidationResult(KeyStatus.CONNECTION_ERROR, "canonical down")
        return ValidationResult(KeyStatus.VALID, "ok on original")

    fake_validator.single_default = staticmethod(single)

    asyncio.run(revalidate_all.revalidate_all(db))

    instance = fake_validator.created[0]
    assert [call[1] for call in instance.validate_calls] == [canonical, original]
    row = _key_row(db, "k-fallback")
    assert row["status"] == "valid"
    assert row["base_url"] == original


def test_revalidate_error_is_counted(fake_validator, db, monkeypatch):
    _insert_key(db, api_key="k-boom", base_url="https://relay.example.com/v1")

    def boom(result):
        raise RuntimeError("network exploded")

    fake_validator.single_default = staticmethod(boom)
    recorder = RecordingLogger()
    monkeypatch.setattr(revalidate_all, "logger", recorder)

    asyncio.run(revalidate_all.revalidate_all(db))

    assert _key_row(db, "k-boom")["status"] == "unverified"
    assert "error: 1" in recorder.text()


def test_revalidate_reports_progress_to_tui(fake_validator, db, fake_tui):
    for index in range(2):
        _insert_key(db, api_key=f"p{index}",
                    base_url="https://relay.example.com/v1")
    fake_validator.single_default = staticmethod(
        lambda result: ValidationResult(KeyStatus.UNVERIFIED, "?"))

    asyncio.run(revalidate_all.revalidate_all(db, task_type="full_revalidate"))

    assert fake_tui[0] == ("set", "full_revalidate", 0, 2)
    assert len([call for call in fake_tui if call[0] == "set"]) == 3  # init + 2
    assert fake_tui[-1] == ("clear", "full_revalidate")


def test_revalidate_splits_work_into_batches(fake_validator, db, fake_tui,
                                             monkeypatch):
    """25 ключей / 2 воркера -> 3 батча, каждый ключ обработан ровно один раз."""
    for index in range(25):
        _insert_key(db, api_key=f"b{index}", platform="custom")
    fake_validator.single_default = staticmethod(
        lambda result: ValidationResult(KeyStatus.VALID, ""))

    real_create_task = asyncio.create_task
    spawned: list = []

    def spy_create_task(coro, **kwargs):
        spawned.append(coro)
        return real_create_task(coro, **kwargs)

    monkeypatch.setattr(asyncio, "create_task", spy_create_task)

    asyncio.run(revalidate_all.revalidate_all(db, workers=2))

    assert len(spawned) == 3  # ceil(25 / (25 // 2))
    calls = fake_validator.created[0].validate_calls
    assert len(calls) == 25
    assert {call[0] for call in calls} == {f"b{i}" for i in range(25)}
    statuses = _fetchall(db, "SELECT status, COUNT(*) FROM leaked_keys "
                             "GROUP BY status")
    assert [tuple(row) for row in statuses] == [("valid", 25)]
    # Прогресс: начальный set(0) + 25 шагов, затем clear.
    sets = [c for c in fake_tui if c[0] == "set"]
    assert sets[0] == ("set", "full_revalidate", 0, 25)
    assert max(c[2] for c in sets) == 25
    assert fake_tui[-1] == ("clear", "full_revalidate")


def test_revalidate_main_cli_args(monkeypatch):
    captured: dict = {}

    async def fake_revalidate(db, limit=0, workers=40, task_type="full_revalidate"):
        captured.update(db=db, limit=limit, workers=workers, task_type=task_type)

    monkeypatch.setattr(revalidate_all, "revalidate_all", fake_revalidate)
    monkeypatch.setattr(revalidate_all, "Database", lambda path: ("db", path))

    monkeypatch.setattr(sys, "argv", ["revalidate_all.py", "--limit", "7",
                                      "--workers", "3"])
    revalidate_all.main()
    assert captured == {"db": ("db", config.db_path), "limit": 7, "workers": 3,
                        "task_type": "full_revalidate"}

    monkeypatch.setattr(sys, "argv", ["revalidate_all.py"])
    revalidate_all.main()
    assert captured["limit"] == 0 and captured["workers"] == 40


# ===========================================================================
#                          E. unverified_drainer.py
# ===========================================================================

@pytest.fixture
def drain_env(monkeypatch):
    monkeypatch.setattr(unverified_drainer, "_ENDPOINTS_CACHE", {})
    monkeypatch.setattr(unverified_drainer, "_ENDPOINTS_LOADED", False)
    monkeypatch.setattr(unverified_drainer, "_CANCEL_REQUESTED", False)
    monkeypatch.setattr(unverified_drainer, "CURRENT_PROGRESS",
                        {"done": 0, "total": 0})
    sleeps: list = []

    async def fast_sleep(delay, *a, **k):
        sleeps.append(delay)

    monkeypatch.setattr(unverified_drainer.asyncio, "sleep", fast_sleep)
    return SimpleNamespace(sleeps=sleeps)


def _drain_worker(db, rows, stats, *, max_attempts=5, validator=None):
    async def scenario():
        semaphore = asyncio.Semaphore(4)
        state = {"done": 0, "total": len(rows), "start": 0.0, "cancelled": False}
        await unverified_drainer._worker(
            validator, db, rows, stats, semaphore, state, max_attempts)

    asyncio.run(scenario())


def _empty_stats():
    return {"total": 0, "confirmed": 0, "valid": 0, "invalid": 0,
            "quota": 0, "connection_error": 0, "unverified": 0,
            "pending": 0, "error": 0}


def test_network_platforms_excludes_bulk_and_empty():
    platforms = unverified_drainer._network_platforms()

    assert platforms == sorted(platforms)
    assert {"openai", "gemini", "anthropic", "groq"} <= set(platforms)
    assert set(platforms) & unverified_drainer._BULK_UNVERIFIABLE == set()
    for name in platforms:
        assert config.default_base_urls[name]


def test_platforms_with_row_urls_unions_azure_and_skips_bulk(db):
    _insert_key(db, platform="azure", api_key="az-key-with-endpoint",
                base_url="https://team.openai.azure.com", status="unverified")
    _insert_key(db, platform="azure", api_key="az-key-no-endpoint",
                base_url="", status="unverified")
    _insert_key(db, platform="aws_access_key", api_key="A" * 40,
                base_url="https://aws.example.com", status="unverified")
    _insert_key(db, platform="relay", api_key="relay-valid",
                base_url="https://relay.example.com/v1", status="valid")

    assert unverified_drainer._platforms_with_row_urls(db) == ["azure"]


def test_drain_platforms_include_url_backed_platforms(db, monkeypatch):
    """azure (без дефолтного URL) попадает в выборку дрейна через base_url строки."""
    _insert_key(db, platform="azure", api_key="az-key",
                base_url="https://team.openai.azure.com", status="unverified")
    monkeypatch.setattr(unverified_drainer, "_ENDPOINTS_CACHE", {})
    monkeypatch.setattr(unverified_drainer, "_ENDPOINTS_LOADED", True)

    platforms = sorted(set(unverified_drainer._network_platforms())
                       | set(unverified_drainer._platforms_with_row_urls(db)))

    assert "azure" in platforms
    assert unverified_drainer._platforms_needing_row_url(platforms) == ["azure"]


def test_drain_selects_url_backed_platform_rows(
        fake_validator, db, drain_env, monkeypatch):
    """azure-строка с base_url проверяется, без base_url — не выбирается."""
    _insert_key(db, platform="azure", api_key="az-with-url",
                base_url="https://team.openai.azure.com", status="unverified")
    _insert_key(db, platform="azure", api_key="az-no-url",
                base_url="", status="unverified")
    _insert_key(db, platform="openai", api_key="sk-openai",
                base_url="", status="unverified")
    fake_validator.single_default = lambda result: ValidationResult(
        KeyStatus.VALID, "ok")

    stats = asyncio.run(unverified_drainer.drain_unverified(
        db, limit=0, workers=2, max_attempts=5, batch_size=50))

    validator = fake_validator.created[-1]
    assert {key for key, _ in validator.validate_calls} == {
        "az-with-url", "sk-openai"}
    assert stats["valid"] == 2


def test_counts_as_attempt_ignores_local_skips():
    local_skip = ValidationResult(KeyStatus.UNVERIFIED,
                                  "Astra: нет проверочного эндпоинта")
    no_url = ValidationResult(KeyStatus.UNVERIFIED, "Нет base_url")
    network = ValidationResult(KeyStatus.UNVERIFIED, "Все эндпоинты молчат")

    assert unverified_drainer._counts_as_attempt(local_skip) is False
    assert unverified_drainer._counts_as_attempt(no_url) is False
    assert unverified_drainer._counts_as_attempt(network) is True


def test_drain_local_skip_does_not_consume_attempts(fake_validator, db, drain_env):
    """Ключ без проверочного эндпоинта остаётся выбираемым: attempts не растут."""
    _insert_key(db, platform="astra", api_key="astra-local-skip",
                base_url="", status="unverified")
    fake_validator.single_default = lambda result: ValidationResult(
        KeyStatus.UNVERIFIED, "Astra: нет проверочного эндпоинта")

    stats = asyncio.run(unverified_drainer.drain_unverified(
        db, limit=0, workers=1, max_attempts=5, batch_size=10))

    row = _key_row(db, "astra-local-skip")
    assert row["status"] == "unverified"
    assert row["confirm_attempts"] == 0
    assert stats["unverified"] == 1


def test_drain_cancel_flag(monkeypatch):
    monkeypatch.setattr(unverified_drainer, "_CANCEL_REQUESTED", False)
    assert unverified_drainer.is_drain_cancelled() is False

    unverified_drainer.request_drain_cancel()

    assert unverified_drainer.is_drain_cancelled() is True


def test_has_log_sink_detects_unknown_path(tmp_path):
    assert unverified_drainer._has_log_sink(str(tmp_path / "no-such.log")) is False


def test_gemini_candidates_are_non_empty_strings():
    assert unverified_drainer.GEMINI_CANDIDATES
    assert all(isinstance(m, str) and m for m in unverified_drainer.GEMINI_CANDIDATES)


def test_validate_key_gemini_retries_quota(fake_validator, drain_env):
    validator = fake_validator(SimpleNamespace())
    validator.gemini = lambda api_key, base_url: ValidationResult(
        KeyStatus.QUOTA_EXCEEDED, "429")

    result, url = asyncio.run(unverified_drainer._validate_key(
        validator, {"platform": "gemini", "api_key": "AIza-x", "base_url": ""}))

    assert result.status == KeyStatus.QUOTA_EXCEEDED
    assert url == config.default_base_urls["gemini"]
    assert len(validator.gemini_calls) == 3
    assert drain_env.sleeps == [2.0, 4.0]


def test_validate_key_gemini_stops_on_non_quota(fake_validator, drain_env):
    validator = fake_validator(SimpleNamespace())
    validator.gemini = lambda api_key, base_url: ValidationResult(
        KeyStatus.VALID, "", models=["gemini-2.5-flash"])

    result, url = asyncio.run(unverified_drainer._validate_key(
        validator, {"platform": "gemini", "api_key": "AIza-y",
                    "base_url": "https://generativelanguage.googleapis.com/v1beta"}))

    assert result.status == KeyStatus.VALID
    assert url == "https://generativelanguage.googleapis.com/v1beta"
    assert len(validator.gemini_calls) == 1
    assert drain_env.sleeps == []


def test_validate_key_without_candidates(fake_validator, drain_env):
    validator = fake_validator(SimpleNamespace())

    result, url = asyncio.run(unverified_drainer._validate_key(
        validator, {"platform": "unknownplat", "api_key": "x", "base_url": ""}))

    assert result.status == KeyStatus.UNVERIFIED
    assert result.info == "Нет base_url"
    assert url == ""
    assert validator.validate_calls == []


def test_validate_key_invalid_auth_short_circuits(fake_validator, drain_env, monkeypatch):
    monkeypatch.setitem(unverified_drainer._ENDPOINTS_CACHE, "openai",
                        ["https://extra.example.com/v1"])
    validator = fake_validator(SimpleNamespace())
    validator.single = lambda result: ValidationResult(
        KeyStatus.INVALID, "401 unauthorized: api key not valid")

    result, url = asyncio.run(unverified_drainer._validate_key(
        validator, {"platform": "openai", "api_key": "k",
                    "base_url": "https://first.example.com/v1"}))

    assert result.status == KeyStatus.INVALID
    assert url == "https://first.example.com/v1"
    assert len(validator.validate_calls) == 1  # дальше эндпоинты не перебираем


def test_validate_key_quota_retry_finds_valid(fake_validator, drain_env):
    validator = fake_validator(SimpleNamespace())
    answers = iter([KeyStatus.QUOTA_EXCEEDED, KeyStatus.VALID])
    validator.single = lambda result: ValidationResult(next(answers), "s")

    result, _url = asyncio.run(unverified_drainer._validate_key(
        validator, {"platform": "openai", "api_key": "k", "base_url": ""}))

    assert result.status == KeyStatus.VALID
    assert len(validator.validate_calls) == 2
    assert drain_env.sleeps == [2.0]


def test_validate_key_quota_terminal_after_retries(fake_validator, drain_env):
    validator = fake_validator(SimpleNamespace())
    validator.single = lambda result: ValidationResult(
        KeyStatus.QUOTA_EXCEEDED, "quota")

    result, _url = asyncio.run(unverified_drainer._validate_key(
        validator, {"platform": "openai", "api_key": "k", "base_url": ""}))

    assert result.status == KeyStatus.QUOTA_EXCEEDED
    assert len(validator.validate_calls) == 3  # 1 + 2 ретрая
    assert drain_env.sleeps == [2.0, 4.0]


def test_validate_key_best_effort_keeps_first_endpoint(fake_validator, drain_env,
                                                      monkeypatch):
    """Перебор кандидатов: base_url -> дефолт платформы -> кэш эндпоинтов.

    best_vr обновляется только при СТРОГО лучшем ранге, поэтому при равных
    рангах (CONNECTION_ERROR на всех) остаётся первый кандидат.
    """
    monkeypatch.setitem(unverified_drainer._ENDPOINTS_CACHE, "openai",
                        ["https://extra.example.com/v1"])
    validator = fake_validator(SimpleNamespace())
    validator.single = lambda result: ValidationResult(
        KeyStatus.CONNECTION_ERROR, "down")

    result, url = asyncio.run(unverified_drainer._validate_key(
        validator, {"platform": "openai", "api_key": "k",
                    "base_url": "https://first.example.com/v1"}))

    assert result.status == KeyStatus.CONNECTION_ERROR
    assert [call[1] for call in validator.validate_calls] == [
        "https://first.example.com/v1",
        config.default_base_urls["openai"],
        "https://extra.example.com/v1",
    ]
    assert url == "https://first.example.com/v1"


def test_load_known_endpoints(db, drain_env):
    _insert_key(db, api_key="ok-1", status="confirmed",
                base_url="https://known.example.com/v1")

    unverified_drainer._load_known_endpoints(db)

    cache = unverified_drainer._ENDPOINTS_CACHE
    assert unverified_drainer._ENDPOINTS_LOADED is True
    assert "https://known.example.com/v1" in cache["openai"]
    assert config.default_base_urls["openai"] in cache["openai"]
    for urls in cache.values():
        assert len(urls) == len(set(urls))  # без дублей


def test_drain_unverified_end_to_end(fake_validator, db, drain_env):
    base = "https://relay.example.com/v1"
    _insert_key(db, api_key="d-valid", base_url=base)
    _insert_key(db, api_key="d-quota", base_url=base)
    _insert_key(db, api_key="d-unver", base_url=base)
    _insert_key(db, api_key="aws-secret", platform="aws_secret_key", base_url="")
    _insert_key(db, api_key="d-invalid", base_url=base, status="invalid")

    answers = {
        "d-valid": ValidationResult(KeyStatus.VALID, "", models=["gpt-test"]),
        "d-quota": ValidationResult(KeyStatus.QUOTA_EXCEEDED, "quota"),
        "d-unver": ValidationResult(KeyStatus.UNVERIFIED, "no answer"),
    }
    fake_validator.single_default = staticmethod(
        lambda result: answers[result.api_key])

    stats = asyncio.run(unverified_drainer.drain_unverified(
        db, workers=2, batch_size=10))

    assert stats["total"] == 3
    assert stats["valid"] == 1
    assert stats["quota"] == 1
    assert stats["unverified"] == 1
    assert stats["error"] == 0

    assert _key_row(db, "d-valid")["status"] == "valid"
    assert _models_of(db, "d-valid") == ["gpt-test"]
    assert _key_row(db, "d-quota")["status"] == "quota_exceeded"
    # Критический инвариант: UNVERIFIED не получает verified_time,
    # иначе ключ навсегда выпадает из выборки дрейна.
    unver = _key_row(db, "d-unver")
    assert unver["status"] == "unverified"
    assert unver["verified_time"] is None
    assert unver["confirm_attempts"] == 1
    # Исключённые платформы и invalid не трогаем.
    assert _key_row(db, "aws-secret")["confirm_attempts"] == 0
    assert _key_row(db, "aws-secret")["status"] == "unverified"
    assert _key_row(db, "d-invalid")["status"] == "invalid"
    # Сессия валидатора закрыта в finally.
    assert fake_validator.created[0].closed == 1


def test_drain_respects_limit(fake_validator, db, drain_env):
    base = "https://relay.example.com/v1"
    for index in range(5):
        _insert_key(db, api_key=f"l{index}", base_url=base)
    fake_validator.single_default = staticmethod(
        lambda result: ValidationResult(KeyStatus.UNVERIFIED, "?"))

    stats = asyncio.run(unverified_drainer.drain_unverified(
        db, limit=2, workers=1, batch_size=10))

    assert stats["total"] == 2
    # Каждый ключ перебирает кандидатов (base_url + дефолт платформы),
    # поэтому вызовов больше, чем ключей — важны уникальные ключи.
    calls = fake_validator.created[0].validate_calls
    assert {call[0] for call in calls} == {"l0", "l1"}
    assert len(calls) == 4
    untouched = [f"l{i}" for i in range(5)
                 if _key_row(db, f"l{i}")["confirm_attempts"] == 0]
    assert len(untouched) == 3


def test_drain_selection_honours_max_attempts(fake_validator, db, drain_env):
    """confirm_attempts >= max_attempts выпадает из выборки; gemini — лимит x3."""
    base = "https://relay.example.com/v1"
    _insert_key(db, api_key="tired", platform="openai", base_url=base, attempts=5)
    _insert_key(db, api_key="fresh", platform="openai", base_url=base, attempts=4)
    _insert_key(db, api_key="gemini-tired", platform="gemini", base_url="",
                attempts=15)
    _insert_key(db, api_key="gemini-fresh", platform="gemini", base_url="",
                attempts=14)
    fake_validator.single_default = staticmethod(
        lambda result: ValidationResult(KeyStatus.UNVERIFIED, "?"))
    fake_validator.gemini_default = staticmethod(
        lambda api_key, base_url: ValidationResult(KeyStatus.UNVERIFIED, "?"))

    stats = asyncio.run(unverified_drainer.drain_unverified(
        db, max_attempts=5, workers=1, batch_size=10))

    assert stats["total"] == 2
    assert stats["unverified"] == 2
    assert {call[0] for call in fake_validator.created[0].validate_calls} == {"fresh"}
    assert [c[0] for c in fake_validator.created[0].gemini_calls] == ["gemini-fresh"]
    assert _key_row(db, "tired")["confirm_attempts"] == 5
    assert _key_row(db, "gemini-tired")["confirm_attempts"] == 15
    assert _key_row(db, "fresh")["confirm_attempts"] == 5
    assert _key_row(db, "gemini-fresh")["confirm_attempts"] == 15


def test_drain_stops_on_cancel(fake_validator, db, drain_env):
    base = "https://relay.example.com/v1"
    for index in range(5):
        _insert_key(db, api_key=f"c{index}", base_url=base)

    def single(result):
        unverified_drainer.request_drain_cancel()
        return ValidationResult(KeyStatus.UNVERIFIED, "?")

    fake_validator.single_default = staticmethod(single)

    stats = asyncio.run(unverified_drainer.drain_unverified(
        db, workers=1, batch_size=1))

    assert stats["total"] == 1
    calls = fake_validator.created[0].validate_calls
    assert {call[0] for call in calls} == {"c0"}
    assert unverified_drainer.is_drain_cancelled() is True


def test_worker_gemini_403_promotes_to_quota(db, drain_env, monkeypatch):
    _insert_key(db, api_key="g-403", platform="gemini", base_url="")

    async def fake_validate(validator, key_row):
        # Маркер ищется подстрокой "доступ" (регистр важен).
        return ValidationResult(KeyStatus.UNVERIFIED, "доступ ограничен (403)"), ""

    monkeypatch.setattr(unverified_drainer, "_validate_key", fake_validate)
    stats = _empty_stats()

    _drain_worker(db, [{"platform": "gemini", "api_key": "g-403",
                        "base_url": ""}], stats, validator=object())

    assert stats["quota"] == 1
    assert _key_row(db, "g-403")["status"] == "quota_exceeded"


def test_worker_marks_confirmed_for_real_generation(db, drain_env, monkeypatch):
    _insert_key(db, api_key="gen-ok", platform="gemini", base_url="")
    # Реалистичный сценарий: /models уже сохранил модель (is_confirmed=0),
    # generateContent подтвердил её -> mark_model_confirmed переводит флаг.
    with db._lock, db._get_connection() as conn:
        key_id = conn.execute(
            "SELECT id FROM leaked_keys WHERE api_key='gen-ok'").fetchone()[0]
        conn.execute(
            "INSERT INTO key_models (key_id, model_name, platform, base_url, "
            "is_confirmed) VALUES (?, 'gemini-2.5-flash', 'gemini', '', 0)",
            (key_id,))
        conn.commit()

    async def fake_validate(validator, key_row):
        return (ValidationResult(KeyStatus.VALID, "Подтверждён response",
                                 models=["gemini-2.5-flash"]), "")

    monkeypatch.setattr(unverified_drainer, "_validate_key", fake_validate)
    stats = _empty_stats()

    _drain_worker(db, [{"platform": "gemini", "api_key": "gen-ok",
                        "base_url": ""}], stats, validator=object())

    assert stats["confirmed"] == 1
    assert _key_row(db, "gen-ok")["status"] == "confirmed"
    assert _models_of(db, "gen-ok") == ["gemini-2.5-flash"]
    confirmed_flag = _fetchall(
        db,
        "SELECT km.is_confirmed FROM key_models km "
        "JOIN leaked_keys lk ON lk.id = km.key_id "
        "WHERE lk.api_key=? AND km.model_name=?",
        ("gen-ok", "gemini-2.5-flash"))
    assert [tuple(row) for row in confirmed_flag] == [(1,)]


def test_worker_connection_error_branch(db, drain_env, monkeypatch):
    _insert_key(db, api_key="conn-err", base_url="https://relay.example.com/v1")

    async def fake_validate(validator, key_row):
        return ValidationResult(KeyStatus.CONNECTION_ERROR, "timeout"), ""

    monkeypatch.setattr(unverified_drainer, "_validate_key", fake_validate)
    stats = _empty_stats()

    _drain_worker(db, [{"platform": "openai", "api_key": "conn-err",
                        "base_url": ""}], stats, validator=object())

    assert stats["connection_error"] == 1
    row = _key_row(db, "conn-err")
    assert row["status"] == "unverified"
    assert row["verified_time"] is None
    assert row["confirm_attempts"] == 1


def test_drain_main_cli_args(monkeypatch):
    captured: dict = {}

    async def fake_drain(db, limit=0, workers=8, max_attempts=5, batch_size=100):
        captured.update(db=db, limit=limit, workers=workers,
                        max_attempts=max_attempts, batch_size=batch_size)

    monkeypatch.setattr(unverified_drainer, "drain_unverified", fake_drain)
    monkeypatch.setattr(unverified_drainer, "Database", lambda path: ("db", path))
    monkeypatch.setattr(config, "db_path", "tmp-drain.db")

    monkeypatch.setattr(sys, "argv", [
        "unverified_drainer.py", "--limit", "3", "--workers", "4",
        "--max-attempts", "9", "--batch", "33",
    ])
    unverified_drainer.main()
    assert captured == {"db": ("db", "tmp-drain.db"), "limit": 3, "workers": 4,
                        "max_attempts": 9, "batch_size": 33}

    monkeypatch.setattr(sys, "argv", ["unverified_drainer.py"])
    unverified_drainer.main()
    assert (captured["limit"], captured["workers"], captured["max_attempts"],
            captured["batch_size"]) == (0, 10, 5, 200)


# ============================================================================
# Регрессия: --fresh / --reset-db на БД без таблицы scan_progress
# ============================================================================

def test_cli_fresh_works_without_scan_progress_table(main_env, monkeypatch):
    """scan_progress создаётся лениво, а --fresh делал прямой DELETE →
    на свежей БД падало sqlite3.OperationalError: no such table."""
    real = Database(str(main_env.db_path))
    with real._lock, real._get_connection() as conn:
        conn.execute("INSERT INTO scanned_blobs (file_sha) VALUES ('cafebabe')")
        conn.commit()
    real.close()

    created = _scanner_recorder(monkeypatch)
    monkeypatch.setattr(sys, "argv", ["main_optimized.py", "--fresh", "--gist"])

    main_optimized.main()  # не должно бросить OperationalError

    check = Database(str(main_env.db_path))
    try:
        assert _fetchall(check, "SELECT * FROM scanned_blobs") == []
        assert _fetchall(check, "SELECT name FROM sqlite_master "
                                "WHERE name='scan_progress'") == []
    finally:
        check.close()
    assert created and created[0].kwargs["enable_gist"] is True


def test_cli_reset_db_reports_valid_key_count(main_env, monkeypatch, capsys):
    """`db` в ветке --reset-db не был создан: печать количества ключей
    падала UnboundLocalError (процесс завершался с кодом 1)."""
    real = Database(str(main_env.db_path))
    real.insert_key(LeakedKey(platform="openai", api_key="sk-reset-count",
                              base_url="https://api.openai.com/v1"))
    real.update_key_status("sk-reset-count", KeyStatus.VALID)
    real.close()

    created = _scanner_recorder(monkeypatch)
    monkeypatch.setattr(
        sys, "argv", ["main_optimized.py", "--reset-db", "--yes",
                      "--db", str(main_env.db_path)])

    main_optimized.main()

    out = capsys.readouterr().out
    assert "очищены" in out
    assert "Ключи сохранены (1 действительных)" in out
    assert created == []  # сканер не стартует


def test_cli_fresh_on_new_db_path_does_not_crash(main_env, monkeypatch, tmp_path):
    """--fresh на ещё не созданной БД: sqlite3.connect() создаёт пустой файл
    без схемы, и DELETE FROM scanned_blobs падал no such table."""
    fresh_path = tmp_path / "brand-new.db"
    created = _scanner_recorder(monkeypatch)
    monkeypatch.setattr(sys, "argv", [
        "main_optimized.py", "--fresh", "--gist", "--db", str(fresh_path)])

    main_optimized.main()  # не должно бросить OperationalError

    assert created and created[0].kwargs["enable_gist"] is True


# ===========================================================================
# Экспорт: redact / SARIF / allowlist / purge-junk
# ===========================================================================


def test_export_redact_masks_keys_in_txt_and_csv(main_env, db, monkeypatch, tmp_path):
    _use_real_database(monkeypatch)
    api_key = "sk-proj-ABCDEFGHIJKLMNOPQRSTUVWX"
    _insert_key(db, api_key=api_key, status="valid")
    txt = tmp_path / "k.txt"
    csv_path = tmp_path / "k.csv"
    monkeypatch.setattr(sys, "argv", [
        "main_optimized.py", "--export", str(txt), "--export-csv", str(csv_path),
        "--redact", "--db", str(db.db_path),
    ])

    main_optimized.main()

    masked = main_optimized.redact_key(api_key)
    assert masked == "sk-pro\u2026UVWX"
    assert api_key not in txt.read_text(encoding="utf-8")
    assert f"Ключ: {masked}" in txt.read_text(encoding="utf-8")

    with csv_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["api_key"] == masked
    assert api_key not in csv_path.read_text(encoding="utf-8")


def test_export_sarif_structure_levels_and_fingerprints(
        main_env, db, monkeypatch, tmp_path):
    _use_real_database(monkeypatch)
    _insert_key(db, api_key="sk-sarif-valid", status="valid", platform="openai",
                base_url="https://api.openai.com/v1")
    _insert_key(db, api_key="AIzaSarifQuota", status="quota_exceeded",
                platform="gemini")
    _insert_key(db, api_key="gsk-sarif-invalid", status="invalid", platform="groq")
    out_file = tmp_path / "report.sarif"
    monkeypatch.setattr(sys, "argv", [
        "main_optimized.py", "--export-sarif", str(out_file),
        "--db", str(db.db_path),
    ])

    main_optimized.main()

    document = json.loads(out_file.read_text(encoding="utf-8"))
    assert document["version"] == "2.1.0"
    assert document["$schema"].endswith("sarif-2.1.0.json")

    run = document["runs"][0]
    rule_ids = [rule["id"] for rule in run["tool"]["driver"]["rules"]]
    assert sorted(rule_ids) == ["gemini", "openai"]  # invalid-ключи не экспортируются
    levels = {res["ruleId"]: res["level"] for res in run["results"]}
    assert levels == {"openai": "error", "gemini": "warning"}

    for result in run["results"]:
        fingerprint = result["partialFingerprints"]["primaryLocationLineHash"]
        assert len(fingerprint) == 16
        assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    # ключи в SARIF маскируются: отчёт уходит в CI-логи
    payload = out_file.read_text(encoding="utf-8")
    assert "sk-sarif-valid" not in payload
    assert "AIzaSarifQuota" not in payload


def test_suppress_filters_exports_and_unsuppress_restores(
        main_env, db, monkeypatch, tmp_path, capsys):
    from database import finding_fingerprint

    _use_real_database(monkeypatch)
    api_key = "sk-suppress-me"
    _insert_key(db, api_key=api_key, status="valid")

    monkeypatch.setattr(sys, "argv", [
        "main_optimized.py", "--suppress", f"openai:{api_key}",
        "--reason", "docs example", "--db", str(db.db_path),
    ])
    main_optimized.main()
    assert "подавлено" in capsys.readouterr().out

    fingerprint = finding_fingerprint("openai", api_key)
    csv_path = tmp_path / "after.csv"
    monkeypatch.setattr(sys, "argv", [
        "main_optimized.py", "--export-csv", str(csv_path),
        "--db", str(db.db_path),
    ])
    main_optimized.main()
    # единственная находка подавлена -> экспорт ничего не пишет
    assert not csv_path.exists()

    monkeypatch.setattr(sys, "argv", [
        "main_optimized.py", "--list-suppressions", "--db", str(db.db_path),
    ])
    main_optimized.main()
    listed = capsys.readouterr().out
    assert fingerprint in listed and "docs example" in listed

    monkeypatch.setattr(sys, "argv", [
        "main_optimized.py", "--unsuppress", fingerprint, "--db", str(db.db_path),
    ])
    main_optimized.main()
    assert "удалено из allowlist" in capsys.readouterr().out

    monkeypatch.setattr(sys, "argv", [
        "main_optimized.py", "--export-csv", str(csv_path),
        "--db", str(db.db_path),
    ])
    main_optimized.main()
    with csv_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["api_key"] for row in rows] == [api_key]


def test_purge_junk_requires_yes_outside_tty(main_env, db, monkeypatch, capsys):
    _use_real_database(monkeypatch)
    _insert_key(db, platform="aws_secret_key", api_key="C" * 40, status="unverified")
    monkeypatch.setattr(sys, "argv", [
        "main_optimized.py", "--purge-junk", "--db", str(db.db_path),
    ])

    main_optimized.main()

    assert "нужен --yes" in capsys.readouterr().out
    assert _fetchall(db, "SELECT COUNT(*) FROM leaked_keys")[0][0] == 1


def test_reset_db_requires_yes_outside_tty(main_env, db, monkeypatch, capsys):
    _use_real_database(monkeypatch)
    with db._lock, db._get_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO scanned_blobs (file_sha, scan_time) "
            "VALUES ('deadbeef', '2026-01-01T00:00:00')")
    monkeypatch.setattr(sys, "argv", [
        "main_optimized.py", "--reset-db", "--db", str(db.db_path),
    ])

    main_optimized.main()

    assert "нужен --yes" in capsys.readouterr().out
    assert _fetchall(db, "SELECT COUNT(*) FROM scanned_blobs")[0][0] == 1


def test_purge_junk_backs_up_and_deletes_only_unverified_aws(
        main_env, db, monkeypatch, tmp_path):
    import gzip

    _use_real_database(monkeypatch)
    _insert_key(db, platform="aws_secret_key", api_key="A" * 40, status="unverified")
    _insert_key(db, platform="aws_secret_key", api_key="B" * 40, status="valid")
    _insert_key(db, platform="openai", api_key="sk-keep-me", status="unverified")
    backup = tmp_path / "aws.jsonl.gz"

    monkeypatch.setattr(sys, "argv", [
        "main_optimized.py", "--purge-junk", "--purge-dry-run",
        "--db", str(db.db_path),
    ])
    main_optimized.main()
    assert _fetchall(db, "SELECT COUNT(*) FROM leaked_keys")[0][0] == 3  # dry-run

    monkeypatch.setattr(sys, "argv", [
        "main_optimized.py", "--purge-junk", "--purge-backup", str(backup),
        "--yes", "--db", str(db.db_path),
    ])
    main_optimized.main()

    rows = [json.loads(line) for line in
            gzip.open(backup, "rt", encoding="utf-8").read().splitlines()]
    assert len(rows) == 1 and rows[0]["api_key"] == "A" * 40

    remaining = {row[0] for row in
                 _fetchall(db, "SELECT api_key FROM leaked_keys")}
    assert remaining == {"B" * 40, "sk-keep-me"}
