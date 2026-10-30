#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GitHub Secret Scanner Pro - Оптимизированная основная программа

Оптимизации:
1. Асинхронная база данных (AsyncDatabase) - повышение производительности в 3-5 раз
2. asyncio.Queue вместо queue.Queue - устранение блокировок
3. Проверка конфигурации - проверка при запуске
4. Улучшенная обработка ошибок
5. Метрики мониторинга производительности
"""

import sys
import signal
import asyncio
import threading
import time
import argparse
import csv
import gzip
import hashlib
import json
import queue
import re
from datetime import datetime
from typing import Optional

from config import config
from database import Database, KeyStatus, finding_fingerprint
from async_database import AsyncDatabase, try_enable_uvloop
from scanner import start_scanner
from validator import start_validators
from ui import Dashboard
from source_pastebin import start_pastebin_scanner
from source_paster import start_paster_scanner
from source_gist import start_gist_scanner
from source_gitlab import start_gitlab_scanner
from source_realtime import start_realtime_scanner
from source_mcp import start_mcp_scanner
from source_codegraph import start_codegraph_scanner
from source_telegram import start_telegram_scanner
from source_search import start_search_scanner
from source_huggingface import start_huggingface_scanner

from loguru import logger
import os

try:
    from tui_i18n import t as _i18n_t, tf as _i18n_tf, resolve_lang as _i18n_lang
except Exception:
    def _i18n_t(key, lang=None):
        return key
    def _i18n_tf(key, lang=None, **kw):
        try:
            return key.format(**kw)
        except Exception:
            return key
    def _i18n_lang(pref=None):
        return "en"

# Effective UI/log language for this process (OS / UI_LANG / TUI_LANG)
_LOG_LANG = _i18n_lang()

# Настройка логирования в файл
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scanner.log")
logger.remove()
logger.add(sys.stderr, level="INFO", format="<green>{time:HH:mm:ss}</green> | <level>{level: <8}</level> | {message}")
logger.add(LOG_FILE, level="DEBUG", rotation="10 MB", retention="3 days",
           format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}")


# ============================================================================
#              Авто-завершение старых процессов сканера/TUI
# ============================================================================

def _kill_stale_scanner_processes() -> int:
    """
    Убить старые запущенные копии сканера/TUI перед стартом нового.

    Ищем процессы, чья командная строка содержит 'main_optimized.py' или
    'tui_app.py' (сам сканер и его TUI-обёртка), исключая текущий процесс.
    Возвращает число завершённых процессов.
    """
    try:
        import psutil
    except Exception:
        return 0
    my_pid = os.getpid()
    try:
        my_create = psutil.Process(my_pid).create_time()
    except Exception:
        my_create = None
    killed = 0
    markers = ("main_optimized.py", "tui_app.py")
    for proc in psutil.process_iter(["pid", "name", "cmdline", "create_time"]):
        try:
            info = proc.info
            name = (info.get("name") or "").lower()
            if name not in ("python.exe", "pythonw.exe", "python", "pythonw"):
                continue
            cmd = " ".join(info.get("cmdline") or [])
        except Exception:
            continue
        low = cmd.lower()
        if not any(m.lower() in low for m in markers):
            continue
        pid = info.get("pid")
        if pid is None or pid == my_pid:
            continue
        # Не убиваем процесс, который стартовал ПОЗЖЕ или одновременно
        # с текущим (иначе при запуске через обёртки вроде cmd /c start /B
        # находим сами себя — свой же процесс с другой обёрткой).
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
    if killed:
        logger.info(_i18n_tf("log_stale_killed_scanner", _LOG_LANG, n=killed))
    return killed


# ============================================================================
#                          Проверка конфигурации
# ============================================================================

class ConfigValidator:
    """Валидатор конфигурации"""

    @staticmethod
    def validate() -> tuple[bool, list[str]]:
        """
        Проверка валидности конфигурации

        Returns:
            (is_valid, error_messages)
        """
        errors = []

        # GitHub tokens
        if not config.github_tokens or not any(config.github_tokens):
            errors.append(_i18n_t("err_no_github_tokens", _LOG_LANG))

        # Database path
        if not config.db_path:
            errors.append(_i18n_t("err_no_db_path", _LOG_LANG))

        # Proxy (optional)
        if config.proxy_url:
            if not config.proxy_url.startswith(('http://', 'https://', 'socks5://')):
                errors.append(_i18n_tf("err_bad_proxy", _LOG_LANG, url=config.proxy_url))

        return len(errors) == 0, errors

    @staticmethod
    def validate_github_tokens() -> tuple[int, int]:
        """
        Проверка валидности GitHub Token

        Returns:
            (valid_count, total_count)
        """
        # TODO: Реализовать логику проверки Token
        # Можно отправить простой API-запрос для тестирования
        return len(config.github_tokens), len(config.github_tokens)


# ============================================================================
#                          Мониторинг производительности
# ============================================================================

class PerformanceMetrics:
    """Сборщик метрик производительности"""

    def __init__(self):
        self.keys_found = 0
        self.keys_valid = 0
        self.keys_invalid = 0
        self.scan_errors = 0
        self.start_time = time.time()

    def increment_found(self):
        self.keys_found += 1

    def increment_valid(self):
        self.keys_valid += 1

    def increment_invalid(self):
        self.keys_invalid += 1

    def increment_errors(self):
        self.scan_errors += 1

    def get_stats(self) -> dict:
        """Получение статистики"""
        runtime = time.time() - self.start_time
        return {
            'keys_found': self.keys_found,
            'keys_valid': self.keys_valid,
            'keys_invalid': self.keys_invalid,
            'scan_errors': self.scan_errors,
            'runtime_seconds': runtime,
            'keys_per_minute': (self.keys_found / runtime * 60) if runtime > 0 else 0
        }


# ============================================================================
#                          Оптимизированный сканер
# ============================================================================

class OptimizedSecretScanner:
    """Оптимизированная система сканирования ключей"""

    def __init__(self, enable_pastebin: bool = False, enable_gist: bool = False,
                 enable_gitlab: bool = False,
                 enable_realtime: bool = False, pastebin_api_key: str = "",
                 enable_paster: bool = False, enable_mcp: bool = False,
                 enable_codegraph: bool = False, enable_telegram: bool = False,
                 enable_huggingface: bool = False, enable_search: bool = False):
        self.stop_event = threading.Event()

        # Использование queue.Queue (синхронная, для потоков)
        self.result_queue = queue.Queue(maxsize=10000)

        # Асинхронная база данных
        self.async_db: Optional[AsyncDatabase] = None

        # Синхронная база данных (для экспорта и т.д.)
        self.db = Database(config.db_path)

        self.dashboard = Dashboard()
        self.metrics = PerformanceMetrics()

        self.scanner_thread = None
        self.validator_threads = []
        self.pastebin_thread = None
        self.paster_thread = None
        self.gist_thread = None
        self.gitlab_thread = None
        self.realtime_thread = None
        self.mcp_thread = None
        self.codegraph_thread = None
        self.telegram_thread = None
        self.search_thread = None
        self.huggingface_thread = None

        # Переключатели источников сканирования
        self.enable_pastebin = enable_pastebin
        self.enable_paster = enable_paster
        self.enable_gist = enable_gist
        self.enable_gitlab = enable_gitlab
        self.enable_realtime = enable_realtime
        self.enable_mcp = enable_mcp
        self.enable_codegraph = enable_codegraph
        self.enable_telegram = enable_telegram
        self.enable_search = enable_search
        self.enable_huggingface = enable_huggingface
        self.pastebin_api_key = pastebin_api_key

        enabled_sources = {
            "github": True,
            "paster": enable_paster,
            "pastebin": enable_pastebin,
            "gist": enable_gist,
            "gitlab": enable_gitlab,
            "realtime": enable_realtime,
            "mcp": enable_mcp,
            "codegraph": enable_codegraph,
            "telegram": enable_telegram,
            "huggingface": enable_huggingface,
            "search": enable_search,
        }
        for source, enabled in enabled_sources.items():
            self.db.upsert_source_progress(
                source,
                status="starting" if enabled else "disabled",
                phase="startup" if enabled else "disabled",
                current=0,
                total=0,
                processed=0,
                found=0,
                errors=0,
                message="",
            )

        # Обработка сигналов
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Обработка сигналов"""
        self.stop()

    async def _init_async_db(self):
        """Инициализация асинхронной базы данных"""
        self.async_db = AsyncDatabase(config.db_path)
        await self.async_db.init()
        logger.info(_i18n_t("log_async_db_ready", _LOG_LANG))

    def start(self):
        """Запуск системы сканирования"""
        # Проверка конфигурации
        is_valid, errors = ConfigValidator.validate()
        if not is_valid:
            logger.error(_i18n_t("startup_config_err", _LOG_LANG))
            for error in errors:
                logger.error(f"  - {error}")
            sys.exit(1)

        logger.info(_i18n_t("startup_config_ok", _LOG_LANG))
        logger.info("=" * 60)
        logger.info("Secret Scanner Pro")
        logger.info(_i18n_tf("startup_tokens", _LOG_LANG, n=len(config.github_tokens)))
        logger.info(_i18n_tf("startup_db", _LOG_LANG, path=config.db_path))
        logger.info("=" * 60)

        # Попытка включения uvloop
        try_enable_uvloop()

        # Инициализация асинхронной базы данных
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._init_async_db())

        # Загрузка и отображение статистики из БД
        db_stats = self.db.get_stats()
        sha_count = self.db.get_scanned_blob_count()
        logger.info(
            _i18n_tf(
                "startup_stats",
                _LOG_LANG,
                keys=db_stats["total"],
                blobs=sha_count,
            )
        )
        for status, count in db_stats.get('statuses', {}).items():
            logger.info(f"  {status}: {count}")

        # Инициализация статистики панели с данными из БД
        statuses = db_stats.get('statuses', {})
        self.dashboard.update_stats(
            total_tokens=len(config.github_tokens),
            is_running=True,
            total_keys_found=db_stats['total'],
            valid_keys=statuses.get('valid', 0) + statuses.get('quota_exceeded', 0),
            invalid_keys=statuses.get('invalid', 0),
            quota_exceeded=statuses.get('quota_exceeded', 0),
            connection_errors=statuses.get('connection_error', 0),
        )

        # Запуск валидаторов (Consumer) — используют синхронный Database в потоках
        # num_workers=1: внутри _validator_thread_worker asyncio.Semaphore уже
        # даёт параллель запросов (validate_single асинхронен). 2 потока
        # дублировали pending/confirm/unverified дрейнеры → тройной лог-спам.
        self.validator_threads = start_validators(
            self.result_queue,
            self.db,
            self.stop_event,
            dashboard=self.dashboard,
            num_workers=1
        )

        # Запуск GitHub сканера (Producer) — использует синхронный Database в потоке
        self.scanner_thread = start_scanner(
            self.result_queue,
            self.db,
            self.stop_event,
            dashboard=self.dashboard
        )

        # Запуск других источников сканирования
        if self.enable_pastebin:
            self.pastebin_thread = start_pastebin_scanner(
                self.result_queue,
                self.stop_event,
                dashboard=self.dashboard,
                api_key=self.pastebin_api_key,
                db=self.db,
            )
            self.dashboard.add_log(
                _i18n_tf("log_source_enabled", _LOG_LANG, src="Pastebin"), "INFO")

        if self.enable_paster:
            self.paster_thread = start_paster_scanner(
                self.result_queue,
                self.db,
                self.stop_event,
                dashboard=self.dashboard,
            )
            self.dashboard.add_log(
                _i18n_tf("log_source_enabled", _LOG_LANG, src="Paster.sh"), "INFO")

        if self.enable_gist:
            self.gist_thread = start_gist_scanner(
                self.result_queue,
                self.stop_event,
                dashboard=self.dashboard,
                db=self.db,
            )
            self.dashboard.add_log(
                _i18n_tf("log_source_enabled", _LOG_LANG, src="Gist"), "INFO")

        if self.enable_gitlab:
            self.gitlab_thread = start_gitlab_scanner(
                self.result_queue,
                self.stop_event,
                dashboard=self.dashboard,
                db=self.db,
            )
            self.dashboard.add_log(
                _i18n_tf("log_source_enabled", _LOG_LANG, src="GitLab"), "INFO")

        if self.enable_realtime:
            self.realtime_thread = start_realtime_scanner(
                self.result_queue,
                self.stop_event,
                dashboard=self.dashboard,
                db=self.db,
            )
            self.dashboard.add_log(
                _i18n_tf("log_source_enabled", _LOG_LANG, src="Realtime"), "INFO")

        if self.enable_mcp:
            self.mcp_thread = start_mcp_scanner(
                self.result_queue,
                self.stop_event,
                dashboard=self.dashboard,
                db=self.db,
            )
            self.dashboard.add_log(
                _i18n_tf("log_source_enabled", _LOG_LANG, src="MCP"), "INFO")

        if self.enable_codegraph:
            self.codegraph_thread = start_codegraph_scanner(
                self.result_queue,
                self.stop_event,
                dashboard=self.dashboard,
                db=self.db,
            )
            self.dashboard.add_log(
                _i18n_tf("log_source_enabled", _LOG_LANG, src="CodeGraph"), "INFO")

        if self.enable_telegram:
            self.telegram_thread = start_telegram_scanner(
                self.result_queue,
                self.db,
                self.stop_event,
                dashboard=self.dashboard,
            )
            self.dashboard.add_log(
                _i18n_tf("log_source_enabled", _LOG_LANG, src="Telegram"), "INFO")

        if self.enable_search:
            self.search_thread = start_search_scanner(
                self.result_queue,
                self.db,
                self.stop_event,
                dashboard=self.dashboard,
            )
            self.dashboard.add_log(
                _i18n_tf("log_source_enabled", _LOG_LANG, src="Search"), "INFO")

        if self.enable_huggingface:
            self.huggingface_thread = start_huggingface_scanner(
                self.result_queue,
                self.db,
                self.stop_event,
                dashboard=self.dashboard,
            )
            self.dashboard.add_log(
                _i18n_tf("log_source_enabled", _LOG_LANG, src="HuggingFace"),
                "INFO")

        # Headless run loop (old Rich Live UI removed — use tui_app / start_tui.bat)
        with self.dashboard.start():
            try:
                logger.info(_i18n_t("startup_headless", _LOG_LANG))
                while not self.stop_event.is_set():
                    queue_size = self.result_queue.qsize()
                    self.dashboard.update_stats(queue_size=queue_size)
                    time.sleep(1.0)
            except KeyboardInterrupt:
                pass
            finally:
                self.stop()

    def stop(self):
        """Остановка системы"""
        if self.stop_event.is_set():
            return

        logger.info(_i18n_t("startup_stopping", _LOG_LANG))
        self.dashboard.stop()
        self.stop_event.set()

        # Закрытие асинхронной базы данных
        if self.async_db:
            loop = asyncio.get_event_loop()
            loop.run_until_complete(self.async_db.close())
            logger.info(_i18n_t("log_async_db_closed", _LOG_LANG))

        # Wait for worker threads
        threads = [
            self.scanner_thread,
            self.pastebin_thread,
            self.paster_thread,
            self.gist_thread,
            self.gitlab_thread,
            self.realtime_thread,
            self.mcp_thread,
            self.codegraph_thread,
            self.telegram_thread,
            self.huggingface_thread,
            self.search_thread,
        ] + self.validator_threads

        for thread in threads:
            if thread and thread.is_alive():
                thread.join(timeout=5)

        stats = self.metrics.get_stats()
        logger.info(_i18n_tf("log_perf_stats", _LOG_LANG, stats=stats))


# ============================================================================
#                          Функция экспорта (шифрованная версия)
# ============================================================================

def export_keys_encrypted(db_path: str, output_file: str, status_filter: str = None):
    """
    Шифрованный экспорт ключей

    Использует симметричное шифрование Fernet
    """
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        logger.error("Необходимо установить cryptography: pip install cryptography")
        return

    from rich.console import Console
    import json

    console = Console()
    db = Database(db_path)

    if status_filter:
        try:
            status = KeyStatus(status_filter)
            keys = db.get_keys_by_status(status)
        except ValueError:
            console.print(f"[red]Неверный статус: {status_filter}[/]")
            return
    else:
        keys = db.get_valid_keys()

    if not keys:
        console.print("[yellow]Нет ключей, соответствующих условиям[/]")
        return

    # Генерация ключа шифрования
    encryption_key = Fernet.generate_key()
    cipher = Fernet(encryption_key)

    # Подготовка данных
    data = [{
        'platform': k.platform,
        'api_key': k.api_key,
        'base_url': k.base_url,
        'status': k.status,
        'balance': k.balance,
        'source_url': k.source_url
    } for k in keys]

    # Шифрование
    json_data = json.dumps(data, ensure_ascii=False, indent=2)
    encrypted_data = cipher.encrypt(json_data.encode())

    # Запись в зашифрованный файл
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)

    # Сохранение ключа
    key_file = output_file + '.key'
    with open(key_file, 'wb') as f:
        f.write(encryption_key)

    console.print(f"[green]✓ Зашифрованный экспорт {len(keys)} ключей[/]")
    console.print(f"[cyan]Файл данных: {output_file}[/]")
    console.print(f"[cyan]Файл ключа: {key_file}[/]")
    console.print(f"[yellow]⚠️  Сохраните файл ключа в надежном месте![/]")


def decrypt_keys(encrypted_file: str, key_file: str):
    """Дешифрование экспортированных ключей"""
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        logger.error("Необходимо установить cryptography: pip install cryptography")
        return

    from rich.console import Console
    import json

    console = Console()

    try:
        # Чтение ключа
        with open(key_file, 'rb') as f:
            encryption_key = f.read()

        cipher = Fernet(encryption_key)

        # Чтение зашифрованных данных
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()

        # Дешифрование
        decrypted_data = cipher.decrypt(encrypted_data)
        keys = json.loads(decrypted_data.decode())

        console.print(f"[green]✓ Успешно дешифровано {len(keys)} ключей[/]")

        # Отображение первых 3
        for i, key in enumerate(keys[:3]):
            console.print(f"\n[cyan]Ключ {i+1}:[/]")
            console.print(f"  Платформа: {key['platform']}")
            console.print(f"  Ключ: {key['api_key'][:20]}...")
            console.print(f"  URL: {key['base_url']}")

        if len(keys) > 3:
            console.print(f"\n[yellow]... и еще {len(keys) - 3} ключей[/]")

    except Exception as e:
        console.print(f"[red]Ошибка дешифрования: {e}[/]")


# ============================================================================
#                          Оригинальная функция экспорта (совместимость)
# ============================================================================

# ============================================================================
#                     Экспорт: маскирование, baseline, SARIF
# ============================================================================

def redact_key(api_key: str) -> str:
    """Маска ключа для отчётов: sk-abcd…wxyz (первые 6 + последние 4)."""
    if not api_key:
        return ""
    if len(api_key) <= 12:
        return "*" * len(api_key)
    return f"{api_key[:6]}…{api_key[-4:]}"


def _select_export_keys(db: Database, status_filter: str = None):
    """Ключи для экспорта: по статусу или все действительные.

    None означает «неизвестный статус» (экспорт не выполняется).
    """
    if status_filter:
        try:
            status = KeyStatus(status_filter)
        except ValueError:
            return None
        return db.get_keys_by_status(status)
    return db.get_valid_keys()


def _drop_suppressed(db: Database, keys):
    """Убрать находки, подавленные через baseline (--suppress)."""
    suppressed = db.get_suppressed_fingerprints()
    if not suppressed:
        return keys
    return [
        key for key in keys
        if finding_fingerprint(key.platform, key.api_key) not in suppressed
    ]


def export_keys(db_path: str, output_file: str, status_filter: str = None,
                redact: bool = False):
    from rich.console import Console
    from rich.table import Table

    console = Console()
    db = Database(db_path)

    keys = _select_export_keys(db, status_filter)
    if keys is None:
        console.print(f"[red]Неверный статус: {status_filter}[/]")
        return
    keys = _drop_suppressed(db, keys)

    if not keys:
        console.print("[yellow]Нет ключей, соответствующих условиям[/]")
        return

    # Запись в файл
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# Результаты экспорта GitHub Secret Scanner\n")
        f.write(f"# Время: {datetime.now().isoformat()}\n")
        f.write(f"# Количество: {len(keys)}\n")
        f.write("=" * 60 + "\n\n")

        for key in keys:
            f.write(f"Платформа: {key.platform}\n")
            f.write(f"Статус: {key.status}\n")
            f.write(f"Ключ: {redact_key(key.api_key) if redact else key.api_key}\n")
            f.write(f"URL: {key.base_url}\n")
            f.write(f"Информация: {key.balance}\n")
            f.write(f"Источник: {key.source_url}\n")
            f.write("-" * 40 + "\n\n")

    console.print(f"[green]✓ Экспортировано {len(keys)} ключей в {output_file}[/]")


def export_keys_csv(db_path: str, output_file: str, status_filter: str = None,
                    redact: bool = False):
    """Экспорт ключей в CSV файл"""
    from rich.console import Console

    console = Console()
    db = Database(db_path)

    keys = _select_export_keys(db, status_filter)
    if keys is None:
        console.print(f"[red]Неверный статус: {status_filter}[/]")
        return
    keys = _drop_suppressed(db, keys)

    if not keys:
        console.print("[yellow]Нет ключей, соответствующих условиям[/]")
        return

    # Запись в CSV файл
    fieldnames = [
        "id", "platform", "status", "api_key", "base_url", "balance",
        "source_url", "model_tier", "rpm", "is_high_value", "found_time",
        "fingerprint",
    ]

    with open(output_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for key in keys:
            writer.writerow({
                "id": getattr(key, "id", ""),
                "platform": key.platform,
                "status": key.status,
                "api_key": redact_key(key.api_key) if redact else key.api_key,
                "base_url": key.base_url,
                "balance": key.balance,
                "source_url": key.source_url,
                "model_tier": key.model_tier,
                "rpm": key.rpm,
                "is_high_value": int(bool(getattr(key, "is_high_value", False))),
                "found_time": key.found_time.isoformat() if getattr(key, "found_time", None) else "",
                "fingerprint": finding_fingerprint(key.platform, key.api_key),
            })

    console.print(f"[green]✓ Экспортировано {len(keys)} ключей в CSV: {output_file}[/]")


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# SARIF уровни: valid -> error (живой ключ), quota -> warning, invalid -> note
SARIF_LEVEL_BY_STATUS = {
    KeyStatus.VALID.value: "error",
    KeyStatus.CONFIRMED.value: "error",
    KeyStatus.QUOTA_EXCEEDED.value: "warning",
    KeyStatus.INVALID.value: "note",
}


def export_sarif(db_path: str, output_file: str, status_filter: str = None):
    """Экспорт в SARIF 2.1.0 (GitHub code scanning, DefectDojo, SonarQube).

    Ключи в отчёте всегда маскируются: SARIF уходит в CI-логи, полный ключ
    там = утечка пула. Подавленные находки (--suppress) не попадают.
    """
    from rich.console import Console

    console = Console()
    db = Database(db_path)

    keys = _select_export_keys(db, status_filter)
    if keys is None:
        console.print(f"[red]Неверный статус: {status_filter}[/]")
        return
    keys = _drop_suppressed(db, keys)

    if not keys:
        console.print("[yellow]Нет ключей, соответствующих условиям[/]")
        return

    rules = []
    seen_rules = set()
    results = []

    for key in keys:
        fingerprint = finding_fingerprint(key.platform, key.api_key)
        if key.platform not in seen_rules:
            seen_rules.add(key.platform)
            rules.append({
                "id": key.platform,
                "name": key.platform.replace("_", " ").title(),
                "shortDescription": {
                    "text": f"Exposed {key.platform} credential"
                },
            })

        location = key.source_url or key.base_url or "unknown"
        message = (
            f"{key.platform} key detected (status: {key.status}): "
            f"{redact_key(key.api_key)}"
        )
        if getattr(key, "balance", ""):
            message += f", balance: {key.balance}"

        results.append({
            "ruleId": key.platform,
            "level": SARIF_LEVEL_BY_STATUS.get(key.status, "none"),
            "message": {"text": message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": location},
                },
            }],
            "partialFingerprints": {"primaryLocationLineHash": fingerprint},
        })

    document = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Github-API-scan",
                    "informationUri": "https://github.com/ByJotaro/Github-API-scan",
                    "rules": rules,
                },
            },
            "results": results,
        }],
    }

    with open(output_file, "w", encoding="utf-8") as handle:
        json.dump(document, handle, ensure_ascii=False, indent=2)

    console.print(
        f"[green]✓ Экспортировано {len(results)} находок в SARIF: {output_file}[/]")


def confirm_destructive(action: str, assume_yes: bool = False) -> bool:
    """Подтверждение разрушительной операции.

    Неинтерактивный запуск (CI, bat-файл, перенаправленный stdin) без
    явного --yes отказывает: раньше --reset-db и --purge-junk срабатывали
    молча, и один неверный флаг стирал данные.
    """
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print(f"[!] {action}: неинтерактивный режим, нужен --yes")
        return False
    try:
        answer = input(f"[?] {action}. Продолжить? [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes", "д", "да")


def purge_junk(db_path: str, backup_path: str = "", dry_run: bool = False,
               platform: str = "aws_secret_key") -> dict:
    """Удалить невалидированный мусор платформы (40-char base64 без контекста).

    Исторические строки появились до контекстного гейта (scanner.py:
    key_needs_context_gate) и новых таких уже не будет. Перед удалением
    строки выгружаются в gzip-JSONL, если указан backup_path.
    """
    import sqlite3

    result = {"platform": platform, "found": 0, "deleted": 0,
              "backup": "", "size_before": 0, "size_after": 0, "dry_run": dry_run}
    if not os.path.exists(db_path):
        return result

    result["size_before"] = os.path.getsize(db_path)
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        where = "platform = ? AND status = ?"
        params = (platform, KeyStatus.UNVERIFIED.value)
        cur.execute(f"SELECT COUNT(*) FROM leaked_keys WHERE {where}", params)
        result["found"] = cur.fetchone()[0]

        if dry_run or result["found"] == 0:
            return result

        if backup_path:
            with gzip.open(backup_path, "wt", encoding="utf-8") as dump:
                cur.execute(
                    "SELECT platform, api_key, base_url, status, source_url, "
                    f"found_time FROM leaked_keys WHERE {where}", params)
                for row in cur.fetchall():
                    dump.write(json.dumps({
                        "platform": row[0], "api_key": row[1], "base_url": row[2],
                        "status": row[3], "source_url": row[4],
                        "found_time": row[5],
                    }, ensure_ascii=False) + "\n")
            result["backup"] = backup_path

        cur.execute(f"DELETE FROM leaked_keys WHERE {where}", params)
        conn.commit()
        result["deleted"] = cur.rowcount
        cur.execute("VACUUM")
        conn.commit()
    finally:
        conn.close()

    result["size_after"] = os.path.getsize(db_path)
    return result


def show_stats(db_path: str):
    """Отображение статистики"""
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box

    console = Console()
    db = Database(db_path)
    stats = db.get_stats()

    # Таблица статистики
    table = Table(show_header=False, box=box.ROUNDED)
    table.add_column("Элемент", style="cyan")
    table.add_column("Количество", justify="right", style="white")

    table.add_row("Всего ключей", str(stats['total']))
    table.add_row("", "")

    statuses = stats.get('statuses', {})
    table.add_row("[green]✓ Действительные[/]", f"[green]{statuses.get('valid', 0)}[/]")
    table.add_row("[yellow]💰 Квота исчерпана[/]", f"[yellow]{statuses.get('quota_exceeded', 0)}[/]")
    table.add_row("[red]✗ Недействительные[/]", f"[red]{statuses.get('invalid', 0)}[/]")
    table.add_row("[magenta]🔌 Ошибка подключения[/]", f"[magenta]{statuses.get('connection_error', 0)}[/]")

    if stats.get('platforms'):
        table.add_row("", "")
        table.add_row("[bold]Распределение по платформам[/]", "")
        for platform, count in stats['platforms'].items():
            table.add_row(f"  {platform}", str(count))

    console.print(Panel(table, title="📊 Статистика базы данных", border_style="cyan"))


# ============================================================================
#                          Главная функция
# ============================================================================

def _clear_table(cur, name):
    """DELETE FROM name, только если таблица существует.

    Часть таблиц создаётся лениво (scan_progress — в save_scan_progress), а
    sqlite3.connect() на новом пути создаёт пустой файл без схемы: прямой
    DELETE падал sqlite3.OperationalError: no such table.
    """
    cur.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,))
    if cur.fetchone():
        cur.execute(f"DELETE FROM {name}")


def start_model_sync_thread(stale_hours: float = 6.0, limit: int = 60,
                           interval: int = 3600,
                           first_delay: int = 120) -> threading.Thread:
    """Фоновая синхронизация списков моделей в процессе сканера.

    Валидация ключей снимает снапшот `/models`; без фонового обновления
    новые модели провайдера не появляются, а убранные висят вечно. Поток
    раз в час сверяет эндпоинты, которые не трогали 6 часов (окно внутри
    refresh_models), и после изменений пересобирает active_pool прокси.
    """
    def _loop() -> None:
        from model_sync import refresh_models
        from proxy_server import ActivePool
        db_local = Database(config.db_path)
        time.sleep(max(0, first_delay))
        while True:
            try:
                stats = asyncio.run(refresh_models(
                    db_local, stale_hours=stale_hours, limit=limit))
                if stats["added"] or stats["removed"] or stats["demoted"]:
                    ActivePool(db_local).resync_pool()
            except Exception as e:
                logger.debug(f"model-sync thread: {type(e).__name__}: {e}")
            time.sleep(max(60, interval))

    thread = threading.Thread(target=_loop, daemon=True, name="model-sync")
    thread.start()
    return thread


def main():
    """Главная функция"""
    parser = argparse.ArgumentParser(
        description="GitHub Secret Scanner Pro - Оптимизированная версия",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры:
  python main_optimized.py --all-sources      # Headless сканер (без Rich UI)
  python tui_app.py                           # Операторский Textual TUI
  start_tui.bat                               # То же, double-click (Windows)
  python main_optimized.py --stats            # Статистика БД
  python main_optimized.py --export keys.txt  # Экспорт ключей
        """
    )

    parser.add_argument('--export', type=str, metavar='FILE', help='Экспорт ключей в текстовый файл')
    parser.add_argument('--export-csv', type=str, metavar='CSV', help='Экспорт ключей в CSV файл')
    parser.add_argument('--export-encrypted', type=str, metavar='FILE', help='Шифрованный экспорт ключей')
    parser.add_argument('--decrypt', type=str, metavar='FILE', help='Дешифрование экспортированных ключей')
    parser.add_argument('--key-file', type=str, metavar='KEY', help='Файл ключа для дешифрования')
    parser.add_argument('--status', type=str, help='Фильтр по статусу экспорта (valid/quota_exceeded)')
    parser.add_argument('--redact', action='store_true',
                        help='Маскировать ключи в текстовом/CSV экспорте (sk-abcd…wxyz)')
    parser.add_argument('--export-sarif', type=str, metavar='FILE',
                        help='Экспорт находок в SARIF 2.1.0 (для CI; ключи маскируются)')
    parser.add_argument('--suppress', type=str, metavar='FP|PLATFORM:KEY',
                        help='Добавить находку в allowlist (16-hex fingerprint или platform:key)')
    parser.add_argument('--reason', type=str, default='', help='Причина подавления (--suppress)')
    parser.add_argument('--unsuppress', type=str, metavar='FP', help='Убрать находку из allowlist')
    parser.add_argument('--list-suppressions', action='store_true', help='Показать allowlist находок')
    parser.add_argument('--purge-junk', action='store_true',
                        help='Удалить невалидированный мусор aws_secret_key (с бэкапом)')
    parser.add_argument('--purge-backup', type=str, default='',
                        help='Куда сохранить бэкап удаляемых строк (.jsonl.gz)')
    parser.add_argument('--purge-dry-run', action='store_true',
                        help='Только посчитать, сколько удалил бы --purge-junk')
    parser.add_argument('--stats', action='store_true', help='Отобразить статистику')
    parser.add_argument('--db', type=str, default=None, help='Путь к базе данных')
    parser.add_argument('--proxy', type=str, help='Адрес прокси')

    # Режимы сканирования
    parser.add_argument('--fresh', action='store_true',
                        help='Полное пересканирование: очистить SHA-кэш и сканировать заново')
    parser.add_argument('--reset-db', action='store_true',
                        help='Сброс прогресса сканирования (SHA-кэш и прогресс; '
                             'найденные ключи сохраняются)')
    parser.add_argument('--yes', action='store_true',
                        help='Не спрашивать подтверждение для --reset-db/--purge-junk')
    parser.add_argument('--tui', action='store_true',
                        help='Запустить Textual TUI (то же, что python tui_app.py / start_tui.bat)')
    parser.add_argument('--revalidate', action='store_true',
                        help='Повторная проверка ключей со статусом connection_error/pending')
    parser.add_argument('--refresh-models', action='store_true',
                        help='Перечитать GET /models у провайдеров: обновить списки '
                             'моделей в БД и пересобрать пул прокси')
    parser.add_argument('--models-limit', type=int, default=0,
                        help='--refresh-models: максимум эндпоинтов за прогон (0 = все)')
    parser.add_argument('--models-base-url', type=str, default='',
                        help='--refresh-models: синхронизировать только этот base_url')

    # Опции источников сканирования
    parser.add_argument('--pastebin', action='store_true', help='Включить сканирование Pastebin')
    parser.add_argument('--paster', action='store_true', help='Включить сканирование Paster.sh')
    parser.add_argument('--pastebin-key', type=str, default='', help='Pastebin Pro API Key')
    parser.add_argument('--gist', action='store_true', help='Включить сканирование GitHub Gist')
    parser.add_argument('--gitlab', action='store_true', help='Включить сканирование GitLab проектов')
    parser.add_argument('--realtime', action='store_true', help='Включить мониторинг в реальном времени')
    parser.add_argument('--mcp', action='store_true', help='Включить MCP Registry сканер (glama.ai + smithery.ai)')
    parser.add_argument('--codegraph', action='store_true', help='Включить SourceGraph code search (замена SearchCode)')
    parser.add_argument('--telegram', action='store_true',
                        help='Включить Telegram (публичные превью t.me/s/<channel>)')
    parser.add_argument('--huggingface', action='store_true',
                        help='Включить HuggingFace (полнотекстовый поиск по коду репозиториев)')
    parser.add_argument('--search', action='store_true',
                        help='Включить веб-поиск по доркам (DuckDuckGo / Google CSE)')
    parser.add_argument('--all-sources', action='store_true', help='Включить все источники сканирования')

    args = parser.parse_args()

    if args.proxy:
        config.proxy_url = args.proxy
    if args.db:
        config.db_path = args.db

    # Режим сброса базы данных
    if args.reset_db:
        import sqlite3
        db_path = config.db_path
        if os.path.exists(db_path):
            if not confirm_destructive(
                    f"сброс прогресса сканирования в {db_path}", args.yes):
                return 1
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            _clear_table(c, "scanned_blobs")
            _clear_table(c, "scan_progress")
            # Ключи не удаляем — считаем на том же соединении.
            # `db` в этой ветке ещё не создан: обращение к нему давало
            # UnboundLocalError и выход с кодом 1.
            valid_count = c.execute(
                "SELECT COUNT(*) FROM leaked_keys WHERE status IN (?, ?)",
                (KeyStatus.VALID.value, KeyStatus.QUOTA_EXCEEDED.value),
            ).fetchone()[0]
            conn.commit()
            conn.close()
            print(f"[OK] SHA-кэш и прогресс очищены в {db_path}")
            print(f"     Ключи сохранены ({valid_count} действительных)")
        else:
            print(f"База данных {db_path} не найдена")
        return

    # Режим интерактивного TUI
    if args.tui:
        from tui_app import run_tui
        run_tui()
        return

    # Синхронизация списков моделей с провайдерами (без сканирования)
    if args.refresh_models:
        from model_sync import refresh_models
        db = Database(config.db_path)
        stats = asyncio.run(refresh_models(
            db, force=True, limit=args.models_limit,
            only_base_url=args.models_base_url))
        print(f"[OK] эндпоинтов: {stats['endpoints']} | ок: {stats['ok']} | "
              f"ошибок: {stats['failed']} | ключей: {stats['keys']}")
        print(f"     моделей: +{stats['added']} новых, "
              f"-{stats['removed']} убранных, "
              f"{stats['demoted']} снято с подтверждения")
        for err in stats.get("errors", []):
            print(f"     ! {err}")
        try:
            from proxy_server import ActivePool
            pool = ActivePool(db).resync_pool()
            print(f"     пул: +{pool['added']} пар, обновлено {pool['updated']}, "
                  f"убрано {pool['removed']}")
        except Exception as e:
            print(f"     пул не обновлён: {type(e).__name__}: {e}")
        return

    # Режим дешифрования
    if args.decrypt:
        if not args.key_file:
            logger.error("Для дешифрования необходимо указать --key-file")
            return
        decrypt_keys(args.decrypt, args.key_file)
        return

    # Allowlist находок (baseline): --suppress / --unsuppress / --list-suppressions
    if args.suppress or args.unsuppress or args.list_suppressions:
        db = Database(config.db_path)
        if args.suppress:
            arg = args.suppress.strip()
            if re.fullmatch(r"[0-9a-f]{16}", arg):
                platform, api_key = "", ""
                fingerprint = arg
                with db._lock, db._get_connection() as conn:
                    conn.execute(
                        "INSERT OR REPLACE INTO finding_suppressions "
                        "(fingerprint, platform, api_key, reason) VALUES (?, ?, ?, ?)",
                        (fingerprint, platform, api_key, args.reason))
                    conn.commit()
            elif ":" in arg:
                platform, api_key = arg.split(":", 1)
                fingerprint = db.add_suppression(platform, api_key.strip(), args.reason)
            else:
                print("[!] --suppress принимает 16-hex fingerprint или platform:key")
                return
            print(f"[OK] подавлено: {fingerprint}")
        if args.unsuppress:
            removed = db.remove_suppression(args.unsuppress.strip())
            print("[OK] удалено из allowlist" if removed else "[!] fingerprint не найден")
        if args.list_suppressions:
            rows = db.list_suppressions()
            if not rows:
                print("[i] allowlist пуст")
            for row in rows:
                print(f"{row['fingerprint']}  {row['platform']:<16} "
                      f"{redact_key(row['api_key']):<18} {row['reason']}")
        return

    # Режим экспорта
    if args.export or args.export_csv or args.export_encrypted or args.export_sarif:
        if args.export:
            export_keys(config.db_path, args.export, args.status, redact=args.redact)
        if args.export_csv:
            export_keys_csv(config.db_path, args.export_csv, args.status,
                            redact=args.redact)
        if args.export_encrypted:
            export_keys_encrypted(config.db_path, args.export_encrypted, args.status)
        if args.export_sarif:
            export_sarif(config.db_path, args.export_sarif, args.status)
        return

    # Обслуживание БД: удалить исторический мусор (до контекстного гейта)
    if args.purge_junk:
        if not args.purge_dry_run and not confirm_destructive(
                f"удаление невалидированных строк aws_secret_key из "
                f"{config.db_path}", args.yes):
            return 1
        result = purge_junk(
            config.db_path,
            backup_path=args.purge_backup,
            dry_run=args.purge_dry_run,
        )
        if not result["found"]:
            print(f"[i] нечего удалять: нет unverified-строк {result['platform']}")
        elif result["dry_run"]:
            print(f"[i] dry-run: удалил бы {result['found']} строк {result['platform']}")
        else:
            print(f"[OK] удалено {result['deleted']} строк {result['platform']}")
            if result["backup"]:
                print(f"     бэкап: {result['backup']}")
            print(f"     БД: {result['size_before'] / 1048576:.1f} MB -> "
                  f"{result['size_after'] / 1048576:.1f} MB")
        return

    # Режим статистики
    if args.stats:
        show_stats(config.db_path)
        return

    # Режим повторной валидации
    if args.revalidate:
        import asyncio as _aio
        from validator import AsyncValidator
        db = Database(config.db_path)
        validator = AsyncValidator(db)
        stats = _aio.run(validator.revalidate_failed_keys())
        print(f"\n[OK] Повторная проверка завершена:")
        print(f"  Всего перепроверено: {stats['revalidated']}")
        print(f"  Валидных:            {stats['valid']}")
        print(f"  Невалидных:          {stats['invalid']}")
        print(f"  Квота исчерпана:     {stats['quota']}")
        print(f"  Ошибок соединения:   {stats['connection_error']}")
        print(f"  Непроверяемых:       {stats['unverified']}")
        return

    # Режим сканирования. TUI по умолчанию: голый запуск без флагов
    # открывает операторский TUI (удобно + безопасно: сканер стартует
    # из TUI как subprocess с --all-sources). Headless — только явными
    # флагами источников/утилит (--all-sources, --pastebin, --stats ...).
    _headless_flags = (
        args.pastebin or args.paster or args.gist or args.gitlab
        or args.realtime or args.mcp or args.codegraph or args.all_sources
        or args.export or args.export_csv or args.export_encrypted
        or args.export_sarif or args.suppress or args.unsuppress
        or args.list_suppressions or args.purge_junk
        or args.telegram or args.huggingface or args.search
        or args.decrypt or args.stats or args.revalidate or args.fresh
        or args.reset_db or args.proxy or args.db
    )
    if not _headless_flags and not args.tui:
        from tui_app import run_tui
        run_tui()
        return

    enable_pastebin = args.pastebin or args.all_sources
    enable_paster = args.paster or args.all_sources
    enable_gist = args.gist or args.all_sources
    enable_gitlab = args.gitlab or args.all_sources
    enable_realtime = args.realtime or args.all_sources
    enable_mcp = args.mcp or args.all_sources
    enable_codegraph = args.codegraph or args.all_sources
    enable_telegram = args.telegram or args.all_sources
    enable_huggingface = args.huggingface or args.all_sources
    enable_search = args.search or args.all_sources
    # Режим fresh: очистить SHA-кэш перед сканированием
    if args.fresh:
        import sqlite3
        conn = sqlite3.connect(config.db_path)
        c = conn.cursor()
        _clear_table(c, "scanned_blobs")
        _clear_table(c, "scan_progress")
        conn.commit()
        conn.close()
        print("[OK] SHA-кэш очищен для полного пересканирования")

    start_model_sync_thread()
    scanner = OptimizedSecretScanner(
        enable_pastebin=enable_pastebin,
        enable_gist=enable_gist,
        enable_gitlab=enable_gitlab,
        enable_realtime=enable_realtime,
        pastebin_api_key=args.pastebin_key or config.pastebin_api_key,
        enable_paster=enable_paster,
        enable_mcp=enable_mcp,
        enable_codegraph=enable_codegraph,
        enable_telegram=enable_telegram,
        enable_huggingface=enable_huggingface,
        enable_search=enable_search,
    )
    scanner.start()


if __name__ == "__main__":
    main()
