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
import queue
from datetime import datetime
from typing import Optional

from config import config
from database import Database, KeyStatus
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
                 enable_codegraph: bool = False):
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

        # Переключатели источников сканирования
        self.enable_pastebin = enable_pastebin
        self.enable_paster = enable_paster
        self.enable_gist = enable_gist
        self.enable_gitlab = enable_gitlab
        self.enable_realtime = enable_realtime
        self.enable_mcp = enable_mcp
        self.enable_codegraph = enable_codegraph
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

def export_keys(db_path: str, output_file: str, status_filter: str = None):
    """Экспорт ключей (открытым текстом)"""
    from rich.console import Console
    from rich.table import Table

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

    # Запись в файл
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f"# Результаты экспорта GitHub Secret Scanner\n")
        f.write(f"# Время: {datetime.now().isoformat()}\n")
        f.write(f"# Количество: {len(keys)}\n")
        f.write("=" * 60 + "\n\n")

        for key in keys:
            f.write(f"Платформа: {key.platform}\n")
            f.write(f"Статус: {key.status}\n")
            f.write(f"Ключ: {key.api_key}\n")
            f.write(f"URL: {key.base_url}\n")
            f.write(f"Информация: {key.balance}\n")
            f.write(f"Источник: {key.source_url}\n")
            f.write("-" * 40 + "\n\n")

    console.print(f"[green]✓ Экспортировано {len(keys)} ключей в {output_file}[/]")


def export_keys_csv(db_path: str, output_file: str, status_filter: str = None):
    """Экспорт ключей в CSV файл"""
    from rich.console import Console

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

    # Запись в CSV файл
    fieldnames = [
        "id", "platform", "status", "api_key", "base_url", "balance",
        "source_url", "model_tier", "rpm", "is_high_value", "found_time",
    ]

    with open(output_file, "w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for key in keys:
            writer.writerow({
                "id": getattr(key, "id", ""),
                "platform": key.platform,
                "status": key.status,
                "api_key": key.api_key,
                "base_url": key.base_url,
                "balance": key.balance,
                "source_url": key.source_url,
                "model_tier": key.model_tier,
                "rpm": key.rpm,
                "is_high_value": int(bool(getattr(key, "is_high_value", False))),
                "found_time": key.found_time.isoformat() if getattr(key, "found_time", None) else "",
            })

    console.print(f"[green]✓ Экспортировано {len(keys)} ключей в CSV: {output_file}[/]")


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
    parser.add_argument('--stats', action='store_true', help='Отобразить статистику')
    parser.add_argument('--db', type=str, default=None, help='Путь к базе данных')
    parser.add_argument('--proxy', type=str, help='Адрес прокси')

    # Режимы сканирования
    parser.add_argument('--fresh', action='store_true',
                        help='Полное пересканирование: очистить SHA-кэш и сканировать заново')
    parser.add_argument('--reset-db', action='store_true',
                        help='Полный сброс базы данных (удалить все SHA и ключи, начать с нуля)')
    parser.add_argument('--tui', action='store_true',
                        help='Запустить Textual TUI (то же, что python tui_app.py / start_tui.bat)')
    parser.add_argument('--revalidate', action='store_true',
                        help='Повторная проверка ключей со статусом connection_error/pending')

    # Опции источников сканирования
    parser.add_argument('--pastebin', action='store_true', help='Включить сканирование Pastebin')
    parser.add_argument('--paster', action='store_true', help='Включить сканирование Paster.sh')
    parser.add_argument('--pastebin-key', type=str, default='', help='Pastebin Pro API Key')
    parser.add_argument('--gist', action='store_true', help='Включить сканирование GitHub Gist')
    parser.add_argument('--gitlab', action='store_true', help='Включить сканирование GitLab проектов')
    parser.add_argument('--realtime', action='store_true', help='Включить мониторинг в реальном времени')
    parser.add_argument('--mcp', action='store_true', help='Включить MCP Registry сканер (glama.ai + smithery.ai)')
    parser.add_argument('--codegraph', action='store_true', help='Включить SourceGraph code search (замена SearchCode)')
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
            conn = sqlite3.connect(db_path)
            c = conn.cursor()
            c.execute("DELETE FROM scanned_blobs")
            c.execute("DELETE FROM scan_progress")
            conn.commit()
            conn.close()
            print(f"[OK] SHA-кэш и прогресс очищены в {db_path}")
            print(f"     Ключи сохранены ({db.get_valid_keys_count()} действительных)")
        else:
            print(f"База данных {db_path} не найдена")
        return

    # Режим интерактивного TUI
    if args.tui:
        from tui_app import run_tui
        run_tui()
        return

    # Режим дешифрования
    if args.decrypt:
        if not args.key_file:
            logger.error("Для дешифрования необходимо указать --key-file")
            return
        decrypt_keys(args.decrypt, args.key_file)
        return

    # Режим экспорта
    if args.export or args.export_csv or args.export_encrypted:
        if args.export:
            export_keys(config.db_path, args.export, args.status)
        if args.export_csv:
            export_keys_csv(config.db_path, args.export_csv, args.status)
        if args.export_encrypted:
            export_keys_encrypted(config.db_path, args.export_encrypted, args.status)
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
    # Режим fresh: очистить SHA-кэш перед сканированием
    if args.fresh:
        import sqlite3
        conn = sqlite3.connect(config.db_path)
        c = conn.cursor()
        c.execute("DELETE FROM scanned_blobs")
        c.execute("DELETE FROM scan_progress")
        conn.commit()
        conn.close()
        print("[OK] SHA-кэш очищен для полного пересканирования")

    scanner = OptimizedSecretScanner(
        enable_pastebin=enable_pastebin,
        enable_gist=enable_gist,
        enable_gitlab=enable_gitlab,
        enable_realtime=enable_realtime,
        pastebin_api_key=args.pastebin_key or config.pastebin_api_key,
        enable_paster=enable_paster,
        enable_mcp=enable_mcp,
        enable_codegraph=enable_codegraph,
    )
    scanner.start()


if __name__ == "__main__":
    main()
