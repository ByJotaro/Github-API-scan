"""UI language: system default + Settings override (en / ru / auto)."""
from __future__ import annotations

import locale
import os
from typing import Dict, Literal

Lang = Literal["en", "ru"]
LangPref = Literal["en", "ru", "auto"]

_STRINGS: Dict[str, Dict[str, str]] = {
    "en": {
        "app_title": "Secret Scanner Pro",
        "app_subtitle": "8 sources",
        "loading": "Loading...",
        "tab_dashboard": "Dashboard",
        "tab_keys": "Keys",
        "tab_models": "Models",
        "tab_providers": "Providers",
        "tab_api": "API",
        "tab_settings": "Settings",
        "tab_logs": "Logs",
        "bind_quit": "Quit",
        "bind_dashboard": "Dashboard",
        "bind_keys": "Keys",
        "bind_models": "Models",
        "bind_providers": "Providers",
        "bind_api": "API",
        "bind_settings": "Settings",
        "bind_logs": "Logs",
        "bind_refresh": "Refresh",
        "bind_toggle_scanner": "Start/Stop",
        "bind_revalidate": "Re-validate",
        "bind_drain": "Drain UNVERIFIED",
        "bind_proxy": "Proxy ON/OFF",
        "bind_copy": "Copy key",
        "bind_search": "Search",
        "bind_help": "Help",
        "panel_workers": "Sources (workers)",
        "panel_progress": "Scan progress",
        "panel_funnel": "Validation funnel",
        "panel_statuses": "Key statuses",
        "panel_tasks": "Tasks / activity",
        "panel_platforms": "Platforms (top-8)",
        "panel_recent_keys": "Recent high-value / valid",
        "panel_top_models": "Top confirmed models",
        "panel_live_log": "Live log",
        "filter_all": "All",
        "filter_all_platforms": "All platforms",
        "btn_high_value": "High-value",
        "btn_reveal": "Reveal",
        "btn_refresh": "Refresh",
        "btn_proxy_on": "Proxy ON",
        "btn_external_ip": "External IP",
        "btn_test_url": "Test URL",
        "btn_check_all": "Check all",
        "btn_clear_pool": "Clear pool",
        "btn_toggle": "Toggle",
        "btn_delete": "Delete",
        "btn_start": "Start",
        "btn_stop": "Stop",
        "btn_restart": "Restart",
        "btn_load": "Load",
        "btn_clear": "Clear",
        "btn_copy": "Copy",
        "search_keys": "Search: key / url / balance...",
        "search_model": "Search model...",
        "search_provider": "Search provider or URL...",
        "search_log": "Filter (error/found/platform)...",
        "hint_keys": "Click header to sort | c = copy key | Reveal = show key",
        "hint_keys_detail": "Select a row to view details.",
        "hint_models": "Double-click row to add/remove from API pool. * = in pool.",
        "hint_models_detail": "Select a model to view providers and keys.",
        "hint_providers_detail": "Select a provider to view models and keys.",
        "hint_api": (
            "Double-click Models/Providers tabs to add to pool. "
            "Click a model on the left → its providers on the right (▲▼ order). "
            "Double-click a row to remove.\n"
            "Base URL: http://127.0.0.1:8818/v1  "
            "chat/completions, completions, embeddings; Authorization: Bearer any"
        ),
        "pool_models": "Models in pool",
        "pool_providers": "Model providers",
        "pool_providers_hint": "(select a model on the left)",
        "key_selection": "Key selection:",
        "method_rr": "Method: round-robin",
        "method_sticky": "Method: sticky",
        "trace_title": "Request trace",
        "settings_scanner": "Scanner control",
        "settings_db": "Database maintenance",
        "settings_revalidate": "Key re-validation",
        "settings_export": "Export keys",
        "settings_config": "Configuration",
        "settings_log": "Action log",
        "settings_language": "Language",
        "lang_auto": "System",
        "lang_en": "English",
        "lang_ru": "Russian",
        "lang_hint": "Default follows OS language. Change here and restart TUI (or apply).",
        "btn_clear_sha": "Clear SHA",
        "btn_clear_prog": "Reset progress",
        "btn_vacuum": "VACUUM",
        "btn_del_invalid": "Delete invalid",
        "btn_reset_attempts": "Reset attempts",
        "btn_mark_hv": "HV confirmed",
        "btn_revalidate_all": "Full re-check",
        "btn_revalidate_failed": "Re-check pending/unverified",
        "btn_confirm_all": "Confirm VALID → CONFIRMED",
        "btn_drain": "Drain UNVERIFIED",
        "btn_confirm_models": "Models CONFIRMED",
        "hint_revalidate": (
            "Full: normalize endpoints + validate + confirm + test models\n"
            "Pending: only unverified/pending keys\n"
            "Confirm: confirm (2+32=) for VALID keys only\n"
            "Drain: network UNVERIFIED via real generation\n"
            "Models: re-check ALL models of CONFIRMED keys"
        ),
        "hint_export": "Files saved in project dir: exported_keys.{txt,csv,json}",
        "family_all": "All families",
        "sort_caps": "Capabilities",
        "sort_newest": "Newest ↓",
        "sort_keys": "Keys ↓",
        "sort_name": "Name A-Z",
        "sort_family": "Family",
        "sort_confirmed": "Confirmed ↓",
        "sort_models": "Models ↓",
        "btn_confirmed_only": "Confirmed only",
        "col_source": "Source",
        "col_status": "Status",
        "col_phase": "Phase",
        "col_progress": "Progress",
        "col_proc": "Proc",
        "col_found": "Found",
        "col_keys": "Keys",
        "col_err": "Err",
        "col_age": "Age",
        "col_platform": "Platform",
        "col_key": "Key",
        "col_balance": "Balance/Model",
        "col_base": "Base URL",
        "col_src": "Source",
        "col_high": "High",
        "col_found_time": "Found",
        "col_model": "Model",
        "col_family": "Family",
        "col_cap": "Cap",
        "col_provider": "Provider",
        "col_release": "Release",
        "col_tier": "Tier",
        "col_access": "Access",
        "col_platforms": "Platforms",
        "col_endpoint": "Endpoint",
        "col_confirmed": "Confirmed",
        "col_top_models": "Top models",
        "gh_title": "GitHub tokens required",
        "gh_continue": "Continue",
        "gh_copy": "Copy path",
        "gh_copied": "Path copied",
        "log_proxy_autostart": "Proxy auto-started :8818",
        "log_scanner_already": "Scanner already running",
        "log_scanner_started": "Scanner started (pid {pid})",
        "log_scanner_start_fail": "Failed to start: {err}",
        "log_scanner_not_running": "Scanner is not running",
        "log_scanner_stopped": "Scanner stopped",
        "log_scanner_stop_fail": "Stop error: {err}",
        "log_scanner_died": "Scanner process died (rc={rc}) — restarting in {delay}s",
        "log_scanner_watchdog_restart": "Watchdog: scanner restarted (pid {pid}, attempt {n})",
        "log_scanner_watchdog_max": "Watchdog: too many restarts — giving up (re-enable via Restart button)",
        "log_proxy_stopped": "Proxy stopped",
        "log_proxy_started": "Proxy started on :8818",
        "log_proxy_external": "Proxy on 0.0.0.0:8818 (external access)",
        "log_proxy_local_only": "External IP mode off (localhost only)",
        "log_proxy_restarted": "Proxy restarted: {host}:8818",
        "log_proxy_restart_fail": "Proxy restart error: {err}",
        "log_method_set": "Selection method: {mode}",
        "log_method_fail": "Failed to set method: {err}",
        "log_no_tokens": "No working GitHub tokens. Put them in: {path}",
        "log_stale_killed": "[ok] Stopped {n} old TUI/scanner process(es)",
        "log_lang_applied": "Language: pref={pref} → {lang}",
        "startup_config_ok": "Configuration check passed",
        "startup_tokens": "Tokens: {n}",
        "startup_db": "Database: {path}",
        "startup_stats": "DB stats: {keys} keys, {blobs} scanned files",
        "startup_headless": "Headless scanner. Operator UI: python tui_app.py  or  start_tui.bat",
        "startup_stopping": "Stopping scanner...",
        "startup_config_err": "Configuration validation failed:",
        # Dashboard dynamic panels
        "task_none": "no active tasks",
        "task_running": "running | {m}:{s:02d}",
        "validation_label": "Validation:",
        "validation_queue": "queued: {q} | UNVERIFIED: {u}",
        "no_data": "no data",
        "no_valid_keys_yet": "no valid keys yet",
        "no_confirmed_models": "no confirmed models",
        "task_full_revalidate": "Full re-check",
        "task_failed_revalidate": "Re-check pending/unverified",
        "task_confirm_all": "Confirm VALID→CONFIRMED",
        "task_drain_unverified": "Drain UNVERIFIED",
        "task_confirm_models": "Re-check CONFIRMED models",
        "task_started": "{label} started...",
        "task_done": "{label} finished",
        "task_error": "Error: {err}",
        "log_revalidate_start": "Re-checking failed keys...",
        "log_revalidate_done": "Done: {valid} valid, {invalid} invalid, {quota} quota, {conn} connection errors",
        "log_copy_need_row": "Select a key row to copy (c)",
        "log_key_copied": "Copied key {key}",
        "log_clipboard_err": "Clipboard: {err}. Key: {key}",
        "log_pool_add": "+ pool: {name}",
        "log_pool_remove": "− pool: {name}",
        "log_drain_already": "UNVERIFIED drain already running",
        "log_test_url_start": "URL test started (background)...",
        "log_pick_provider": "Select a provider in the right table",
        "log_proxy_for_reorder": "Start proxy for reorder",
        "log_toggled": "toggled {name}",
        "log_removed_from_model": "X removed {name} from {model}",
        "log_check_all_models": "Checking all models in pool...",
        "log_sha_cleared": "SHA cleared, rescan allowed",
        "log_progress_reset": "Scan progress reset",
        "log_vacuum_start": "VACUUM running in background...",
        "log_vacuum_done": "VACUUM done",
        "log_invalid_deleted": "Deleted invalid keys: {n}",
        "log_attempts_reset": "Reset attempts for keys",
        "log_hv_marked": "* high-value: {n} confirmed keys",
        "log_no_valid_confirm": "No VALID keys to confirm",
        "log_confirm_start": "Confirming {n} VALID keys...",
        "log_confirm_done": "Confirmed: {n}/{total} keys",
        "log_no_models_export": "No confirmed models to export",
        "log_export_models": "Models: {n} -> {path}",
        "log_no_keys_export": "No keys to export",
        "log_export_err": "Export error: {err}",
        "log_export_ok": "Export {fmt}: {n} keys -> {path}",
        "log_log_copied": "Log copied to clipboard",
        "log_log_empty": "Log is empty",
        "log_copy_err": "Copy error: {err}",
        "pool_type_model": "model",
        "pool_type_provider": "provider",
        "pool_no_confirmed": "X no confirmed",
        "pool_details_hint": "Details (select a model or provider on the left)",
        "pool_providers_for": "Providers for model:",
        "pool_models_for": "Models for provider:",
        "pool_endpoints_n": "Endpoints: {n}",
        "pool_models_n": "Models: {n}",
        # Scanner / worker logs
        "log_async_db_ready": "Async database initialized",
        "log_async_db_closed": "Async database closed",
        "log_db_init_done": "Database ready: {path} (scanned files: {blobs}, keys: {keys})",
        "log_source_enabled": "[{src}] scan source enabled",
        "log_searching": "Search \"{kw}\"...",
        "log_search_kw": "Search: {kw}",
        "log_github_api_query": "GitHub API query: {q}",
        "log_keyword_projects": "Keyword '{kw}': {n} projects",
        "log_stale_killed_scanner": "Stopped {n} old scanner/TUI process(es)",
        "log_perf_stats": "Performance stats: {stats}",
        "err_no_github_tokens": "GitHub tokens not configured",
        "err_no_db_path": "Database path not configured",
        "err_bad_proxy": "Invalid proxy URL: {url}",
        "pool_added_model": "Added to models: {name}",
        "pool_added_provider": "Added to providers: {name}",
        "pool_removed": "Removed: {name}",
        "pool_removed_pair": "Removed: {name} @ {endpoint}",
        "log_token_rejected": "GitHub token rejected (401 Bad credentials): …{tail}",
        "log_token_added": "Added found GitHub token: {prefix}... (@{user})",
        "log_sha_cache_loaded": "Loaded {n} SHAs into memory cache",
        "log_sha_load_err": "SHA load error: {err}",
        "log_skip_key": "Skip {key} ({reason})",
        "log_skip_url": "Skip {key} (URL: {reason})",
        "log_tokens_exhausted": "All tokens exhausted, waiting {s:.0f}s...",
        "log_processed_results": "Processed {n} results (SHA skipped: {skip})",
        "log_rate_limit": "Rate limited, rotating token...",
        "log_all_tokens_dead": "All GitHub tokens rejected (401). Check config.github_tokens.",
        "log_api_error": "API error: {err}",
        "log_search_error": "Search error: {err}",
        "log_resume_checkpoint": "Resume from checkpoint: keyword {cur}/{total}",
        "log_no_checkpoint": "No valid checkpoint, starting scan from beginning",
        "log_auto_restart": "Auto-restart: new scan pass...",
        "log_tokens_pause": "GitHub: all tokens 401. Pause 60s, retry round...",
    },
    "ru": {
        "app_title": "Secret Scanner Pro",
        "app_subtitle": "8 источников",
        "loading": "Загрузка...",
        "tab_dashboard": "Дашборд",
        "tab_keys": "Ключи",
        "tab_models": "Модели",
        "tab_providers": "Провайдеры",
        "tab_api": "API",
        "tab_settings": "Настройки",
        "tab_logs": "Логи",
        "bind_quit": "Выход",
        "bind_dashboard": "Дашборд",
        "bind_keys": "Ключи",
        "bind_models": "Модели",
        "bind_providers": "Провайдеры",
        "bind_api": "API",
        "bind_settings": "Настройки",
        "bind_logs": "Логи",
        "bind_refresh": "Обновить",
        "bind_toggle_scanner": "Старт/Стоп",
        "bind_revalidate": "Re-validate",
        "bind_drain": "Дрейн UNVERIFIED",
        "bind_proxy": "Прокси ON/OFF",
        "bind_copy": "Копировать ключ",
        "bind_search": "Поиск",
        "bind_help": "Помощь",
        "panel_workers": "Источники (воркеры)",
        "panel_progress": "Прогресс сканирования",
        "panel_funnel": "Воронка валидации",
        "panel_statuses": "Статусы ключей",
        "panel_tasks": "Задачи / активность",
        "panel_platforms": "Платформы (top-8)",
        "panel_recent_keys": "Последние high-value / валидные",
        "panel_top_models": "Топ подтверждённые модели",
        "panel_live_log": "Живой лог",
        "filter_all": "Все",
        "filter_all_platforms": "Все платформы",
        "btn_high_value": "High-value",
        "btn_reveal": "Reveal",
        "btn_refresh": "Обновить",
        "btn_proxy_on": "Прокси ON",
        "btn_external_ip": "Внешний IP",
        "btn_test_url": "Тест URL",
        "btn_check_all": "Проверить все",
        "btn_clear_pool": "Очистить пул",
        "btn_toggle": "Вкл/выкл",
        "btn_delete": "Удалить",
        "btn_start": "Старт",
        "btn_stop": "Стоп",
        "btn_restart": "Рестарт",
        "btn_load": "Загрузить",
        "btn_clear": "Очистить",
        "btn_copy": "Копировать",
        "search_keys": "Поиск: ключ / url / баланс...",
        "search_model": "Поиск модели...",
        "search_provider": "Поиск провайдера или URL...",
        "search_log": "Фильтр (error/found/platform)...",
        "hint_keys": "Клик по заголовку - сортировка | c - копировать | Reveal - показать",
        "hint_keys_detail": "Выберите строку для просмотра деталей.",
        "hint_models": "Двойной клик -> добавить/убрать из пула API. * = в пуле.",
        "hint_models_detail": "Выберите модель для просмотра провайдеров и ключей.",
        "hint_providers_detail": "Выберите провайдера для просмотра моделей и ключей.",
        "hint_api": (
            "Двойной клик во вкладках Модели/Провайдеры - добавить в пул. "
            "Клик по модели слева -> её провайдеры справа (▲▼ порядок). "
            "Двойной клик по строке - убрать.\n"
            "Base URL: http://127.0.0.1:8818/v1  "
            "chat/completions, completions, embeddings; Authorization: Bearer any"
        ),
        "pool_models": "Модели в пуле",
        "pool_providers": "Провайдеры модели",
        "pool_providers_hint": "(выберите модель слева)",
        "key_selection": "Выбор ключа:",
        "method_rr": "Метод: round-robin",
        "method_sticky": "Метод: sticky",
        "trace_title": "Трейс запросов",
        "settings_scanner": "Управление сканером",
        "settings_db": "Обслуживание базы данных",
        "settings_revalidate": "Перепроверка ключей",
        "settings_export": "Экспорт ключей",
        "settings_config": "Конфигурация",
        "settings_log": "Журнал действий",
        "settings_language": "Язык",
        "lang_auto": "Системный",
        "lang_en": "English",
        "lang_ru": "Русский",
        "lang_hint": "По умолчанию — язык ОС. Смена здесь применяется сразу (pref сохраняется).",
        "btn_clear_sha": "Очистить SHA",
        "btn_clear_prog": "Сбросить прогресс",
        "btn_vacuum": "VACUUM",
        "btn_del_invalid": "Удалить invalid",
        "btn_reset_attempts": "Сброс attempts",
        "btn_mark_hv": "HV confirmed",
        "btn_revalidate_all": "Полная перепроверка",
        "btn_revalidate_failed": "Перепроверка pending/unverified",
        "btn_confirm_all": "Подтвердить VALID → CONFIRMED",
        "btn_drain": "Дрейн UNVERIFIED",
        "btn_confirm_models": "Модели CONFIRMED",
        "hint_revalidate": (
            "Полная: нормализация эндпоинтов + валидация + подтверждение + тест моделей\n"
            "Pending: только unverified/pending ключи\n"
            "Подтвердить: confirm (2+32=) для VALID\n"
            "Дрейн: UNVERIFIED через реальную генерацию\n"
            "Модели: перепроверить все модели CONFIRMED-ключей"
        ),
        "hint_export": "Файлы: exported_keys.{txt,csv,json} в каталоге проекта",
        "family_all": "Все семейства",
        "sort_caps": "Capabilities",
        "sort_newest": "Новизна ↓",
        "sort_keys": "Ключей ↓",
        "sort_name": "Имя A-Z",
        "sort_family": "Семейство",
        "sort_confirmed": "Подтверждённых ↓",
        "sort_models": "Моделей ↓",
        "btn_confirmed_only": "Только подтв.",
        "col_source": "Источник",
        "col_status": "Статус",
        "col_phase": "Фаза",
        "col_progress": "Прогресс",
        "col_proc": "Proc",
        "col_found": "Found",
        "col_keys": "Keys",
        "col_err": "Err",
        "col_age": "Age",
        "col_platform": "Платформа",
        "col_key": "Ключ",
        "col_balance": "Баланс/Модель",
        "col_base": "Base URL",
        "col_src": "Источник",
        "col_high": "High",
        "col_found_time": "Найден",
        "col_model": "Модель",
        "col_family": "Семейство",
        "col_cap": "Cap",
        "col_provider": "Провайдер",
        "col_release": "Релиз",
        "col_tier": "Tier",
        "col_access": "Доступ",
        "col_platforms": "Платформы",
        "col_endpoint": "Эндпоинт",
        "col_confirmed": "Подтверж.",
        "col_top_models": "Топ модели",
        "gh_title": "Нужны GitHub-токены",
        "gh_continue": "Продолжить",
        "gh_copy": "Копировать путь",
        "gh_copied": "Путь скопирован",

        "log_proxy_autostart": "Прокси автозапущен :8818",
        "log_scanner_already": "Сканер уже запущен",
        "log_scanner_started": "Сканер запущен (pid {pid})",
        "log_scanner_start_fail": "Не удалось запустить: {err}",
        "log_scanner_not_running": "Сканер не запущен",
        "log_scanner_stopped": "Сканер остановлен",
        "log_scanner_stop_fail": "Ошибка остановки: {err}",
        "log_scanner_died": "Процесс сканера умер (rc={rc}) — перезапуск через {delay}с",
        "log_scanner_watchdog_restart": "Watchdog: сканер перезапущен (pid {pid}, попытка {n})",
        "log_scanner_watchdog_max": "Watchdog: слишком много перезапусков — остановлено (включи кнопкой Restart)",
        "log_proxy_stopped": "Прокси остановлен",
        "log_proxy_started": "Прокси запущен на :8818",
        "log_proxy_external": "Прокси на 0.0.0.0:8818 (внешний доступ)",
        "log_proxy_local_only": "Режим внешнего IP выключен (только localhost)",
        "log_proxy_restarted": "Прокси перезапущен: {host}:8818",
        "log_proxy_restart_fail": "Ошибка перезапуска прокси: {err}",
        "log_method_set": "Метод выбора: {mode}",
        "log_method_fail": "Не удалось задать метод: {err}",
        "log_no_tokens": "Нет рабочих GitHub-токенов. Положите сюда: {path}",
        "log_stale_killed": "[ok] Завершено старых процессов TUI/сканера: {n}",
        "log_lang_applied": "Язык: pref={pref} → {lang}",
        "startup_config_ok": "Проверка конфигурации пройдена",
        "startup_tokens": "Токенов: {n}",
        "startup_db": "База данных: {path}",
        "startup_stats": "Статистика БД: {keys} ключей, {blobs} отсканированных файлов",
        "startup_headless": "Сканер headless. Операторский UI: python tui_app.py  или  start_tui.bat",
        "startup_stopping": "Остановка системы сканирования...",
        "startup_config_err": "Ошибка проверки конфигурации:",
        # Dashboard dynamic panels
        "task_none": "нет активных задач",
        "task_running": "выполняется | {m}:{s:02d}",
        "validation_label": "Валидация:",
        "validation_queue": "в очереди: {q} | UNVERIFIED: {u}",
        "no_data": "нет данных",
        "no_valid_keys_yet": "пока нет валидных ключей",
        "no_confirmed_models": "нет подтверждённых моделей",
        "task_full_revalidate": "Полная перепроверка",
        "task_failed_revalidate": "Перепроверка pending/unverified",
        "task_confirm_all": "Подтверждение VALID->CONFIRMED",
        "task_drain_unverified": "Дрейн UNVERIFIED",
        "task_confirm_models": "Перепроверка моделей CONFIRMED",
        "task_started": "{label} запущена...",
        "task_done": "{label} завершена",
        "task_error": "Ошибка: {err}",
        "log_revalidate_start": "Начата повторная проверка failed-ключей...",
        "log_revalidate_done": "Готово: {valid} валидных, {invalid} невалидных, {quota} квота, {conn} ошибок соединения",
        "log_copy_need_row": "Выберите ключ в таблице для копирования (c)",
        "log_key_copied": "Скопирован ключ {key}",
        "log_clipboard_err": "Clipboard: {err}. Ключ: {key}",
        "log_pool_add": "+ пул: {name}",
        "log_pool_remove": "− пул: {name}",
        "log_drain_already": "Дрейн UNVERIFIED уже активен",
        "log_test_url_start": "Тест URL запущен (фон)...",
        "log_pick_provider": "Выберите провайдера в таблице справа",
        "log_proxy_for_reorder": "Запустите прокси для reorder",
        "log_toggled": "переключён {name}",
        "log_removed_from_model": "X удалён {name} с {model}",
        "log_check_all_models": "Проверка всех моделей в пуле...",
        "log_sha_cleared": "SHA очищены, повторное сканирование разрешено",
        "log_progress_reset": "Прогресс сканирования сброшен",
        "log_vacuum_start": "VACUUM выполняется в фоне...",
        "log_vacuum_done": "VACUUM выполнен",
        "log_invalid_deleted": "Удалено invalid-ключей: {n}",
        "log_attempts_reset": "Сброшены attempts для ключей",
        "log_hv_marked": "* high-value: {n} confirmed ключей",
        "log_no_valid_confirm": "Нет VALID ключей для подтверждения",
        "log_confirm_start": "Подтверждение {n} VALID ключей...",
        "log_confirm_done": "Подтверждено: {n}/{total} ключей",
        "log_no_models_export": "Нет подтверждённых моделей для экспорта",
        "log_export_models": "Модели: {n} -> {path}",
        "log_no_keys_export": "Нет ключей для экспорта",
        "log_export_err": "Ошибка экспорта: {err}",
        "log_export_ok": "Экспорт {fmt}: {n} ключей -> {path}",
        "log_log_copied": "Лог скопирован в буфер обмена",
        "log_log_empty": "Лог пуст",
        "log_copy_err": "Ошибка копирования: {err}",
        "pool_type_model": "модель",
        "pool_type_provider": "провайдер",
        "pool_no_confirmed": "X нет confirmed",
        "pool_details_hint": "Детали (выберите модель или провайдера слева)",
        "pool_providers_for": "Провайдеры модели:",
        "pool_models_for": "Модели провайдера:",
        "pool_endpoints_n": "Эндпоинтов: {n}",
        "pool_models_n": "Моделей: {n}",
        # Scanner / worker logs
        "log_async_db_ready": "Асинхронная база данных инициализирована",
        "log_async_db_closed": "Асинхронная база данных закрыта",
        "log_db_init_done": "Инициализация базы данных завершена: {path} (отсканировано файлов: {blobs}, ключей в базе: {keys})",
        "log_source_enabled": "[{src}] Источник сканирования включен",
        "log_searching": "Поиск \"{kw}\"...",
        "log_search_kw": "Поиск: {kw}",
        "log_github_api_query": "Запрос к GitHub API: {q}",
        "log_keyword_projects": "Ключевое слово '{kw}': {n} проектов",
        "log_stale_killed_scanner": "Завершено старых процессов сканера/TUI: {n}",
        "log_perf_stats": "Статистика производительности: {stats}",
        "err_no_github_tokens": "GitHub Tokens не настроены",
        "err_no_db_path": "Путь к базе данных не настроен",
        "err_bad_proxy": "Неверный формат адреса прокси: {url}",
        "pool_added_model": "Добавлено в модели: {name}",
        "pool_added_provider": "Добавлено в провайдеры: {name}",
        "pool_removed": "Удалено: {name}",
        "pool_removed_pair": "Удалено: {name} @ {endpoint}",
        "log_token_rejected": "GitHub-токен отбракован (401 Bad credentials): …{tail}",
        "log_token_added": "Добавлен найденный GitHub токен: {prefix}... (@{user})",
        "log_sha_cache_loaded": "Загружено {n} SHA в кэш памяти",
        "log_sha_load_err": "Ошибка загрузки SHA: {err}",
        "log_skip_key": "Пропуск {key} ({reason})",
        "log_skip_url": "Пропуск {key} (URL: {reason})",
        "log_tokens_exhausted": "Все токены исчерпаны, ожидание {s:.0f}с...",
        "log_processed_results": "Обработано {n} результатов (SHA пропущено: {skip})",
        "log_rate_limit": "Ограничение частоты запросов, переключение токена...",
        "log_all_tokens_dead": "Все GitHub-токены отбракованы (401). Проверь config.github_tokens.",
        "log_api_error": "Ошибка API: {err}",
        "log_search_error": "Ошибка поиска: {err}",
        "log_resume_checkpoint": "Возобновление с точки останова: ключевое слово {cur}/{total}",
        "log_no_checkpoint": "Действительная точка останова не найдена, начало сканирования с начала",
        "log_auto_restart": "Авто-рестарт: новый прогон сканирования...",
        "log_tokens_pause": "GitHub: все токены 401. Пауза 60с, повтор раунд...",
    },
}


def detect_system_lang() -> Lang:
    """Return 'ru' if OS locale is Russian, else 'en'."""
    env = (os.environ.get("TUI_LANG") or "").strip().lower()
    if env in ("en", "ru"):
        return env  # type: ignore[return-value]
    if env in ("auto", ""):
        pass
    try:
        loc = locale.getlocale()
        name = " ".join(x for x in loc if x) if loc else ""
    except Exception:
        name = ""
    if not name:
        try:
            name = locale.setlocale(locale.LC_CTYPE) or ""
        except Exception:
            name = ""
    if not name:
        name = os.environ.get("LANG") or os.environ.get("LC_ALL") or ""
    low = name.lower()
    if low.startswith("ru") or "russian" in low or "ru_ru" in low:
        return "ru"
    return "en"


def load_lang_pref() -> LangPref:
    """Read UI_LANG from env or config_local (auto|en|ru)."""
    env = (os.environ.get("TUI_LANG") or "").strip().lower()
    if env in ("en", "ru", "auto"):
        return env  # type: ignore[return-value]
    try:
        import config_local  # type: ignore

        raw = str(getattr(config_local, "UI_LANG", "auto") or "auto").strip().lower()
        if raw in ("en", "ru", "auto"):
            return raw  # type: ignore[return-value]
    except Exception:
        pass
    return "auto"


def resolve_lang(pref: LangPref | None = None) -> Lang:
    p = pref if pref is not None else load_lang_pref()
    if p == "auto":
        return detect_system_lang()
    return p  # type: ignore[return-value]


def t(key: str, lang: Lang | None = None) -> str:
    lg = lang or resolve_lang()
    return _STRINGS.get(lg, _STRINGS["en"]).get(key) or _STRINGS["en"].get(key, key)

def tf(key: str, lang: Lang | None = None, **kwargs) -> str:
    """Translate and format with {placeholders}."""
    try:
        return t(key, lang).format(**kwargs)
    except Exception:
        return t(key, lang)


def save_lang_pref(pref: LangPref) -> None:
    """Persist UI_LANG into config_local.py (create or update)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config_local.py")
    line = f'UI_LANG = "{pref}"\n'
    try:
        if os.path.isfile(path):
            text = open(path, encoding="utf-8", errors="replace").read()
            if "UI_LANG" in text:
                import re

                text = re.sub(
                    r'^UI_LANG\s*=\s*[^\n]+\n?',
                    line,
                    text,
                    count=1,
                    flags=re.M,
                )
            else:
                text = text.rstrip() + "\n\n# TUI language: auto | en | ru\n" + line
            open(path, "w", encoding="utf-8", newline="\n").write(text)
        else:
            # НЕ пишем GITHUB_TOKENS = [] — пустой список затирал бы токены
            # из env при следующем импорте config (guard в config.py тоже
            # есть, но лучше не создавать триггер вовсе).
            open(path, "w", encoding="utf-8", newline="\n").write(
                "# Auto-created for UI language preference\n"
                f"# TUI language: auto | en | ru\n{line}"
            )
    except OSError:
        pass
