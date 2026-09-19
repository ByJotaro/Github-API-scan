#!/usr/bin/env python3
"""
Фоновый движок перебора UNVERIFIED ключей по реальным эндпоинтам.

Главная задача — превратить сетевые UNVERIFIED ключи (gemini, relay, openai,
anthropic, …) в VALID/CONFIRMED/QUOTA/INVALID через реальную проверку
(не только GET /models, как validate_single, но и generateContent/chat).

Ключевая дыра, которую закрывает модуль:
  validate_gemini делал только GET /models → 3954 gemini застряли в UNVERIFIED.
  Здесь gemini гоняется через validate_gemini_deep (GET /models → generateContent).

КРИТИЧЕСКИЙ ИНВАРИИАНТ (см. план):
  database.update_key_status ВСЕГДА прописывает verified_time = now().
  Поэтому вызывать update_key_status ТОЛЬКО при переходе в терминальный/
  улучшенный статус (VALID/CONFIRMED/QUOTA/INVALID). Для оставшихся
  UNVERIFIED/CONNECTION_ERROR — только increment_confirm_attempts (без
  update_key_status), иначе ключ получит verified_time и навсегда выпадет из
  выборки verified_time IS NULL.

Запуск:
    python unverified_drainer.py [--limit N] [--workers W] [--max-attempts M]
"""
import argparse
import asyncio
import os
import random
import sys
import time
from types import SimpleNamespace
from typing import Dict, List

from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import Database, KeyStatus
from validator import AsyncValidator, ValidationResult
from config import config

# Loguru: писать прогресс дрейна в scanner.log, чтобы он отображался в живом
# логе TUI (#mlog читает scanner.log). Без этого sink'а логи уходили в stderr
# и не были видны в TUI. Добавляем idempotently — проверяем, нет ли уже sink'а
# с этим же файлом (иначе каждая строка дублировалась: сканер + дрейн).
_LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "scanner.log")


def _has_log_sink(path: str) -> bool:
    """Уже есть ли loguru-sink с этим файлом назначения?"""
    try:
        for h in logger._core.handlers.values():
            sink = h._sink
            fn = getattr(sink, "_path", None) or getattr(sink, "_file", None)
            if fn and os.path.abspath(str(fn)) == os.path.abspath(path):
                return True
    except Exception:
        pass
    return False


if not _has_log_sink(_LOG_FILE):
    logger.add(_LOG_FILE, level="INFO",
               format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {message}",
               rotation="10 MB", retention="3 days", enqueue=True,
               backtrace=False, diagnose=False)


# --- Сетевые платформы: те, у кого есть проверяемый онлайн-эндпоинт -----------
# Обратное дополнение к AsyncValidator._UNVERIFIABLE + облачным bulk-ключам,
# которые нельзя проверить онлайн. Берём из config.default_base_urls (непустой
# URL — признак наличия эндпоинта) и вычитаем unverifiable.
_BULK_UNVERIFIABLE = frozenset({
    "aws_secret_key", "aws_access_key", "shadeform", "modal",
    "google_api_key", "firebase", "heroku", "figma_token",
    "runpod", "lambdalabs", "coreweave",
    "digitalocean", "linode", "vultr", "hetzner", "scaleway",
})


def _network_platforms() -> List[str]:
    """Платформы с проверяемым онлайн-эндпоинтом (из config.default_base_urls)."""
    return sorted([
        p for p, url in config.default_base_urls.items()
        if url and p not in _BULK_UNVERIFIABLE
    ])


# GEMINI_CANDIDATES — fallback-модели для generateContent, когда /models
# не отдал список (403/400/404).
GEMINI_CANDIDATES = [
    "gemini-2.5-flash", "gemini-2.0-flash",
    "gemini-1.5-flash", "gemini-1.5-pro",
    "gemini-flash-latest",
]


def _build_scan_result(key_row: dict) -> SimpleNamespace:
    return SimpleNamespace(
        platform=key_row.get("platform", ""),
        api_key=key_row.get("api_key", ""),
        base_url=key_row.get("base_url", ""),
        source_url=key_row.get("source_url", ""),
        is_azure=key_row.get("platform", "").lower() == "azure",
    )


# Кеш известных эндпоинтов по платформам (построение раз в запуск дрейна).
# Берётся из БД: все base_url, на которых хотя бы один ключ дал валидный ответ,
# плюс дефолтный URL платформы из config.default_base_urls. Это даёт дрейну
# набор «точно живых» хостов, чтобы перебирать их с базовой проверкой доступа.
_ENDPOINTS_CACHE: Dict[str, List[str]] = {}
_ENDPOINTS_LOADED = False

# Модульный флаг отмены дрейна. TUI выставляет через request_drain_cancel().
# Без него дрейн проходит весь набор UNVERIFIED (тысячи ключей, часы).
_CANCEL_REQUESTED = False

# Текущий прогресс дрейна для отображения в TUI (done/total). TUI читает.
CURRENT_PROGRESS: Dict[str, int] = {"done": 0, "total": 0}


def request_drain_cancel() -> None:
    """Запросить мягкую остановку дрейна (из TUI)."""
    global _CANCEL_REQUESTED
    _CANCEL_REQUESTED = True


def is_drain_cancelled() -> bool:
    return _CANCEL_REQUESTED


def _load_known_endpoints(db: Database) -> None:
    """Загрузить из БД уникальные рабочие эндпоинты по каждой платформе.

    Рабочий = base_url, на котором есть хотя бы один ключ со статусом
    valid/confirmed/quota_exceeded (значит хост отвечает на API-запросы).
    """
    global _ENDPOINTS_LOADED
    cache: Dict[str, List[str]] = {}
    try:
        with db._get_connection() as conn:
            rows = conn.execute(
                "SELECT platform, base_url FROM leaked_keys "
                "WHERE base_url != '' "
                "AND status IN ('valid','confirmed','quota_exceeded') "
                "GROUP BY platform, base_url"
            ).fetchall()
        for r in rows:
            plat = (r["platform"] or "").lower()
            url = r["base_url"]
            if plat and url:
                cache.setdefault(plat, [])
                if url not in cache[plat]:
                    cache[plat].append(url)
        # Добавить дефолтный URL каждой сетевой платформы
        for plat, default in config.default_base_urls.items():
            if default and default not in cache.get(plat, []):
                cache.setdefault(plat, []).append(default)
    except Exception as e:
        logger.debug(f"_load_known_endpoints error: {e}")
    _ENDPOINTS_CACHE.clear()
    _ENDPOINTS_CACHE.update(cache)
    _ENDPOINTS_LOADED = True
    total = sum(len(v) for v in cache.values())
    logger.info(f"[drain] загружено эндпоинтов: {total} "
                f"по {len(cache)} платформам")


def _status_rank(s: KeyStatus) -> int:
    """Чем выше ранг — тем лучше статус."""
    return {
        KeyStatus.CONFIRMED: 6,
        KeyStatus.VALID: 5,
        KeyStatus.QUOTA_EXCEEDED: 4,
        KeyStatus.UNVERIFIED: 3,
        KeyStatus.CONNECTION_ERROR: 2,
        KeyStatus.INVALID: 1,
        KeyStatus.PENDING: 0,
    }.get(s, 0)


async def _validate_key(validator: AsyncValidator, key_row: dict) -> tuple:
    """
    Проверить один ключ глубоко. Возвращает (ValidationResult, resolved_url).

    Для gemini — validate_gemini_deep (GET /models + generateContent).
    Для прочих — validate_single с подстановкой дефолтного URL при пустом.
    """
    platform = (key_row.get("platform") or "").lower()
    api_key = key_row.get("api_key", "")
    base_url = key_row.get("base_url", "") or ""
    resolved_url = base_url

    if platform == "gemini":
        # Gemini агрессивно режет 429 (per-minute quota). Временный rate-limit
        # не означает невалидность ключа — повторим пару раз с паузой.
        vr = None
        for attempt in range(3):
            vr = await validator.validate_gemini_deep(
                api_key, base_url, GEMINI_CANDIDATES)
            if vr.status != KeyStatus.QUOTA_EXCEEDED:
                break
            if attempt < 2:
                await asyncio.sleep(2.0 * (attempt + 1))
        return vr, resolved_url or config.default_base_urls.get("gemini", "")

    # Прочие сетевые платформы — перебор всех известных эндпоинтов
    # с базовой проверкой доступа (GET /models для openai-compat).
    result = _build_scan_result(key_row)

    # Сформировать упорядоченный список кандидатов-эндпоинтов:
    #   1) свой base_url ключа (если есть)
    #   2) дефолтный URL платформы
    #   3) все известные рабочие эндпоинты этой платформы из БД
    candidates: List[str] = []
    if base_url:
        candidates.append(base_url)
    default = config.default_base_urls.get(platform, "")
    if default and default not in candidates:
        candidates.append(default)
    for ep in _ENDPOINTS_CACHE.get(platform, []):
        if ep not in candidates:
            candidates.append(ep)

    if not candidates:
        return (ValidationResult(KeyStatus.UNVERIFIED, "Нет base_url"),
                base_url)

    best_vr = None
    resolved_url = base_url
    for url in candidates:
        result.base_url = url
        try:
            vr = await validator.validate_single(result)
        except Exception as e:
            logger.debug(f"probe {url[:40]} error: {e}")
            continue
        # Положительные ответы — выходим сразу. QUOTA (429) для non-gemini —
        # часто временный rate-limit: повторим этот же эндпоинт 2× с паузой,
        # прежде чем признать QUOTA терминальной.
        if vr.status in (KeyStatus.VALID, KeyStatus.CONFIRMED):
            return vr, url
        if vr.status == KeyStatus.QUOTA_EXCEEDED:
            quota_vr = vr
            resolved = False
            for attempt in range(2):
                await asyncio.sleep(2.0 * (attempt + 1))
                try:
                    vr2 = await validator.validate_single(result)
                except Exception:
                    break
                if vr2.status in (KeyStatus.VALID, KeyStatus.CONFIRMED):
                    return vr2, url
                if vr2.status != KeyStatus.QUOTA_EXCEEDED:
                    quota_vr = vr2
                    resolved = True
                    break
            # Не разрешилось — QUOTA терминален, либо новый статус (quota_vr
            # уже переприсвоен на vr2 при resolved=True). Оба случая — (vr, url).
            return quota_vr, url
        # Явный отказ auth (ключ отозван) — не имеет смысла пробовать другие
        # эндпоинты: ключ мёртв везде. INVALID с auth-маркером = терминал.
        if vr.status == KeyStatus.INVALID:
            info_lower = (vr.info or "").lower()
            if any(k in info_lower for k in
                   ("auth", "отвергнут", "401", "api key not valid",
                    "permission_denied", "недействителен")):
                return vr, url
            # INVALID без auth-маркера (модель/формат) — запомним, проверим др.
        # Запоминаем лучший нетерминальный результат
        if best_vr is None or _status_rank(vr.status) > _status_rank(best_vr.status):
            best_vr = vr
            resolved_url = url
        # UNVERIFIED/CONNECTION_ERROR — пробуем следующий эндпоинт

    return (best_vr if best_vr is not None
            else ValidationResult(KeyStatus.UNVERIFIED, "Все эндпоинты молчат"),
            resolved_url)


async def _worker(
    validator: AsyncValidator,
    db: Database,
    rows: List[dict],
    stats: dict,
    semaphore: asyncio.Semaphore,
    progress: dict,
    max_attempts: int,
):
    """Обработать батч UNVERIFIED ключей."""
    confirm_platforms = {
        'openai', 'relay', 'xai', 'openrouter', 'cerebras', 'groq',
        'deepseek', 'perplexity', 'together', 'mistral', 'fireworks',
        'moonshot', 'siliconflow', 'dashscope', 'anthropic', 'gemini',
        'huggingface', 'replicate', 'cohere', 'anyscale', 'lepton',
        'jina', 'voyage', 'zhipu', 'yi', 'baichuan', 'stepfun',
        'minimax', 'internlm', 'volcengine',
    }
    pending_url_updates: List[tuple] = []  # (api_key, new_url) — batch в конце

    async def _process_one(key_row: dict) -> None:
        """Обработать один ключ под semaphore (запускаются конкурентно)."""
        if progress["cancelled"]:
            return
        api_key = key_row.get("api_key", "")
        platform = (key_row.get("platform") or "").lower()
        old_url = key_row.get("base_url", "") or ""

        async with semaphore:
            done = progress["done"] = progress["done"] + 1
            CURRENT_PROGRESS["done"] = done
            CURRENT_PROGRESS["total"] = progress["total"]
            if done % 50 == 0 or done == progress["total"]:
                elapsed = time.time() - progress["start"]
                rate = done / elapsed if elapsed > 0 else 0
                # Сводка ИЗ БД (cumulative, не зависит от перезапуска дрейна) —
                # реальная картина работы, а не stats текущего прогона.
                try:
                    with db._get_connection() as conn:
                        row = conn.execute(
                            "SELECT "
                            "SUM(status='confirmed') AS c, "
                            "SUM(status='valid') AS v, "
                            "SUM(status='quota_exceeded') AS q, "
                            "SUM(status='invalid') AS i "
                            "FROM leaked_keys").fetchone()
                        db_c, db_v, db_q, db_i = (row[0] or 0), (row[1] or 0), \
                            (row[2] or 0), (row[3] or 0)
                except Exception:
                    db_c = db_v = db_q = db_i = 0
                logger.info(
                    f"[drain {done}/{progress['total']}] "
                    f"({rate:.1f}/s, сессия: ✓{stats.get('confirmed',0)} "
                    f"V{stats.get('valid',0)} Q{stats.get('quota',0)} "
                    f"✗{stats.get('invalid',0)} ?{stats.get('unverified',0)}) | "
                    f"всего в БД: ✓{db_c} V{db_v} Q{db_q} ✗{db_i}")
            try:
                vr, resolved_url = await _validate_key(validator, key_row)
                status = vr.status

                # ---- КЛЮЧЕВОЙ блок: запись по статусу (инвариант) ----
                if status == KeyStatus.VALID:
                    # _confirm_gemini возвращает VALID с info "Подтверждён"
                    # — это реальная генерация, значит CONFIRMED.
                    if "Подтверждён" in (vr.info or ""):
                        db.update_key_status(
                            api_key, KeyStatus.CONFIRMED,
                            balance=vr.info or "")
                        if vr.models:
                            for m in vr.models:
                                db.mark_model_confirmed(api_key, m)
                        stats["confirmed"] = stats.get("confirmed", 0) + 1
                    else:
                        # VALID через /models — обычный VALID
                        balance = ""
                        if vr.balance_usd and vr.balance_usd > 0:
                            balance = f"${vr.balance_usd:.2f}"
                        db.update_key_status(
                            api_key, KeyStatus.VALID,
                            balance=balance or (vr.info or ""),
                            model_tier=vr.model_tier, rpm=vr.rpm,
                            is_high_value=vr.is_high_value)
                        if vr.models:
                            db.save_key_models(api_key, vr.models)
                            logger.info(
                                f"[drain] ✓ VALID {platform} "
                                f"{api_key[:10]}… : {len(vr.models)} моделей")
                        # Опционально поднять до CONFIRMED для chat-платформ
                        became_confirmed = False
                        if (platform in confirm_platforms and resolved_url
                                and vr.models):
                            try:
                                cr = await validator.confirm_key(
                                    api_key, resolved_url, vr.models,
                                    platform=platform)
                                if (cr.status == KeyStatus.VALID
                                        and "Подтверждён" in (cr.info or "")):
                                    db.update_key_status(
                                        api_key, KeyStatus.CONFIRMED,
                                        balance=cr.info or "")
                                    if cr.models:
                                        for m in cr.models:
                                            db.mark_model_confirmed(
                                                api_key, m)
                                    became_confirmed = True
                                    stats["confirmed"] = (
                                        stats.get("confirmed", 0) + 1)
                            except Exception as e:
                                logger.debug(f"drain confirm error: {e}")
                        # Считаем VALID только если НЕ повышен до CONFIRMED
                        if not became_confirmed:
                            stats["valid"] = stats.get("valid", 0) + 1
                    # Запомнить обновление base_url для batch-записи
                    if resolved_url and resolved_url != old_url:
                        pending_url_updates.append((resolved_url, api_key))

                elif status == KeyStatus.QUOTA_EXCEEDED:
                    db.update_key_status(
                        api_key, KeyStatus.QUOTA_EXCEEDED,
                        balance=vr.info or "Квота исчерпана")
                    stats["quota"] = stats.get("quota", 0) + 1
                    if resolved_url and resolved_url != old_url:
                        pending_url_updates.append((resolved_url, api_key))

                elif status == KeyStatus.INVALID:
                    db.update_key_status(
                        api_key, KeyStatus.INVALID,
                        balance=vr.info or "Недействителен")
                    stats["invalid"] = stats.get("invalid", 0) + 1

                else:
                    # UNVERIFIED / CONNECTION_ERROR / PENDING
                    current_attempts = db.increment_confirm_attempts(api_key)
                    # Gemini 403 "доступ ограничен" — сразу QUOTA (после 1 попытки).
                    # 403 = API не включён в проекте. Это не rate-limit.
                    # Прекращает бесконечный цикл 403 → UNVERIFIED → 403.
                    if (status == KeyStatus.UNVERIFIED
                            and platform == "gemini"
                            and "доступ" in (vr.info or "")):
                        db.update_key_status(
                            api_key, KeyStatus.QUOTA_EXCEEDED,
                            balance="Gemini: доступ ограничен (403)")
                        stats["quota"] = stats.get("quota", 0) + 1
                    elif status == KeyStatus.CONNECTION_ERROR:
                        stats["connection_error"] = (
                            stats.get("connection_error", 0) + 1)
                    else:
                        stats["unverified"] = stats.get("unverified", 0) + 1

                # Троттлинг: gemini агрессивно режет 429
                if platform == "gemini":
                    await asyncio.sleep(random.uniform(0.05, 0.2))

            except Exception as e:
                logger.debug(f"drain error {api_key[:12]}: {e}")
                stats["error"] = stats.get("error", 0) + 1

    # Запускаем все ключи батча конкурентно под общим semaphore (workers).
    # Раньше semaphore был в одной корутине → бесполезен (строго последовательно).
    await asyncio.gather(*[_process_one(r) for r in rows])

    # ---- Пакетная запись base_url (4.3): одна транзакция вместо N ----
    if pending_url_updates:
        try:
            with db._lock:
                with db._get_connection() as conn:
                    conn.executemany(
                        "UPDATE leaked_keys SET base_url = ? WHERE api_key = ?",
                        pending_url_updates)
                    conn.commit()
        except Exception as e:
            logger.debug(f"drain batch base_url error: {e}")


async def drain_unverified(
    db: Database,
    limit: int = 0,
    workers: int = 8,
    max_attempts: int = 5,
    batch_size: int = 100,
) -> dict:
    """
    Прогнать сетевые UNVERIFIED ключи через реальную проверку.

    Args:
        limit: 0 = все; иначе ограничить общее число обработанных.
        workers: конкурентность (gemini режет 429 — держим небольшой).
        max_attempts: лимит confirm_attempts; ключи с attempts >= max skip.
        batch_size: размер страницы SQL-выборки (точка отмены/отдачи прогресса).

    Возвращает словарь stats.

    Фильтр выборки — confirm_attempts < max_attempts (а НЕ verified_time IS
    NULL: у исторических данных verified_time уже заполнен для всех unverified).
    Курсор всегда OFFSET 0: после обработки ключ либо меняет статус, либо
    инкрементит confirm_attempts — в обоих случаях выпадает из следующей
    выборки, поэтому пагинация по OFFSET не нужна и не даёт дублей/пропусков.
    """
    validator = AsyncValidator(db)
    validator._circuit_breaker.reset()

    # Загрузить известные рабочие эндпоинты для перебора (раз в запуск)
    if not _ENDPOINTS_LOADED:
        _load_known_endpoints(db)

    platforms = _network_platforms()
    stats = {"total": 0, "confirmed": 0, "valid": 0, "invalid": 0,
             "quota": 0, "connection_error": 0, "unverified": 0,
             "pending": 0, "error": 0}
    progress = {"done": 0, "total": 0, "start": time.time(),
                "cancelled": False}

    semaphore = asyncio.Semaphore(workers)
    placeholders = ",".join("?" * len(platforms))
    # Gemini часто отдаёт transient 403/429 (rate-limit, не отзыв ключа) —
    # его перепроверяем с бóльшим лимитом попыток, чем прочие платформы.
    gemini_max = max(max_attempts * 3, 15)

    # Условие выборки: gemini — расширенный лимит, остальные — обычный.
    where_clause = (
        f"status='unverified' AND platform IN ({placeholders}) "
        f"AND ((platform='gemini' AND confirm_attempts < ?) "
        f"     OR (platform!='gemini' AND confirm_attempts < ?))")

    # Оценка общего числа для прогресса (один раз, до цикла)
    with db._get_connection() as conn:
        total_count = conn.execute(
            f"SELECT COUNT(*) FROM leaked_keys WHERE {where_clause}",
            (*platforms, gemini_max, max_attempts),
        ).fetchone()[0]
    progress["total"] = total_count
    logger.info(f"[drain] ключей к проверке: {total_count}, workers={workers} "
                f"(gemini лимит {gemini_max}, прочие {max_attempts})")

    total_done = 0
    global _CANCEL_REQUESTED
    _CANCEL_REQUESTED = False  # сброс флага отмены на новый запуск
    try:
        while not progress["cancelled"] and not _CANCEL_REQUESTED:
            if limit and total_done >= limit:
                break
            # Guard против бесконечного цикла: один проход по выборке, не больше
            # total_count уникальных ключей. Раньше 403-ключи (без смены статуса)
            # выбирались повторно → done рос сверх total (3600/3562).
            if total_done >= total_count:
                break
            page = batch_size
            if limit and total_done + page > limit:
                page = max(1, limit - total_done)
            if total_done + page > total_count:
                page = max(1, total_count - total_done)

            with db._get_connection() as conn:
                rows = [dict(r) for r in conn.execute(
                    f"SELECT * FROM leaked_keys WHERE {where_clause} "
                    f"ORDER BY confirm_attempts ASC, found_time ASC LIMIT ?",
                    (*platforms, gemini_max, max_attempts, page),
                ).fetchall()]

            if not rows:
                break

            await _worker(validator, db, rows, stats, semaphore, progress,
                          max_attempts)

            total_done += len(rows)
    finally:
        # Закрыть aiohttp-сессию (иначе «Unclosed client session» в фоне)
        try:
            await validator.close()
        except Exception:
            pass

    elapsed = time.time() - progress["start"]
    logger.info(f"[drain] === Готово за {elapsed:.0f}s, "
                f"обработано {total_done} ===")
    for k, v in sorted(stats.items()):
        if k != "total" and v:
            logger.info(f"  {k}: {v}")
    stats["total"] = total_done
    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Фоновый дрейн UNVERIFIED ключей")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--workers", type=int, default=10)
    parser.add_argument("--max-attempts", type=int, default=5)
    parser.add_argument("--batch", type=int, default=200)
    args = parser.parse_args()
    db = Database(config.db_path)
    asyncio.run(drain_unverified(
        db, limit=args.limit, workers=args.workers,
        max_attempts=args.max_attempts, batch_size=args.batch))


if __name__ == "__main__":
    main()
