"""Синхронизация списков моделей с провайдерами.

Провайдеры добавляют и убирают модели, а `key_models` заполнялась только в
момент валидации ключа — список во вкладке «Модели» и в `/v1/models` прокси
замирал на снапшоте. Здесь список перечитывается через GET /models и
сливается с БД (`Database.sync_key_models`), поэтому:

- новые модели появляются в списке без перевалидации ключа;
- модели, которых провайдер больше не отдаёт, снимаются с подтверждения и
  удаляются после второго пропуска подряд (защита от одиночного сбоя);
- один запрос на эндпоинт: список моделей у всех ключей одного base_url
  одинаковый, ключи перебираются только чтобы обойти 401/403.

Запуск: `main_optimized.py --refresh-models` или фоновой задачей прокси
(POST /admin/refresh-models дергает то же самое принудительно).
"""
from __future__ import annotations

import asyncio
import ssl
from typing import List, Optional, Tuple

import aiohttp
from loguru import logger

from database import Database

TIMEOUT = aiohttp.ClientTimeout(total=25, connect=8)
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0 Safari/537.36")
MAX_KEYS_PER_ENDPOINT = 3


def model_urls(base_url: str) -> List[str]:
    """Кандидаты URL для списка моделей (порядок = приоритет)."""
    root = (base_url or "").strip().strip("/")
    for suffix in ("/chat/completions", "/completions", "/models"):
        if root.endswith(suffix):
            root = root[: -len(suffix)]
            break
    if not root:
        return []
    if not root.startswith("http"):
        root = "https://" + root
    if root.endswith("/v1") or root.endswith("/v1beta") or root.endswith("/api/v1"):
        return [f"{root}/models"]
    return [f"{root}/v1/models", f"{root}/models"]


def auth_headers(api_key: str, base_url: str, platform: str = "") -> dict:
    plat = (platform or "").lower()
    if plat == "gemini" or "googleapis.com" in (base_url or ""):
        return {"x-goog-api-key": api_key, "Accept": "application/json",
                "User-Agent": UA}
    if plat == "anthropic" or "anthropic.com" in (base_url or ""):
        return {"x-api-key": api_key, "anthropic-version": "2023-06-01",
                "Accept": "application/json", "User-Agent": UA}
    return {"Authorization": f"Bearer {api_key}",
            "Accept": "application/json", "User-Agent": UA}


def parse_models(payload) -> List[str]:
    """Идентификаторы моделей из ответа /models (OpenAI, Gemini, OpenRouter)."""
    items = []
    if isinstance(payload, dict):
        raw = payload.get("data")
        if isinstance(raw, dict):  # некоторые шлюзы: {"data": {"models": [...]}}
            raw = raw.get("models")
        if not isinstance(raw, list):
            raw = payload.get("models")
    else:
        raw = payload
    if not isinstance(raw, list):
        return []
    for item in raw:
        mid = ""
        if isinstance(item, str):
            mid = item
        elif isinstance(item, dict):
            mid = item.get("id") or item.get("name") or item.get("model") or ""
        mid = str(mid).strip()
        if mid.startswith("models/"):  # Gemini: models/gemini-2.5-flash
            mid = mid[len("models/"):]
        if mid:
            items.append(mid)
    seen = set()
    out = []
    for m in items:
        if m.lower() not in seen:
            seen.add(m.lower())
            out.append(m)
    return out


async def _fetch_endpoint_models(session: aiohttp.ClientSession,
                                 base_url: str, keys: List[dict]) -> Tuple[List[str], int, str]:
    """Список моделей эндпоинта: перебор ключей и URL-вариантов.

    Возвращает (models, status, error). models пуст при неудаче.
    """
    last_status = 0
    last_error = ""
    for key in keys[:MAX_KEYS_PER_ENDPOINT]:
        headers = auth_headers(key["api_key"], base_url, key.get("platform", ""))
        for url in model_urls(base_url):
            try:
                async with session.get(url, headers=headers) as resp:
                    last_status = resp.status
                    if resp.status == 200:
                        try:
                            payload = await resp.json(content_type=None)
                        except Exception as exc:
                            last_error = f"json: {type(exc).__name__}"
                            continue
                        models = parse_models(payload)
                        if models:
                            return models, 200, ""
                        last_error = "empty model list"
                        continue
                    if resp.status in (401, 403):
                        last_error = f"HTTP {resp.status}"
                        break  # ключ отвергнут — следующий ключ
                    if resp.status == 404:
                        last_error = "HTTP 404"
                        continue  # другой URL-вариант
                    last_error = f"HTTP {resp.status}"
            except Exception as exc:
                last_error = f"{type(exc).__name__}: {str(exc)[:80]}"
                continue
    return [], last_status, last_error


async def refresh_models(db: Database, *, stale_hours: float = 6.0,
                         limit: int = 0, force: bool = False,
                         only_base_url: str = "", concurrency: int = 6,
                         log=logger) -> dict:
    """Обновить списки моделей у провайдеров.

    stale_hours: не трогать эндпоинты, синхронизированные раньше, чем N часов
    назад (force=True игнорирует). limit: сколько эндпоинтов за прогон (0 = все).
    """
    # limit применяется ПОСЛЕ фильтра по base_url: иначе
    # --models-base-url при limit=1 получал чужой первый эндпоинт и пустой список.
    targets = db.get_model_sync_targets(
        stale_hours=0 if force else stale_hours,
        limit=0 if only_base_url else limit)
    if only_base_url:
        targets = [t for t in targets if t["base_url"] == only_base_url]
        if limit:
            targets = targets[:limit]

    stats = {"endpoints": len(targets), "ok": 0, "failed": 0,
             "added": 0, "removed": 0, "demoted": 0, "keys": 0,
             "errors": []}
    if not targets:
        return stats

    ssl_ctx = ssl.create_default_context()
    connector = aiohttp.TCPConnector(
        limit=concurrency * 2, limit_per_host=2, ssl=ssl_ctx,
        resolver=aiohttp.resolver.ThreadedResolver(), force_close=False,
        use_dns_cache=True, ttl_dns_cache=300, enable_cleanup_closed=True)
    semaphore = asyncio.Semaphore(concurrency)

    async with aiohttp.ClientSession(connector=connector, timeout=TIMEOUT,
                                     trust_env=True) as session:

        async def one(target: dict) -> None:
            base_url = target["base_url"]
            keys = db.get_live_keys_for_endpoint(base_url)
            if not keys:
                return
            async with semaphore:
                models, status, error = await _fetch_endpoint_models(
                    session, base_url, keys)
            if not models:
                db.record_model_sync(base_url, target.get("platform", ""), 0,
                                     "error" if status != 200 else "empty",
                                     error)
                stats["failed"] += 1
                if len(stats["errors"]) < 10:
                    stats["errors"].append(
                        f"{base_url}: HTTP {status or '-'} {error}")
                return
            synced = 0
            for key in keys:
                res = db.sync_key_models(key["api_key"], models, authoritative=True)
                stats["added"] += res["added"]
                stats["removed"] += res["removed"]
                stats["demoted"] += res["demoted"]
                synced += 1
            stats["keys"] += synced
            stats["ok"] += 1
            db.record_model_sync(base_url, target.get("platform", ""),
                                 len(models), "ok")
            log.debug(f"models sync {base_url}: {len(models)} моделей, "
                      f"ключей {synced}, +{stats['added']}")

        await asyncio.gather(*[one(t) for t in targets], return_exceptions=True)

    log.info(f"Модели: эндпоинтов {stats['endpoints']}, ок {stats['ok']}, "
             f"ошибок {stats['failed']}, ключей {stats['keys']}; "
             f"+{stats['added']} новых, -{stats['removed']} убранных, "
             f"{stats['demoted']} снято с подтверждения")
    return stats


def refresh_models_sync(db: Database, **kwargs) -> dict:
    """Синхронная обёртка для CLI/потоков."""
    return asyncio.run(refresh_models(db, **kwargs))
