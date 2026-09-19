#!/usr/bin/env python3
"""
Локальный OpenAI-совместимый прокси-сервер с ротацией ключей/эндпоинтов.

Запуск:
    python proxy_server.py [--port 8818]

Использование:
    OpenAI-совместимые приложения → http://localhost:8818/v1/chat/completions
    Без API ключа (или с любым) — прокси сам подставляет ключи из пула.

Возможности:
- /v1/models — список моделей из active pool + все модели с эндпоинтов
- /v1/chat/completions — отправка с автоматической ротацией:
  1. Находит модель в active pool (по имени или алиасу)
  2. Берёт эндпоинты/ключи для этой модели (ротация round-robin)
  3. При 429/402 → следующий ключ, затем следующий эндпоинт
  4. Anthropic эндпоинты автоматически конвертируются в OpenAI формат
- Статистика обращений: /stats
- Управление пулом: /pool/add, /pool/remove, /pool/list
"""
import argparse
import asyncio
import json
import os
import sys
import time
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional, Tuple
from collections import Counter, deque

import aiohttp
import ssl
from aiohttp import web, TCPConnector
from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Трейс запросов прокси (ring buffer, последние 200 событий). TUI читает для
# панели «Трейс запросов»: попытки ключей со статусами, итог запроса.
TRACE: Deque[Dict[str, Any]] = deque(maxlen=200)
_trace_counter = 0


def push_trace(model: str, attempt: int, key_masked: str, endpoint: str,
               status: int, detail: str = "") -> None:
    """Записать событие трейса запроса (попытка ключа)."""
    global _trace_counter
    _trace_counter += 1
    TRACE.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "req_id": _trace_counter,
        "model": model,
        "attempt": attempt,
        "key": key_masked,
        "endpoint": endpoint,
        "status": status,  # 200/429/401/None
        "detail": detail,  # ✓/⚠/✗ + описание
    })


def push_trace_summary(model: str, success: bool, attempts: int,
                       detail: str = "") -> None:
    """Записать итог запроса (после всех попыток)."""
    global _trace_counter
    _trace_counter += 1
    TRACE.append({
        "time": datetime.now().strftime("%H:%M:%S"),
        "req_id": _trace_counter,
        "model": model,
        "attempt": -1,  # маркер итога
        "key": "",
        "endpoint": "",
        "status": 200 if success else 503,
        "detail": ("✓ " if success else "✗ ") + detail,
        "summary": True,
    })


def get_trace(n: int = 50) -> List[Dict[str, Any]]:
    """Последние n событий трейса (для TUI)."""
    return list(TRACE)[-n:]


def _mask_key(api_key: str) -> str:
    """Короткая безопасная маска ключа для логов и трейса."""
    if len(api_key) < 12:
        return api_key[:4] + "..."
    return api_key[:8] + "..." + api_key[-4:]


def _upstream_url(endpoint: str, path: str) -> str:
    """Склеить base_url провайдера с OpenAI-compatible path.

    В базе endpoint обычно уже нормализован до API-корня (`.../v1`), но
    некоторые URL — только host (`https://api.minimaxi.com`) без `/v1`.
    Также режем известный хвост, чтобы не получить `/chat/completions/...`.
    """
    endpoint = (endpoint or "").rstrip("/")
    path = path.strip("/")
    for suffix in (
        "/chat/completions", "/completions", "/embeddings", "/responses",
        "/models", "/messages",
    ):
        if endpoint.lower().endswith(suffix):
            endpoint = endpoint[:-len(suffix)].rstrip("/")
            break
    # OpenAI-совместимые пути всегда под /v1/...
    # host-only base like https://api.minimaxi.com → .../v1/chat/completions
    el = endpoint.lower()
    if path and not path.startswith("v1/") and not any(
        el.endswith(s) for s in ("/v1", "/v1beta", "/v1alpha", "/openai/v1")
    ):
        endpoint = endpoint + "/v1"
    return f"{endpoint}/{path}"


async def _read_response(resp: aiohttp.ClientResponse) -> Tuple[Any, str]:
    """Прочитать JSON или текст ответа провайдера без падения на text/html."""
    text = await resp.text()
    if not text:
        return {}, ""
    try:
        return json.loads(text), text
    except Exception:
        return {"raw": text}, text

from database import Database
from config import config


# ---------------------------------------------------------------------------
# Пул активных моделей/эндпоинтов
# ---------------------------------------------------------------------------

class ActivePool:
    """Управление пулом активных моделей и привязанных эндпоинтов/ключей."""

    def __init__(self, db: Database):
        self.db = db
        self._lock = asyncio.Lock()
        # model_name → [{"endpoint": url, "keys": [api_key,...], "platform": str}]
        # Хранится в БД (active_pool table), кэшируется в памяти.
        self._cache: Dict[str, List[Dict]] = {}
        # Ротация: model → (endpoint_idx, key_idx)
        self._rotation: Dict[str, List[int]] = {}
        # Кулдаун: api_key → until_timestamp
        self._cooldowns: Dict[str, float] = {}
        self._cooldown_durations: Dict[str, int] = {}  # адаптивный кулдаун: ключ → секунды
        # Статистика: api_key → {"calls": N, "errors": N, "last_status": int}
        self._stats: Dict[str, Dict] = {}
        # Метод выбора ключа: 'round_robin' (по кругу) | 'sticky' (первый пока работает)
        self._selection_mode: str = "round_robin"
        self._load_cache()

    def _load_cache(self):
        """Загрузить active pool из БД.

        Источники с source='model' (модель добавлена явно в левую колонку) идут
        ПЕРВЫМИ — приоритет при маршрутизации. source='endpoint' (правая
        колонка) — fallback, используется только когда левые в кулдауне/недоступны.
        """
        try:
            with self.db._lock:
                with self.db._get_connection() as conn:
                    conn.execute("""
                        CREATE TABLE IF NOT EXISTS active_pool (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            model_name TEXT NOT NULL,
                            endpoint TEXT NOT NULL,
                            platform TEXT DEFAULT '',
                            api_keys TEXT DEFAULT '[]',
                            added_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                            enabled BOOLEAN DEFAULT 1,
                            UNIQUE(model_name, endpoint)
                        )
                    """)
                    # Миграция колонок source/priority/zone (если старая схема)
                    try:
                        cols = [c[1] for c in conn.execute(
                            "PRAGMA table_info(active_pool)").fetchall()]
                        if "source" not in cols:
                            conn.execute("ALTER TABLE active_pool "
                                         "ADD COLUMN source TEXT DEFAULT 'model'")
                        if "priority" not in cols:
                            conn.execute("ALTER TABLE active_pool "
                                         "ADD COLUMN priority INTEGER DEFAULT 0")
                        if "zone" not in cols:
                            conn.execute("ALTER TABLE active_pool "
                                         "ADD COLUMN zone TEXT DEFAULT 'model'")
                    except Exception:
                        pass
                    rows = conn.execute(
                        "SELECT model_name, endpoint, platform, api_keys, "
                        "enabled, source, priority, zone FROM active_pool "
                        "ORDER BY priority DESC"
                    ).fetchall()
            self._cache.clear()
            for r in rows:
                model = r[0]
                endpoint = r[1]
                platform = r[2]
                keys = json.loads(r[3]) if r[3] else []
                enabled = bool(r[4])
                source = r[5] if len(r) > 5 and r[5] else "model"
                priority = r[6] if len(r) > 6 and r[6] is not None else 0
                zone = r[7] if len(r) > 7 and r[7] else "model"
                if model not in self._cache:
                    self._cache[model] = []
                self._cache[model].append({
                    "endpoint": endpoint,
                    "platform": platform,
                    "keys": keys,
                    "enabled": enabled,
                    "source": source,
                    "priority": priority,
                    "zone": zone,
                })
            # Сортировка: source='model' первыми + priority DESC (reorder)
            for model in self._cache:
                self._cache[model].sort(
                    key=lambda e: (0 if e.get("source") == "model" else 1,
                                   -(e.get("priority", 0) or 0)))
        except Exception as e:
            logger.error(f"ActivePool load error: {e}")

    def reorder_endpoint(self, endpoint: str, direction: str) -> None:
        """Изменить приоритет эндпоинта (up=выше, down=ниже). Выше = раньше
        в маршрутизации (полезно для sticky + round-robin порядка)."""
        delta = 1 if direction == "up" else -1
        try:
            with self.db._lock:
                with self.db._get_connection() as conn:
                    conn.execute(
                        "UPDATE active_pool SET priority = "
                        "COALESCE(priority, 0) + ? WHERE endpoint=?",
                        (delta, endpoint))
                    conn.commit()
            self._load_cache()
        except Exception as e:
            logger.error(f"reorder error: {e}")

    def toggle_source(self, model: str, endpoint: str) -> None:
        """Вкл/выкл провайдера модели (enabled 0↔1)."""
        try:
            with self.db._lock:
                with self.db._get_connection() as conn:
                    conn.execute(
                        "UPDATE active_pool SET enabled = "
                        "CASE WHEN enabled=1 THEN 0 ELSE 1 END "
                        "WHERE model_name=? AND endpoint=?",
                        (model, endpoint))
                    conn.commit()
            self._load_cache()
        except Exception as e:
            logger.error(f"toggle_source error: {e}")

    def remove_source(self, model: str, endpoint: str) -> None:
        """Удалить связь модель↔эндпоинт из active_pool."""
        try:
            with self.db._lock:
                with self.db._get_connection() as conn:
                    conn.execute(
                        "DELETE FROM active_pool WHERE model_name=? AND endpoint=?",
                        (model, endpoint))
                    conn.commit()
            self._load_cache()
        except Exception as e:
            logger.error(f"remove_source error: {e}")

    def model_sources(self, model: str) -> List[Dict]:
        """Провайдеры модели (из active_pool, zone=model): для UI правой таблицы.
        endpoint, platform, priority, enabled, zone + счётчики ключей."""
        out = []
        try:
            with self.db._lock:
                with self.db._get_connection() as conn:
                    rows = conn.execute(
                        "SELECT endpoint, platform, priority, enabled, zone "
                        "FROM active_pool WHERE model_name=? "
                        "ORDER BY priority DESC", (model,)).fetchall()
                    # Ключи по статусам для каждого эндпоинта+модели
                    for r in rows:
                        ep, plat, prio, enbl, zone = r
                        kc = conn.execute(
                            "SELECT lk.status FROM key_models km "
                            "JOIN leaked_keys lk ON lk.id = km.key_id "
                            "WHERE km.model_name=? AND lk.base_url=?",
                            (model, ep)).fetchall()
                        n_keys = len(kc)
                        n_conf = sum(1 for k in kc if k[0] == "confirmed")
                        out.append({
                            "endpoint": ep, "platform": plat,
                            "priority": prio or 0,
                            "enabled": bool(enbl), "zone": zone or "model",
                            "keys": n_keys, "confirmed": n_conf,
                        })
        except Exception as e:
            logger.error(f"model_sources error: {e}")
        return out

    def reload(self):
        self._load_cache()

    def list_models(self) -> List[str]:
        """Все модели в пуле (включая алиасы)."""
        return sorted(self._cache.keys())

    def get_all_available_models(self) -> List[str]:
        """Модели, доступные через прокси = только active pool (то, что добавлено
        в пул во вкладках Модели/Провайдеры). Раньше добавлялись ВСЕ confirmed
        модели из БД → /v1/models показывал «кучу» того, что юзер не добавлял."""
        return sorted(self._cache.keys())

    def add_model(self, model_name: str, endpoint: str = "",
                  platform: str = "", api_keys: List[str] = None) -> str:
        """Добавить модель в пул. Если endpoint пустой — берёт все доступные."""
        if api_keys is None:
            api_keys = []

        # Если endpoint не указан — найти все эндпоинты с этой моделью
        if not endpoint:
            sources = self._find_endpoints_for_model(model_name)
        else:
            sources = [{"endpoint": endpoint, "platform": platform, "keys": api_keys}]

        if not sources:
            return f"Модель '{model_name}' не найдена ни на одном эндпоинте"

        added = 0
        with self.db._lock:
            with self.db._get_connection() as conn:
                for src in sources:
                    keys_json = json.dumps(src["keys"])
                    try:
                        conn.execute(
                            "INSERT OR IGNORE INTO active_pool "
                            "(model_name, endpoint, platform, api_keys, zone) "
                            "VALUES (?, ?, ?, ?, 'model')",
                            (model_name, src["endpoint"],
                             src.get("platform", ""), keys_json))
                        added += 1
                    except Exception:
                        pass
                conn.commit()
        self._load_cache()
        return f"Добавлено: {model_name} ({added} эндпоинтов)"

    def add_endpoint(self, endpoint: str, platform: str = "") -> str:
        """Добавить ВСЕ модели с эндпоинта в пул."""
        # Найти все confirmed модели на этом эндпоинте
        try:
            with self.db._lock:
                with self.db._get_connection() as conn:
                    rows = conn.execute(
                        "SELECT DISTINCT km.model_name, "
                        "GROUP_CONCAT(DISTINCT lk.api_key) as keys "
                        "FROM key_models km "
                        "JOIN leaked_keys lk ON lk.id = km.key_id "
                        "WHERE lk.base_url=? AND km.is_confirmed=1 "
                        "AND lk.status IN ('valid','confirmed') "
                        "GROUP BY km.model_name",
                        (endpoint,)).fetchall()
        except Exception:
            rows = []

        if not rows:
            # Попробовать без is_confirmed
            try:
                with self.db._lock:
                    with self.db._get_connection() as conn:
                        rows = conn.execute(
                            "SELECT DISTINCT km.model_name, "
                            "GROUP_CONCAT(DISTINCT lk.api_key) as keys "
                            "FROM key_models km "
                            "JOIN leaked_keys lk ON lk.id = km.key_id "
                            "WHERE lk.base_url=? "
                            "AND lk.status IN ('valid','confirmed') "
                            "GROUP BY km.model_name",
                            (endpoint,)).fetchall()
            except Exception:
                rows = []

        if not rows:
            return f"Не найдено моделей на {endpoint}"

        added = 0
        with self.db._lock:
            with self.db._get_connection() as conn:
                for r in rows:
                    model = r[0]
                    keys = r[1].split(",") if r[1] else []
                    keys_json = json.dumps(keys)
                    try:
                        conn.execute(
                            "INSERT OR IGNORE INTO active_pool "
                            "(model_name, endpoint, platform, api_keys, zone) "
                            "VALUES (?, ?, ?, ?, 'endpoint')",
                            (model, endpoint, platform, keys_json))
                        added += 1
                    except Exception:
                        pass
                conn.commit()
        self._load_cache()
        return f"Добавлено {added} моделей с {endpoint}"

    def remove_model(self, model_name: str) -> str:
        with self.db._lock:
            with self.db._get_connection() as conn:
                n = conn.execute(
                    "DELETE FROM active_pool WHERE model_name=?",
                    (model_name,)).rowcount
                conn.commit()
        self._load_cache()
        return f"Удалено: {n} записей для {model_name}"

    def clear_pool(self) -> str:
        with self.db._lock:
            with self.db._get_connection() as conn:
                conn.execute("DELETE FROM active_pool")
                conn.commit()
        self._load_cache()
        return "Пул очищен"

    def _find_endpoints_for_model(self, model_name: str) -> List[Dict]:
        """Найти все эндпоинты где модель подтверждена.

        ТОЛЬКО confirmed ключи (status='confirmed' AND is_confirmed=1). Valid-
        ключи (is_confirmed=0) не подтверждались реальным запросом — к ним
        запросы не шлём (они не ответят / дадут мусор).
        """
        try:
            with self.db._lock:
                with self.db._get_connection() as conn:
                    rows = conn.execute(
                        "SELECT lk.base_url, lk.platform, lk.api_key "
                        "FROM key_models km "
                        "JOIN leaked_keys lk ON lk.id = km.key_id "
                        "WHERE km.model_name=? "
                        "AND lk.status='confirmed' AND km.is_confirmed=1",
                        (model_name,)).fetchall()
        except Exception:
            return []

        endpoints: Dict[str, Dict] = {}
        for r in rows:
            url = r[0]
            if url not in endpoints:
                endpoints[url] = {"endpoint": url, "platform": r[1], "keys": []}
            endpoints[url]["keys"].append(r[2])
        return list(endpoints.values())

    def _get_sources_for_model(self, model_name: str) -> List[Dict]:
        """Получить источники (endpoint+keys) для модели.

        Раздельные зоны:
        - Если модель в pool_models (добавлена явно) → только zone='model' источники
          (крутит провайдеров). НЕ включает zone='endpoint'.
        - Если только через pool_endpoints → только zone='endpoint' (крутит свои ключи).
        - Ни там ни там → все confirmed (fallback).
        """
        # Определить зону модели: есть ли она в pool_models / pool_endpoints
        zone = self._model_zone(model_name)
        pool_entries = self._cache.get(model_name, [])
        sources = []
        for entry in pool_entries:
            # Фильтр по зоне (если зона известна)
            if zone and entry.get("zone", "model") != zone:
                continue
            if not entry.get("enabled", True):
                continue
            keys = entry.get("keys", [])
            if not keys:
                src = self._find_endpoints_for_model(model_name)
                for s in src:
                    if s["endpoint"] == entry["endpoint"]:
                        keys = s["keys"]
                        break
            sources.append({
                "endpoint": entry["endpoint"],
                "platform": entry.get("platform", ""),
                "keys": keys,
                "source": entry.get("source", "model"),
            })

        # Если нет в пуле — найти автоматически (все confirmed)
        if not sources:
            sources = self._find_endpoints_for_model(model_name)
        return sources

    def _model_zone(self, model_name: str) -> str:
        """Зона модели: 'model' (в pool_models) | 'endpoint' (через провайдера) | '' (auto)."""
        try:
            with self.db._lock:
                with self.db._get_connection() as conn:
                    in_models = conn.execute(
                        "SELECT 1 FROM pool_models WHERE model_name=? LIMIT 1",
                        (model_name,)).fetchone()
                    if in_models:
                        return "model"
                    in_eps = conn.execute(
                        "SELECT 1 FROM active_pool WHERE model_name=? "
                        "AND zone='endpoint' LIMIT 1",
                        (model_name,)).fetchone()
                    if in_eps:
                        return "endpoint"
        except Exception:
            pass
        return ""

    def _get_next_key(self, model_name: str, sources: List[Dict]
                      ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Получить следующий ключ — честный round-robin + кулдаун.

        Ротация: каждый вызов возвращает СЛЕДУЮЩИЙ ключ (ep+key) по кругу,
        равномерно распределяя нагрузку. Ключи в кулдауне пропускаются.

        ПРИОРИТЕТ: источники source='model' (левая колонка) перебираются
        первыми; source='endpoint' (правая) — fallback когда все model-ключи
        в кулдауне. rot хранит позицию ОТДЕЛЬНО для model и endpoint, чтобы
        восстановить приоритет после выхода из кулдауна.

        Returns: (api_key, endpoint, platform) или (None, None, None)
        """
        now = time.time()
        # Очистить истекшие кулдауны + сбросить адаптивную длительность
        expired = [k for k, t in self._cooldowns.items() if t < now]
        for k in expired:
            del self._cooldowns[k]
            # Сбросить адаптивную длительность при истечении
            self._cooldown_durations.pop(k, None)

        # rot хранит ОДИН глобальный курсор по «плоскому» списку всех ключей.
        # Но приоритет model: если есть model-ключи вне кулдауна — берём только
        # их. Поэтому два курсора: model-only и all.
        state = self._rotation.setdefault(model_name, {"model": 0, "all": 0})
        total_sources = len(sources)
        if total_sources == 0:
            return None, None, None

        has_model_src = any(s.get("source", "model") == "model"
                            for s in sources)

        def _flat(only: Optional[str]):
            """Плоский список (api_key, endpoint, platform) для source=only.

            Дедуп по api_key: ключ может встречаться и в source=model, и в
            source=endpoint (если модель и провайдер добавлены одновременно).
            Берём первое вхождение (приоритет model-источника сохранён сортировкой).
            """
            seen = set()
            out = []
            for src in sources:
                if only and src.get("source", "model") != only:
                    continue
                for k in src["keys"]:
                    if k in seen:
                        continue
                    seen.add(k)
                    out.append((k, src["endpoint"], src.get("platform", "")))
            return out

        def _pick(flat, cursor):
            """Взять следующий не-в-кулдауне ключ.

            round_robin: сдвинуть курсор на следующий (равномерное распределение).
            sticky: курсор не двигать — всегда первый приоритетный, следующий
                    только когда все до него в кулдауне.
            """
            if not flat:
                return None, cursor
            n = len(flat)
            for off in range(n):
                idx = (cursor + off) % n
                k, ep, plat = flat[idx]
                if k in self._cooldowns:
                    continue
                if self._selection_mode == "sticky":
                    # Sticky: не двигаем курсор — приоритет порядка (reorder)
                    return (k, ep, plat), cursor
                # round_robin: сдвинуть на следующий
                return (k, ep, plat), (idx + 1) % n
            return None, cursor

        # 1) Приоритет: model-источники
        if has_model_src:
            flat_m = _flat("model")
            r, state["model"] = _pick(flat_m, state["model"])
            if r:
                return r
        # 2) Fallback: все источники
        flat_all = _flat(None)
        r, state["all"] = _pick(flat_all, state["all"])
        return r if r else (None, None, None)

    def _put_cooldown(self, api_key: str, seconds: float = 60):
        """Поставить ключ в кулдаун (429/quota)."""
        self._cooldowns[api_key] = time.time() + seconds

    def _record_stat(self, api_key: str, status: int):
        """Записать статистику."""
        s = self._stats.setdefault(api_key, {"calls": 0, "errors": 0, "ok": 0})
        s["calls"] += 1
        s["last_status"] = status
        if 200 <= status < 300:
            s["ok"] += 1
        else:
            s["errors"] += 1

    def get_stats(self) -> Dict[str, Any]:
        # Агрегаты по всем ключам
        total_calls = sum(s.get("calls", 0) for s in self._stats.values())
        total_ok = sum(s.get("ok", 0) for s in self._stats.values())
        total_err = sum(s.get("errors", 0) for s in self._stats.values())
        return {
            "pool_models": len(self._cache),
            "pool_sources": sum(len(v) for v in self._cache.values()),
            "cooldown_keys": len(self._cooldowns),
            "total_calls": total_calls,
            "total_ok": total_ok,
            "total_errors": total_err,
            "success_rate": (round(100 * total_ok / total_calls, 1)
                             if total_calls else 0),
            "key_stats": dict(list(self._stats.items())[:50]),
        }


# ---------------------------------------------------------------------------
# Конвертер Anthropic ↔ OpenAI
# ---------------------------------------------------------------------------

def anthropic_to_openai_request(body: Dict, model: str) -> Dict:
    """Конвертировать OpenAI chat/completions запрос → Anthropic /v1/messages."""
    messages = body.get("messages", [])
    system_msg = ""
    filtered = []
    for msg in messages:
        if msg.get("role") == "system":
            system_msg += msg.get("content", "") + "\n"
        else:
            filtered.append({
                "role": msg.get("role", "user"),
                "content": msg.get("content", ""),
            })
    return {
        "model": model,
        # Anthropic требует max_tokens и трактует как жёсткий лимит. Клиенты
        # OpenAI часто не передают его → дефолт 100 обрезал ответы. 8192.
        "max_tokens": body.get("max_tokens") or 8192,
        "temperature": body.get("temperature", 0),
        "system": system_msg.strip() if system_msg else None,
        "messages": filtered,
    }


def anthropic_to_openai_response(data: Dict, model: str) -> Dict:
    """Конвертировать ответ Anthropic → OpenAI format."""
    content = ""
    for block in data.get("content", []):
        if isinstance(block, dict):
            content += block.get("text", "")
    usage = data.get("usage", {})
    return {
        "id": data.get("id", "chatcmpl-proxy"),
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": data.get("stop_reason", "stop"),
        }],
        "usage": {
            "prompt_tokens": usage.get("input_tokens", 0),
            "completion_tokens": usage.get("output_tokens", 0),
            "total_tokens": (usage.get("input_tokens", 0)
                             + usage.get("output_tokens", 0)),
        },
    }


def is_anthropic_endpoint(endpoint: str, platform: str = "") -> bool:
    """Определить, нужен ли Anthropic формат."""
    return ("anthropic.com" in endpoint.lower()
            or platform.lower() == "anthropic")


# ---------------------------------------------------------------------------
# Прокси-сервер
# ---------------------------------------------------------------------------

class ProxyServer:
    """OpenAI-совместимый прокси с ротацией ключей."""

    def __init__(self, db: Database, port: int = 8818, host: str = "127.0.0.1"):
        self.db = db
        self.port = port
        self.host = host  # 127.0.0.1 (только локально) или 0.0.0.0 (внешний доступ)
        self.pool = ActivePool(db)
        self.session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=120, connect=10)
            connector = TCPConnector(
                limit=20,
                limit_per_host=10,
                ssl=ssl.create_default_context(),
                force_close=False,
                use_dns_cache=True,
                ttl_dns_cache=600,
                keepalive_timeout=60,
                enable_cleanup_closed=True,
                resolver=aiohttp.resolver.ThreadedResolver(),
            )
            self.session = aiohttp.ClientSession(
                connector=connector, timeout=timeout, trust_env=True
            )
        return self.session

    async def handle_models(self, request: web.Request) -> web.Response:
        """GET /v1/models — список доступных моделей."""
        models = self.pool.get_all_available_models()
        data = {
            "object": "list",
            "data": [{"id": m, "object": "model",
                      "created": 0, "owned_by": "proxy"}
                     for m in models],
        }
        return web.json_response(data)

    async def handle_chat(self, request: web.Request) -> web.StreamResponse:
        """POST /v1/chat/completions — отправка с ротацией."""
        return await self._handle_openai_request(
            request, upstream_path="chat/completions",
            kind="chat", require_field="messages")

    async def handle_completions(self, request: web.Request) -> web.StreamResponse:
        """POST /v1/completions — legacy completions endpoint."""
        return await self._handle_openai_request(
            request, upstream_path="completions",
            kind="completion", require_field="prompt")

    async def handle_embeddings(self, request: web.Request) -> web.StreamResponse:
        """POST /v1/embeddings — OpenAI-compatible embeddings endpoint."""
        return await self._handle_openai_request(
            request, upstream_path="embeddings",
            kind="embedding", require_field="input")

    async def _handle_openai_request(
        self,
        request: web.Request,
        upstream_path: str,
        kind: str,
        require_field: str = "",
    ) -> web.StreamResponse:
        """Единая ротация для OpenAI-compatible endpoints.

        Все параметры запроса передаются провайдеру как есть: temperature,
        top_p, max_tokens/max_completion_tokens, tools, tool_choice, response_format,
        stream_options и прочее. Прокси меняет только Authorization и, для
        Anthropic chat, конвертирует формат.
        """
        try:
            body = await request.json()
        except Exception:
            return web.json_response(
                {"error": {"message": "Invalid JSON"}}, status=400)

        model = body.get("model", "")
        if not model:
            return web.json_response(
                {"error": {"message": "Model not specified"}}, status=400)

        # Ранняя валидация — не тратить попытку ключа на пустой запрос.
        if require_field and require_field not in body:
            return web.json_response(
                {"error": {"message": f"{require_field} required"}}, status=400)

        # Stream support
        stream = bool(body.get("stream", False))

        # Найти источники для модели
        sources = self.pool._get_sources_for_model(model)
        if not sources:
            # Алиас: попробовать найти частичное совпадение
            all_models = self.pool.get_all_available_models()
            for m in all_models:
                if model.lower() in m.lower():
                    sources = self.pool._get_sources_for_model(m)
                    model = m  # используем точное имя
                    break

        if not sources:
            return web.json_response(
                {"error": {"message": f"Model '{model}' not found in pool",
                           "type": "not_found"}}, status=404)

        # Ротация: перебираем ключи/эндпоинты
        tried = []
        tried_counts: Counter = Counter()  # число попыток по (key, endpoint)
        # Лимит: 2× уникальных (key,endpoint) пар — достаточно для повторных
        # попыток при transient-ошибках, но без бесконечного цикла.
        unique_pairs = set()
        for s in sources:
            for k in s["keys"]:
                unique_pairs.add((k, s["endpoint"]))
        max_attempts = len(unique_pairs) * 2 if unique_pairs else 1
        last_error: Dict[str, Any] = {}

        for attempt in range(max_attempts):
            api_key, endpoint, platform = self.pool._get_next_key(model, sources)
            if not api_key:
                break

            # Анти-цикл: если уже пробовали эту (key,endpoint) пару 2+ раз — skip
            pair = (api_key, endpoint)
            if tried_counts[pair] >= 2:
                # Поставить в кулдаун чтобы _get_next_key больше не вернул
                self.pool._put_cooldown(api_key, seconds=30)
                continue

            masked = _mask_key(api_key)
            tried.append(f"{masked}@{endpoint}")
            tried_counts[pair] += 1
            logger.info(
                f"Proxy: {kind}/{model} attempt {attempt+1} -> {masked} @ {endpoint}")

            # Определить формат запроса
            is_anthropic = is_anthropic_endpoint(endpoint, platform)

            if is_anthropic and kind == "chat":
                # Anthropic формат. endpoint уже содержит /v1 (канонический),
                # поэтому добавляем только /messages (иначе /v1/v1/messages → 404).
                url = _upstream_url(endpoint, "messages")
                req_body = anthropic_to_openai_request(body, model)
                headers = {
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                }
            elif is_anthropic:
                # Anthropic не является OpenAI-compatible для embeddings/completions.
                self.pool._put_cooldown(api_key, seconds=10)
                push_trace(model, attempt + 1, masked, endpoint, 400,
                           f"Anthropic не поддерживает {kind}")
                continue
            else:
                # OpenAI формат
                url = _upstream_url(endpoint, upstream_path)
                req_body = body
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json",
                }

            session = await self._get_session()
            try:
                async with session.post(url, json=req_body, headers=headers) as resp:
                    status = resp.status

                    # Streaming (SSE): проксируем поток как text/event-stream.
                    # Anthropic/OpenAI оба шлют `data: {...}\n\n` чанки.
                    if stream and status == 200:
                        sr = web.StreamResponse(
                            status=200,
                            headers={"Content-Type": "text/event-stream",
                                     "Cache-Control": "no-cache"})
                        await sr.prepare(request)
                        self.pool._record_stat(api_key, status)
                        async for chunk in resp.content:
                            await sr.write(chunk)
                        await sr.write_eof()
                        logger.info(f"Proxy: ✓ {model} (stream) via {masked}")
                        push_trace(model, attempt + 1, masked, endpoint, 200,
                                   f"✓ stream {kind}")
                        push_trace_summary(model, True, attempt + 1,
                                           f"{kind} stream via {masked}@{endpoint[:24]}")
                        return sr

                    resp_data, resp_text = (
                        await _read_response(resp) if status != 204 else ({}, "")
                    )

                    self.pool._record_stat(api_key, status)

                    if status == 200:
                        # Конвертировать Anthropic → OpenAI если нужно
                        if is_anthropic and kind == "chat":
                            resp_data = anthropic_to_openai_response(resp_data, model)
                        logger.info(f"Proxy: ✓ {kind}/{model} via {masked}")
                        push_trace(model, attempt + 1, masked, endpoint, 200,
                                   f"✓ {kind} ответ")
                        push_trace_summary(model, True, attempt + 1,
                                           f"{kind} {model} via {masked}@{endpoint[:24]}")
                        return web.json_response(resp_data)

                    elif status in (429, 402):
                        # Квота → кулдаун (адаптивный: 60→120→300с)
                        current_cd = self.pool._cooldown_durations.get(api_key, 60)
                        new_cd = min(current_cd * 2, 300)  # максимум 5 мин
                        self.pool._cooldown_durations[api_key] = new_cd
                        self.pool._put_cooldown(api_key, seconds=new_cd)
                        logger.info(f"Proxy: ⚠ 429 {masked} → cooldown {new_cd}s")
                        push_trace(model, attempt + 1, masked, endpoint, status,
                                   f"⚠ квота → кулдаун {new_cd}s, следующий ключ")
                        last_error = {"status": status, "body": resp_data or resp_text}
                        continue

                    elif status in (401, 403):
                        # Отозван → исключить на 1 час
                        self.pool._put_cooldown(api_key, seconds=3600)
                        logger.info(f"Proxy: ✗ 401 {masked} → excluded")
                        push_trace(model, attempt + 1, masked, endpoint, status,
                                   f"✗ auth отвергнут → исключить")
                        last_error = {"status": status, "body": resp_data or resp_text}
                        continue

                    else:
                        # 500/502/503/другое → короткий кулдаун + ротация
                        self.pool._put_cooldown(api_key, seconds=15)
                        logger.info(f"Proxy: ✗ {status} {masked} → cooldown 15s")
                        push_trace(model, attempt + 1, masked, endpoint, status,
                                   f"✗ HTTP {status} → следующий ключ")
                        last_error = {"status": status, "body": resp_data or resp_text}
                        continue

            except asyncio.TimeoutError:
                # Таймаут → кулдаун 30с + ротация
                self.pool._put_cooldown(api_key, seconds=30)
                logger.info(f"Proxy: ⏱ timeout {masked} → cooldown 30s")
                push_trace(model, attempt + 1, masked, endpoint, None, "⏱ timeout → след.")
                continue
            except Exception as e:
                # Сетевая ошибка → кулдаун 30с + ротация
                self.pool._put_cooldown(api_key, seconds=30)
                logger.info(f"Proxy: error {masked}: {e} → cooldown 30s")
                push_trace(model, attempt + 1, masked, endpoint, None,
                           f"✗ ошибка: {str(e)[:30]}")
                last_error = {"status": None, "body": str(e)}
                continue

        # Все ключи исчерпаны
        push_trace_summary(model, False, len(tried),
                           f"все ключи исчерпаны ({len(tried)} попыток)")
        return web.json_response(
            {"error": {"message": f"All keys exhausted for '{model}'. "
                                  f"Tried: {len(tried)}",
                       "type": "all_keys_exhausted",
                       "tried": tried[:10],
                       "last_error": last_error}}, status=503)

    async def handle_stats(self, request: web.Request) -> web.Response:
        """GET /stats — статистика прокси."""
        return web.json_response(self.pool.get_stats())

    async def handle_health(self, request: web.Request) -> web.Response:
        """GET /health — живость прокси + сводка."""
        st = self.pool.get_stats()
        return web.json_response({
            "status": "ok",
            "pool_models": st["pool_models"],
            "cooldown_keys": st["cooldown_keys"],
            "total_calls": st["total_calls"],
            "success_rate": st["success_rate"],
        })

    async def handle_usage(self, request: web.Request) -> web.Response:
        """GET /v1/usage — агрегат обращений (OpenAI-style usage)."""
        return web.json_response({"data": self.pool.get_stats()})

    async def handle_options(self, request: web.Request) -> web.Response:
        """CORS preflight для браузерных OpenAI-compatible клиентов."""
        return web.Response(status=204)

    async def handle_selection_mode(self, request: web.Request) -> web.Response:
        """GET/POST /pool/selection_mode — метод выбора ключа.
        GET → {mode}, POST {mode: 'round_robin'|'sticky'} → установить."""
        if request.method == "POST":
            try:
                body = await request.json()
                mode = body.get("mode", "round_robin")
                if mode not in ("round_robin", "sticky"):
                    return web.json_response(
                        {"error": "mode must be round_robin|sticky"}, status=400)
                self.pool._selection_mode = mode
                push_trace_summary(mode, True, 0,
                                   f"метод выбора: {mode}")
            except Exception as e:
                return web.json_response({"error": str(e)}, status=400)
        return web.json_response({"mode": self.pool._selection_mode})

    async def handle_reorder(self, request: web.Request) -> web.Response:
        """POST /pool/reorder {endpoint, direction: 'up'|'down'} — приоритет."""
        try:
            body = await request.json()
            endpoint = body.get("endpoint", "")
            direction = body.get("direction", "up")
            if not endpoint or direction not in ("up", "down"):
                return web.json_response(
                    {"error": "endpoint + direction(up|down) required"}, status=400)
            self.pool.reorder_endpoint(endpoint, direction)
            return web.json_response({"ok": True, "mode": direction})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def handle_trace(self, request: web.Request) -> web.Response:
        """GET /trace — последние события трейса запросов."""
        n = int(request.query.get("n", "50"))
        return web.json_response({"events": get_trace(n)})

    async def handle_toggle_source(self, request: web.Request) -> web.Response:
        """POST /pool/toggle {model, endpoint} → вкл/выкл провайдера модели."""
        try:
            body = await request.json()
            model = body.get("model", "")
            endpoint = body.get("endpoint", "")
            if not model or not endpoint:
                return web.json_response(
                    {"error": "model + endpoint required"}, status=400)
            self.pool.toggle_source(model, endpoint)
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def handle_remove_source(self, request: web.Request) -> web.Response:
        """POST /pool/remove_source {model, endpoint} → удалить связь."""
        try:
            body = await request.json()
            model = body.get("model", "")
            endpoint = body.get("endpoint", "")
            if not model or not endpoint:
                return web.json_response(
                    {"error": "model + endpoint required"}, status=400)
            self.pool.remove_source(model, endpoint)
            return web.json_response({"ok": True})
        except Exception as e:
            return web.json_response({"error": str(e)}, status=400)

    async def handle_model_sources(self, request: web.Request) -> web.Response:
        """GET /pool/model_sources?model=X → провайдеры модели (zone=model).
        endpoint, keys_count, confirmed_count, enabled, priority, zone."""
        model = request.query.get("model", "")
        if not model:
            return web.json_response({"error": "model required"}, status=400)
        return web.json_response({"sources": self.pool.model_sources(model)})

    async def _add_cors(self, request: web.Request, response: web.StreamResponse):
        """CORS + стандартные заголовки OpenAI-совместимости.

        Чтобы любой OpenAI-клиент (вкл. веб-UI в браузере) мог стучать к прокси
        без CORS-блокировок, и видел стандартные заголовки.
        """
        response.headers.setdefault("Access-Control-Allow-Origin", "*")
        response.headers.setdefault("Access-Control-Allow-Methods",
                                    "GET, POST, OPTIONS")
        response.headers.setdefault("Access-Control-Allow-Headers",
                                    "Authorization, Content-Type, Accept")
        response.headers.setdefault("Access-Control-Max-Age", "86400")
        response.headers.setdefault("x-request-id", str(id(request)))

    async def handle_pool_add_model(self, request: web.Request) -> web.Response:
        """POST /pool/add/model — добавить модель."""
        body = await request.json()
        model = body.get("model", "")
        endpoint = body.get("endpoint", "")
        result = self.pool.add_model(model, endpoint)
        return web.json_response({"result": result})

    async def handle_pool_add_endpoint(self, request: web.Request) -> web.Response:
        """POST /pool/add/endpoint — добавить все модели с эндпоинта."""
        body = await request.json()
        endpoint = body.get("endpoint", "")
        platform = body.get("platform", "")
        result = self.pool.add_endpoint(endpoint, platform)
        return web.json_response({"result": result})

    async def handle_pool_list(self, request: web.Request) -> web.Response:
        """GET /pool/list — список активного пула."""
        models = self.pool.list_models()
        detail = {}
        for m in models:
            sources = self.pool._cache.get(m, [])
            detail[m] = [{"endpoint": s["endpoint"],
                          "keys": len(s.get("keys", [])),
                          "enabled": s.get("enabled", True)}
                         for s in sources]
        return web.json_response({"models": models, "detail": detail})

    async def handle_pool_remove(self, request: web.Request) -> web.Response:
        """POST /pool/remove — удалить модель."""
        body = await request.json()
        model = body.get("model", "")
        result = self.pool.remove_model(model)
        return web.json_response({"result": result})

    async def handle_pool_clear(self, request: web.Request) -> web.Response:
        """POST /pool/clear — очистить пул."""
        result = self.pool.clear_pool()
        return web.json_response({"result": result})

    async def _auto_reload_pool(self) -> None:
        """Каждые 30с перезагружать cache пула. Новый confirmed-ключ (после
        confirm_drainer/дрейна) попадает в active_pool и становится доступен
        для запросов без ручного /pool/add. Логирует прирост в трейс."""
        prev_count = -1
        while True:
            try:
                await asyncio.sleep(30)
                before = sum(len(v) for v in self.pool._cache.values())
                self.pool._load_cache()
                after = sum(len(v) for v in self.pool._cache.values())
                if after > before and before >= 0:
                    push_trace_summary(
                        "(auto)", True, 0,
                        f"пул обновлён: +{after - before} новых confirmed источников")
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def start(self):
        """Запустить прокси-сервер.

        OpenAI-совместимые эндпоинты (стандарт /v1/ + алиасы без префикса для
        клиентов, которые стучат на голый /models):
          GET  /v1/models, /models
          POST /v1/chat/completions, /chat/completions
          POST /v1/completions, /completions          (legacy)
          POST /v1/embeddings, /embeddings            (делегируем на ключ)
        """
        # client_max_size 32 МБ — для больших контекстов (128k токенов)
        app = web.Application(client_max_size=32 * 1024 * 1024)
        # CORS + стандартные заголовки для любого OpenAI-совместимого клиента
        app.on_response_prepare.append(self._add_cors)
        # OpenAI стандарт /v1/
        app.router.add_get("/v1/models", self.handle_models)
        app.router.add_post("/v1/chat/completions", self.handle_chat)
        app.router.add_post("/v1/completions", self.handle_completions)
        app.router.add_post("/v1/embeddings", self.handle_embeddings)
        # Алиасы без /v1 (некоторые клиенты/вебаппы стучат на голый /models)
        app.router.add_get("/models", self.handle_models)
        app.router.add_post("/chat/completions", self.handle_chat)
        app.router.add_post("/completions", self.handle_completions)
        app.router.add_post("/embeddings", self.handle_embeddings)
        # Управление / статистика
        app.router.add_get("/stats", self.handle_stats)
        app.router.add_post("/pool/add/model", self.handle_pool_add_model)
        app.router.add_post("/pool/add/endpoint", self.handle_pool_add_endpoint)
        app.router.add_get("/pool/list", self.handle_pool_list)
        app.router.add_post("/pool/remove", self.handle_pool_remove)
        app.router.add_post("/pool/clear", self.handle_pool_clear)
        app.router.add_get("/health", self.handle_health)
        app.router.add_get("/v1/usage", self.handle_usage)
        app.router.add_get("/pool/selection_mode", self.handle_selection_mode)
        app.router.add_post("/pool/selection_mode", self.handle_selection_mode)
        app.router.add_post("/pool/reorder", self.handle_reorder)
        app.router.add_get("/trace", self.handle_trace)
        app.router.add_post("/pool/toggle", self.handle_toggle_source)
        app.router.add_post("/pool/remove_source", self.handle_remove_source)
        app.router.add_get("/pool/model_sources", self.handle_model_sources)
        app.router.add_options("/{tail:.*}", self.handle_options)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, self.host, self.port)
        await site.start()
        bind_desc = "0.0.0.0 (внешний доступ)" if self.host == "0.0.0.0" else "127.0.0.1"
        logger.info(f"Proxy server started on {bind_desc}:{self.port}")
        logger.info(f"  OpenAI: http://127.0.0.1:{self.port}/v1/chat/completions")
        logger.info(f"  Models: http://127.0.0.1:{self.port}/v1/models")
        logger.info(f"  Stats:  http://127.0.0.1:{self.port}/stats")

        # Авто-reload пула: новые confirmed-ключи появляются в cache без
        # ручного /pool/add. Раз в 30с сравниваем число источников.
        asyncio.create_task(self._auto_reload_pool())

        # Держать сервер живым
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        finally:
            if self.session and not self.session.closed:
                await self.session.close()
            await runner.cleanup()


def main():
    parser = argparse.ArgumentParser(description="Proxy server with key rotation")
    parser.add_argument("--port", type=int, default=8818)
    parser.add_argument("--host", default="127.0.0.1",
                        help="127.0.0.1 (локально) или 0.0.0.0 (внешний доступ)")
    args = parser.parse_args()

    db = Database(config.db_path)
    server = ProxyServer(db, port=args.port, host=args.host)
    asyncio.run(server.start())


if __name__ == "__main__":
    main()
