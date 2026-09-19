#!/usr/bin/env python3
"""Поиск утечек API-ключей в GitHub Gists, Issues и Commits.

Gists содержат в ~10x больше ключей на единицу контента, чем репозитории:
- Люди копируют конфиги без code review
- .env файлы коммитятся напрямую
- Нет PR/approval процесса

Запускается как параллельный модуль к основному сканеру.
"""
import asyncio
import json
import os
import sys
import time
from typing import Dict, List, Optional
from urllib.parse import quote

import ssl

import aiohttp
from aiohttp import TCPConnector
from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import config, REGEX_PATTERNS

GITHUB_API = "https://api.github.com"
MAX_PAGES = 3  # до 3 страниц × 30 = 90 результатов на запрос


class GistSearcher:
    """Поиск ключей в GitHub Gists, Issues, Commits через REST API."""

    def __init__(self, tokens: List[str]):
        self.tokens = tokens
        self.token_idx = 0
        self._rate_limited: set = set()
        self.session: Optional[aiohttp.ClientSession] = None

    async def _paginated_get(self, base_url: str, headers: Dict,
                             max_pages: int = MAX_PAGES,
                             extra_headers: Optional[Dict] = None) -> List[Dict]:
        """Пагинированный GET с ротацией токенов при rate limit."""
        all_items = []
        session = await self._get_session()
        merged_headers = {**headers, **(extra_headers or {})}
        for page in range(1, max_pages + 1):
            url = f"{base_url}&page={page}"
            try:
                h = merged_headers if page == 1 else {**self._get_headers(), **(extra_headers or {})}
                async with session.get(url, headers=h) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        items = data.get("items", [])
                        all_items.extend(items)
                        if len(items) < 30:
                            break
                    elif resp.status == 403:
                        remaining = resp.headers.get("X-RateLimit-Remaining", "0")
                        if remaining == "0":
                            idx = (self.token_idx - 1) % len(self.tokens)
                            self._rate_limited.add(idx)
                        break
                    else:
                        break
            except Exception:
                break
        return all_items

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
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

    def _get_headers(self) -> Dict[str, str]:
        # Пропустить исчерпанные токены
        for _ in range(len(self.tokens)):
            idx = self.token_idx % len(self.tokens)
            self.token_idx += 1
            if idx not in self._rate_limited:
                token = self.tokens[idx]
                return {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
        # Все исчерпаны — сбросить и использовать первый
        self._rate_limited.clear()
        token = self.tokens[self.token_idx % len(self.tokens)]
        self.token_idx += 1
        return {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}

    async def search_gists(self, keyword: str) -> List[Dict]:
        """Поиск ключей в GitHub Gists.

        GitHub Search API не поддерживает прямой поиск по gist-контенту
        как search_code, поэтому используем несколько стратегий:
        1. Search Issues (Gist-issues и комментарии)
        2. Search по паттернам ключей в gist описаниях
        3. Просмотр свежих public gist через Gists API
        """
        results = []
        headers = self._get_headers()
        session = await self._get_session()

        # Strategy: search for the keyword in code (gists are included in code search)
        # GitHub Code Search covers gist.github.com URLs
        # We add 'in:file' and 'is:public' qualifiers
        queries = [
            f"{keyword} in:file is:public gist:true",
            f"{keyword} in:path gist:true",
            f"{keyword} gist.gisthub.com",
        ]
        if "filename:." in keyword:
            queries.insert(0, keyword.replace(" in:file", " in:file gist:true"))

        for q in queries[:2]:
            try:
                url = f"{GITHUB_API}/search/code?q={quote(q)}&per_page=30"
                items = await self._paginated_get(url, headers)
                for item in items:
                    repo_url = item.get("repository", {}).get("html_url", "")
                    if "gist" not in repo_url.lower():
                        continue
                    results.append({
                        "url": item.get("html_url", ""),
                        "path": item.get("path", ""),
                        "repo_url": repo_url,
                        "sha": item.get("sha", ""),
                        "type": "gist",
                    })
            except Exception as e:
                logger.debug(f"Gist search error: {e}")

        return results

    async def search_commits(self, keyword: str) -> List[Dict]:
        """Поиск ключей в коммитах (истории). Ключи часто удалены в HEAD
        но остаются в истории коммитов."""
        results = []
        headers = self._get_headers()

        q = f"{keyword} is:public"
        try:
            url = f"{GITHUB_API}/search/commits?q={quote(q)}&per_page=30"
            items = await self._paginated_get(
                url, headers,
                extra_headers={"Accept": "application/vnd.github.cloak-preview"})
            for item in items:
                results.append({
                    "url": item.get("html_url", ""),
                    "sha": item.get("sha", ""),
                    "repo": item.get("repository", {}).get("full_name", ""),
                    "message": (item.get("commit", {}).get("message", "") or "")[:120],
                    "type": "commit",
                })
        except Exception as e:
            logger.debug(f"Commit search error: {e}")

        return results

    async def search_issues(self, keyword: str) -> List[Dict]:
        """Поиск ключей в Issues и Discussions."""
        results = []
        headers = self._get_headers()

        q = f"{keyword} is:public is:issue"
        try:
            url = f"{GITHUB_API}/search/issues?q={quote(q)}&per_page=30"
            items = await self._paginated_get(url, headers)
            for item in items:
                results.append({
                    "url": item.get("html_url", ""),
                    "title": item.get("title", ""),
                    "body": (item.get("body", "") or "")[:200],
                    "type": "issue",
                })
        except Exception as e:
            logger.debug(f"Issue search error: {e}")

        return results

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()


async def main():
    """Пример запуска: поискать gist с ключами"""
    searcher = GistSearcher(config.github_tokens)

    # Тестовые запросы
    test_queries = [
        'OPENAI_API_KEY in:file is:public',
    ]

    for q in test_queries:
        print(f"\n=== Gist search: {q[:60]} ===")
        results = await searcher.search_gists(q)
        print(f"  Found {len(results)} gists")

        commits = await searcher.search_commits(q)
        print(f"  Found {len(commits)} commits")

        issues = await searcher.search_issues(q)
        print(f"  Found {len(issues)} issues")

    await searcher.close()


if __name__ == "__main__":
    asyncio.run(main())
