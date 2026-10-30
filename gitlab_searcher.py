#!/usr/bin/env python3
"""Поиск утечек API-ключей через GitLab API.

GitLab содержит огромный пласт проектов (особенно китайских/русских),
которые не индексируются GitHub Search API.
"""
import asyncio
import os
import ssl
import sys
import time
from typing import Dict, List, Optional
from urllib.parse import quote, urlencode

import aiohttp
from aiohttp import TCPConnector
from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import config

GITLAB_API = "https://gitlab.com/api/v4"
GITLAB_FILE_URL = "https://gitlab.com/{project_path}/-/raw/{ref}/{file_path}"

# Паттерны для поиска в GitLab (формат GitLab Code Search)
# GitLab search uses basic: ?search=KEYWORD&scope=blobs
GITLAB_DORKS = [
    # AI providers
    "sk-proj-",
    "sk-ant-",
    "AIzaSy",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GROQ_API_KEY",
    "DEEPSEEK_API_KEY",
    "PERPLEXITY_API_KEY",
    # Git tokens
    "ghp_",
    "GITLAB_TOKEN",
    "GL_TOKEN",
    "GITLAB_PRIVATE_TOKEN",
    # env files
    "filename:.env",
    "filename:.env.local",
]


class GitLabSearcher:
    """Поиск ключей через GitLab API Code Search."""

    def __init__(self, tokens: List[str] = None):
        self.tokens = tokens or config.github_tokens
        self.token_idx = 0
        self.session: Optional[aiohttp.ClientSession] = None

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
        # GitLab doesn't require auth for public projects search
        return {"Accept": "application/json",
                "User-Agent": "GitHub-API-Scan/1.0"}

    async def search_code(self, keyword: str, per_page: int = 50) -> List[Dict]:
        """Поиск утечек через GitLab Code Search API — параллельно по проектам."""
        results = []
        session = await self._get_session()
        headers = self._get_headers()

        try:
            params = {"search": keyword, "scope": "blobs", "per_page": per_page}
            url = f"{GITLAB_API}/projects?{urlencode(params)}"
            async with session.get(url, headers=headers) as resp:
                if resp.status != 200:
                    if resp.status == 429:
                        logger.warning("GitLab rate limit hit")
                    return results
                data = await resp.json()

            sem = asyncio.Semaphore(3)

            async def _search_project_blobs(project: Dict) -> List[Dict]:
                proj_path = project.get("path_with_namespace", "")
                default_branch = project.get("default_branch", "main")
                if not proj_path:
                    return []
                async with sem:
                    blob_params = {"search": keyword, "scope": "blobs", "per_page": 20}
                    blob_url = (f"{GITLAB_API}/projects/"
                                f"{quote(proj_path, safe='')}"
                                f"/search?{urlencode(blob_params)}")
                    try:
                        async with session.get(blob_url, headers=headers) as br:
                            if br.status != 200:
                                return []
                            blobs = await br.json()
                            out = []
                            for blob in blobs[:5]:
                                fpath = blob.get("filename", "")
                                out.append({
                                    "url": (f"https://gitlab.com/{proj_path}/-/"
                                            f"blob/{default_branch}/{fpath}"),
                                    "path": fpath,
                                    "project": proj_path,
                                    "branch": default_branch,
                                    "type": "gitlab_blob",
                                })
                            return out
                    except Exception:
                        return []

            tasks = [_search_project_blobs(p) for p in data[:10]]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in batch_results:
                if isinstance(r, list):
                    results.extend(r)

        except Exception as e:
            logger.debug(f"GitLab search error for '{keyword}': {e}")

        return results

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()


async def main():
    """Тестовый запуск GitLab поиска."""
    s = GitLabSearcher()
    print("Testing GitLab search...")
    results = await s.search_code("OPENAI_API_KEY")
    print(f"  Found: {len(results)} results")
    for r in results[:5]:
        print(f"    {r['project']}: {r['path']}")
    await s.close()


if __name__ == "__main__":
    asyncio.run(main())
