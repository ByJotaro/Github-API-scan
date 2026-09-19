#!/usr/bin/env python3
"""Извлечение ключей из результатов расширенного поиска (gists/commits/issues)."""
import asyncio
import os
import re
import ssl
import sys
from typing import Dict, List, Optional
from urllib.parse import urlparse

import aiohttp
from aiohttp import TCPConnector
from loguru import logger

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import config as app_config, COMPILED_REGEX_PATTERNS
from database import normalize_base_url

_COMPILED_PATTERNS = COMPILED_REGEX_PATTERNS

# Предкомпилированный URL-паттерн (используется в hot loop)
_URL_RE = re.compile(r'https?://[^\s"\']{10,}')



def _match_context(content: str, start: int, end: int, radius_lines: int = 12) -> str:
    """Вернуть контекст по строкам, а не жёстким числом символов."""
    line_start = content.rfind("\n", 0, start) + 1
    line_end = content.find("\n", end)
    if line_end < 0:
        line_end = len(content)
    lo = line_start
    for _ in range(radius_lines):
        prev = content.rfind("\n", 0, lo - 1)
        if prev < 0:
            lo = 0
            break
        lo = prev + 1
    hi = line_end
    for _ in range(radius_lines):
        nxt = content.find("\n", hi + 1)
        if nxt < 0:
            hi = len(content)
            break
        hi = nxt
    return content[lo:hi]


def _choose_base_url(urls: List[str], key_context: str) -> str:
    """Выбрать API URL, предпочитая тот же блок/типичный API endpoint."""
    candidates = []
    key_low = key_context.lower()
    for raw in urls:
        url = raw.rstrip("/\"'")
        low = url.lower()
        if any(host in low for host in _BLACKLIST_HOSTS):
            continue
        score = 0
        if any(x in low for x in ("/v1", "/v1beta", "/models", "/chat", "/messages", "/api")):
            score += 5
        if any(x in key_low for x in ("base_url", "endpoint", "api_url", "api_base")):
            score += 2
        candidates.append((score, url))
    return max(candidates, default=(0, ""))[1]
_MAX_FILE_SIZE_KB = 500
_BLOCKED_EXTS = frozenset(".png .jpg .jpeg .gif .ico .svg .woff .woff2 .ttf .eot .cur .webp .mp4 .mp3 .pdf .zip .exe .dll .pyc .lock .sum .gitkeep .gitignore .DS_Store .class .jar .dex .apk .aab .o .so .a .dylib .bin .exif .icc .psd .ai".split())
_PATH_BLACKLIST = frozenset(['node_modules', 'dist/', 'build/', '__pycache__', '.git/'])
_IMPORTANT_FILES = frozenset(['dockerfile', '.env', 'config', 'secret', 'credential',
                               'settings', 'constants', 'secrets', 'application',
                               'appsettings', 'properties', 'litellm', 'proxy',
                               'gateway', 'values.yaml', 'values.yml'])

_COMMIT_FILE_KEYWORDS = frozenset(['.env', 'config.', 'secret', 'credential',
                                   '.json', '.yaml', '.yml', '.xml',
                                   'settings.', 'appsettings.',
                                   'docker-compose', 'credentials.json',
                                   'constants.', 'secrets.', 'litellm',
                                   'proxy_config', 'gateway_config',
                                   'values.yaml', 'values.yml',
                                   '.tf', '.tfvars', '.toml', '.ini', '.cfg',
                                   'application.', 'properties.'])

_BLACKLIST_HOSTS = frozenset(['github', 'gitlab'])


def _should_skip_file(file_path: str, file_size: int = 0) -> bool:
    file_path_lower = file_path.lower()
    if file_size > _MAX_FILE_SIZE_KB * 1024:
        return True
    for bp in _PATH_BLACKLIST:
        if bp in file_path_lower:
            return True
    ext = '.' + file_path.rsplit('.', 1)[-1].lower() if '.' in file_path else ''
    if ext in _BLOCKED_EXTS:
        return True
    fname = file_path.rsplit('/', 1)[-1].lower() if '/' in file_path else file_path.lower()
    if any(imp in fname for imp in _IMPORTANT_FILES):
        return False
    # Файлы без расширения (Dockerfile, .env, Makefile) — сканируем.
    # Остальные кодовые расширения (.py/.js/...) — сканируем (не скипаем).
    return False


class KeyExtractor:
    """Загрузка содержимого gists/commits и извлечение API-ключей."""

    def __init__(self):
        self.session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        if self.session is None or self.session.closed:
            timeout = aiohttp.ClientTimeout(total=15, connect=10)
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

    async def fetch_and_extract(self, url: str) -> List[Dict]:
        """Скачать содержимое URL и извлечь API-ключи."""
        results = []
        session = await self._get_session()
        try:
            async with session.get(url) as resp:
                if resp.status != 200:
                    return []
                content = await resp.text(errors='replace')

            if len(content) > 500000 or len(content) < 10:
                return []
            if _should_skip_file(url, len(content)):
                return []

            for platform, pattern in _COMPILED_PATTERNS.items():
                for match in pattern.finditer(content):
                    key = match.group(0).strip()
                    if len(key) < 8:
                        continue
                    context = _match_context(content, match.start(), match.end())
                    if platform in ("aws_secret_key", "aws_secret"):
                        ctx_low = context.lower()
                        if not any(word in ctx_low for word in (
                            "aws_secret_access_key", "aws_secret_key",
                            "aws_secret", "secret_access_key", "secret key",
                            "access_key", "aws_access")):
                            continue
                    urls = _URL_RE.findall(context)
                    base_url = _choose_base_url(urls, context)
                    actual_platform = (
                        "opencode_zen"
                        if "opencode.ai" in base_url.lower()
                        else platform
                    )

                    results.append({
                        "platform": actual_platform,
                        "api_key": key,
                        "base_url": base_url,
                        "source_url": url,
                    })
                    # Кап убран: multi-key .env раньше обрезался до 3 ключей.

        except Exception as e:
            logger.debug(f"KeyExtractor failed for {url[:50]}: {e}")
        return results

    async def process_commits(self, commits: List[Dict]) -> List[Dict]:
        """Загрузить RAW файлы из коммита через GitHub API — параллельно."""
        results = []
        session = await self._get_session()
        token = app_config.github_tokens[0] if app_config.github_tokens else ""
        headers = {}
        if token:
            headers["Authorization"] = f"token {token}"

        async def _process_one_commit(commit: Dict) -> List[Dict]:
            url = commit.get("url", "")
            if not url or len(url) < 30:
                return []
            parts = url.replace("https://github.com/", "").split("/commit/")
            if len(parts) != 2:
                return []
            repo, sha = parts
            api_url = f"https://api.github.com/repos/{repo}/commits/{sha}"
            try:
                async with session.get(api_url, headers=headers) as resp:
                    if resp.status != 200:
                        return []
                    detail = await resp.json()
                    changed_files = detail.get("files", [])
                    target_files = [
                        f for f in changed_files
                        if any(x in (f.get("filename") or "").lower()
                               for x in _COMMIT_FILE_KEYWORDS)
                    ]
                    if not target_files:
                        target_files = changed_files[:3]

                    file_results = []
                    sem = asyncio.Semaphore(3)
                    async def _fetch_file(f):
                        async with sem:
                            raw_url = f.get("raw_url", "")
                            if not raw_url:
                                return []
                            keys = await self.fetch_and_extract(raw_url)
                            for k in keys:
                                k["source_url"] = f"https://github.com/{repo}/commit/{sha}"
                            return keys
                    tasks = [_fetch_file(f) for f in target_files if f.get("raw_url")]
                    file_results = await asyncio.gather(*tasks, return_exceptions=True)
                    out = []
                    for r in file_results:
                        if isinstance(r, list):
                            out.extend(r)
                    return out
            except Exception as e:
                logger.debug(f"Commit API error: {e}")
                return []

        tasks = [_process_one_commit(c) for c in commits[:10]]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in batch_results:
            if isinstance(r, list):
                results.extend(r)
        return results

    async def process_gists(self, gists: List[Dict]) -> List[Dict]:
        """Загрузить raw gist файлы и извлечь ключи — параллельно."""
        sem = asyncio.Semaphore(5)

        async def _process_one(gist: Dict) -> List[Dict]:
            async with sem:
                raw_url = gist.get("url", "")
                if "gist" in raw_url.lower():
                    raw_url = raw_url.replace("/blob/", "/raw/")
                return await self.fetch_and_extract(raw_url)

        tasks = [_process_one(g) for g in gists]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)
        results = []
        for r in batch_results:
            if isinstance(r, list):
                results.extend(r)
        return results

    async def close(self):
        if self.session and not self.session.closed:
            await self.session.close()
