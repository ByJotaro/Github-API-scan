"""Реестр моделей LLM с датами релиза и категориями.

Используется вкладкой «Модели» для сортировки от самых новых к старым
и для категоризации (family/provider). Дата релиза — ISO-строка (YYYY-MM-DD).

Для моделей, отсутствующих в реестре, применяется эвристика по имени
(год/версия в идентификаторе).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from typing import Dict, List, Optional, Tuple


@dataclass(frozen=True)
class ModelInfo:
    name: str          # канонический идентификатор (как в /models)
    family: str        # семейство: GPT, Claude, Gemini, Llama, Mistral, ...
    provider: str      # первичный провайдер: OpenAI, Anthropic, Google, ...
    release: str       # ISO дата релиза (YYYY-MM-DD) или "" если неизвестна
    tier: str = ""     # tier: frontier / standard / legacy / embedding / image
    # --- расширенные поля (заполняются в lookup() если не заданы явно) ---
    capabilities: str = ""  # comma-separated: text,vision,audio,function_calling,streaming,reasoning,embedding,image,search
    context_window: int = 0  # размер контекста в токенах (0 = неизвестно)
    max_output: int = 0      # макс. выходных токенов (0 = неизвестно)
    input_price: float = 0.0   # $ за 1M входных токенов
    output_price: float = 0.0  # $ за 1M выходных токенов


# ---------------------------------------------------------------------------
# База известных моделей. Сортировка по дате релиза (новые → старые) в UI.
# Дата — день публичного анонса/доступа API (приближённая).
# ---------------------------------------------------------------------------
_KNOWN: List[ModelInfo] = [
    # ---- OpenAI GPT-5 (2026) ----
    ModelInfo("gpt-5.5", "GPT", "OpenAI", "2026-05-01", "frontier"),
    ModelInfo("openai/gpt-5.5", "GPT", "OpenAI", "2026-05-01", "frontier"),
    ModelInfo("gpt5.5", "GPT", "OpenAI", "2026-05-01", "frontier"),
    ModelInfo("gpt-5.4", "GPT", "OpenAI", "2026-04-15", "frontier"),
    ModelInfo("openai/gpt-5.4", "GPT", "OpenAI", "2026-04-15", "frontier"),
    ModelInfo("gpt-5.4-mini", "GPT", "OpenAI", "2026-04-15", "standard"),
    ModelInfo("gpt-5.4-nano", "GPT", "OpenAI", "2026-04-15", "standard"),
    ModelInfo("gpt-5.2", "GPT", "OpenAI", "2026-03-01", "frontier"),
    ModelInfo("openai/gpt-5.2", "GPT", "OpenAI", "2026-03-01", "frontier"),
    ModelInfo("gpt-5.1", "GPT", "OpenAI", "2026-02-01", "frontier"),
    ModelInfo("openai/gpt-5.1", "GPT", "OpenAI", "2026-02-01", "frontier"),
    ModelInfo("gpt-5", "GPT", "OpenAI", "2026-01-15", "frontier"),
    ModelInfo("openai/gpt-5", "GPT", "OpenAI", "2026-01-15", "frontier"),
    ModelInfo("gpt5", "GPT", "OpenAI", "2026-01-15", "frontier"),
    ModelInfo("gpt-5-mini", "GPT", "OpenAI", "2026-01-15", "standard"),
    
    # ---- Anthropic Claude Opus 4 (2026) ----
    ModelInfo("claude-opus-4.8", "Claude", "Anthropic", "2026-04-20", "frontier"),
    ModelInfo("anthropic/claude-opus-4.8", "Claude", "Anthropic", "2026-04-20", "frontier"),
    ModelInfo("claude-opus-4.5", "Claude", "Anthropic", "2026-03-10", "frontier"),
    ModelInfo("anthropic/claude-opus-4.5", "Claude", "Anthropic", "2026-03-10", "frontier"),
    ModelInfo("claude-opus-4", "Claude", "Anthropic", "2026-02-01", "frontier"),
    ModelInfo("anthropic/claude-opus-4", "Claude", "Anthropic", "2026-02-01", "frontier"),
    ModelInfo("claude-4.8-opus-20260420", "Claude", "Anthropic", "2026-04-20", "frontier"),
    ModelInfo("claude-4.5-opus-20260310", "Claude", "Anthropic", "2026-03-10", "frontier"),
    ModelInfo("anthropic/claude-haiku-4-5", "Claude", "Anthropic", "2026-03-01", "standard"),
    ModelInfo("anthropic/claude-opus-4-6", "Claude", "Anthropic", "2026-03-20", "frontier"),
    ModelInfo("anthropic/claude-opus-4-7", "Claude", "Anthropic", "2026-04-05", "frontier"),
    
    # ---- Zhipu GLM-5 (2026) ----
    ModelInfo("glm-5.2", "GLM", "Zhipu", "2026-04-01", "frontier"),
    ModelInfo("glm5.2", "GLM", "Zhipu", "2026-04-01", "frontier"),
    ModelInfo("glm-5.1", "GLM", "Zhipu", "2026-02-15", "frontier"),
    ModelInfo("glm-5", "GLM", "Zhipu", "2026-01-20", "frontier"),
    ModelInfo("glm-5-plus", "GLM", "Zhipu", "2026-01-20", "frontier"),
    ModelInfo("glm5", "GLM", "Zhipu", "2026-01-20", "frontier"),
    
    # ---- Moonshot Kimi k2.x (2026) ----
    ModelInfo("kimi-k2.7", "Kimi", "Moonshot", "2026-05-01", "frontier"),
    ModelInfo("kimi-k2.6", "Kimi", "Moonshot", "2026-04-01", "frontier"),
    ModelInfo("kimi-k2.5", "Kimi", "Moonshot", "2026-03-01", "frontier"),
    ModelInfo("kimi-k2", "Kimi", "Moonshot", "2026-02-01", "frontier"),
    ModelInfo("moonshot-v2-2026", "Kimi", "Moonshot", "2026-02-01", "frontier"),
    ModelInfo("moonshot/kimi-k2", "Kimi", "Moonshot", "2026-02-01", "frontier"),
    
    # ---- Minimax (2026) ----
    ModelInfo("minimax-text-01", "Minimax", "Minimax", "2026-01-15", "frontier"),
    ModelInfo("MiniMax-Text-01", "Minimax", "Minimax", "2026-01-15", "frontier"),
    ModelInfo("minimax/abab6.5", "Minimax", "Minimax", "2026-02-01", "frontier"),
    
    # ---- Stepfun (2026) ----
    ModelInfo("step-2-16k", "StepFun", "StepFun", "2026-01-20", "frontier"),
    ModelInfo("step-1v-32k", "StepFun", "StepFun", "2025-10-01", "standard"),
    
    # ---- Google Gemini 3.x (2026) ----
    ModelInfo("gemini-3.5-flash", "Gemini", "Google", "2026-04-01", "frontier"),
    ModelInfo("google/gemini-3.5-flash", "Gemini", "Google", "2026-04-01", "frontier"),
    ModelInfo("gemini3.5-flash", "Gemini", "Google", "2026-04-01", "frontier"),
    ModelInfo("gemini-3.1-pro-preview", "Gemini", "Google", "2026-03-15", "frontier"),
    ModelInfo("gemini-3.1-flash-lite", "Gemini", "Google", "2026-03-15", "standard"),
    ModelInfo("gemini-3.1-flash-lite-preview", "Gemini", "Google", "2026-03-15", "standard"),
    ModelInfo("gemini-3-flash-preview", "Gemini", "Google", "2026-02-20", "frontier"),
    ModelInfo("gemini-3-pro-image-preview", "Gemini", "Google", "2026-02-20", "frontier"),
    
    # ---- DeepSeek v4 (2026) ----
    ModelInfo("deepseek-v4-pro", "DeepSeek", "DeepSeek", "2026-03-01", "frontier"),
    ModelInfo("deepseek/deepseek-v4-pro", "DeepSeek", "DeepSeek", "2026-03-01", "frontier"),
    ModelInfo("deepseek-v4-flash", "DeepSeek", "DeepSeek", "2026-03-01", "standard"),
    ModelInfo("deepseek-r1", "DeepSeek", "DeepSeek", "2025-01-20", "frontier"),
    ModelInfo("deepseek/deepseek-r1", "DeepSeek", "DeepSeek", "2025-01-20", "frontier"),
    ModelInfo("deepseek-reasoner", "DeepSeek", "DeepSeek", "2025-01-20", "frontier"),
    
    # ---- Perplexity Sonar (2026) ----
    ModelInfo("perplexity/sonar", "Sonar", "Perplexity", "2026-01-15", "frontier"),
    ModelInfo("sonar", "Sonar", "Perplexity", "2026-01-15", "frontier"),
    ModelInfo("perplexity/sonar-pro", "Sonar", "Perplexity", "2026-01-15", "frontier"),
    ModelInfo("perplexity/sonar-reasoning", "Sonar", "Perplexity", "2026-01-15", "frontier"),
    
    # ---- Nvidia Nemotron (2026) ----
    ModelInfo("nvidia/nemotron-3-super-120b-a12b", "Nemotron", "Nvidia", "2026-02-01", "frontier"),
    ModelInfo("nvidia/llama-3.3-nemotron-super-49b-v1.5", "Nemotron", "Nvidia", "2026-01-15", "frontier"),
    
    # ---- OpenAI GPT-4.1 (2025) ----
    ModelInfo("gpt-4.1", "GPT", "OpenAI", "2025-04-01", "frontier"),
    ModelInfo("openai/gpt-4.1", "GPT", "OpenAI", "2025-04-01", "frontier"),
    ModelInfo("gpt-4.1-mini", "GPT", "OpenAI", "2025-04-01", "standard"),
    ModelInfo("gpt-4.1-nano", "GPT", "OpenAI", "2025-04-01", "standard"),
    
    # ---- OpenAI GPT-4o (2024-2025) ----
    ModelInfo("gpt-4o-2024-11-20", "GPT", "OpenAI", "2024-11-20", "frontier"),
    ModelInfo("gpt-4o-2024-08-06", "GPT", "OpenAI", "2024-08-06", "frontier"),
    ModelInfo("gpt-4o-2024-05-13", "GPT", "OpenAI", "2024-05-13", "frontier"),
    ModelInfo("gpt-4o", "GPT", "OpenAI", "2024-05-13", "frontier"),
    ModelInfo("gpt-4o-mini-2024-07-18", "GPT", "OpenAI", "2024-07-18", "standard"),
    ModelInfo("gpt-4o-mini", "GPT", "OpenAI", "2024-07-18", "standard"),
    ModelInfo("o3-mini-2025-01-31", "o-series", "OpenAI", "2025-01-31", "frontier"),
    ModelInfo("o3-mini", "o-series", "OpenAI", "2025-01-31", "frontier"),
    ModelInfo("o1-2024-12-17", "o-series", "OpenAI", "2024-12-17", "frontier"),
    ModelInfo("o1", "o-series", "OpenAI", "2024-12-17", "frontier"),
    ModelInfo("o1-preview-2024-09-12", "o-series", "OpenAI", "2024-09-12", "frontier"),
    ModelInfo("o1-preview", "o-series", "OpenAI", "2024-09-12", "frontier"),
    ModelInfo("o1-mini-2024-09-12", "o-series", "OpenAI", "2024-09-12", "standard"),
    ModelInfo("o1-mini", "o-series", "OpenAI", "2024-09-12", "standard"),
    ModelInfo("gpt-4-turbo-2024-04-09", "GPT", "OpenAI", "2024-04-09", "frontier"),
    ModelInfo("gpt-4-turbo", "GPT", "OpenAI", "2024-04-09", "frontier"),
    ModelInfo("gpt-4-0125-preview", "GPT", "OpenAI", "2024-01-25", "frontier"),
    ModelInfo("gpt-4-1106-preview", "GPT", "OpenAI", "2023-11-06", "frontier"),
    ModelInfo("gpt-4-0613", "GPT", "OpenAI", "2023-06-13", "legacy"),
    ModelInfo("gpt-4", "GPT", "OpenAI", "2023-03-14", "legacy"),
    ModelInfo("gpt-3.5-turbo-0125", "GPT", "OpenAI", "2024-01-25", "standard"),
    ModelInfo("gpt-3.5-turbo-1106", "GPT", "OpenAI", "2023-11-06", "standard"),
    ModelInfo("gpt-3.5-turbo-0613", "GPT", "OpenAI", "2023-06-13", "legacy"),
    ModelInfo("gpt-3.5-turbo", "GPT", "OpenAI", "2023-03-01", "legacy"),
    # ---- Anthropic Claude ----
    ModelInfo("claude-3-5-sonnet-20241022", "Claude", "Anthropic", "2024-10-22", "frontier"),
    ModelInfo("claude-3-5-sonnet-20240620", "Claude", "Anthropic", "2024-06-20", "frontier"),
    ModelInfo("claude-3-5-sonnet-latest", "Claude", "Anthropic", "2024-10-22", "frontier"),
    ModelInfo("claude-3-5-haiku-20241022", "Claude", "Anthropic", "2024-10-22", "standard"),
    ModelInfo("claude-3-opus-20240229", "Claude", "Anthropic", "2024-02-29", "frontier"),
    ModelInfo("claude-3-opus", "Claude", "Anthropic", "2024-02-29", "frontier"),
    ModelInfo("claude-3-sonnet-20240229", "Claude", "Anthropic", "2024-02-29", "standard"),
    ModelInfo("claude-3-haiku-20240307", "Claude", "Anthropic", "2024-03-07", "standard"),
    ModelInfo("claude-3-haiku", "Claude", "Anthropic", "2024-03-07", "standard"),
    ModelInfo("claude-2.1", "Claude", "Anthropic", "2023-11-21", "legacy"),
    ModelInfo("claude-2.0", "Claude", "Anthropic", "2023-07-11", "legacy"),
    ModelInfo("claude-instant-1.2", "Claude", "Anthropic", "2023-08-09", "legacy"),
    # ---- Google Gemini ----
    ModelInfo("gemini-2.0-flash", "Gemini", "Google", "2024-12-11", "frontier"),
    ModelInfo("gemini-2.0-flash-exp", "Gemini", "Google", "2024-12-09", "frontier"),
    ModelInfo("gemini-1.5-pro-002", "Gemini", "Google", "2024-09-24", "frontier"),
    ModelInfo("gemini-1.5-pro-001", "Gemini", "Google", "2024-02-15", "frontier"),
    ModelInfo("gemini-1.5-pro", "Gemini", "Google", "2024-02-15", "frontier"),
    ModelInfo("gemini-1.5-flash-002", "Gemini", "Google", "2024-09-24", "standard"),
    ModelInfo("gemini-1.5-flash-001", "Gemini", "Google", "2024-02-15", "standard"),
    ModelInfo("gemini-1.5-flash", "Gemini", "Google", "2024-02-15", "standard"),
    ModelInfo("gemini-1.5-flash-8b", "Gemini", "Google", "2024-10-03", "standard"),
    ModelInfo("gemini-1.0-pro", "Gemini", "Google", "2023-12-06", "legacy"),
    ModelInfo("gemini-pro", "Gemini", "Google", "2023-12-06", "legacy"),
    ModelInfo("gemini-pro-vision", "Gemini", "Google", "2023-12-06", "legacy"),
    # ---- Meta Llama ----
    ModelInfo("llama-3.3-70b-versatile", "Llama", "Meta", "2024-12-06", "frontier"),
    ModelInfo("llama-3.3-70b", "Llama", "Meta", "2024-12-06", "frontier"),
    ModelInfo("llama-3.1-405b-reasoning", "Llama", "Meta", "2024-07-23", "frontier"),
    ModelInfo("llama-3.1-70b-versatile", "Llama", "Meta", "2024-07-23", "frontier"),
    ModelInfo("llama-3.1-8b-instant", "Llama", "Meta", "2024-07-23", "standard"),
    ModelInfo("llama-3.1-70b", "Llama", "Meta", "2024-07-23", "frontier"),
    ModelInfo("llama-3.1-8b", "Llama", "Meta", "2024-07-23", "standard"),
    ModelInfo("llama3-70b-8192", "Llama", "Meta", "2024-04-18", "frontier"),
    ModelInfo("llama3-8b-8192", "Llama", "Meta", "2024-04-18", "standard"),
    ModelInfo("llama2-70b-4096", "Llama", "Meta", "2023-07-18", "legacy"),
    ModelInfo("llama2-13b", "Llama", "Meta", "2023-07-18", "legacy"),
    # ---- Mistral ----
    ModelInfo("mistral-large-latest", "Mistral", "Mistral", "2024-07-24", "frontier"),
    ModelInfo("mistral-large-2407", "Mistral", "Mistral", "2024-07-24", "frontier"),
    ModelInfo("mistral-large-2402", "Mistral", "Mistral", "2024-02-26", "frontier"),
    ModelInfo("mistral-medium", "Mistral", "Mistral", "2023-12-11", "standard"),
    ModelInfo("mistral-small-latest", "Mistral", "Mistral", "2024-02-26", "standard"),
    ModelInfo("mistral-small-2402", "Mistral", "Mistral", "2024-02-26", "standard"),
    ModelInfo("mistral-tiny", "Mistral", "Mistral", "2023-09-27", "legacy"),
    ModelInfo("mixtral-8x7b-32768", "Mixtral", "Mistral", "2023-12-11", "standard"),
    ModelInfo("mixtral-8x22b", "Mixtral", "Mistral", "2024-04-10", "frontier"),
    ModelInfo("open-mixtral-8x22b", "Mixtral", "Mistral", "2024-04-10", "frontier"),
    ModelInfo("open-mistral-7b", "Mistral", "Mistral", "2023-09-27", "legacy"),
    # ---- Cohere Command ----
    ModelInfo("command-r-plus", "Command", "Cohere", "2024-04-04", "frontier"),
    ModelInfo("command-r", "Command", "Cohere", "2024-04-04", "standard"),
    ModelInfo("command", "Command", "Cohere", "2022-11-01", "legacy"),
    ModelInfo("command-light", "Command", "Cohere", "2023-02-01", "legacy"),
    # ---- xAI Grok ----
    ModelInfo("grok-2-latest", "Grok", "xAI", "2024-08-13", "frontier"),
    ModelInfo("grok-2", "Grok", "xAI", "2024-08-13", "frontier"),
    ModelInfo("grok-2-mini", "Grok", "xAI", "2024-08-13", "standard"),
    ModelInfo("grok-beta", "Grok", "xAI", "2023-11-03", "legacy"),
    # ---- DeepSeek ----
    ModelInfo("deepseek-chat", "DeepSeek", "DeepSeek", "2024-05-06", "standard"),
    ModelInfo("deepseek-coder", "DeepSeek", "DeepSeek", "2024-01-25", "standard"),
    ModelInfo("deepseek-reasoner", "DeepSeek", "DeepSeek", "2025-01-20", "frontier"),
    ModelInfo("deepseek-r1", "DeepSeek", "DeepSeek", "2025-01-20", "frontier"),
    # ---- Groq hosted ----
    ModelInfo("gemma2-9b-it", "Gemma", "Google", "2024-06-27", "standard"),
    ModelInfo("gemma-7b-it", "Gemma", "Google", "2024-02-21", "standard"),
    # ---- Perplexity ----
    ModelInfo("llama-3.1-sonar-large-128k-online", "Sonar", "Perplexity", "2024-07-23", "frontier"),
    ModelInfo("llama-3.1-sonar-small-128k-online", "Sonar", "Perplexity", "2024-07-23", "standard"),
    ModelInfo("llama-3.1-sonar-huge-128k-online", "Sonar", "Perplexity", "2024-07-23", "frontier"),
    # ---- Together / Fireworks hosted variants ----
    ModelInfo("qwen2.5-72b-instruct", "Qwen", "Alibaba", "2024-09-13", "frontier"),
    ModelInfo("qwen2.5-7b-instruct", "Qwen", "Alibaba", "2024-09-13", "standard"),
    ModelInfo("qwen2-72b-instruct", "Qwen", "Alibaba", "2024-06-07", "frontier"),
    ModelInfo("qwen2-7b-instruct", "Qwen", "Alibaba", "2024-06-07", "standard"),
    ModelInfo("phi-3-medium-4k-instruct", "Phi", "Microsoft", "2024-06-19", "standard"),
    ModelInfo("phi-3-mini-4k-instruct", "Phi", "Microsoft", "2024-04-22", "standard"),
    # ---- Embeddings (старые) ----
    ModelInfo("text-embedding-3-large", "Embedding", "OpenAI", "2024-01-25", "embedding"),
    ModelInfo("text-embedding-3-small", "Embedding", "OpenAI", "2024-01-25", "embedding"),
    ModelInfo("text-embedding-ada-002", "Embedding", "OpenAI", "2022-12-15", "embedding"),
    ModelInfo("embed-english-v3.0", "Embedding", "Cohere", "2023-11-02", "embedding"),
    # ---- Image ----
    ModelInfo("dall-e-3", "DALL-E", "OpenAI", "2023-10-01", "image"),
    ModelInfo("dall-e-2", "DALL-E", "OpenAI", "2022-11-03", "image"),
    ModelInfo("stable-image-core", "Stable", "Stability", "2024-06-26", "image"),
    # ---- Cerebras ----
    ModelInfo("llama3.1-8b", "Llama", "Cerebras", "2024-07-23", "standard"),
    ModelInfo("llama3.1-70b", "Llama", "Cerebras", "2024-07-23", "frontier"),

    # ---- OpenCode Zen (https://opencode.ai/zen/v1, OpenAI-совместимый gateway) ----
    # Бесплатные модели (Free tier) — помечены tier "standard" и -free в имени.
    ModelInfo("deepseek-v4-flash-free", "DeepSeek", "OpenCode Zen", "2026-08-01", "standard"),
    ModelInfo("mimo-v2.5-free", "MiMo", "OpenCode Zen", "2026-08-01", "standard"),
    ModelInfo("hy3-free", "Hy3", "OpenCode Zen", "2026-08-01", "standard"),
    ModelInfo("laguna-s-2.1-free", "Laguna", "OpenCode Zen", "2026-08-01", "standard"),
    ModelInfo("ling-3.0-tiny-free", "Ling", "OpenCode Zen", "2026-08-01", "standard"),
    ModelInfo("nemotron-3-ultra-free", "Nemotron", "OpenCode Zen", "2026-08-01", "standard"),
    ModelInfo("nemotron-3.5-lightning-free", "Nemotron", "OpenCode Zen", "2026-08-01", "standard"),
    ModelInfo("big-pickle", "BigPickle", "OpenCode Zen", "2026-08-01", "standard"),
    # Платные модели zen (популярные; многие дублируются в реестре выше —
    # точный матч вернёт первую запись, что ок: метаданные те же).
    ModelInfo("deepseek-v4-pro", "DeepSeek", "OpenCode Zen", "2026-08-01", "frontier"),
    ModelInfo("deepseek-v4-flash", "DeepSeek", "OpenCode Zen", "2026-08-01", "standard"),
    ModelInfo("glm-5.2", "GLM", "OpenCode Zen", "2026-08-01", "frontier"),
    ModelInfo("glm-5.1", "GLM", "OpenCode Zen", "2026-08-01", "frontier"),
    ModelInfo("minimax-m3", "MiniMax", "OpenCode Zen", "2026-08-01", "frontier"),
    ModelInfo("minimax-m2.7", "MiniMax", "OpenCode Zen", "2026-08-01", "standard"),
    ModelInfo("minimax-m2.5", "MiniMax", "OpenCode Zen", "2026-08-01", "standard"),
    ModelInfo("kimi-k3", "Kimi", "OpenCode Zen", "2026-08-01", "frontier"),
    ModelInfo("kimi-k2.7-code", "Kimi", "OpenCode Zen", "2026-08-01", "standard"),
    ModelInfo("kimi-k2.6", "Kimi", "OpenCode Zen", "2026-08-01", "standard"),
    ModelInfo("kimi-k2.5", "Kimi", "OpenCode Zen", "2026-08-01", "standard"),
    ModelInfo("qwen3.6-plus", "Qwen", "OpenCode Zen", "2026-08-01", "standard"),
    ModelInfo("qwen3.5-plus", "Qwen", "OpenCode Zen", "2026-08-01", "standard"),
    ModelInfo("gpt-5.6-sol", "GPT", "OpenCode Zen", "2026-08-01", "frontier"),
    ModelInfo("gpt-5.6-terra", "GPT", "OpenCode Zen", "2026-08-01", "frontier"),
    ModelInfo("gpt-5.6-luna", "GPT", "OpenCode Zen", "2026-08-01", "standard"),
    ModelInfo("gpt-5.3-codex", "GPT", "OpenCode Zen", "2026-08-01", "frontier"),
    ModelInfo("gpt-5.3-codex-spark", "GPT", "OpenCode Zen", "2026-08-01", "frontier"),
    ModelInfo("grok-build-0.1", "Grok", "OpenCode Zen", "2026-08-01", "standard"),
    ModelInfo("grok-4.6", "Grok", "OpenCode Zen", "2026-08-01", "frontier"),
    ModelInfo("grok-4.5", "Grok", "OpenCode Zen", "2026-08-01", "frontier"),
]

# Быстрый поиск по точному имени (lowercase)
_BY_NAME: Dict[str, ModelInfo] = {m.name.lower(): m for m in _KNOWN}

# Префиксы семейств для эвристики
_FAMILY_PREFIXES: List[Tuple[str, str]] = [
    ("gpt-4o", "GPT"), ("gpt-4", "GPT"), ("gpt-3.5", "GPT"), ("gpt-3", "GPT"),
    ("o3", "o-series"), ("o1", "o-series"), ("o4", "o-series"),
    ("claude-3-5", "Claude"), ("claude-3", "Claude"), ("claude-2", "Claude"),
    ("gemini-2", "Gemini"), ("gemini-1.5", "Gemini"), ("gemini-1", "Gemini"),
    ("llama-3.3", "Llama"), ("llama-3.1", "Llama"), ("llama3", "Llama"),
    ("llama-3", "Llama"), ("llama2", "Llama"), ("llama-2", "Llama"),
    ("mistral-large", "Mistral"), ("mistral-small", "Mistral"),
    ("mistral-medium", "Mistral"), ("mistral-tiny", "Mistral"),
    ("open-mistral", "Mistral"), ("mixtral", "Mixtral"), ("open-mixtral", "Mixtral"),
    ("command-r", "Command"), ("command", "Command"),
    ("grok-2", "Grok"), ("grok", "Grok"),
    ("deepseek", "DeepSeek"),
    ("gemma", "Gemma"), ("qwen", "Qwen"), ("phi-3", "Phi"), ("phi", "Phi"),
    ("dall-e", "DALL-E"), ("stable", "Stable"),
    ("text-embedding", "Embedding"), ("embed-", "Embedding"),
    ("whisper", "Audio"), ("tts", "Audio"),
]

# ---------------------------------------------------------------------------
# Capabilities — переопределения для конкретных моделей
# ---------------------------------------------------------------------------
# Формат: "text,vision,audio,function_calling,streaming,reasoning,embedding,image,search"
_CAP_OVERRIDES: Dict[str, str] = {
    # GPT — 4o/4-turbo имеют vision, 3.5 — нет
    "gpt-4o": "text,vision,function_calling,streaming",
    "gpt-4o-mini": "text,vision,function_calling,streaming",
    "gpt-4-turbo": "text,vision,function_calling,streaming",
    "gpt-4": "text,function_calling,streaming",
    "gpt-4-0613": "text,function_calling,streaming",
    "gpt-3.5-turbo": "text,function_calling,streaming",
    # o-series — reasoning, без vision (o1) / с vision (o3)
    "o1": "text,reasoning,streaming",
    "o1-preview": "text,reasoning,streaming",
    "o1-mini": "text,reasoning,streaming",
    "o3-mini": "text,vision,reasoning,streaming",
    # Claude 3+ — vision
    "claude-3-5-sonnet-20241022": "text,vision,function_calling,streaming",
    "claude-3-5-sonnet-20240620": "text,vision,function_calling,streaming",
    "claude-3-opus-20240229": "text,vision,function_calling,streaming",
    "claude-3-haiku-20240307": "text,vision,function_calling,streaming",
    "claude-2.1": "text,streaming",
    "claude-2.0": "text,streaming",
    # Gemini — multimodal (text+vision+audio)
    "gemini-2.0-flash": "text,vision,audio,function_calling,streaming",
    "gemini-1.5-pro": "text,vision,audio,function_calling,streaming",
    "gemini-1.5-flash": "text,vision,audio,function_calling,streaming",
    # Embeddings
    "text-embedding-3-large": "embedding",
    "text-embedding-3-small": "embedding",
    "text-embedding-ada-002": "embedding",
    "embed-english-v3.0": "embedding",
    # Image
    "dall-e-3": "image",
    "dall-e-2": "image",
    "stable-image-core": "image",
}

# Размер контекста (в токенах) по family или точному имени
_CONTEXT_WINDOWS: Dict[str, int] = {
    "gpt-4o": 128000, "gpt-4o-mini": 128000,
    "gpt-4-turbo": 128000, "gpt-4": 8192, "gpt-4-0613": 8192,
    "gpt-3.5-turbo": 16385, "gpt-3.5-turbo-0125": 16385,
    "o1": 200000, "o1-preview": 128000, "o1-mini": 128000, "o3-mini": 200000,
    "claude-3-5-sonnet-20241022": 200000, "claude-3-opus-20240229": 200000,
    "claude-3-haiku-20240307": 200000, "claude-2.1": 200000,
    "gemini-2.0-flash": 1048576, "gemini-1.5-pro": 2000000,
    "gemini-1.5-flash": 1000000,
    "llama-3.3-70b": 128000, "llama-3.1-405b": 128000,
    "deepseek-r1": 64000, "deepseek-reasoner": 64000,
    "qwen2.5-72b-instruct": 131072, "mistral-large": 128000,
}

# Макс. выходных токенов
_MAX_OUTPUT: Dict[str, int] = {
    "gpt-4o": 16384, "gpt-4o-mini": 16384,
    "o1": 100000, "o1-preview": 32768, "o1-mini": 65536, "o3-mini": 100000,
    "gpt-4-turbo": 4096, "gpt-4": 8192, "gpt-3.5-turbo": 4096,
    "claude-3-5-sonnet-20241022": 8192, "claude-3-opus-20240229": 4096,
    "gemini-2.0-flash": 8192, "gemini-1.5-pro": 8192,
}

# Цены ($ за 1M токенов): (input, output)
_PRICING: Dict[str, Tuple[float, float]] = {
    "gpt-4o": (2.5, 10.0), "gpt-4o-mini": (0.15, 0.60),
    "o1": (15.0, 60.0), "o1-preview": (15.0, 60.0),
    "o1-mini": (1.10, 4.40), "o3-mini": (1.10, 4.40),
    "gpt-4-turbo": (10.0, 30.0), "gpt-4": (30.0, 60.0),
    "gpt-3.5-turbo": (0.50, 1.50),
    "claude-3-5-sonnet-20241022": (3.0, 15.0),
    "claude-3-opus-20240229": (15.0, 75.0),
    "claude-3-haiku-20240307": (0.25, 1.25),
    "gemini-2.0-flash": (0.10, 0.40),
    "gemini-1.5-pro": (1.25, 5.0), "gemini-1.5-flash": (0.075, 0.30),
    "deepseek-r1": (0.55, 2.19), "deepseek-reasoner": (0.55, 2.19),
    "llama-3.3-70b": (0.59, 0.79),
    "mistral-large": (2.0, 6.0),
    "qwen2.5-72b-instruct": (0.35, 0.40),
}

# Порядок сортировки по capabilities (меньше = раньше):
# 0=text-only, 1=vision, 2=audio, 3=multimodal(text+vision+audio),
# 4=reasoning, 5=embedding, 6=image, 7=search, 8=other
_CAP_RANK = {
    "text": 0, "vision": 1, "audio": 2,
    "reasoning": 4, "embedding": 5, "image": 6, "search": 7, "other": 8,
}


def infer_capabilities(name: str, family: str, tier: str) -> str:
    """Определить capabilities модели по имени/семейству/tier."""
    low = name.lower()
    bare = low.split('/')[-1] if '/' in low else low

    if tier == "embedding" or "embed" in low:
        return "embedding"
    if tier == "image" or "dall-e" in low or "stable-image" in low:
        return "image"
    if "whisper" in low or "tts" in low or "audio" in family.lower():
        return "audio"
    if "sonar" in low:
        return "text,search,streaming"

    caps = {"text", "streaming", "function_calling"}

    # Vision
    if family in ("GPT", "Claude", "Gemini", "Grok"):
        if not any(x in bare for x in ("gpt-3.5", "gpt-3-", "claude-2", "claude-instant")):
            caps.add("vision")
    if "vision" in low or "4o" in bare or "claude-3" in bare or "gemini" in bare:
        caps.add("vision")
    if "llava" in low or "vision" in low:
        caps.add("vision")

    # Audio (Gemini multimodal)
    if family == "Gemini":
        caps.add("audio")

    # Reasoning
    if family == "o-series" or "reasoner" in low or "-r1" in low or "reasoning" in low:
        caps.add("reasoning")
        caps.discard("function_calling")

    return ",".join(sorted(caps))


def capability_rank(name: str, family: str, tier: str, caps: str = "") -> int:
    """Ранг для сортировки: text(0) → vision(1) → audio(2) → multimodal(3) → ..."""
    if not caps:
        caps = infer_capabilities(name, family, tier)
    cap_set = set(caps.split(","))

    if "embedding" in cap_set:
        return 5
    if "image" in cap_set:
        return 6
    if "audio" in cap_set and "text" in cap_set and "vision" in cap_set:
        return 3  # multimodal
    if "audio" in cap_set:
        return 2
    if "reasoning" in cap_set and "vision" in cap_set:
        return 4  # reasoning+vision (o3 etc)
    if "reasoning" in cap_set:
        return 4
    if "vision" in cap_set:
        return 1
    if "search" in cap_set:
        return 7
    if "text" in cap_set:
        return 0
    return 8


def capability_label(caps: str) -> str:
    """Короткая метка для отображения в таблице."""
    if not caps:
        return "text"
    cap_set = set(caps.split(","))
    if "embedding" in cap_set:
        return "embed"
    if "image" in cap_set:
        return "image"
    if "audio" in cap_set and "vision" in cap_set and "text" in cap_set:
        return "multi"
    if "audio" in cap_set:
        return "audio"
    if "reasoning" in cap_set and "vision" in cap_set:
        return "think+vis"
    if "reasoning" in cap_set:
        return "think"
    if "vision" in cap_set:
        return "vision"
    if "search" in cap_set:
        return "search"
    if "text" in cap_set:
        return "text"
    return caps[:8]


def _parse_iso(d: str) -> Optional[date]:
    try:
        return date.fromisoformat(d)
    except (ValueError, TypeError):
        return None


def _guess_release(name: str) -> str:
    """Эвристика даты релиза по идентификатору модели.

    Ищет YYYY-MM-DD или YYYYMMDD суффикс; иначе YYYY (год); иначе "".
    """
    m = re.search(r'(20\d{2})-(\d{2})-(\d{2})', name)
    if m:
        d = _parse_iso(f"{m.group(1)}-{m.group(2)}-{m.group(3)}")
        if d:
            return d.isoformat()
    m = re.search(r'(20\d{2})(\d{2})(\d{2})', name)
    if m:
        d = _parse_iso(f"{m.group(1)}-{m.group(2)}-{m.group(3)}")
        if d:
            return d.isoformat()
    m = re.search(r'(20\d{2})', name)
    if m:
        return f"{m.group(1)}-01-01"
    return ""


def _guess_family(name: str) -> str:
    low = name.lower()
    # Удалить префикс провайдера (openai/, google/, anthropic/, meta/, ...)
    bare = low.split('/')[-1] if '/' in low else low
    for prefix, fam in _FAMILY_PREFIXES:
        if bare.startswith(prefix) or low.startswith(prefix):
            return fam
    # Дополнительные эвристики по подстроке
    if 'gemini' in low:
        return "Gemini"
    if 'gpt' in low or 'o1' in low or 'o3' in low:
        return "GPT"
    if 'claude' in low:
        return "Claude"
    if 'llama' in low or 'llama3' in low:
        return "Llama"
    if 'mistral' in low or 'mixtral' in low:
        return "Mistral"
    if 'grok' in low:
        return "Grok"
    if 'deepseek' in low:
        return "DeepSeek"
    if 'qwen' in low:
        return "Qwen"
    if 'gemma' in low:
        return "Gemma"
    if 'phi' in low:
        return "Phi"
    if 'command' in low:
        return "Command"
    if 'sonar' in low:
        return "Sonar"
    if 'embedding' in low or 'embed' in low:
        return "Embedding"
    if 'dall-e' in low or 'stable' in low:
        return "Image"
    if 'glm' in low:
        return "GLM"
    if 'kimi' in low or 'moonshot' in low:
        return "Kimi"
    if 'minimax' in low or 'abab' in low:
        return "Minimax"
    if 'nemotron' in low:
        return "Nemotron"
    if 'step' in low and 'stepfun' in low:
        return "StepFun"
    return "Other"


def lookup(model_id: str) -> ModelInfo:
    """Возвращает ModelInfo для произвольного идентификатора модели.

    Точное совпадение → данные из реестра; иначе эвристика (family/release).
    Capabilities, context_window, pricing — заполняются через inference.
    """
    if not model_id:
        return ModelInfo("", "Other", "Unknown", "")
    low = model_id.lower()
    if low in _BY_NAME:
        info = _BY_NAME[low]
        # Заполнить расширенные поля если пустые
        caps = info.capabilities or _CAP_OVERRIDES.get(low, "") or \
            infer_capabilities(info.name, info.family, info.tier)
        ctx = info.context_window or _lookup_ctx(low, info.family)
        mo = info.max_output or _MAX_OUTPUT.get(low, 0)
        ip, op = info.input_price, info.output_price
        if ip == 0.0 and op == 0.0:
            ip, op = _lookup_price(low, info.family)
        return ModelInfo(info.name, info.family, info.provider, info.release,
                         info.tier, caps, ctx, mo, ip, op)
    family = _guess_family(model_id)
    release = _guess_release(model_id)
    caps = _CAP_OVERRIDES.get(low, "") or infer_capabilities(model_id, family, "")
    ctx = _lookup_ctx(low, family)
    mo = _MAX_OUTPUT.get(low, 0)
    ip, op = _lookup_price(low, family)
    return ModelInfo(model_id, family, "", release, "", caps, ctx, mo, ip, op)


def _lookup_ctx(low: str, family: str) -> int:
    if low in _CONTEXT_WINDOWS:
        return _CONTEXT_WINDOWS[low]
    # по семейству — среднее
    fam_map = {"GPT": 128000, "Claude": 200000, "Gemini": 1000000,
               "o-series": 200000, "Llama": 128000, "Mistral": 32000,
               "Mixtral": 32000, "DeepSeek": 64000, "Qwen": 131072,
               "Gemma": 8192, "Phi": 4096, "Command": 128000,
               "Grok": 128000, "Sonar": 128000}
    return fam_map.get(family, 0)


def _lookup_price(low: str, family: str) -> Tuple[float, float]:
    if low in _PRICING:
        return _PRICING[low]
    return (0.0, 0.0)


def sort_key(model_id: str) -> Tuple[int, str, str]:
    """Ключ сортировки: новизна (release desc), затем family, затем имя.

    Возвращает кортеж для sorted(key=..., reverse=False): модели без даты
    идут последними (используем 0001-01-01 как минимальную дату).
    """
    info = lookup(model_id)
    rel = info.release or "0001-01-01"
    # Инвертируем дату, чтобы новые шли первыми при reverse=False
    inv = rel.replace("-", "")[::-1]
    return (0 if rel != "0001-01-01" else 1, 9999 - int(rel.replace("-", "") or 0), model_id.lower())


def capability_sort_key(model_id: str) -> Tuple[int, int, int, str]:
    """Ключ сортировки по capabilities, затем по новизне.

    Порядок: text(0) → vision(1) → audio(2) → multimodal(3) → reasoning(4)
             → embedding(5) → image(6) → search(7) → other(8)
    Внутри одной категории — новизна (новые первыми), затем имя.
    """
    info = lookup(model_id)
    rank = capability_rank(info.name, info.family, info.tier, info.capabilities)
    rel = info.release or "0001-01-01"
    rel_int = int(rel.replace("-", "") or 0)
    # Новые первыми → инвертируем
    return (rank, 99999999 - rel_int, 0 if rel != "0001-01-01" else 1, model_id.lower())


def model_family(model_id: str) -> str:
    return lookup(model_id).family


def all_known() -> List[ModelInfo]:
    return list(_KNOWN)
