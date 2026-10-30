"""Тесты реестра моделей (model_registry.py).

Покрывают: регистрацию/поиск моделей (lookup), эвристики для неизвестных
моделей (family/release), дефолты для пустого идентификатора, capabilities
(infer/rank/label), сортировку (sort_key/capability_sort_key) и целостность
базы известных моделей.

Сеть не используется: модуль полностью офлайн и чистый.
"""

from __future__ import annotations

import dataclasses
from datetime import date

import pytest

import model_registry as mr


# ---------------------------------------------------------------------------
# ModelInfo / дефолты
# ---------------------------------------------------------------------------

def test_model_info_defaults_for_extended_fields():
    info = mr.ModelInfo("m", "GPT", "OpenAI", "2024-01-01")
    assert info.tier == ""
    assert info.capabilities == ""
    assert info.context_window == 0
    assert info.max_output == 0
    assert info.input_price == 0.0
    assert info.output_price == 0.0


def test_model_info_is_frozen():
    info = mr.ModelInfo("m", "GPT", "OpenAI", "2024-01-01")
    with pytest.raises(dataclasses.FrozenInstanceError):
        info.name = "other"


def test_lookup_empty_id_returns_unknown_defaults():
    info = mr.lookup("")
    assert info.name == ""
    assert info.family == "Other"
    assert info.provider == "Unknown"
    assert info.release == ""
    assert info.capabilities == ""
    assert info.context_window == 0
    assert info.input_price == 0.0
    assert info.output_price == 0.0


# ---------------------------------------------------------------------------
# lookup: точное совпадение
# ---------------------------------------------------------------------------

def test_lookup_exact_known_model_returns_registry_row():
    info = mr.lookup("gpt-4o")
    assert info.name == "gpt-4o"
    assert info.family == "GPT"
    assert info.provider == "OpenAI"
    assert info.release == "2024-05-13"
    assert info.tier == "frontier"


def test_lookup_fills_capabilities_from_override():
    info = mr.lookup("gpt-4o")
    # _CAP_OVERRIDES["gpt-4o"]
    assert info.capabilities == "text,vision,function_calling,streaming"


def test_lookup_fills_context_window_and_max_output():
    info = mr.lookup("gpt-4o")
    assert info.context_window == 128000
    assert info.max_output == 16384


def test_lookup_fills_pricing():
    info = mr.lookup("gpt-4o")
    assert info.input_price == pytest.approx(2.5)
    assert info.output_price == pytest.approx(10.0)


def test_lookup_is_case_insensitive_and_returns_canonical_name():
    lower = mr.lookup("gpt-4o-mini")
    upper = mr.lookup("GPT-4O-MINI")
    assert upper.name == lower.name == "gpt-4o-mini"
    assert upper.provider == "OpenAI"
    assert upper.input_price == pytest.approx(0.15)
    assert upper.output_price == pytest.approx(0.60)


def test_lookup_known_embedding_has_empty_price_and_context():
    info = mr.lookup("text-embedding-3-large")
    assert info.family == "Embedding"
    assert info.tier == "embedding"
    assert info.capabilities == "embedding"
    assert info.context_window == 0
    assert info.max_output == 0
    assert info.input_price == 0.0 and info.output_price == 0.0


def test_lookup_known_image_model():
    info = mr.lookup("dall-e-3")
    assert info.family == "DALL-E"
    assert info.tier == "image"
    assert info.capabilities == "image"


def test_lookup_sonar_has_search_capability():
    info = mr.lookup("perplexity/sonar")
    assert info.family == "Sonar"
    assert info.provider == "Perplexity"
    assert info.capabilities == "text,search,streaming"
    assert info.context_window == 128000


def test_lookup_o3_mini_reasoning_with_vision():
    info = mr.lookup("o3-mini")
    assert info.family == "o-series"
    assert "reasoning" in info.capabilities.split(",")
    assert "vision" in info.capabilities.split(",")
    assert "function_calling" not in info.capabilities.split(",")


# ---------------------------------------------------------------------------
# lookup: неизвестные модели (эвристика)
# ---------------------------------------------------------------------------

def test_lookup_unknown_model_uses_heuristics():
    info = mr.lookup("my-custom-gpt-4o-2024-11-20")
    assert info.name == "my-custom-gpt-4o-2024-11-20"
    assert info.family == "GPT"
    assert info.provider == ""
    assert info.release == "2024-11-20"
    assert info.tier == ""
    # family GPT ⇒ vision; caps отсортированы по алфавиту
    assert info.capabilities == "function_calling,streaming,text,vision"
    assert info.context_window == 128000  # по family
    assert info.max_output == 0
    assert info.input_price == 0.0 and info.output_price == 0.0


def test_lookup_fully_unknown_model_gets_other_family():
    info = mr.lookup("zzz-unknown")
    assert info.family == "Other"
    assert info.release == ""
    assert info.context_window == 0
    assert info.capabilities == "function_calling,streaming,text"


def test_lookup_unknown_whisper_is_audio():
    info = mr.lookup("whisper-1")
    assert info.family == "Audio"
    assert info.capabilities == "audio"


def test_duplicate_registry_names_resolve_to_last_registration():
    """В _KNOWN есть повторяющиеся lowercase-имена (вендор + OpenCode Zen).

    Контракт: _BY_NAME строится словарным включением, побеждает последняя
    запись; lookup обязан следовать тому же порядку (детерминизм).
    """
    seen = {}
    for info in mr._KNOWN:
        seen[info.name.lower()] = info
    assert mr._BY_NAME == seen
    assert mr._BY_NAME["glm-5.2"] is seen["glm-5.2"]
    dup_lookup = mr.lookup("glm-5.2")
    assert dup_lookup.provider == seen["glm-5.2"].provider


# ---------------------------------------------------------------------------
# _parse_iso / _guess_release
# ---------------------------------------------------------------------------

def test_parse_iso_valid_and_invalid():
    assert mr._parse_iso("2024-02-29") == date(2024, 2, 29)
    assert mr._parse_iso("2024-02-30") is None  # несуществующая дата
    assert mr._parse_iso("not-a-date") is None
    assert mr._parse_iso(None) is None
    assert mr._parse_iso("") is None


def test_guess_release_full_iso_date():
    assert mr._guess_release("claude-3-opus-20240229") == "2024-02-29"
    assert mr._guess_release("model-2024-11-20-preview") == "2024-11-20"


def test_guess_release_compact_and_year_only():
    assert mr._guess_release("x-20250304") == "2025-03-04"
    assert mr._guess_release("x-2025") == "2025-01-01"


def test_guess_release_invalid_date_falls_back_to_year():
    # 13-й месяц не парсится → остаётся только год
    assert mr._guess_release("x-2025-13-45") == "2025-01-01"


def test_guess_release_without_date_returns_empty():
    assert mr._guess_release("nothing-here") == ""


# ---------------------------------------------------------------------------
# _guess_family
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "model_id, family",
    [
        ("meta-llama/Llama-3.3-70B", "Llama"),       # префикс провайдера срезан
        ("mixtral-8x7b", "Mixtral"),
        ("command-r-plus", "Command"),
        ("text-embedding-3-large", "Embedding"),
        ("deepseek-r1", "DeepSeek"),
        ("qwen2.5", "Qwen"),
        ("gemma-2", "Gemma"),
        ("phi-3-mini", "Phi"),
        ("grok-2", "Grok"),
        ("abab6.5", "Minimax"),
        ("glm-5", "GLM"),
        ("kimi-k2", "Kimi"),
        ("nemotron-super", "Nemotron"),
        ("stable-diffusion-xl", "Stable"),
        ("dall-e-3", "DALL-E"),
        ("whisper-1", "Audio"),
        ("o1-preview", "o-series"),
        ("gpt-4-turbo", "GPT"),
        ("zzz", "Other"),
    ],
)
def test_guess_family_prefix_table(model_id, family):
    assert mr._guess_family(model_id) == family


# ---------------------------------------------------------------------------
# infer_capabilities
# ---------------------------------------------------------------------------

def test_infer_capabilities_embedding_by_tier_or_name():
    assert mr.infer_capabilities("whatever", "Other", "embedding") == "embedding"
    assert mr.infer_capabilities("x-embed-v9", "Other", "") == "embedding"


def test_infer_capabilities_image():
    assert mr.infer_capabilities("dall-e-3", "DALL-E", "image") == "image"
    assert mr.infer_capabilities("stable-image-core", "Stable", "") == "image"


def test_infer_capabilities_audio():
    assert mr.infer_capabilities("whisper-1", "Audio", "") == "audio"
    assert mr.infer_capabilities("tts-1", "Other", "") == "audio"


def test_infer_capabilities_sonar_is_text_search_streaming():
    assert mr.infer_capabilities("sonar-pro", "Sonar", "frontier") == \
        "text,search,streaming"


def test_infer_capabilities_gpt35_has_no_vision():
    caps = mr.infer_capabilities("gpt-3.5-turbo", "GPT", "standard")
    assert caps == "function_calling,streaming,text"
    assert "vision" not in caps.split(",")


def test_infer_capabilities_gpt4o_has_vision():
    caps = mr.infer_capabilities("gpt-4o", "GPT", "frontier")
    assert "vision" in caps.split(",")
    assert "function_calling" in caps.split(",")


def test_infer_capabilities_oseries_drops_function_calling():
    caps = mr.infer_capabilities("o1-mini", "o-series", "frontier")
    assert caps == "reasoning,streaming,text"


def test_infer_capabilities_gemini_is_multimodal():
    caps = mr.infer_capabilities("gemini-2.0-flash", "Gemini", "frontier")
    assert caps == "audio,function_calling,streaming,text,vision"


def test_infer_capabilities_reasoner_name_marks_reasoning():
    caps = mr.infer_capabilities("deepseek-reasoner", "DeepSeek", "frontier")
    assert caps == "reasoning,streaming,text"


# ---------------------------------------------------------------------------
# capability_rank / capability_label
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "caps, rank",
    [
        ("text", 0),
        ("text,vision", 1),
        ("audio", 2),
        ("audio,text,vision", 3),
        ("reasoning", 4),
        ("reasoning,vision", 4),
        ("embedding", 5),
        ("image", 6),
        ("search", 7),
        ("video", 8),
    ],
)
def test_capability_rank_explicit_caps(caps, rank):
    assert mr.capability_rank("m", "Other", "", caps) == rank


def test_capability_rank_infers_when_caps_empty():
    # gpt-4o → text+vision+function_calling+streaming ⇒ vision(1)
    assert mr.capability_rank("gpt-4o", "GPT", "frontier") == 1
    # пустые данные ⇒ только text ⇒ 0
    assert mr.capability_rank("", "", "") == 0


@pytest.mark.parametrize(
    "caps, label",
    [
        ("", "text"),
        ("text", "text"),
        ("text,vision", "vision"),
        ("text,vision,audio", "multi"),
        ("audio", "audio"),
        ("reasoning,vision", "think+vis"),
        ("reasoning", "think"),
        ("embedding", "embed"),
        ("image", "image"),
        ("search", "search"),
        ("weird,stuff", "weird,st"),
    ],
)
def test_capability_label(caps, label):
    assert mr.capability_label(caps) == label


# ---------------------------------------------------------------------------
# Сортировка
# ---------------------------------------------------------------------------

def test_sort_key_puts_newest_first_and_undated_last():
    ids = ["gpt-4o", "gpt-5.5", "zzz-unknown"]
    assert sorted(ids, key=mr.sort_key) == ["gpt-5.5", "gpt-4o", "zzz-unknown"]


def test_sort_key_shape():
    key = mr.sort_key("gpt-4o")
    assert key[0] == 0          # дата известна
    assert key[2] == "gpt-4o"   # имя в нижнем регистре
    undated = mr.sort_key("zzz-unknown")
    assert undated[0] == 1


def test_sort_key_is_deterministic_and_dates_are_monotonic():
    older = mr.sort_key("gpt-4o")        # 2024-05-13
    newer = mr.sort_key("gpt-5.5")       # 2026-05-01
    assert newer < older  # при reverse=False новые идут первыми


def test_capability_sort_key_ranks_and_newest_first():
    text_old = mr.capability_sort_key("llama-3.3-70b")   # rank 0
    vision = mr.capability_sort_key("gpt-4o")            # rank 1
    assert text_old[0] == 0
    assert vision[0] == 1
    # внутри одного ранга — новее первым
    newer = mr.capability_sort_key("gpt-5.5")
    older = mr.capability_sort_key("gpt-4o")
    assert newer[0] == older[0] == 1
    assert newer < older


def test_capability_sort_key_marks_undated_models():
    undated = mr.capability_sort_key("zzz-unknown")
    assert undated[2] == 1  # нет даты релиза
    assert mr.capability_sort_key("gpt-4o")[2] == 0


# ---------------------------------------------------------------------------
# Публичные обёртки и целостность базы
# ---------------------------------------------------------------------------

def test_model_family_wrapper_matches_lookup():
    assert mr.model_family("meta-llama/Llama-3.1-8B") == "Llama"
    assert mr.model_family("gpt-4o") == "GPT"


def test_all_known_returns_copy_not_registry_list():
    first = mr.all_known()
    assert first is not mr._KNOWN
    assert len(first) == len(mr._KNOWN)
    first.clear()
    assert len(mr.all_known()) == len(mr._KNOWN)


def test_registry_rows_have_required_fields_and_valid_dates():
    for info in mr._KNOWN:
        assert info.name
        assert info.family
        assert info.provider
        if info.release:
            assert mr._parse_iso(info.release) is not None, info.name
        assert info.tier in {"frontier", "standard", "legacy", "embedding", "image"}


def test_every_registered_model_is_lookupable_by_its_own_name():
    # Повторяющиеся имена (вендор + реселлер) разрешаются к последней записи,
    # поэтому сверяемся именно с ней.
    last = {}
    for info in mr._KNOWN:
        last[info.name.lower()] = info
    for name, info in last.items():
        found = mr.lookup(name)
        assert found.name.lower() == name
        assert found.family == info.family
        assert found.release == info.release
        assert found.provider == info.provider
