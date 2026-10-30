"""config.py: env / config_local.py / defaults precedence + token rotation.

Also covers tui_i18n: t()/tf() lookup and fallbacks, resolve_lang()/detect_system_lang()
resolution order and the (safe, tmp-dir) save_lang_pref() writer.

Никакой сети, никаких реальных токенов: значения из config_local.py никогда
не логируются и не используются в ассертах. Каждый тест, которому нужен
config_local.py, получает СВОЙ временный файл и изолированную копию config.py,
поэтому реальный config_local.py проекта не читается и не пишется.
"""
from __future__ import annotations

import importlib.util
import locale as locale_module
import os
import sys
import types
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config as config_module  # noqa: E402  (import печатает [OK] про config_local)
import tui_i18n  # noqa: E402
from config import Config  # noqa: E402

ENV_KEYS = ("PROXY_URL", "GITHUB_TOKENS", "PASTEBIN_API_KEY")


@pytest.fixture(autouse=True)
def _no_config_env(monkeypatch):
    """Никаких унаследованных PROXY_URL/GITHUB_TOKENS из окружения теста."""
    for key in ENV_KEYS:
        monkeypatch.delenv(key, raising=False)


# ---------------------------------------------------------------------------
#                    Config(): значения по умолчанию / env
# ---------------------------------------------------------------------------

def test_config_reads_env_at_construction(monkeypatch):
    monkeypatch.setenv("PROXY_URL", "socks5://127.0.0.1:1080")
    monkeypatch.setenv("GITHUB_TOKENS", "ghp_one,ghp_two")
    monkeypatch.setenv("PASTEBIN_API_KEY", "pb-test")

    cfg = Config()

    assert cfg.proxy_url == "socks5://127.0.0.1:1080"
    assert cfg.github_tokens == ["ghp_one", "ghp_two"]
    assert cfg.pastebin_api_key == "pb-test"


def test_config_defaults_without_env():
    cfg = Config()

    assert cfg.proxy_url == ""
    assert cfg.github_tokens == []
    assert cfg.pastebin_api_key == ""
    # Пути и прикладные дефолты не должны «плыть» от окружения.
    assert cfg.db_path == "leaked_keys.db"
    assert cfg.consumer_threads == 20
    assert cfg.request_timeout == 15
    assert cfg.circuit_breaker_enabled is True
    assert cfg.validator_max_retries == 3
    assert cfg.validator_retry_backoff == 1.5
    assert cfg.rescan_interval_hours == 24
    assert cfg.context_window == 10


def test_empty_env_value_is_not_a_token(monkeypatch):
    # Пустая переменная не должна превращаться в список с пустой строкой.
    monkeypatch.setenv("GITHUB_TOKENS", "")
    cfg = Config()
    assert cfg.github_tokens == []


def test_proxies_property(monkeypatch):
    monkeypatch.setenv("PROXY_URL", "http://proxy.local:3128")
    cfg = Config()
    assert cfg.proxies == {
        "http": "http://proxy.local:3128",
        "https": "http://proxy.local:3128",
    }

    monkeypatch.delenv("PROXY_URL")
    assert Config().proxies is None


def test_default_base_urls_have_openai_and_gemini():
    urls = Config().default_base_urls
    assert urls["openai"].startswith("https://")
    assert urls["gemini"].startswith("https://")
    assert urls["anthropic"].startswith("https://")
    # Все значения — строки; пустая строка означает «нет онлайн-эндпоинта»
    # (azure/aws*), по ней unverified_drainer отсекает платформу.
    assert all(isinstance(v, str) for v in urls.values())
    assert {k for k, v in urls.items() if not v} == {
        "azure", "aws_access_key", "aws_secret_key"}


# ---------------------------------------------------------------------------
#                        Ротация токенов GitHub
# ---------------------------------------------------------------------------

def _cfg_with_tokens(tokens):
    cfg = Config()
    cfg.github_tokens = list(tokens)
    cfg._token_index = 0
    return cfg


def test_get_token_and_rotate_wraps_around():
    cfg = _cfg_with_tokens(["a", "b", "c"])

    assert cfg.get_token() == "a"
    assert cfg.rotate_token() == "b"
    assert cfg.get_token() == "b"
    assert cfg.rotate_token() == "c"
    assert cfg.rotate_token() == "a"  # wrap
    assert cfg.get_token() == "a"


def test_token_rotation_on_empty_pool_returns_empty_string():
    cfg = _cfg_with_tokens([])

    assert cfg.get_token() == ""
    assert cfg.rotate_token() == ""
    assert cfg.get_random_token() == ""
    assert cfg._token_index == 0


def test_get_random_token_membership_and_passthrough(monkeypatch):
    cfg = _cfg_with_tokens(["alpha", "beta"])

    # Детерминизм: подменяем random.choice и проверяем проброс в пул.
    monkeypatch.setattr(
        config_module.random, "choice", lambda seq: seq[-1]
    )
    assert cfg.get_random_token() == "beta"

    monkeypatch.undo()
    for _ in range(64):
        assert cfg.get_random_token() in ("alpha", "beta")


# ---------------------------------------------------------------------------
#              Изолированная загрузка config.py + config_local.py
# ---------------------------------------------------------------------------

def _load_config_copy(tmp_path: Path, local_source: str | None,
                      monkeypatch, env: dict | None = None):
    """Скопировать config.py во временный каталог и выполнить его.

    Рядом (опционально) кладётся config_local.py. Реальный config_local.py
    проекта на время импорта убирается из sys.modules, поэтому копия видит
    только временный файл.
    """
    (tmp_path / "config.py").write_text(
        Path(config_module.__file__).read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    if local_source is not None:
        (tmp_path / "config_local.py").write_text(local_source, encoding="utf-8")

    for key, value in (env or {}).items():
        monkeypatch.setenv(key, value)

    saved_local = sys.modules.pop("config_local", None)
    try:
        monkeypatch.syspath_prepend(str(tmp_path))
        if local_source is None:
            # sys.modules[name] = None заставляет `import config_local`
            # бросить ImportError, иначе он найдётся в PROJECT_ROOT (он есть
            # в sys.path) и копия подхватит РЕАЛЬНЫЕ токены.
            sys.modules["config_local"] = None
        spec = importlib.util.spec_from_file_location(
            "config_copy_under_test", tmp_path / "config.py"
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.modules.pop("config_local", None)
        # Возвращаем «настоящий» config_local в кэш импорта.
        if saved_local is not None:
            sys.modules["config_local"] = saved_local


LOCAL_FULL = """
GITHUB_TOKENS = ["local-token"]
PROXY_URL = "http://local.proxy:1"
DB_PATH = "local.db"
CONSUMER_THREADS = 7
REQUEST_TIMEOUT = 9
PASTEBIN_API_KEY = "local-pb"
UI_LANG = "ru"
"""


def test_local_config_overrides_env_and_defaults(tmp_path, monkeypatch, capsys):
    module = _load_config_copy(
        tmp_path,
        LOCAL_FULL,
        monkeypatch,
        env={
            "GITHUB_TOKENS": "env-a,env-b",
            "PROXY_URL": "http://env.proxy:2",
            "PASTEBIN_API_KEY": "env-pb",
        },
    )

    cfg = module.config
    # Явно заданные (непустые) значения config_local.py перекрывают env…
    assert cfg.github_tokens == ["local-token"]
    assert cfg.proxy_url == "http://local.proxy:1"
    assert cfg.pastebin_api_key == "local-pb"
    # …и перекрывают дефолты dataclass.
    assert cfg.db_path == "local.db"
    assert cfg.consumer_threads == 7
    assert cfg.request_timeout == 9

    out = capsys.readouterr().out
    assert "[OK]" in out
    assert "config_local.py" in out
    # Значения токена в вывод не попадают.
    assert "local-token" not in out


LOCAL_EMPTY = """
GITHUB_TOKENS = []
PROXY_URL = ""
DB_PATH = ""
CONSUMER_THREADS = 0
REQUEST_TIMEOUT = 0
PASTEBIN_API_KEY = ""
"""


def test_empty_local_values_do_not_clobber_env(tmp_path, monkeypatch):
    module = _load_config_copy(
        tmp_path,
        LOCAL_EMPTY,
        monkeypatch,
        env={"GITHUB_TOKENS": "env-only", "PROXY_URL": "http://env.proxy:2"},
    )

    cfg = module.config
    # Guard: пустой список в config_local.py не затирает токены из env.
    assert cfg.github_tokens == ["env-only"]
    assert cfg.proxy_url == "http://env.proxy:2"
    # Пустые строки/нули не затирают дефолты dataclass.
    assert cfg.db_path == "leaked_keys.db"
    assert cfg.consumer_threads == 20
    assert cfg.request_timeout == 15
    assert cfg.pastebin_api_key == ""


def test_env_wins_over_defaults_without_config_local(tmp_path, monkeypatch, capsys):
    module = _load_config_copy(
        tmp_path, None, monkeypatch, env={"GITHUB_TOKENS": "only-token"}
    )

    cfg = module.config
    assert cfg.github_tokens == ["only-token"]
    assert cfg.proxy_url == ""
    assert cfg.db_path == "leaked_keys.db"

    out = capsys.readouterr().out
    assert "[WARNING]" not in out  # токены есть -> предупреждения нет


def test_missing_config_local_and_no_tokens_warns(tmp_path, monkeypatch, capsys):
    module = _load_config_copy(tmp_path, None, monkeypatch)

    assert module.config.github_tokens == []
    out = capsys.readouterr().out
    assert "[WARNING]" in out
    assert "GITHUB_TOKENS" in out


def test_broken_config_local_is_non_fatal(tmp_path, monkeypatch, capsys):
    module = _load_config_copy(
        tmp_path, 'raise RuntimeError("boom-config")\n', monkeypatch
    )

    cfg = module.config
    assert cfg.github_tokens == []
    assert cfg.db_path == "leaked_keys.db"
    out = capsys.readouterr().out
    assert "[WARNING]" in out
    assert "Failed to load config_local.py" in out
    assert "boom-config" in out


# ---------------------------------------------------------------------------
#                               tui_i18n: t()/tf()
# ---------------------------------------------------------------------------

def test_t_known_keys_ru_and_en():
    assert tui_i18n.t("tab_dashboard", "en") == "Dashboard"
    assert tui_i18n.t("tab_dashboard", "ru") == "Дашборд"
    assert tui_i18n.t("startup_config_ok", "en") == "Configuration check passed"
    assert tui_i18n.t("startup_config_ok", "ru") != "Configuration check passed"


def test_t_unknown_key_returns_key_itself():
    assert tui_i18n.t("no_such_key_xyz", "en") == "no_such_key_xyz"
    assert tui_i18n.t("no_such_key_xyz", "ru") == "no_such_key_xyz"


def test_t_unknown_lang_falls_back_to_english(monkeypatch):
    monkeypatch.setitem(tui_i18n._STRINGS, "xx", {"only_xx": "value-xx"})

    assert tui_i18n.t("only_xx", "xx") == "value-xx"
    # ключа нет в 'xx' -> берём английский
    assert tui_i18n.t("tab_dashboard", "xx") == "Dashboard"
    # ключа нет нигде -> сам ключ
    assert tui_i18n.t("missing_both", "xx") == "missing_both"


def test_t_uses_resolve_lang_when_lang_omitted(monkeypatch):
    monkeypatch.setattr(tui_i18n, "resolve_lang", lambda pref=None: "ru")
    assert tui_i18n.t("tab_dashboard") == "Дашборд"

    # Явный lang имеет приоритет над resolve_lang.
    assert tui_i18n.t("tab_dashboard", "en") == "Dashboard"


def test_tf_formats_placeholders(monkeypatch):
    monkeypatch.setitem(tui_i18n._STRINGS, "en", dict(tui_i18n._STRINGS["en"]))

    assert tui_i18n.tf("startup_tokens", "en", n=3) == "Tokens: 3"
    assert tui_i18n.tf("startup_db", "en", path="/tmp/x.db") == "Database: /tmp/x.db"


def test_tf_missing_placeholder_returns_template_instead_of_raising():
    # {n} не передан -> format() падает, tf обязан вернуть шаблон.
    assert tui_i18n.tf("startup_tokens", "en") == "Tokens: {n}"
    assert tui_i18n.tf("no_such_key_xyz", "en", x=1) == "no_such_key_xyz"


# ---------------------------------------------------------------------------
#                    tui_i18n: load/resolve/detect language
# ---------------------------------------------------------------------------

def test_load_lang_pref_env_values(monkeypatch):
    for value in ("en", "ru", "auto"):
        monkeypatch.setenv("TUI_LANG", value)
        assert tui_i18n.load_lang_pref() == value

    monkeypatch.setenv("TUI_LANG", "EN")
    assert tui_i18n.load_lang_pref() == "en"  # регистр не важен


def test_load_lang_pref_falls_back_to_config_local(monkeypatch):
    monkeypatch.delenv("TUI_LANG", raising=False)
    monkeypatch.setitem(
        sys.modules, "config_local", types.SimpleNamespace(UI_LANG="ru")
    )
    assert tui_i18n.load_lang_pref() == "ru"

    # Мусорное значение в config_local.py -> auto.
    monkeypatch.setitem(
        sys.modules, "config_local", types.SimpleNamespace(UI_LANG="klingon")
    )
    assert tui_i18n.load_lang_pref() == "auto"


def test_load_lang_pref_without_any_config(monkeypatch):
    monkeypatch.delenv("TUI_LANG", raising=False)
    # config_local недоступен -> ImportError внутри load_lang_pref.
    monkeypatch.setitem(sys.modules, "config_local", None)
    assert tui_i18n.load_lang_pref() == "auto"


def test_resolve_lang_explicit_pref():
    assert tui_i18n.resolve_lang("en") == "en"
    assert tui_i18n.resolve_lang("ru") == "ru"


def test_resolve_lang_auto_uses_detection(monkeypatch):
    monkeypatch.setattr(tui_i18n, "detect_system_lang", lambda: "ru")
    assert tui_i18n.resolve_lang("auto") == "ru"


def test_resolve_lang_none_uses_saved_pref(monkeypatch):
    monkeypatch.setattr(tui_i18n, "load_lang_pref", lambda: "en")
    assert tui_i18n.resolve_lang() == "en"


def test_detect_system_lang_env_override(monkeypatch):
    monkeypatch.setenv("TUI_LANG", "en")
    assert tui_i18n.detect_system_lang() == "en"
    monkeypatch.setenv("TUI_LANG", "ru")
    assert tui_i18n.detect_system_lang() == "ru"


@pytest.mark.parametrize("tui_lang", ["auto", "", None])
def test_detect_system_lang_uses_locale(monkeypatch, tui_lang):
    if tui_lang is None:
        monkeypatch.delenv("TUI_LANG", raising=False)
    else:
        monkeypatch.setenv("TUI_LANG", tui_lang)

    monkeypatch.setattr(
        tui_i18n.locale, "getlocale", lambda: ("ru_RU", "UTF-8")
    )
    assert tui_i18n.detect_system_lang() == "ru"

    monkeypatch.setattr(
        tui_i18n.locale, "getlocale", lambda: ("en_US", "UTF-8")
    )
    assert tui_i18n.detect_system_lang() == "en"


def test_detect_system_lang_falls_back_to_lang_env(monkeypatch):
    monkeypatch.delenv("TUI_LANG", raising=False)
    monkeypatch.setattr(tui_i18n.locale, "getlocale", lambda: (None, None))
    monkeypatch.setattr(tui_i18n.locale, "setlocale", lambda *a, **k: "")
    monkeypatch.setenv("LANG", "ru_RU.UTF-8")
    monkeypatch.delenv("LC_ALL", raising=False)
    assert tui_i18n.detect_system_lang() == "ru"

    monkeypatch.setenv("LANG", "C")
    assert tui_i18n.detect_system_lang() == "en"


def test_detect_system_lang_survives_locale_errors(monkeypatch):
    monkeypatch.delenv("TUI_LANG", raising=False)
    monkeypatch.delenv("LANG", raising=False)
    monkeypatch.delenv("LC_ALL", raising=False)

    def _boom(*a, **k):
        raise ValueError("no locale")

    monkeypatch.setattr(tui_i18n.locale, "getlocale", _boom)
    monkeypatch.setattr(tui_i18n.locale, "setlocale", _boom)
    assert tui_i18n.detect_system_lang() == "en"


# ---------------------------------------------------------------------------
#                     tui_i18n: save_lang_pref (tmp-dir)
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_i18n_file(tmp_path, monkeypatch):
    """Подменить __file__ модуля, чтобы save_lang_pref писал в tmp_path."""
    fake = tmp_path / "tui_i18n.py"
    monkeypatch.setattr(tui_i18n, "__file__", str(fake))
    return tmp_path / "config_local.py"


def test_save_lang_pref_creates_file_without_tokens(fake_i18n_file):
    dest = fake_i18n_file
    tui_i18n.save_lang_pref("ru")

    text = dest.read_text(encoding="utf-8")
    assert 'UI_LANG = "ru"' in text
    # Раньше здесь писался GITHUB_TOKENS = [] и затирал токены из env.
    assert "GITHUB_TOKENS" not in text


def test_save_lang_pref_replaces_existing_line_once(fake_i18n_file):
    dest = fake_i18n_file
    dest.write_text(
        "GITHUB_TOKENS = ['keep-me']\nUI_LANG = \"auto\"\nOTHER = 1\n",
        encoding="utf-8",
    )

    tui_i18n.save_lang_pref("en")

    text = dest.read_text(encoding="utf-8")
    assert text.count("UI_LANG") == 1
    assert 'UI_LANG = "en"' in text
    assert "GITHUB_TOKENS = ['keep-me']" in text
    assert "OTHER = 1" in text


def test_save_lang_pref_appends_when_missing(fake_i18n_file):
    dest = fake_i18n_file
    dest.write_text("GITHUB_TOKENS = ['keep-me']\n", encoding="utf-8")

    tui_i18n.save_lang_pref("ru")

    text = dest.read_text(encoding="utf-8")
    assert "GITHUB_TOKENS = ['keep-me']" in text
    assert text.rstrip().endswith('UI_LANG = "ru"')


def test_save_lang_pref_swallows_os_errors(tmp_path, monkeypatch):
    # Каталог не существует -> OSError внутри, наружу не выходит.
    monkeypatch.setattr(
        tui_i18n, "__file__", str(tmp_path / "missing_dir" / "tui_i18n.py")
    )
    tui_i18n.save_lang_pref("ru")  # не должен бросить


def test_locale_module_reference_is_intact():
    # Защита от случайной подмены глобального locale между тестами.
    assert tui_i18n.locale is locale_module
    assert os.path.basename(str(tui_i18n.__file__)) == "tui_i18n.py"
