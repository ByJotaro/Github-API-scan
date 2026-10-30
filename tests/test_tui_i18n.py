"""Language detection + resolve preference."""
from __future__ import annotations

import os
from unittest.mock import patch

import tui_i18n


def test_detect_russian_locale():
    with patch("tui_i18n.locale.getlocale", return_value=("ru_RU", "UTF-8")):
        with patch.dict(os.environ, {"TUI_LANG": "", "LANG": ""}, clear=False):
            # clear TUI_LANG if set
            os.environ.pop("TUI_LANG", None)
            assert tui_i18n.detect_system_lang() == "ru"


def test_detect_english_locale():
    with patch("tui_i18n.locale.getlocale", return_value=("en_US", "UTF-8")):
        os.environ.pop("TUI_LANG", None)
        assert tui_i18n.detect_system_lang() == "en"


def test_resolve_pref_en():
    assert tui_i18n.resolve_lang("en") == "en"
    assert tui_i18n.resolve_lang("ru") == "ru"


def test_t_english_tabs():
    assert tui_i18n.t("tab_dashboard", "en") == "Dashboard"
    assert tui_i18n.t("tab_dashboard", "ru") == "Дашборд"
    assert tui_i18n.t("panel_workers", "en") == "Sources (workers)"


def test_env_override():
    with patch.dict(os.environ, {"TUI_LANG": "en"}):
        assert tui_i18n.load_lang_pref() == "en"
        assert tui_i18n.resolve_lang() == "en"
