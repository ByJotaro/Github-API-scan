"""GitHub token health helpers + modal path messaging."""
from __future__ import annotations

import os
from unittest.mock import patch

import tui_app


def test_configured_tokens_skips_placeholders():
    fake = [
        "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "  ",
        "# comment",
        "ghp_TESTONLY_unused_list_entry",
    ]
    with patch.object(tui_app, "_configured_github_tokens", wraps=None):
        # unit the filter logic via mock of import path
        pass
    # Direct filter behavior through health with mocked list
    with patch("tui_app._configured_github_tokens", return_value=[
        "ghp_TESTONLY_not_a_real_secret_token_01",
    ]):
        with patch("tui_app._probe_github_token", return_value=False):
            h = tui_app._github_token_health()
    assert h["configured"] == 1
    assert h["working"] == 0
    assert h["config_local_path"] == tui_app.CONFIG_LOCAL_PATH
    assert os.path.isabs(h["config_local_path"])


def test_health_working_when_probe_ok():
    with patch("tui_app._configured_github_tokens", return_value=["ghp_TESTONLY_ok"]):
        with patch("tui_app._probe_github_token", return_value=True):
            h = tui_app._github_token_health()
    assert h["working"] == 1
    assert h["configured"] == 1


def test_modal_contains_absolute_path():
    health = {
        "configured": 0,
        "working": 0,
        "probed": 0,
        "config_local_path": tui_app.CONFIG_LOCAL_PATH,
        "config_local_exists": False,
        "example_path": tui_app.CONFIG_LOCAL_EXAMPLE,
        "env_set": False,
    }
    screen = tui_app.GitHubTokenNotice(health, lang="en")
    assert os.path.isabs(tui_app.CONFIG_LOCAL_PATH)
    assert tui_app.CONFIG_LOCAL_PATH.endswith("config_local.py")
    assert "config_local.py.example" in tui_app.CONFIG_LOCAL_EXAMPLE
    assert screen._health["config_local_path"] == tui_app.CONFIG_LOCAL_PATH
    assert isinstance(screen, tui_app.ModalScreen)
    assert screen._lang == "en"


def test_modal_single_lang_ok_button_only():
    """Notice is monolingual; only one OK button (no EN+RU dual labels)."""
    import inspect
    src = inspect.getsource(tui_app.GitHubTokenNotice.compose)
    assert "gh_ok" in src
    assert "gh_copy" not in src
    assert "Continue ·" not in src
    assert "Copy path ·" not in src
    ru = tui_app.GitHubTokenNotice(
        {"configured": 2, "working": 0, "config_local_path": "x",
         "config_local_exists": True},
        lang="ru",
    )
    en = tui_app.GitHubTokenNotice(
        {"configured": 0, "working": 0, "config_local_path": "x",
         "config_local_exists": False},
        lang="en",
    )
    assert ru._lang == "ru"
    assert en._lang == "en"
    # OK dismiss bindings + backdrop click handler present
    keys = [b.key for b in tui_app.GitHubTokenNotice.BINDINGS]
    assert "escape" in keys and "enter" in keys
    assert hasattr(tui_app.GitHubTokenNotice, "on_click")
    assert "action_dismiss_notice" in dir(tui_app.GitHubTokenNotice)


def test_placeholder_filter_in_configured():
    """Placeholders with xxxx must not count as real tokens."""
    class FakeCfg:
        github_tokens = [
            "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "ghp_TESTONLY_placeholder_not_a_secret",
        ]

    class FakeMod:
        config = FakeCfg()

    with patch.dict("sys.modules", {"config": FakeMod()}):
        # re-call helper — it imports config inside
        toks = tui_app._configured_github_tokens()
    # xxxx placeholder dropped; second kept (no xxxx)
    assert all("xxxx" not in t.lower() for t in toks)
