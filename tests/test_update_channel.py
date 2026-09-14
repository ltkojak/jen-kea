"""
tests/test_update_channel.py
────────────────────────────
v5.32.0 (Q38) — release channels. `[updates] channel` in jen.config
(read by the web side through AppConfig and by the root updater
straight from the INI), the channel-aware "check for updates", the
superadmin-only selector, and the root script's own reading of the key.
The release picker itself is covered in tests/test_version.py.
"""

import configparser
import json
import pathlib
from types import SimpleNamespace

import pytest

from jen import extensions
from jen.config import _parse_update_channel, app_config
from tests.test_appconfig import isolated_config  # noqa: F401 — fixture reuse
from tests.test_jen_update_root import jen_update_root  # noqa: F401 — fixture reuse

LISTING = [
    {
        "tag_name": "v5.32.0-beta.2",
        "prerelease": True,
        "draft": False,
        "html_url": "https://x/b2",
        "published_at": "2026-09-15T00:00:00Z",
        "assets": [
            {
                "name": "jen-v5.32.0-beta.2.tar.gz",
                "browser_download_url": "https://github.com/ltkojak/jen-kea/releases/download/v5.32.0-beta.2/jen-v5.32.0-beta.2.tar.gz",
            }
        ],
    },
    {
        "tag_name": "v5.31.3",
        "prerelease": False,
        "draft": False,
        "html_url": "https://x/s",
        "published_at": "2026-09-14T00:00:00Z",
        "assets": [
            {
                "name": "jen-v5.31.3.tar.gz",
                "browser_download_url": "https://github.com/ltkojak/jen-kea/releases/download/v5.31.3/jen-v5.31.3.tar.gz",
            }
        ],
    },
    {
        "tag_name": "v5.32.0-beta.1",
        "prerelease": True,
        "draft": False,
        "html_url": "https://x/b1",
        "published_at": "2026-09-14T12:00:00Z",
        "assets": [],
    },
]


class TestConfigParsing:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("stable", "stable"),
            ("beta", "beta"),
            (" Beta ", "beta"),
            ("", "stable"),
            ("nightly", "stable"),
            (None, "stable"),
        ],
    )
    def test_parse_update_channel(self, raw, expected):
        assert _parse_update_channel(raw) == expected

    def test_default_is_stable_when_section_absent(self, isolated_config):  # noqa: F811
        assert extensions.UPDATE_CHANNEL == "stable"

    def test_write_value_round_trips_and_rederives(self, isolated_config):  # noqa: F811
        app_config.write_value("updates", "channel", "beta")
        assert extensions.UPDATE_CHANNEL == "beta"
        on_disk = configparser.ConfigParser()
        on_disk.read(isolated_config)
        assert on_disk.get("updates", "channel") == "beta"
        app_config.write_value("updates", "channel", "garbage")
        assert extensions.UPDATE_CHANNEL == "stable"  # conservative reading of a typo


def _fake_get(payload, status=200):
    def get(url, headers=None, timeout=None):
        assert url.endswith("/releases?per_page=30"), url  # the LIST, not /releases/latest
        return SimpleNamespace(status_code=status, json=lambda: payload)

    return get


class TestCheckUpdate:
    def _check(self, client, monkeypatch, channel, current="5.31.3", payload=LISTING, status=200):
        import requests

        monkeypatch.setattr(requests, "get", _fake_get(payload, status))
        monkeypatch.setattr(extensions, "UPDATE_CHANNEL", channel)
        monkeypatch.setattr("jen.JEN_VERSION", current)
        r = client.get("/settings/infrastructure/check-update")
        assert r.status_code == 200, r.data
        return r.get_json()

    def test_stable_box_is_up_to_date_while_betas_exist(self, logged_in_client, monkeypatch):
        d = self._check(logged_in_client, monkeypatch, "stable")
        assert d["status"] == "up_to_date" and d["latest"] == "5.31.3" and d["channel"] == "stable"

    def test_beta_box_is_offered_the_newest_beta(self, logged_in_client, monkeypatch):
        d = self._check(logged_in_client, monkeypatch, "beta")
        assert d["status"] == "update_available"
        assert d["latest"] == "5.32.0-beta.2" and d["prerelease"] is True and d["channel"] == "beta"
        assert d["asset_url"].endswith("jen-v5.32.0-beta.2.tar.gz")

    def test_beta_box_on_beta_1_sees_beta_2(self, logged_in_client, monkeypatch):
        d = self._check(logged_in_client, monkeypatch, "beta", current="5.32.0-beta.1")
        assert d["status"] == "update_available" and d["latest"] == "5.32.0-beta.2"

    def test_beta_box_on_the_final_is_not_offered_its_own_betas(self, logged_in_client, monkeypatch):
        d = self._check(logged_in_client, monkeypatch, "beta", current="5.32.0")
        assert d["status"] == "up_to_date"

    def test_switching_to_stable_never_downgrades(self, logged_in_client, monkeypatch):
        d = self._check(logged_in_client, monkeypatch, "stable", current="5.32.0-beta.2")
        assert d["status"] == "up_to_date"  # 5.31.3 < 5.32.0-beta.2; nothing to offer yet

    def test_only_drafts_or_nothing_means_no_releases(self, logged_in_client, monkeypatch):
        d = self._check(logged_in_client, monkeypatch, "beta", payload=[{"tag_name": "v9.0.0", "draft": True}])
        assert d["status"] == "no_releases" and d["channel"] == "beta"

    def test_github_error_is_reported_not_raised(self, logged_in_client, monkeypatch):
        d = self._check(logged_in_client, monkeypatch, "stable", payload=[], status=503)
        assert d["status"] == "error" and "503" in d["message"]


class TestChannelSelector:
    def test_page_shows_the_channel_and_selector(self, logged_in_client, monkeypatch):
        monkeypatch.setattr(extensions, "UPDATE_CHANNEL", "beta")
        page = logged_in_client.get("/settings/system").get_data(as_text=True)
        assert "beta channel" in page
        assert 'action="/settings/infrastructure/update-channel"' in page
        assert '<option value="beta" selected>' in page

    def test_superadmin_saves_the_channel_and_audits(self, logged_in_client, isolated_config, db):  # noqa: F811
        r = logged_in_client.post(
            "/settings/infrastructure/update-channel", data={"channel": "beta"}, follow_redirects=True
        )
        assert r.status_code == 200
        assert b"follows the beta channel" in r.data
        assert extensions.UPDATE_CHANNEL == "beta"
        on_disk = configparser.ConfigParser()
        on_disk.read(isolated_config)
        assert on_disk.get("updates", "channel") == "beta"
        with db.cursor() as cur:
            cur.execute("SELECT details FROM audit_log WHERE action='UPDATE_CHANNEL' ORDER BY id DESC LIMIT 1")
            assert cur.fetchone()["details"] == "stable -> beta"
        r = logged_in_client.post(
            "/settings/infrastructure/update-channel", data={"channel": "stable"}, follow_redirects=True
        )
        assert b"follows the stable channel" in r.data and extensions.UPDATE_CHANNEL == "stable"

    def test_unknown_channel_is_refused(self, logged_in_client, isolated_config):  # noqa: F811
        r = logged_in_client.post(
            "/settings/infrastructure/update-channel", data={"channel": "nightly"}, follow_redirects=True
        )
        assert b"Pick stable or beta" in r.data
        assert extensions.UPDATE_CHANNEL == "stable"

    def test_admin_and_viewer_are_refused(self, client, db):
        from tests.conftest import restricted_client

        for role, name in (("admin", "_chan_admin"), ("viewer", "_chan_viewer")):
            c, _uid = restricted_client(client, db, allowed_subnets=None, role=role, username=name)
            r = c.post("/settings/infrastructure/update-channel", data={"channel": "beta"}, follow_redirects=True)
            assert b"superadmin access required" in r.data.lower(), role


class TestRootScriptReadsTheSameKey:
    def test_update_channel_from_ini(self, jen_update_root, tmp_path):  # noqa: F811
        cfg = tmp_path / "jen.config"
        assert jen_update_root._update_channel(str(cfg)) == "stable"  # missing file → stable
        cfg.write_text("[updates]\nchannel = beta\n")
        assert jen_update_root._update_channel(str(cfg)) == "beta"
        cfg.write_text("[updates]\nchannel = Nightly\n")
        assert jen_update_root._update_channel(str(cfg)) == "stable"
        cfg.write_text("[server]\nthreads = 8\n")
        assert jen_update_root._update_channel(str(cfg)) == "stable"

    def test_main_flow_fetches_the_list_and_picks_per_channel(self, jen_update_root):  # noqa: F811
        src = pathlib.Path(jen_update_root.__file__).read_text(encoding="utf-8")
        assert "/releases?per_page=30" in src
        assert "/releases/latest" not in src
        assert "pick_release(fetch_json(GITHUB_RELEASES_API), channel)" in src

    def test_picker_agrees_with_the_web_side(self, jen_update_root):  # noqa: F811
        assert jen_update_root.pick_release(LISTING, "stable")["tag_name"] == "v5.31.3"
        assert jen_update_root.pick_release(LISTING, "beta")["tag_name"] == "v5.32.0-beta.2"
        assert json.dumps(jen_update_root.parse_version("5.32.0-beta.2")) == json.dumps([5, 32, 0, 0, 2])
