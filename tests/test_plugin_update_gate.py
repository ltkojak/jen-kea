"""
tests/test_plugin_update_gate.py
──────────────────────────────────
v5.65.10 (Q99 e) — a box running a Jen older than a plugin's `requires_jen` is not offered the update.

The registry is read from `main`, so the moment a plugin release raises `requires_jen` every older Jen
sees it. The Plugins page used to show "update available" and an Update button anyway (`version_ok`
was computed and never consulted for the update branch), and pressing it downloaded, verified and
extracted the zip - or, on a systemd host, wrote a request marker and started a root service - before
refusing. Now the page says what the update needs, and the refusal happens before any of that.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from jen.services import plugins as plugins_svc


def _entry(**over):
    e = {
        "id": "watchdog",
        "name": "Host Watchdog",
        "version": "99.0.0",
        "requires_jen": "99.0.0",
        "download_url": "https://example.invalid/raw/v99.0.0",
        "sha256": "0" * 64,
    }
    e.update(over)
    return e


def _installed():
    m = json.loads(Path("plugins/watchdog/manifest.json").read_text(encoding="utf-8"))
    m.update(path="/x", bundled=False, root_owned=False, enabled=True, version_ok=True, api_ok=True)
    return m


class TestTheServiceRefusesBeforeAnyDownloadOrRequest:
    def test_a_newer_jen_requirement_is_refused_first(self, monkeypatch):
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: True)
        with (
            patch.object(plugins_svc, "_write_plugin_request", side_effect=AssertionError("marker written")) as marker,
            patch.object(plugins_svc, "_start_plugin_install_unit", side_effect=AssertionError("unit started")),
            patch("jen.services.plugins.requests.get", side_effect=AssertionError("downloaded")) as get,
        ):
            ok, msg = plugins_svc.install_plugin("watchdog", _entry())
        assert ok is False and "needs Jen 99.0.0" in msg and "upgrade Jen first" in msg
        marker.assert_not_called()
        get.assert_not_called()

    def test_the_same_refusal_off_systemd(self, monkeypatch):
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: False)
        with patch("jen.services.plugins.requests.get", side_effect=AssertionError("downloaded")) as get:
            ok, msg = plugins_svc.install_plugin("watchdog", _entry())
        assert ok is False and "upgrade Jen first" in msg
        get.assert_not_called()

    def test_an_entry_with_no_requirement_is_not_blocked(self, monkeypatch):
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: False)
        entry = _entry()
        del entry["requires_jen"]
        with patch("jen.services.plugins.requests.get") as get:
            get.return_value.status_code = 404
            ok, msg = plugins_svc.install_plugin("watchdog", entry)
        assert ok is False and "HTTP 404" in msg  # got as far as the download


class TestThePageAndTheRoutes:
    @pytest.fixture
    def stable_box(self):
        with (
            patch("jen.services.plugins.fetch_registry", return_value=([_entry()], None)),
            patch("jen.services.plugins.discover_plugins", return_value=[_installed()]),
        ):
            yield

    def test_the_page_says_what_the_update_needs_instead_of_offering_it(self, logged_in_client, stable_box):
        body = logged_in_client.get("/settings/plugins").get_data(as_text=True)
        assert "Update needs Jen v99.0.0" in body and "upgrade Jen first" in body
        assert "/settings/plugins/update/watchdog" not in body, "no Update form for an update that cannot be taken"
        assert "UPDATE AVAILABLE" not in body

    def test_the_post_is_refused_and_writes_no_request(self, logged_in_client, stable_box):
        with (
            patch.object(plugins_svc, "_write_plugin_request", side_effect=AssertionError("marker written")),
            patch("jen.services.plugins.requests.get", side_effect=AssertionError("downloaded")),
        ):
            r = logged_in_client.post("/settings/plugins/update/watchdog", follow_redirects=True)
        assert r.status_code == 200 and "upgrade Jen first" in r.get_data(as_text=True)

    def test_an_update_the_jen_can_take_still_shows_its_button(self, logged_in_client):
        with (
            patch("jen.services.plugins.fetch_registry", return_value=([_entry(requires_jen="5.57.0")], None)),
            patch("jen.services.plugins.discover_plugins", return_value=[_installed()]),
        ):
            body = logged_in_client.get("/settings/plugins").get_data(as_text=True)
        assert "/settings/plugins/update/watchdog" in body and "Update needs Jen" not in body
