"""
tests/test_plugin_registry.py
────────────────────────────────
v5.21.1 (Q17) — plugin registry checksums. `fetch_registry()` used to
live-fetch each plugin's own manifest.json from its own repo's `main`
branch and overlay version/description/db_migrations, to avoid a
second, easy-to-forget commit syncing those fields on every plugin
release. That's gone: every registry entry's download_url is now
pinned to a release TAG (not `main`), with a real sha256 of that tag's
plugin.zip computed out-of-band — so a live fetch of `main` could
report a version/migration-list that doesn't even match what
install_plugin() downloads and verifies. registry.json is the source
of truth again, updated by hand in the same commit that pins the tag
and the checksum (see plugins/README.md).

Two kinds of test here: fetch_registry()'s simplified, single-request
behavior (all requests.get calls mocked — no real network), and
install_plugin()'s now-fail-closed checksum verification (missing,
mismatched, matching). The last class checks the real, committed
plugins/registry.json itself, so a future entry added without a real
checksum or a tag-pinned download_url fails CI immediately.
"""

import hashlib
import json
import pathlib
import re
from unittest.mock import MagicMock, patch

from jen import extensions
from jen.services import plugins as plugins_svc


def _mock_response(status_code=200, json_data=None, content=b""):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data if json_data is not None else {}
    resp.content = content
    return resp


class TestFetchRegistry:
    def test_returns_the_entries_as_is(self):
        static = [{"id": "ipam", "version": "1.4.1", "download_url": "https://example.com/x"}]
        with patch("jen.services.plugins.requests.get", return_value=_mock_response(200, static)):
            entries, err = plugins_svc.fetch_registry()
        assert err is None
        assert entries == static

    def test_makes_exactly_one_request_no_per_plugin_overlay(self):
        static = [
            {"id": "ipam", "download_url": "https://example.com/ipam"},
            {"id": "network-discovery", "download_url": "https://example.com/nd"},
        ]
        with patch("jen.services.plugins.requests.get", return_value=_mock_response(200, static)) as mock_get:
            plugins_svc.fetch_registry()
        assert mock_get.call_count == 1

    def test_registry_fetch_failure_returns_error(self):
        with patch("jen.services.plugins.requests.get", return_value=_mock_response(500)):
            entries, err = plugins_svc.fetch_registry()
        assert entries == []
        assert "HTTP 500" in err

    def test_registry_fetch_timeout_returns_error(self):
        import requests as requests_module

        with patch("jen.services.plugins.requests.get", side_effect=requests_module.Timeout()):
            entries, err = plugins_svc.fetch_registry()
        assert entries == []
        assert "timed out" in err.lower()

    def test_non_list_registry_body_is_rejected(self):
        with patch("jen.services.plugins.requests.get", return_value=_mock_response(200, {"not": "a list"})):
            entries, err = plugins_svc.fetch_registry()
        assert entries == []
        assert "invalid" in err.lower()


class TestInstallPluginChecksumVerification:
    """install_plugin() downloads a zip and checksums it BEFORE ever
    extracting anything — these tests never reach real zip extraction,
    a checksum failure (missing or mismatched) returns before that."""

    _ZIP_BYTES = b"pretend-this-is-a-zip-file-the-content-does-not-matter-for-these-tests"

    def test_missing_checksum_is_refused(self):
        with patch("jen.services.plugins.requests.get", return_value=_mock_response(200, content=self._ZIP_BYTES)):
            ok, msg = plugins_svc.install_plugin("ipam", {"download_url": "https://example.com/ipam"})
        assert ok is False
        assert msg == "Registry entry has no checksum — refusing to install."

    def test_blank_checksum_is_treated_as_missing(self):
        with patch("jen.services.plugins.requests.get", return_value=_mock_response(200, content=self._ZIP_BYTES)):
            ok, msg = plugins_svc.install_plugin("ipam", {"download_url": "https://example.com/ipam", "sha256": "  "})
        assert ok is False
        assert msg == "Registry entry has no checksum — refusing to install."

    def test_mismatched_checksum_is_refused(self):
        wrong_hash = "0" * 64
        with patch("jen.services.plugins.requests.get", return_value=_mock_response(200, content=self._ZIP_BYTES)):
            ok, msg = plugins_svc.install_plugin(
                "ipam", {"download_url": "https://example.com/ipam", "sha256": wrong_hash}
            )
        assert ok is False
        assert "checksum verification" in msg.lower()

    def test_matching_checksum_proceeds_past_verification(self):
        # A correct checksum on non-zip bytes proceeds to extraction,
        # which then fails for an unrelated reason (bad zip) — proving
        # the checksum gate itself passed rather than refusing.
        real_hash = hashlib.sha256(self._ZIP_BYTES).hexdigest()
        with patch("jen.services.plugins.requests.get", return_value=_mock_response(200, content=self._ZIP_BYTES)):
            ok, msg = plugins_svc.install_plugin(
                "ipam", {"download_url": "https://example.com/ipam", "sha256": real_hash}
            )
        assert ok is False
        assert "checksum" not in msg.lower()

    def test_checksum_comparison_is_case_insensitive(self):
        real_hash = hashlib.sha256(self._ZIP_BYTES).hexdigest().upper()
        with patch("jen.services.plugins.requests.get", return_value=_mock_response(200, content=self._ZIP_BYTES)):
            ok, msg = plugins_svc.install_plugin(
                "ipam", {"download_url": "https://example.com/ipam", "sha256": real_hash}
            )
        assert "checksum" not in msg.lower()

    def test_download_failure_short_circuits_before_any_checksum_logic(self):
        with patch("jen.services.plugins.requests.get", return_value=_mock_response(503)):
            ok, msg = plugins_svc.install_plugin(
                "ipam", {"download_url": "https://example.com/ipam", "sha256": "a" * 64}
            )
        assert ok is False
        assert "503" in msg


class TestRealRegistryEntriesAreFullyPinned:
    """The actual, committed plugins/registry.json — not a fixture.
    A future plugin release that forgets the checksum or leaves
    download_url pointed at `main` fails this in CI immediately."""

    def _entries(self):
        path = pathlib.Path("plugins/registry.json")
        return json.loads(path.read_text(encoding="utf-8"))

    def test_registry_is_a_non_empty_list(self):
        entries = self._entries()
        assert isinstance(entries, list)
        assert len(entries) >= 2

    def test_every_entry_has_a_64_hex_sha256(self):
        for entry in self._entries():
            sha = entry.get("sha256", "")
            assert re.fullmatch(r"[0-9a-f]{64}", sha), f"{entry.get('id')}: sha256 {sha!r} is not 64 lowercase hex"

    def test_every_entry_download_url_is_pinned_to_a_release_tag(self):
        for entry in self._entries():
            url = entry.get("download_url", "")
            assert re.search(r"/raw/v\d+\.\d+\.\d+$", url), (
                f"{entry.get('id')}: download_url {url!r} is not pinned to a vX.Y.Z tag"
            )
            assert "/raw/main" not in url, f"{entry.get('id')}: download_url still points at main"

    def test_every_entry_download_url_is_https(self):
        for entry in self._entries():
            assert entry.get("download_url", "").startswith("https://")


class TestInstallPluginOnSystemdHost:
    """v5.27.0 (Q23) — on a real systemd host, install_plugin() becomes a
    requester: it writes an empty marker and triggers
    jen-plugin-install.service instead of doing any download/verify/
    extract work itself (that now happens root-side, in
    jen-update-root.py --plugins). CI sets JEN_ROOT, which is why every
    other test in this file exercises the pre-5.27.0 in-process path
    unmodified — is_systemd_host() is False there."""

    def test_writes_install_marker_and_triggers_unit(self, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(tmp_path / "plugin-requests"))
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: True)
        with patch.object(plugins_svc, "_start_plugin_install_unit") as trigger:
            ok, msg = plugins_svc.install_plugin(
                "ipam", {"download_url": "https://example.com/ipam", "sha256": "a" * 64}
            )
        assert ok is True
        assert "requested" in msg.lower()
        trigger.assert_called_once()
        assert (tmp_path / "plugin-requests" / "ipam.install").exists()

    def test_invalid_plugin_id_never_reaches_the_systemd_host_path(self, monkeypatch):
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: True)
        with patch.object(plugins_svc, "_start_plugin_install_unit") as trigger:
            ok, msg = plugins_svc.install_plugin("../evil", {})
        assert ok is False
        trigger.assert_not_called()


class TestUninstallPluginOnSystemdHost:
    def test_root_owned_plugin_requests_removal_instead_of_deleting_it(self, tmp_path, monkeypatch):
        root_dir = tmp_path / "root-installed"
        (root_dir / "sample").mkdir(parents=True)
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(root_dir))
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(tmp_path / "plugin-requests"))
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: True)
        with patch.object(plugins_svc, "_start_plugin_install_unit") as trigger:
            ok, msg = plugins_svc.uninstall_plugin("sample")
        assert ok is True
        assert "requested" in msg.lower()
        trigger.assert_called_once()
        assert (tmp_path / "plugin-requests" / "sample.remove").exists()
        # Removal is root-side, later — this call must not touch the
        # root-owned directory itself.
        assert (root_dir / "sample").is_dir()

    def test_legacy_writable_plugin_is_still_removed_in_process(self, tmp_path, monkeypatch):
        content_dir = tmp_path / "content-plugins"
        (content_dir / "myplug").mkdir(parents=True)
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(content_dir))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(tmp_path / "root-absent"))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(tmp_path / "bundled-absent"))
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: True)
        ok, msg = plugins_svc.uninstall_plugin("myplug")
        assert ok is True
        assert not (content_dir / "myplug").exists()


class TestDiscoverPluginsRootOwnedPrecedence:
    """v5.27.0 (Q23) adds a third tier between bundled and writable.
    tests/test_content_layout.py::TestDiscoverPluginsMerge already
    covers bundled-vs-writable; these cover the new tier."""

    def _manifest(self, base, plugin_id="sample", version="1.0.0"):
        d = base / plugin_id
        d.mkdir(parents=True)
        (d / "manifest.json").write_text(f'{{"id":"{plugin_id}","name":"Sample","version":"{version}"}}')

    def test_root_owned_wins_over_bundled(self, tmp_path, monkeypatch):
        bundled, root = tmp_path / "bundled", tmp_path / "root"
        self._manifest(bundled, version="1.0.0")
        self._manifest(root, version="2.0.0")
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(bundled))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(root))
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(tmp_path / "writable-absent"))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))
        found = {p["id"]: p for p in plugins_svc.discover_plugins()}
        assert found["sample"]["version"] == "2.0.0"
        assert found["sample"]["root_owned"] is True
        assert found["sample"]["bundled"] is False

    def test_writable_still_wins_over_root_owned(self, tmp_path, monkeypatch):
        root, writable = tmp_path / "root", tmp_path / "writable"
        self._manifest(root, version="2.0.0")
        self._manifest(writable, version="3.0.0")
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(tmp_path / "bundled-absent"))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(root))
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(writable))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))
        found = {p["id"]: p for p in plugins_svc.discover_plugins()}
        assert found["sample"]["version"] == "3.0.0"
        assert found["sample"]["root_owned"] is False


class TestPluginInstallUnitStatus:
    def test_parses_systemctl_show_output(self):
        show = MagicMock(returncode=0, stdout="ActiveState=inactive\nSubState=dead\n", stderr="")
        with patch.object(plugins_svc.subprocess, "run", return_value=show):
            status = plugins_svc.plugin_install_unit_status()
        assert status == {"active_state": "inactive", "sub_state": "dead"}

    def test_query_failure_degrades_to_unknown(self):
        with patch.object(plugins_svc.subprocess, "run", side_effect=OSError("no systemctl")):
            status = plugins_svc.plugin_install_unit_status()
        assert status == {"active_state": "unknown", "sub_state": ""}


class TestReadPluginRequestResult:
    def test_reads_and_deletes_the_result_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(tmp_path))
        (tmp_path / "ipam.result").write_text("ok\n")
        assert plugins_svc.read_plugin_request_result("ipam") == "ok"
        assert not (tmp_path / "ipam.result").exists()

    def test_missing_result_file_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(tmp_path))
        assert plugins_svc.read_plugin_request_result("ipam") is None

    def test_invalid_plugin_id_returns_none_without_touching_disk(self, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(tmp_path))
        assert plugins_svc.read_plugin_request_result("../evil") is None


class TestPluginsPageShowsOwnershipChips:
    """v5.27.0 (Q23) — the plugins page marks each installed plugin
    root-owned or writable-needs-reinstall once is_systemd_host() is
    true; a Docker/dev checkout (is_systemd_host() False, the actual
    case under pytest) shows neither, unchanged from before this
    feature existed."""

    def _install_sample(self, tmp_path, monkeypatch, base_attr):
        base = tmp_path / base_attr
        (base / "sample").mkdir(parents=True)
        (base / "sample" / "manifest.json").write_text(
            '{"id":"sample","name":"Sample Plugin","version":"1.0.0","description":"x"}'
        )
        for attr in ("PLUGIN_DIR_ROOT", "PLUGIN_DIR_BUNDLED", "PLUGIN_DIR"):
            monkeypatch.setattr(extensions, attr, str(tmp_path / "absent" / attr))
        monkeypatch.setattr(extensions, base_attr, str(base))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: True)
        monkeypatch.setattr(plugins_svc, "fetch_registry", lambda: ([], None))

    def test_root_owned_chip_shown(self, logged_in_client, tmp_path, monkeypatch):
        self._install_sample(tmp_path, monkeypatch, "PLUGIN_DIR_ROOT")
        r = logged_in_client.get("/settings/plugins")
        assert r.status_code == 200
        assert b"root-owned" in r.data
        assert b"Reinstall" not in r.data

    def test_writable_chip_and_reinstall_button_shown(self, logged_in_client, tmp_path, monkeypatch):
        self._install_sample(tmp_path, monkeypatch, "PLUGIN_DIR")
        r = logged_in_client.get("/settings/plugins")
        assert r.status_code == 200
        assert b"reinstall to harden" in r.data
        assert b"Reinstall" in r.data
