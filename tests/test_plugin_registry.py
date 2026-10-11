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
import importlib.util
import json
import os
import pathlib
import re
import sys
import textwrap
from unittest.mock import MagicMock, patch

import pytest

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

    def test_a_crash_leftover_old_directory_is_ignored(self, tmp_path, monkeypatch):
        """v5.28.0 (Q24, A4) — jen-update-root.py's crash-safe swap can
        leave `<id>.old-<ts>` sitting next to the live `<id>` directory.
        Its manifest.json still claims `id: <id>` and it sorts AFTER the
        real directory — without skipping invalid directory NAMES (dots
        aren't a valid plugin id), "later wins" would let the leftover
        shadow the live copy."""
        root = tmp_path / "root"
        self._manifest(root, plugin_id="ipam", version="2.0.0")
        leftover = root / "ipam.old-1000000000"
        leftover.mkdir(parents=True)
        (leftover / "manifest.json").write_text('{"id":"ipam","name":"Sample","version":"1.0.0"}')
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(tmp_path / "bundled-absent"))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(root))
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(tmp_path / "writable-absent"))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))
        found = {p["id"]: p for p in plugins_svc.discover_plugins()}
        assert found["ipam"]["version"] == "2.0.0", "the leftover .old- directory must never shadow the live copy"


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


class TestPluginIdRegexMatchesRootScript:
    """v5.28.0 (Q24, A5) — www-data (this module's _PLUGIN_ID_RE) and the
    root-run request processor (jen-update-root.py's own) must agree on
    exactly which ids can ever exist; they used to differ (this module
    allowed a leading '-', the root script never did)."""

    def test_patterns_are_identical(self):
        root_src = pathlib.Path("jen-update-root.py").read_text(encoding="utf-8")
        m = re.search(r'^_PLUGIN_ID_RE = re\.compile\(r"([^"]+)"\)', root_src, re.MULTILINE)
        assert m, "could not find _PLUGIN_ID_RE in jen-update-root.py"
        assert plugins_svc._PLUGIN_ID_RE.pattern == m.group(1)


class TestPluginDirIncludesRootOwned:
    """v5.28.0 (Q24, A7) — _plugin_dir() used to search only
    (PLUGIN_DIR, PLUGIN_DIR_BUNDLED), which made enable_plugin() and
    disable_plugin() silent no-ops for a root-owned plugin: the enable
    marker was never written because _plugin_dir() always returned None
    for it."""

    def test_finds_a_root_owned_plugin(self, tmp_path, monkeypatch):
        root = tmp_path / "root"
        (root / "sample").mkdir(parents=True)
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(tmp_path / "writable-absent"))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(root))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(tmp_path / "bundled-absent"))
        assert plugins_svc._plugin_dir("sample") == str(root / "sample")

    def test_enable_plugin_creates_the_marker_for_a_root_owned_plugin(self, tmp_path, monkeypatch):
        root = tmp_path / "root"
        (root / "sample").mkdir(parents=True)
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(tmp_path / "writable-absent"))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(root))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(tmp_path / "bundled-absent"))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))
        plugins_svc.enable_plugin("sample")
        assert plugins_svc._is_enabled("sample"), "enable_plugin() must work for a root-owned plugin"

    def test_disable_plugin_removes_the_marker_for_a_root_owned_plugin(self, tmp_path, monkeypatch):
        root = tmp_path / "root"
        (root / "sample").mkdir(parents=True)
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(tmp_path / "writable-absent"))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(root))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(tmp_path / "bundled-absent"))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))
        plugins_svc.enable_plugin("sample")
        assert plugins_svc._is_enabled("sample")
        plugins_svc.disable_plugin("sample")
        assert not plugins_svc._is_enabled("sample")


class TestStartPluginInstallUnitReportsFailure:
    """v5.28.0 (Q24, A8) — the trigger used to be called for its side
    effect only; a sudoers misconfiguration or a missing unit file left
    the caller reporting "Install requested" for a request that would
    never be picked up."""

    def test_nonzero_exit_returns_false(self):
        bad = MagicMock(returncode=1, stderr=b"sudo: a password is required")
        with patch.object(plugins_svc.subprocess, "run", return_value=bad):
            assert plugins_svc._start_plugin_install_unit() is False

    def test_exception_returns_false(self):
        with patch.object(plugins_svc.subprocess, "run", side_effect=OSError("no systemctl")):
            assert plugins_svc._start_plugin_install_unit() is False

    def test_zero_exit_returns_true(self):
        ok = MagicMock(returncode=0, stderr=b"")
        with patch.object(plugins_svc.subprocess, "run", return_value=ok):
            assert plugins_svc._start_plugin_install_unit() is True

    def test_install_plugin_removes_its_marker_and_fails_when_trigger_fails(self, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(tmp_path))
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: True)
        with patch.object(plugins_svc, "_start_plugin_install_unit", return_value=False):
            ok, msg = plugins_svc.install_plugin(
                "ipam", {"download_url": "https://example.com/ipam", "sha256": "a" * 64}
            )
        assert ok is False
        assert "install.sh" in msg
        assert not (tmp_path / "ipam.install").exists(), "the marker must be removed when the trigger fails"

    def test_uninstall_plugin_removes_its_marker_and_fails_when_trigger_fails(self, tmp_path, monkeypatch):
        root = tmp_path / "root"
        (root / "sample").mkdir(parents=True)
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(root))
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(tmp_path / "requests"))
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: True)
        with patch.object(plugins_svc, "_start_plugin_install_unit", return_value=False):
            ok, msg = plugins_svc.uninstall_plugin("sample")
        assert ok is False
        assert "install.sh" in msg
        assert not (tmp_path / "requests" / "sample.remove").exists()
        assert (root / "sample").is_dir(), "the root-owned copy must be untouched"


class TestRecordAndRemovePluginRow:
    """v5.28.0 (Q24, A9) — moved out of jen/routes/plugins.py so both the
    in-process install path and consume_plugin_results() below share
    one implementation."""

    def test_record_then_remove(self, db):
        info = {
            "id": "q24-test-plugin",
            "name": "Q24 Test",
            "version": "1.0.0",
            "description": "desc",
            "author": "someone",
            "requires_jen": "5.0.0",
        }
        try:
            plugins_svc.record_plugin_row(info)
            with db.cursor() as cur:
                cur.execute("SELECT * FROM plugins WHERE id=%s", (info["id"],))
                row = cur.fetchone()
            assert row is not None
            assert row["name"] == "Q24 Test"
            assert row["enabled"] == 1
            # record_plugin_row()/remove_plugin_row() write through a
            # DIFFERENT (jen_db()-pooled) connection than this fixture's
            # own `db`. Without committing here, `db`'s still-open
            # REPEATABLE-READ transaction (opened by the SELECT above)
            # keeps its original snapshot and the next SELECT below
            # would still see the row even after it's deleted elsewhere.
            db.commit()

            plugins_svc.remove_plugin_row(info["id"])
            with db.cursor() as cur:
                cur.execute("SELECT * FROM plugins WHERE id=%s", (info["id"],))
                assert cur.fetchone() is None
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM plugins WHERE id=%s", (info["id"],))
            db.commit()

    def test_record_is_an_upsert(self, db):
        info = {
            "id": "q24-upsert-plugin",
            "name": "V1",
            "version": "1.0.0",
            "description": "",
            "author": "",
            "requires_jen": "",
        }
        try:
            plugins_svc.record_plugin_row(info)
            info["name"] = "V2"
            info["version"] = "2.0.0"
            plugins_svc.record_plugin_row(info)
            with db.cursor() as cur:
                cur.execute("SELECT * FROM plugins WHERE id=%s", (info["id"],))
                rows = cur.fetchall()
            assert len(rows) == 1
            assert rows[0]["name"] == "V2"
            assert rows[0]["version"] == "2.0.0"
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM plugins WHERE id=%s", (info["id"],))
            db.commit()


class TestConsumePluginResults:
    """v5.28.0 (Q24, A9) — the QUEUED -> CONFIRMED half of the split
    v5.27.0 started: applying a root-run <id>.<action>.result to Jen's
    own state (DB row, enable marker, restart_pending, audit log)."""

    def _last_audit(self, db, action, entity):
        with db.cursor() as cur:
            cur.execute(
                "SELECT * FROM audit_log WHERE action=%s AND entity=%s ORDER BY id DESC LIMIT 1", (action, entity)
            )
            return cur.fetchone()

    def test_install_ok_records_row_enables_and_audits(self, tmp_path, monkeypatch, db):
        requests_dir = tmp_path / "requests"
        root = tmp_path / "root"
        requests_dir.mkdir()
        plugin_dir = root / "q24-consume-a"
        plugin_dir.mkdir(parents=True)
        manifest = {
            "id": "q24-consume-a",
            "name": "Consume A",
            "version": "1.2.3",
            "description": "",
            "author": "",
            "requires_jen": "",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))
        (requests_dir / "q24-consume-a.install.result").write_text("ok\n")

        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(requests_dir))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(root))
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(tmp_path / "writable-absent"))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(tmp_path / "bundled-absent"))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))

        try:
            results = plugins_svc.consume_plugin_results()
            assert results == [{"id": "q24-consume-a", "action": "install", "ok": True, "detail": "installed v1.2.3"}]
            assert not (requests_dir / "q24-consume-a.install.result").exists()
            assert plugins_svc._is_enabled("q24-consume-a")

            with db.cursor() as cur:
                cur.execute("SELECT * FROM plugins WHERE id=%s", ("q24-consume-a",))
                row = cur.fetchone()
            assert row is not None and row["version"] == "1.2.3"

            with db.cursor() as cur:
                cur.execute("SELECT setting_value FROM settings WHERE setting_key='restart_pending'")
                setting = cur.fetchone()
            assert setting is not None and setting["setting_value"] == "true"

            assert self._last_audit(db, "PLUGIN_INSTALL", "q24-consume-a") is not None
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM plugins WHERE id=%s", ("q24-consume-a",))
            db.commit()

    def test_remove_ok_without_bundled_copy_disables_and_removes_row(self, tmp_path, monkeypatch, db):
        requests_dir = tmp_path / "requests"
        requests_dir.mkdir()
        (requests_dir / "q24-consume-b.remove.result").write_text("ok\n")
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(requests_dir))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(tmp_path / "bundled-absent"))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))

        plugins_svc.record_plugin_row(
            {
                "id": "q24-consume-b",
                "name": "B",
                "version": "1.0.0",
                "description": "",
                "author": "",
                "requires_jen": "",
            }
        )
        # Pretend it was enabled before removal.
        os.makedirs(str(tmp_path / "en"), exist_ok=True)
        open(str(tmp_path / "en" / "q24-consume-b"), "w").close()

        try:
            results = plugins_svc.consume_plugin_results()
            assert results == [{"id": "q24-consume-b", "action": "remove", "ok": True, "detail": "removed"}]
            assert not plugins_svc._is_enabled("q24-consume-b")
            with db.cursor() as cur:
                cur.execute("SELECT * FROM plugins WHERE id=%s", ("q24-consume-b",))
                assert cur.fetchone() is None
            assert self._last_audit(db, "PLUGIN_UNINSTALL", "q24-consume-b") is not None
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM plugins WHERE id=%s", ("q24-consume-b",))
            db.commit()

    def test_remove_ok_with_a_bundled_copy_keeps_the_enable_marker(self, tmp_path, monkeypatch, db):
        requests_dir = tmp_path / "requests"
        bundled = tmp_path / "bundled"
        requests_dir.mkdir()
        (bundled / "q24-consume-c").mkdir(parents=True)
        (bundled / "q24-consume-c" / "manifest.json").write_text('{"id":"q24-consume-c"}')
        (requests_dir / "q24-consume-c.remove.result").write_text("ok\n")
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(requests_dir))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(bundled))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))

        os.makedirs(str(tmp_path / "en"), exist_ok=True)
        open(str(tmp_path / "en" / "q24-consume-c"), "w").close()

        results = plugins_svc.consume_plugin_results()
        assert results == [
            {
                "id": "q24-consume-c",
                "action": "remove",
                "ok": True,
                "detail": "the built-in copy of 'q24-consume-c' is active again",
            }
        ]
        assert plugins_svc._is_enabled("q24-consume-c"), "the enable marker must survive for the bundled fallback"

    def test_error_result_changes_no_state_but_audits_failure(self, tmp_path, monkeypatch, db):
        requests_dir = tmp_path / "requests"
        requests_dir.mkdir()
        (requests_dir / "q24-consume-d.install.result").write_text("error: checksum verification failed\n")
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(requests_dir))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(tmp_path / "root-absent"))
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(tmp_path / "writable-absent"))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(tmp_path / "bundled-absent"))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))

        results = plugins_svc.consume_plugin_results()
        assert results == [
            {"id": "q24-consume-d", "action": "install", "ok": False, "detail": "error: checksum verification failed"}
        ]
        with db.cursor() as cur:
            cur.execute("SELECT * FROM plugins WHERE id=%s", ("q24-consume-d",))
            assert cur.fetchone() is None
        assert self._last_audit(db, "PLUGIN_INSTALL_FAILED", "q24-consume-d") is not None

    def test_stale_pre_5_28_result_filename_is_deleted_without_being_applied(self, tmp_path, monkeypatch):
        requests_dir = tmp_path / "requests"
        requests_dir.mkdir()
        (requests_dir / "ipam.result").write_text("ok\n")
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(requests_dir))

        results = plugins_svc.consume_plugin_results()
        assert results == []
        assert not (requests_dir / "ipam.result").exists()

    def test_no_requests_dir_returns_empty_list(self, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(tmp_path / "does-not-exist"))
        assert plugins_svc.consume_plugin_results() == []

    def test_transient_remove_failure_is_retried_without_duplicate_row_errors(self, tmp_path, monkeypatch, db):
        """v5.28.1 (Q26, C1) — apply-then-delete-then-audit: if os.remove()
        fails after a successful apply, the result file must survive so
        the next call retries it. record_plugin_row/enable_plugin are
        idempotent, so re-applying the same result is harmless."""
        requests_dir = tmp_path / "requests"
        root = tmp_path / "root"
        requests_dir.mkdir()
        plugin_dir = root / "q26-retry-plugin"
        plugin_dir.mkdir(parents=True)
        manifest = {
            "id": "q26-retry-plugin",
            "name": "Retry Plugin",
            "version": "1.0.0",
            "description": "",
            "author": "",
            "requires_jen": "",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))
        result_path = requests_dir / "q26-retry-plugin.install.result"
        result_path.write_text("ok\n")

        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(requests_dir))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(root))
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(tmp_path / "writable-absent"))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(tmp_path / "bundled-absent"))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))

        real_remove = os.remove
        calls = {"n": 0}

        def flaky_remove(path):
            calls["n"] += 1
            if calls["n"] == 1 and str(path) == str(result_path):
                raise OSError("simulated transient failure")
            real_remove(path)

        try:
            with patch("os.remove", flaky_remove):
                r1 = plugins_svc.consume_plugin_results()
            assert r1 == [{"id": "q26-retry-plugin", "action": "install", "ok": True, "detail": "installed v1.0.0"}]
            assert result_path.exists(), "the result file must survive a failed os.remove()"

            r2 = plugins_svc.consume_plugin_results()
            assert r2 == [{"id": "q26-retry-plugin", "action": "install", "ok": True, "detail": "installed v1.0.0"}]
            assert not result_path.exists()

            with db.cursor() as cur:
                cur.execute("SELECT * FROM plugins WHERE id=%s", ("q26-retry-plugin",))
                rows = cur.fetchall()
            assert len(rows) == 1, "record_plugin_row's upsert must not create a duplicate row on retry"
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM plugins WHERE id=%s", ("q26-retry-plugin",))
            db.commit()

    def test_an_exception_applying_a_result_leaves_the_file_for_the_next_call(self, tmp_path, monkeypatch):
        """v5.28.1 (Q26, C1) — the old order deleted the result file
        BEFORE applying it, so a crash/exception mid-apply lost the only
        authoritative record. Now the file is only removed once
        _apply_plugin_result() returns successfully."""
        requests_dir = tmp_path / "requests"
        requests_dir.mkdir()
        result_path = requests_dir / "q26-raises-plugin.install.result"
        result_path.write_text("ok\n")
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(requests_dir))
        monkeypatch.setattr(
            plugins_svc, "_apply_plugin_result", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom"))
        )

        results = plugins_svc.consume_plugin_results()
        assert results == []
        assert result_path.exists()


class TestRootPathPluginMigrationGate:
    """v5.28.1 (Q26, C3-ii) — a root-owned install's manifest migrations
    now run inside _apply_plugin_result(), since Jen has DB access and
    the root-run request processor never did. A failing migration must
    leave the plugin un-enabled and record a Plugins-page-visible flag;
    a clean one clears that flag and stamps plugin_migrated_ok."""

    def _cleanup(self, db, plugin_id):
        with db.cursor() as cur:
            cur.execute("DELETE FROM plugins WHERE id=%s", (plugin_id,))
            cur.execute(
                "DELETE FROM settings WHERE setting_key IN (%s, %s)",
                (f"plugin_migrated_ok:{plugin_id}", f"plugin_migration_failed:{plugin_id}"),
            )
        db.commit()

    def test_failing_migration_leaves_plugin_not_enabled_and_flags_it(self, tmp_path, monkeypatch, db):
        plugin_id = "q26-root-migration-fail"
        self._cleanup(db, plugin_id)
        requests_dir = tmp_path / "requests"
        root = tmp_path / "root"
        requests_dir.mkdir()
        plugin_dir = root / plugin_id
        plugin_dir.mkdir(parents=True)
        manifest = {
            "id": plugin_id,
            "name": "Root Migration Fail",
            "version": "1.0.0",
            "description": "",
            "author": "",
            "requires_jen": "",
            "db_migrations": [{"version": 1, "description": "broken", "sql": "NOT VALID SQL AT ALL"}],
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))
        (requests_dir / f"{plugin_id}.install.result").write_text("ok\n")

        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(requests_dir))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(root))
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(tmp_path / "writable-absent"))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(tmp_path / "bundled-absent"))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))

        try:
            results = plugins_svc.consume_plugin_results()
            assert len(results) == 1
            entry = results[0]
            assert entry["ok"] is True  # the root side's OWN action succeeded — the migration is a separate gate
            assert "not enabled" in entry["detail"]
            assert not plugins_svc._is_enabled(plugin_id)

            from jen.models.user import get_global_setting

            assert get_global_setting(f"plugin_migration_failed:{plugin_id}")
            assert get_global_setting(f"plugin_migrated_ok:{plugin_id}") is None

            with db.cursor() as cur:
                cur.execute(
                    "SELECT * FROM audit_log WHERE action=%s AND entity=%s ORDER BY id DESC LIMIT 1",
                    ("PLUGIN_INSTALL_MIGRATION_FAILED", plugin_id),
                )
                assert cur.fetchone() is not None
        finally:
            self._cleanup(db, plugin_id)

    def test_clean_migration_enables_and_stamps_migrated_ok(self, tmp_path, monkeypatch, db):
        plugin_id = "q26-root-migration-ok"
        self._cleanup(db, plugin_id)
        requests_dir = tmp_path / "requests"
        root = tmp_path / "root"
        requests_dir.mkdir()
        plugin_dir = root / plugin_id
        plugin_dir.mkdir(parents=True)
        manifest = {
            "id": plugin_id,
            "name": "Root Migration OK",
            "version": "1.0.0",
            "description": "",
            "author": "",
            "requires_jen": "",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))
        (requests_dir / f"{plugin_id}.install.result").write_text("ok\n")

        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(requests_dir))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(root))
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(tmp_path / "writable-absent"))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(tmp_path / "bundled-absent"))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))

        try:
            results = plugins_svc.consume_plugin_results()
            assert results == [{"id": plugin_id, "action": "install", "ok": True, "detail": "installed v1.0.0"}]
            assert plugins_svc._is_enabled(plugin_id)

            from jen.models.user import get_global_setting

            assert get_global_setting(f"plugin_migrated_ok:{plugin_id}") == "1.0.0"
            assert get_global_setting(f"plugin_migration_failed:{plugin_id}") == ""
        finally:
            self._cleanup(db, plugin_id)


class TestInProcessInstallMigrationGate:
    """v5.28.1 (Q26, C3-i) — the in-process install_plugin() path (dev/
    Docker) runs migrations against the manifest read from tmp_dest
    BEFORE anything touches the live directory, so a failing migration
    leaves an existing install completely untouched."""

    def test_failing_migration_leaves_an_existing_install_byte_identical(self, tmp_path, monkeypatch):
        import io
        import zipfile

        plugin_dir_root = tmp_path / "plugins"
        plugin_dir_root.mkdir()
        dest = plugin_dir_root / "q26-inprocess-fail"
        dest.mkdir()
        (dest / "manifest.json").write_text(json.dumps({"id": "q26-inprocess-fail", "name": "Old", "version": "1.0.0"}))
        (dest / "sentinel.txt").write_text("original bytes, must survive")
        before_listing = sorted(p.name for p in dest.iterdir())
        before_sentinel = (dest / "sentinel.txt").read_text()

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(
                "manifest.json",
                json.dumps(
                    {
                        "id": "q26-inprocess-fail",
                        "name": "New",
                        "version": "2.0.0",
                        "requires_jen": "0.0.0",
                        "db_migrations": [{"version": 1, "description": "broken", "sql": "NOT VALID SQL AT ALL"}],
                    }
                ),
            )
            zf.writestr("plugin.py", "# new version\n")
        zip_bytes = buf.getvalue()
        sha = hashlib.sha256(zip_bytes).hexdigest()

        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(plugin_dir_root))
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: False)
        monkeypatch.setattr(plugins_svc, "run_plugin_migrations", lambda m: (False, "duplicate column", 0))
        monkeypatch.setattr(plugins_svc.requests, "get", lambda *a, **k: _mock_response(200, content=zip_bytes))

        ok, msg = plugins_svc.install_plugin(
            "q26-inprocess-fail", {"download_url": "https://example.com/x", "sha256": sha}
        )

        assert ok is False
        assert "nothing was installed" in msg
        assert dest.is_dir()
        assert sorted(p.name for p in dest.iterdir()) == before_listing
        assert (dest / "sentinel.txt").read_text() == before_sentinel
        leftovers = [p.name for p in plugin_dir_root.iterdir() if p.name != "q26-inprocess-fail"]
        assert leftovers == []


class TestPluginsPageConsumesResultsFirst:
    """v5.28.0 (Q24, A9) — plugins_page() must apply any waiting result
    before rendering, so a result that landed while nobody had the
    poller running still shows up correctly on the next visit."""

    def test_a_waiting_result_is_flashed_and_applied_on_page_render(self, logged_in_client, tmp_path, monkeypatch, db):
        requests_dir = tmp_path / "requests"
        root = tmp_path / "root"
        requests_dir.mkdir()
        plugin_dir = root / "q24-page-consume"
        plugin_dir.mkdir(parents=True)
        manifest = {
            "id": "q24-page-consume",
            "name": "Page Consume",
            "version": "1.0.0",
            "description": "",
            "author": "",
            "requires_jen": "",
        }
        (plugin_dir / "manifest.json").write_text(json.dumps(manifest))
        (requests_dir / "q24-page-consume.install.result").write_text("ok\n")

        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(requests_dir))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(root))
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(tmp_path / "writable-absent"))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(tmp_path / "bundled-absent"))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))
        monkeypatch.setattr(plugins_svc, "fetch_registry", lambda: ([], None))

        try:
            r = logged_in_client.get("/settings/plugins")
            assert r.status_code == 200
            assert b"installed v1.0.0" in r.data
            assert not (requests_dir / "q24-page-consume.install.result").exists()
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM plugins WHERE id=%s", ("q24-page-consume",))
            db.commit()


class TestPluginRoutesDeferredState:
    """v5.28.0 (Q24, A9) — install_plugin()/update_plugin()/
    uninstall_plugin() decide "deferred" from request_is_pending(), and
    must NOT touch the plugins DB row or the completion audit for a
    deferred request — only for one that actually finished in-process."""

    def test_install_route_does_not_insert_a_row_when_deferred(self, logged_in_client, tmp_path, monkeypatch, db):
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(tmp_path))
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: True)
        monkeypatch.setattr(
            plugins_svc,
            "fetch_registry",
            lambda: (
                [{"id": "q24-route-a", "name": "Route A", "version": "1.0.0", "download_url": "x", "sha256": "a" * 64}],
                None,
            ),
        )
        with patch.object(plugins_svc, "_start_plugin_install_unit", return_value=True):
            r = logged_in_client.post("/settings/plugins/install/q24-route-a", follow_redirects=True)
        assert r.status_code == 200

        with db.cursor() as cur:
            cur.execute("SELECT * FROM plugins WHERE id=%s", ("q24-route-a",))
            assert cur.fetchone() is None, "a deferred install must not insert a plugins row yet"
        with db.cursor() as cur:
            cur.execute("SELECT * FROM audit_log WHERE action='PLUGIN_INSTALL_REQUESTED' AND entity='q24-route-a'")
            assert cur.fetchone() is not None
        with db.cursor() as cur:
            cur.execute("SELECT * FROM audit_log WHERE action='PLUGIN_INSTALL' AND entity='q24-route-a'")
            assert cur.fetchone() is None, "the completion audit must wait for consume_plugin_results()"

    def test_update_route_redirects_with_plugin_install_when_deferred(self, logged_in_client, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(tmp_path))
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: True)
        monkeypatch.setattr(
            plugins_svc,
            "fetch_registry",
            lambda: (
                [{"id": "q24-route-b", "name": "Route B", "version": "2.0.0", "download_url": "x", "sha256": "a" * 64}],
                None,
            ),
        )
        with patch.object(plugins_svc, "_start_plugin_install_unit", return_value=True):
            r = logged_in_client.post("/settings/plugins/update/q24-route-b", follow_redirects=False)
        assert r.status_code in (301, 302)
        assert "plugin_install=q24-route-b" in r.headers["Location"]

    def test_install_status_returns_the_result_once_then_none(self, logged_in_client, tmp_path, monkeypatch):
        requests_dir = tmp_path / "requests"
        requests_dir.mkdir()
        (requests_dir / "q24-route-c.install.result").write_text("ok\n")
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(requests_dir))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(tmp_path / "root-absent"))
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(tmp_path / "writable-absent"))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(tmp_path / "bundled-absent"))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))
        monkeypatch.setattr(
            plugins_svc, "plugin_install_unit_status", lambda: {"active_state": "inactive", "sub_state": "dead"}
        )

        first = logged_in_client.get("/settings/plugins/install-status/q24-route-c").get_json()
        assert first["result"] == "ok"

        second = logged_in_client.get("/settings/plugins/install-status/q24-route-c").get_json()
        assert second["result"] is None


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
        # The "About Plugins" card mentions the word "Reinstall" in prose
        # on any systemd host regardless of which plugins are installed
        # — the per-plugin button itself is the thing that must be absent.
        assert b'title="Reinstall as a root-owned copy"' not in r.data

    def test_writable_chip_and_reinstall_button_shown(self, logged_in_client, tmp_path, monkeypatch):
        self._install_sample(tmp_path, monkeypatch, "PLUGIN_DIR")
        r = logged_in_client.get("/settings/plugins")
        assert r.status_code == 200
        assert b"reinstall to harden" in r.data
        assert b'title="Reinstall as a root-owned copy"' in r.data


class TestBundledCopiesMatchRegistry:
    """v5.28.2 — the bundled plugin trees under plugins/ and the registry
    entries that point at the plugins' own repos drifted for a year
    (bundled ipam sat at 1.2.3 while the registry pinned 1.4.1, and the
    bundled network-discovery carried a scan-breaking bug the repo had
    already fixed). The bundled copy is now resynced from the tagged
    release the registry pins, and this keeps it that way: a registry
    re-pin without a resync (or vice versa) fails here."""

    def _pairs(self):
        registry = {e["id"]: e for e in json.loads(pathlib.Path("plugins/registry.json").read_text(encoding="utf-8"))}
        for plugin_id in sorted(registry):
            bundled = json.loads(pathlib.Path(f"plugins/{plugin_id}/manifest.json").read_text(encoding="utf-8"))
            yield plugin_id, registry[plugin_id], bundled

    def test_every_registry_plugin_is_bundled_at_the_same_version(self):
        for plugin_id, reg, bundled in self._pairs():
            assert bundled["version"] == reg["version"], (
                f"{plugin_id}: bundled {bundled['version']} != registry {reg['version']}"
            )
            assert reg["download_url"].endswith(f"/raw/v{reg['version']}"), plugin_id

    def test_registry_metadata_mirrors_the_bundled_manifest(self):
        for plugin_id, reg, bundled in self._pairs():
            for key in ("name", "description", "requires_jen", "db_migrations", "nav", "changelog_url"):
                assert reg.get(key) == bundled.get(key), (
                    f"{plugin_id}: registry '{key}' differs from the bundled manifest"
                )

    def test_bundled_trees_carry_no_release_artifacts(self):
        """plugin.zip is what the plugin's own repo publishes at a tag;
        .enabled is a pre-v5.13.0 marker Jen no longer reads. Neither
        belongs in the bundled tree."""
        for plugin_id, _reg, _bundled in self._pairs():
            assert not pathlib.Path(f"plugins/{plugin_id}/plugin.zip").exists(), plugin_id
            assert not pathlib.Path(f"plugins/{plugin_id}/.enabled").exists(), plugin_id

    def test_every_bundled_dir_is_a_shipped_plugin_id(self, monkeypatch):
        """v5.58.3 (Q88) — the other half of the reverse check the class
        docstring already does (every registry entry IS bundled): every
        id shipped_plugin_ids() reports for the real plugins/ tree is
        also a registry entry, and vice versa. Set equality, not a
        hand-maintained literal that can silently stop matching the
        directory the moment a new plugin is bundled without it.

        conftest.py's session-scoped, autouse test_database fixture points
        extensions.PLUGIN_DIR_BUNDLED at an absent temp path for the whole
        suite (a direct assignment, not a monkeypatch, so it never reverts
        on its own) — repoint it at the real tree for this one test."""
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", "plugins")
        registry_ids = {e["id"] for e in json.loads(pathlib.Path("plugins/registry.json").read_text(encoding="utf-8"))}
        assert plugins_svc.shipped_plugin_ids() == frozenset(registry_ids)


class TestOsPackages:
    """v5.30.0 (Q30, A1) — manifest `os_packages`: Jen reports what's
    missing and, on a systemd host, asks the root-run service to install
    it; it never runs apt itself."""

    def test_os_packages_of_ignores_malformed_names(self):
        m = {"os_packages": ["nmap", "bad name", 42, "../x", "arp-scan"]}
        assert plugins_svc.os_packages_of(m) == ["nmap", "arp-scan"]
        assert plugins_svc.os_packages_of({}) == []
        assert plugins_svc.os_packages_of({"os_packages": "nmap"}) == []

    def test_missing_os_packages_uses_which(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmap" if name == "nmap" else None)
        assert plugins_svc.missing_os_packages({"os_packages": ["nmap", "arp-scan"]}) == ["arp-scan"]
        assert plugins_svc.missing_os_packages({"os_packages": ["nmap"]}) == []

    def test_request_writes_deps_marker_and_triggers_unit(self, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(tmp_path / "plugin-requests"))
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: True)
        with patch.object(plugins_svc, "_start_plugin_install_unit", return_value=True) as trigger:
            ok, msg = plugins_svc.request_plugin_deps("network-discovery")
        assert ok is True and "requested" in msg.lower()
        trigger.assert_called_once()
        marker = tmp_path / "plugin-requests" / "network-discovery.deps"
        assert marker.exists() and marker.read_text() == ""  # empty: the root side derives everything

    def test_request_removes_the_marker_when_the_trigger_fails(self, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(tmp_path / "plugin-requests"))
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: True)
        with patch.object(plugins_svc, "_start_plugin_install_unit", return_value=False):
            ok, _msg = plugins_svc.request_plugin_deps("network-discovery")
        assert ok is False
        assert not (tmp_path / "plugin-requests" / "network-discovery.deps").exists()

    def test_request_refused_off_systemd_and_for_a_bad_id(self, monkeypatch):
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: False)
        ok, msg = plugins_svc.request_plugin_deps("network-discovery")
        assert ok is False and "systemd" in msg
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: True)
        with patch.object(plugins_svc, "_start_plugin_install_unit") as trigger:
            ok, _ = plugins_svc.request_plugin_deps("../evil")
        assert ok is False
        trigger.assert_not_called()

    def test_consume_deps_result_ok_and_failed(self, tmp_path, monkeypatch, db):
        requests_dir = tmp_path / "requests"
        requests_dir.mkdir()
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(requests_dir))
        (requests_dir / "network-discovery.deps.result").write_text("ok\n")
        results = plugins_svc.consume_plugin_results()
        assert results == [
            {"id": "network-discovery", "action": "deps", "ok": True, "detail": "OS package(s) installed"}
        ]
        assert not (requests_dir / "network-discovery.deps.result").exists()
        with db.cursor() as cur:
            cur.execute(
                "SELECT * FROM audit_log WHERE action=%s AND entity=%s ORDER BY id DESC LIMIT 1",
                ("PLUGIN_DEPS", "network-discovery"),
            )
            assert cur.fetchone() is not None
        # audit() writes through a different pooled connection; end this
        # connection's REPEATABLE-READ snapshot before the second cycle.
        db.commit()

        (requests_dir / "network-discovery.deps.result").write_text(
            "error: package 'curl' is not in this Jen version's allowlist\n"
        )
        results = plugins_svc.consume_plugin_results()
        assert results[0]["ok"] is False and "allowlist" in results[0]["detail"]
        with db.cursor() as cur:
            cur.execute(
                "SELECT * FROM audit_log WHERE action=%s AND entity=%s ORDER BY id DESC LIMIT 1",
                ("PLUGIN_DEPS_FAILED", "network-discovery"),
            )
            assert cur.fetchone() is not None


class TestOsPackageBinaryMap:
    """v5.69.0-beta.3 (Q172) - a package is not always named like its binary. `iputils-ping` ships `ping` and `snmp`
    ships `snmpbulkwalk`; `shutil.which("<package>")` reported both missing forever on a host that had them, and the
    page offered to install what was installed. OS_PACKAGE_BINARIES says which binaries a package provides."""

    @staticmethod
    def _which(present):
        return lambda name: f"/usr/bin/{name}" if name in present else None

    def test_ping_and_snmpbulkwalk_on_path_report_nothing_missing(self, monkeypatch):
        monkeypatch.setattr("shutil.which", self._which({"ping", "snmpbulkwalk"}))
        manifest = {"os_packages": ["iputils-ping", "snmp"]}
        assert plugins_svc.missing_os_packages(manifest) == []

    def test_without_the_binaries_exactly_those_two_are_missing(self, monkeypatch):
        monkeypatch.setattr("shutil.which", self._which(set()))
        manifest = {"os_packages": ["iputils-ping", "snmp"]}
        assert plugins_svc.missing_os_packages(manifest) == ["iputils-ping", "snmp"]

    def test_the_package_name_alone_on_path_is_not_the_package(self, monkeypatch):
        """A binary that happens to share the PACKAGE's name is not what the plugin runs."""
        monkeypatch.setattr("shutil.which", self._which({"iputils-ping", "snmp"}))
        manifest = {"os_packages": ["iputils-ping", "snmp"]}
        assert plugins_svc.missing_os_packages(manifest) == ["iputils-ping", "snmp"]

    def test_one_of_a_packages_binaries_is_enough(self, monkeypatch):
        monkeypatch.setitem(plugins_svc.OS_PACKAGE_BINARIES, "two-tools", ("tool-a", "tool-b"))
        monkeypatch.setattr("shutil.which", self._which({"tool-b"}))
        assert plugins_svc.missing_os_packages({"os_packages": ["two-tools"]}) == []
        monkeypatch.setattr("shutil.which", self._which(set()))
        assert plugins_svc.missing_os_packages({"os_packages": ["two-tools"]}) == ["two-tools"]

    def test_a_package_with_no_map_entry_is_looked_up_under_its_own_name(self, monkeypatch):
        monkeypatch.setattr("shutil.which", self._which({"arp-scan"}))
        assert plugins_svc.missing_os_packages({"os_packages": ["arp-scan"]}) == []
        monkeypatch.setattr("shutil.which", self._which(set()))
        assert plugins_svc.missing_os_packages({"os_packages": ["arp-scan"]}) == ["arp-scan"]

    @staticmethod
    def _updater_allowlist():
        """jen-update-root.py is a standalone script; load it by path the way tests/test_jen_update_root.py does."""
        script = pathlib.Path(__file__).resolve().parent.parent / "jen-update-root.py"
        spec = importlib.util.spec_from_file_location("jen_update_root_for_os_packages", script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return frozenset(module._DEPS_ALLOWED_PACKAGES)

    def test_every_bundled_manifest_package_is_in_the_map_and_in_the_updaters_allowlist(self):
        """A plugin cannot declare a package Jen cannot check (no map entry: reported missing forever) or the root
        service would refuse to install (no allowlist entry: the Install button fails)."""
        root = pathlib.Path(__file__).resolve().parent.parent / "plugins"
        allowed = self._updater_allowlist()
        checked = set()
        for manifest_path in sorted(root.glob("*/manifest.json")):
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for package in manifest.get("os_packages", []):
                checked.add(package)
                where = f"{manifest_path.parent.name}: os_packages entry {package!r}"
                assert package in plugins_svc.OS_PACKAGE_BINARIES, (
                    f"{where} has no entry in OS_PACKAGE_BINARIES (jen/services/plugins.py)"
                )
                assert package in allowed, f"{where} is not in _DEPS_ALLOWED_PACKAGES (jen-update-root.py)"
        assert {"nmap", "iputils-ping", "snmp"} <= checked, (
            f"a vacuous pass would hide a broken glob: {sorted(checked)}"
        )

    def test_every_registry_entry_package_is_in_the_map_too(self):
        registry = json.loads(
            (pathlib.Path(__file__).resolve().parent.parent / "plugins" / "registry.json").read_text(encoding="utf-8")
        )
        for entry in registry:
            for package in entry.get("os_packages", []):
                assert package in plugins_svc.OS_PACKAGE_BINARIES, f"{entry['id']}: {package!r}"

    def test_the_map_and_the_allowlist_name_the_same_packages(self):
        """The README's rule: a package in the allowlist and not in the map is reported missing forever."""
        assert set(plugins_svc.OS_PACKAGE_BINARIES) == set(self._updater_allowlist())
        for package, binaries in plugins_svc.OS_PACKAGE_BINARIES.items():
            assert binaries and all(isinstance(b, str) and b for b in binaries), package


class TestDepsRoute:
    def _installed(self, monkeypatch, tmp_path, os_packages):
        root = tmp_path / "root"
        (root / "nd").mkdir(parents=True)
        (root / "nd" / "manifest.json").write_text(
            json.dumps(
                {
                    "id": "nd",
                    "name": "ND",
                    "version": "1.0.0",
                    "description": "test plugin",
                    "author": "",
                    "requires_jen": "0.0.0",
                    "os_packages": os_packages,
                }
            )
        )
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(root))
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(tmp_path / "absent"))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(tmp_path / "absent2"))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(tmp_path / "requests"))

    def test_route_requests_only_what_is_missing(self, logged_in_client, db, tmp_path, monkeypatch):
        self._installed(monkeypatch, tmp_path, ["nmap"])
        monkeypatch.setattr("shutil.which", lambda name: None)
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: True)
        with patch.object(plugins_svc, "_start_plugin_install_unit", return_value=True):
            r = logged_in_client.post("/settings/plugins/deps/nd")
        assert r.status_code == 302 and "plugin_install=nd" in r.headers["Location"]
        assert (tmp_path / "requests" / "nd.deps").exists()

    def test_route_is_a_noop_when_nothing_is_missing(self, logged_in_client, db, tmp_path, monkeypatch):
        self._installed(monkeypatch, tmp_path, ["nmap"])
        monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/nmap")
        with patch.object(plugins_svc, "_start_plugin_install_unit") as trigger:
            r = logged_in_client.post("/settings/plugins/deps/nd", follow_redirects=True)
        trigger.assert_not_called()
        assert b"already installed" in r.data

    def test_page_shows_the_chip_and_the_button_on_systemd(self, logged_in_client, db, tmp_path, monkeypatch):
        self._installed(monkeypatch, tmp_path, ["nmap"])
        monkeypatch.setattr("shutil.which", lambda name: None)
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: True)
        monkeypatch.setattr(plugins_svc, "fetch_registry", lambda: ([], ""))
        body = logged_in_client.get("/settings/plugins").data
        assert b"needs on the Jen host: nmap" in body
        assert b'action="/settings/plugins/deps/nd"' in body
        monkeypatch.setattr(plugins_svc, "is_systemd_host", lambda: False)
        body = logged_in_client.get("/settings/plugins").data
        assert b"sudo apt install nmap" in body and b'action="/settings/plugins/deps/nd"' not in body

    def test_route_is_superadmin_only(self, client, db, tmp_path, monkeypatch):
        from tests.conftest import restricted_client

        self._installed(monkeypatch, tmp_path, ["nmap"])
        c, _uid = restricted_client(client, db, allowed_subnets=[], role="admin")
        with patch.object(plugins_svc, "_start_plugin_install_unit") as trigger:
            r = c.post("/settings/plugins/deps/nd")
        assert r.status_code == 302
        trigger.assert_not_called()


class TestNavIcons:
    """v5.65.3 (Q92) - a manifest naming an icon the sprite lacks put the WORD into the navigation
    ("cable Switch Ports"). The bundled manifests are held to the sprite; the loader is
    forgiving about anything else."""

    def test_every_bundled_manifest_nav_icon_is_in_the_sprite(self):
        from jen.services.icons import is_icon

        root = pathlib.Path(__file__).resolve().parent.parent / "plugins"
        checked = 0
        for manifest_path in sorted(root.glob("*/manifest.json")):
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for item in manifest.get("nav", []):
                checked += 1
                assert is_icon(item.get("icon")), (
                    f"{manifest_path.parent.name}: nav icon {item.get('icon')!r} is not in templates/_icon_sprite.html "
                    "- add it to static/icons/src/ and run tools/build_icon_sprite.py"
                )
        assert checked >= 7  # every bundled plugin has a nav entry; a vacuous pass would hide a broken glob

    def test_the_two_icons_the_round_needed_are_in_the_sprite(self):
        from jen.services.icons import is_icon

        assert is_icon("cable") and is_icon("search-check") and is_icon("puzzle")

    def test_a_missing_sprite_name_becomes_puzzle_and_is_logged(self, caplog):
        manifest = {"id": "demo", "nav": [{"label": "X", "icon": "no-such-icon", "endpoint": "x.index"}]}
        with caplog.at_level("WARNING", logger="jen.services.icons"):
            plugins_svc.sanitize_nav_icons(manifest)
        assert manifest["nav"][0]["icon"] == "puzzle"
        assert "no-such-icon" in caplog.text and "plugin demo" in caplog.text

    def test_a_real_name_an_emoji_and_a_missing_value_are_handled(self):
        manifest = {
            "id": "demo",
            "nav": [
                {"icon": "cable"},  # in the sprite: untouched
                {"icon": "\U0001f50d"},  # a plugin's own emoji: still shown as the text it always was
                {"label": "no icon key at all"},  # nothing to validate
                {"icon": ""},  # empty: the puzzle
            ],
        }
        plugins_svc.sanitize_nav_icons(manifest)
        assert [i.get("icon") for i in manifest["nav"]] == ["cable", "\U0001f50d", None, "puzzle"]

    def test_the_loader_sanitizes_before_it_registers_anything(self, tmp_path):
        manifest = {"id": "iconless", "path": str(tmp_path), "nav": [{"icon": "not-a-real-icon"}]}
        try:
            assert plugins_svc._load_plugin(MagicMock(), manifest) is True
            assert plugins_svc.get_nav_items()[-1]["icon"] == "puzzle"
        finally:
            plugins_svc._loaded_plugins.pop("iconless", None)


class TestBlueprintsAreRegisteredLast:
    """v5.69.0-beta.3 (Q172) - the loader runs a plugin's register(app) with `app.register_blueprint` held back and
    registers what it asked for only after register returned. Every bundled plugin registers its blueprint FIRST and
    then registers jobs, alert types and providers that can raise (the Q89 bug), so a raise used to leave the plugin's
    pages live and the plugin half loaded."""

    @pytest.fixture(autouse=True)
    def _clean(self):
        from jen.services import background

        yield
        plugins_svc._loaded_plugins.pop("demo", None)
        plugins_svc._load_failed.pop("demo", None)
        background.unregister_periodic("demo")
        sys.modules.pop("jen_plugin_demo", None)

    @staticmethod
    def _plugin(tmp_path, register_body):
        """A plugin directory whose plugin.py declares two blueprints and a register(app) with the given body."""
        folder = tmp_path / "demo"
        folder.mkdir(exist_ok=True)
        source = (
            textwrap.dedent(
                """
            from flask import Blueprint

            bp = Blueprint("demo_bp", __name__)
            other_bp = Blueprint("demo_other", __name__)
            SEEN_DURING_REGISTER = []


            @bp.route("/demo/ping")
            def ping():
                return "pong"


            @other_bp.route("/x")
            def other_x():
                return "x"


            def register(app):
            """
            )
            + textwrap.indent(textwrap.dedent(register_body).strip("\n"), "    ")
            + "\n"
        )
        (folder / "plugin.py").write_text(source, encoding="utf-8")
        return {"id": "demo", "path": str(folder), "nav": []}

    @staticmethod
    def _rules(app):
        return {rule.rule for rule in app.url_map.iter_rules()}

    def test_a_register_that_raises_after_its_blueprint_registers_no_route(self, tmp_path, caplog):
        from flask import Flask

        manifest = self._plugin(
            tmp_path,
            """
            app.register_blueprint(bp)
            raise RuntimeError("secret detail at /etc/jen/jen.config")
            """,
        )
        app = Flask("loader-test")
        with caplog.at_level("ERROR", logger="jen.services.plugins"):
            assert plugins_svc._load_plugin(app, manifest) is False
        assert "demo_bp" not in app.blueprints
        assert "/demo/ping" not in self._rules(app)
        assert "demo" not in plugins_svc.get_loaded_plugins()
        assert "Failed to load plugin 'demo'" in caplog.text  # the log keeps the text, for the operator
        assert "secret detail" in caplog.text

    def test_the_failure_is_marked_by_class_name_only(self, tmp_path):
        from flask import Flask

        manifest = self._plugin(
            tmp_path,
            """
            app.register_blueprint(bp)
            raise RuntimeError("secret detail at /etc/jen/jen.config")
            """,
        )
        assert plugins_svc.plugin_load_failed("demo") == ""
        plugins_svc._load_plugin(Flask("loader-test"), manifest)
        marker = plugins_svc.plugin_load_failed("demo")
        assert marker == "RuntimeError"
        assert "secret" not in marker and "/" not in marker

    def test_the_app_is_left_as_it_was_after_a_raise(self, tmp_path):
        from flask import Flask

        manifest = self._plugin(tmp_path, "app.register_blueprint(bp)\nraise ValueError('x')")
        app = Flask("loader-test")
        plugins_svc._load_plugin(app, manifest)
        assert "register_blueprint" not in vars(app)  # the recorder is gone, the class method answers again
        app.register_blueprint(self._blueprint("later"))
        assert "later" in app.blueprints

    @staticmethod
    def _blueprint(name):
        from flask import Blueprint

        return Blueprint(name, __name__)

    def test_a_register_that_returns_registers_every_blueprint_in_order_with_its_options(self, tmp_path):
        from flask import Flask

        manifest = self._plugin(
            tmp_path,
            """
            app.register_blueprint(bp, url_prefix="/a")
            SEEN_DURING_REGISTER.append(sorted(app.blueprints))
            app.register_blueprint(other_bp, name="renamed", url_prefix="/b")
            """,
        )
        app = Flask("loader-test")
        assert plugins_svc._load_plugin(app, manifest) is True
        assert plugins_svc.plugin_load_failed("demo") == ""
        assert "demo" in plugins_svc.get_loaded_plugins()
        assert {"/a/demo/ping", "/b/x"} <= self._rules(app)
        assert "renamed" in app.blueprints and "demo_bp" in app.blueprints
        # nothing was on the app while register(app) was still running: the blueprints come LAST
        assert sys.modules["jen_plugin_demo"].SEEN_DURING_REGISTER == [[]]
        assert [r.endpoint for r in app.url_map.iter_rules() if r.rule in ("/a/demo/ping", "/b/x")]  # both routable

    def test_a_raise_after_a_periodic_job_drops_the_job_too(self, tmp_path):
        from flask import Flask

        from jen.services import background

        manifest = self._plugin(
            tmp_path,
            """
            from jen.services.background import register_periodic

            app.register_blueprint(bp)
            register_periodic("demo", "tick", lambda: None, 5)
            raise RuntimeError("after the job")
            """,
        )
        assert plugins_svc._load_plugin(Flask("loader-test"), manifest) is False
        assert [j for j in background.periodic_jobs() if j["plugin_id"] == "demo"] == []

    def test_a_blueprint_that_cannot_be_registered_is_a_failed_load_too(self, tmp_path):
        """A name already taken makes the replayed registration raise: the load fails and is marked, not swallowed."""
        from flask import Flask

        manifest = self._plugin(
            tmp_path,
            """
            app.register_blueprint(bp)
            app.register_blueprint(other_bp, name="demo_bp")
            """,
        )
        assert plugins_svc._load_plugin(Flask("loader-test"), manifest) is False
        assert plugins_svc.plugin_load_failed("demo") == "ValueError"

    def test_a_fixed_plugin_loaded_again_clears_the_marker(self, tmp_path):
        from flask import Flask

        broken = self._plugin(tmp_path, "raise RuntimeError('first start')")
        assert plugins_svc._load_plugin(Flask("loader-test"), broken) is False
        assert plugins_svc.plugin_load_failed("demo") == "RuntimeError"
        fixed = self._plugin(tmp_path, "app.register_blueprint(bp)")
        assert plugins_svc._load_plugin(Flask("loader-test-2"), fixed) is True
        assert plugins_svc.plugin_load_failed("demo") == ""

    def test_a_test_double_app_gets_its_own_method_back_and_the_replayed_call(self, tmp_path):
        manifest = self._plugin(tmp_path, "app.register_blueprint(bp, url_prefix='/p')")
        app = MagicMock()
        original = app.register_blueprint
        assert plugins_svc._load_plugin(app, manifest) is True
        assert app.register_blueprint is original
        original.assert_called_once()
        assert original.call_args.kwargs == {"url_prefix": "/p"}


class TestThePluginsPageShowsALoadFailure:
    """v5.69.0-beta.3 (Q172) - Settings -> Plugins says "Failed to load (<class>)" for an enabled plugin whose
    register(app) raised in this process, and never prints the exception text."""

    @pytest.fixture(autouse=True)
    def _clean(self):
        yield
        plugins_svc._loaded_plugins.pop("demo", None)
        plugins_svc._load_failed.pop("demo", None)
        sys.modules.pop("jen_plugin_demo", None)

    def _install(self, tmp_path, monkeypatch, enabled=True):
        root = tmp_path / "root"
        (root / "demo").mkdir(parents=True)
        (root / "demo" / "manifest.json").write_text(
            json.dumps(
                {"id": "demo", "name": "Demo Plugin", "version": "1.0.0", "description": "x", "requires_jen": "0.0.0"}
            ),
            encoding="utf-8",
        )
        (root / "demo" / "plugin.py").write_text(
            "def register(app):\n    raise OSError('private text /etc/jen/secret')\n", encoding="utf-8"
        )
        for attr in ("PLUGIN_DIR", "PLUGIN_DIR_BUNDLED"):
            monkeypatch.setattr(extensions, attr, str(tmp_path / "absent" / attr))
        monkeypatch.setattr(extensions, "PLUGIN_DIR_ROOT", str(root))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))
        monkeypatch.setattr(extensions, "CONTENT_PLUGIN_REQUESTS_DIR", str(tmp_path / "requests"))
        monkeypatch.setattr(plugins_svc, "fetch_registry", lambda: ([], None))
        if enabled:
            plugins_svc.enable_plugin("demo")
        manifest = next(m for m in plugins_svc.discover_plugins() if m["id"] == "demo")
        from flask import Flask

        assert plugins_svc._load_plugin(Flask("page-test"), manifest) is False

    def test_an_enabled_plugin_that_failed_is_shown_by_class_name(self, logged_in_client, tmp_path, monkeypatch):
        self._install(tmp_path, monkeypatch)
        r = logged_in_client.get("/settings/plugins")
        assert r.status_code == 200
        assert b"Failed to load (OSError)" in r.data
        assert b"private text" not in r.data and b"/etc/jen/secret" not in r.data

    def test_a_disabled_plugin_does_not_show_a_failure(self, logged_in_client, tmp_path, monkeypatch):
        self._install(tmp_path, monkeypatch, enabled=False)
        assert plugins_svc.plugin_load_failed("demo") == "OSError"  # it was tried, in this process
        r = logged_in_client.get("/settings/plugins")
        assert r.status_code == 200
        assert b"Demo Plugin" in r.data and b"Failed to load" not in r.data

    def test_a_plugin_that_loaded_shows_no_failure(self, logged_in_client, tmp_path, monkeypatch):
        self._install(tmp_path, monkeypatch)
        plugins_svc._load_failed.pop("demo", None)
        r = logged_in_client.get("/settings/plugins")
        assert r.status_code == 200
        assert b"Demo Plugin" in r.data and b"Failed to load" not in r.data
