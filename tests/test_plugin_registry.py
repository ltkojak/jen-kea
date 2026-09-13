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
import os
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
