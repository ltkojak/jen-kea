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
