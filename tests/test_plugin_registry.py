"""
tests/test_plugin_registry.py
────────────────────────────────
fetch_registry() previously trusted registry.json's own embedded
version field as the sole source of truth for "is an update
available" — every real plugin release required a second, manual,
easy-to-forget commit syncing that field into a completely different
repo. It drifted stale for IPAM more than once in a row before this
was fixed. This tests the fix: fetch_registry() now live-fetches each
plugin's own current manifest.json from its own repo and overlays the
genuinely current version/description/db_migrations, so there's no
second copy left to fall out of sync in the first place.

All requests.get calls are mocked — this never touches the real
network, and never depends on GitHub actually being reachable or
jen-plugin-ipam's real content matching what these tests assert.
"""

from unittest.mock import patch, MagicMock

import pytest

from jen.services import plugins as plugins_svc


def _mock_response(status_code=200, json_data=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_data or {}
    return resp


def _static_registry():
    """Fresh copy every call — fetch_registry() mutates entries in
    place (that's the whole point of the overlay), so a single shared
    module-level list would get silently corrupted by whichever test
    happens to run first, contaminating every test after it."""
    return [
        {
            "id": "ipam",
            "name": "IPAM Lite",
            "version": "1.2.3",  # deliberately stale, matching the real bug
            "description": "old stale description",
            "download_url": "https://github.com/ltkojak/jen-plugin-ipam/raw/main",
        },
    ]


class TestFetchRegistryLiveOverlay:
    def test_live_version_overlays_stale_static_version(self):
        registry_resp = _mock_response(200, _static_registry())
        live_manifest_resp = _mock_response(200, {
            "id": "ipam", "version": "1.3.3",
            "description": "current real description",
        })
        with patch("jen.services.plugins.requests.get",
                   side_effect=[registry_resp, live_manifest_resp]):
            entries, err = plugins_svc.fetch_registry()

        assert err is None
        assert entries[0]["version"] == "1.3.3"
        assert entries[0]["description"] == "current real description"

    def test_live_fetch_url_is_built_correctly(self):
        registry_resp = _mock_response(200, _static_registry())
        live_manifest_resp = _mock_response(200, {"id": "ipam", "version": "1.3.3"})
        with patch("jen.services.plugins.requests.get",
                   side_effect=[registry_resp, live_manifest_resp]) as mock_get:
            plugins_svc.fetch_registry()

        second_call_args = mock_get.call_args_list[1]
        assert second_call_args[0][0] == "https://github.com/ltkojak/jen-plugin-ipam/raw/main/manifest.json"

    def test_per_plugin_fetch_failure_falls_back_to_static_version(self):
        registry_resp = _mock_response(200, _static_registry())
        with patch("jen.services.plugins.requests.get",
                   side_effect=[registry_resp, ConnectionError("plugin repo unreachable")]):
            entries, err = plugins_svc.fetch_registry()

        # The whole call still succeeds — one plugin's connectivity
        # issue doesn't fail the entire registry fetch.
        assert err is None
        assert entries[0]["version"] == "1.2.3"  # unchanged, static fallback

    def test_per_plugin_fetch_404_falls_back_to_static_version(self):
        registry_resp = _mock_response(200, _static_registry())
        live_manifest_resp = _mock_response(404)
        with patch("jen.services.plugins.requests.get",
                   side_effect=[registry_resp, live_manifest_resp]):
            entries, err = plugins_svc.fetch_registry()

        assert err is None
        assert entries[0]["version"] == "1.2.3"

    def test_mismatched_id_in_live_manifest_is_rejected(self):
        # A misconfigured download_url pointing at the wrong plugin's
        # manifest shouldn't silently overwrite this entry's version
        # with an unrelated plugin's data.
        registry_resp = _mock_response(200, _static_registry())
        wrong_manifest_resp = _mock_response(200, {"id": "network-discovery", "version": "9.9.9"})
        with patch("jen.services.plugins.requests.get",
                   side_effect=[registry_resp, wrong_manifest_resp]):
            entries, err = plugins_svc.fetch_registry()

        assert err is None
        assert entries[0]["version"] == "1.2.3"  # unchanged, mismatched id rejected

    def test_download_url_and_nav_are_never_overlaid(self):
        # Only version/description/db_migrations get overlaid — a
        # plugin's own manifest can't redirect where its zip is
        # downloaded from or inject different nav entries via this path.
        static_entry = {
            "id": "ipam",
            "download_url": "https://github.com/ltkojak/jen-plugin-ipam/raw/main",
            "nav": [{"section": "network", "label": "IPAM", "endpoint": "ipam.index"}],
        }
        registry_resp = _mock_response(200, [static_entry])
        malicious_manifest_resp = _mock_response(200, {
            "id": "ipam", "version": "1.3.3",
            "download_url": "https://evil.example.com/payload",
            "nav": [{"section": "network", "label": "Definitely Not IPAM", "endpoint": "evil.route"}],
        })
        with patch("jen.services.plugins.requests.get",
                   side_effect=[registry_resp, malicious_manifest_resp]):
            entries, err = plugins_svc.fetch_registry()

        assert err is None
        assert entries[0]["download_url"] == "https://github.com/ltkojak/jen-plugin-ipam/raw/main"
        assert entries[0]["nav"][0]["label"] == "IPAM"

    def test_main_registry_fetch_failure_still_returns_error_as_before(self):
        # Unchanged behavior for the pre-existing failure mode — the
        # live-overlay logic only runs after the base registry fetch
        # already succeeded.
        registry_resp = _mock_response(500)
        with patch("jen.services.plugins.requests.get", return_value=registry_resp):
            entries, err = plugins_svc.fetch_registry()

        assert entries == []
        assert "HTTP 500" in err

    def test_multiple_plugins_each_overlaid_independently(self):
        static = [
            {"id": "ipam", "version": "1.2.3",
             "download_url": "https://github.com/ltkojak/jen-plugin-ipam/raw/main"},
            {"id": "network-discovery", "version": "0.9.0",
             "download_url": "https://github.com/ltkojak/jen-plugin-network-discovery/raw/main"},
        ]
        registry_resp = _mock_response(200, static)
        ipam_live = _mock_response(200, {"id": "ipam", "version": "1.3.3"})
        nd_live = _mock_response(200, {"id": "network-discovery", "version": "1.0.1"})
        with patch("jen.services.plugins.requests.get",
                   side_effect=[registry_resp, ipam_live, nd_live]):
            entries, err = plugins_svc.fetch_registry()

        assert err is None
        by_id = {e["id"]: e for e in entries}
        assert by_id["ipam"]["version"] == "1.3.3"
        assert by_id["network-discovery"]["version"] == "1.0.1"
