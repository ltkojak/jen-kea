"""
tests/test_e2e_pages.py
────────────────────────
v5.65.3 (Q92) — tests/e2e/pages.py derives the plugin pages the screenshot job visits from the
bundled manifests. Pure (no browser, no DB): the derivation itself is what is tested, so a
plugin whose page the job would skip is a failure here, not a gap nobody notices.
"""

import json
import pathlib

import pytest

from tests.e2e import pages

ROOT = pathlib.Path(__file__).resolve().parent.parent

# What every bundled plugin's own page is called today; a plugin added under plugins/ must show up
# in the derivation, and this list is updated with it (the count check below fails until it is).
EXPECTED = {
    "plugin-dns-sync": "/network/dns-sync",
    "plugin-ipam": "/network/ipam",
    "plugin-discovery": "/network/discovery",
    "plugin-presence": "/management/presence",
    "plugin-switchport": "/network/switchport",
    "plugin-watchdog": "/network/watchdog",
    "plugin-wol": "/management/wol",
}


class TestDerivation:
    def test_every_bundled_plugin_contributes_its_own_page(self):
        derived = dict(pages.plugin_pages())
        for name, path in EXPECTED.items():
            assert derived.get(name) == path, f"{name}: expected {path}, derived {derived.get(name)}"

    def test_wake_and_presence_are_no_longer_missing(self):
        """The bug: the hand-typed list had neither, while claiming to cover every plugin."""
        derived = set(dict(pages.plugin_pages()).values())
        assert "/management/wol" in derived and "/management/presence" in derived

    def test_a_plugin_added_under_plugins_cannot_be_skipped(self):
        bundled = {p.parent.name for p in (ROOT / "plugins").glob("*/manifest.json")}
        assert len(bundled) == len(EXPECTED), (
            f"plugins/ has {sorted(bundled)}: add the new plugin's page to EXPECTED (and check the screenshot job opens it)"
        )

    def test_the_second_pages_are_kept(self):
        derived = dict(pages.plugin_pages())
        assert derived["plugin-ipam-subnet"] == "/network/ipam/subnet/kea/1"
        assert derived["plugin-discovery-results"] == "/network/discovery/results/1"

    def test_names_are_unique(self):
        names = [n for n, _p in pages.plugin_pages()]
        assert len(names) == len(set(names))


class TestSynthetic:
    def _plugin(self, root, plugin_id, nav, source, extra=None):
        d = root / plugin_id
        d.mkdir()
        (d / "manifest.json").write_text(json.dumps({"id": plugin_id, "nav": nav, **(extra or {})}), encoding="utf-8")
        (d / "plugin.py").write_text(source, encoding="utf-8")

    SRC = (
        "from flask import Blueprint\n"
        'bp = Blueprint("demo", __name__, url_prefix="/x/demo")\n'
        '@bp.route("/")\n'
        "def index(): pass\n"
        '@bp.route("/second")\n'
        "def second(): pass\n"
        '@bp.route("/item/<int:i>")\n'
        "def item(i): pass\n"
    )

    def test_prefix_and_rule_join_and_a_trailing_slash_goes(self, tmp_path):
        self._plugin(tmp_path, "demo", [{"endpoint": "demo.index"}, {"endpoint": "demo.second"}], self.SRC)
        assert pages.plugin_pages(tmp_path) == [("plugin-demo", "/x/demo"), ("plugin-demo-2", "/x/demo/second")]

    def test_screenshot_pages_in_the_manifest_are_honoured(self, tmp_path):
        self._plugin(
            tmp_path,
            "demo",
            [{"endpoint": "demo.index"}],
            self.SRC,
            {"screenshot_pages": [{"name": "plugin-demo-item", "path": "/x/demo/item/1"}]},
        )
        assert ("plugin-demo-item", "/x/demo/item/1") in pages.plugin_pages(tmp_path)

    def test_an_endpoint_needing_url_arguments_is_an_error_not_a_skip(self, tmp_path):
        self._plugin(tmp_path, "demo", [{"endpoint": "demo.item"}], self.SRC)
        with pytest.raises(ValueError, match="URL arguments"):
            pages.plugin_pages(tmp_path)

    def test_an_endpoint_with_no_route_is_an_error(self, tmp_path):
        self._plugin(tmp_path, "demo", [{"endpoint": "demo.missing"}], self.SRC)
        with pytest.raises(ValueError, match="no @route"):
            pages.plugin_pages(tmp_path)


def test_the_screenshot_module_uses_the_derivation():
    text = (ROOT / "tests" / "e2e" / "test_mobile.py").read_text(encoding="utf-8")
    assert "*plugin_pages()" in text and '("client", f"/client?q={CLIENT_MAC}")' in text
    assert "plugin-watchdog" not in text  # no hand-typed plugin page is left to drift
