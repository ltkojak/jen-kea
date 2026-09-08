"""
tests/test_pwa_manifest.py
─────────────────────────────
v5.2.1 — PWA installability. Deliberately no service worker: this app
shows live Kea/lease status, and a service worker's caching could
serve a stale "Kea: Online" page while Kea is actually down — actively
misleading for a monitoring tool. The manifest + icons alone are
sufficient for genuine installability (manual "Install app"/"Add to
Home Screen" via the browser's own menu works everywhere PWAs are
supported at all).

Mirrors the same "verify the actual shipped asset is real, not just
present" discipline already established for htmx.min.js
(test_htmx_vendoring.py) and Chart.js (test_reports.py) — a manifest
file that exists but is malformed, or references icon files that
don't actually exist on disk, would fail silently in a browser with no
obvious error anywhere.
"""

import json
import pathlib


class TestWebManifest:
    def _manifest(self):
        path = pathlib.Path("static/manifest.webmanifest")
        assert path.exists(), "static/manifest.webmanifest is missing"
        return json.loads(path.read_text(encoding="utf-8"))

    def test_manifest_is_valid_json(self):
        self._manifest()  # raises if malformed

    def test_manifest_has_required_fields(self):
        m = self._manifest()
        for field in ("name", "short_name", "start_url", "display", "icons"):
            assert field in m, f"manifest missing required field: {field}"

    def test_display_mode_is_standalone(self):
        """standalone is what makes it feel like an installed app
        rather than just a bookmarked browser tab."""
        assert self._manifest()["display"] == "standalone"

    def test_icons_list_is_nonempty_and_each_file_exists_on_disk(self):
        m = self._manifest()
        assert len(m["icons"]) >= 1
        for icon in m["icons"]:
            icon_path = pathlib.Path(icon["src"].lstrip("/"))
            assert icon_path.exists(), f"manifest references {icon['src']} but that file doesn't exist"
            assert icon_path.stat().st_size > 0, f"{icon['src']} exists but is empty"

    def test_icons_include_both_192_and_512(self):
        """192 and 512 are the two sizes every major platform's install
        UI actually asks for — missing either produces a blurry or
        outright rejected icon somewhere."""
        m = self._manifest()
        sizes = {icon["sizes"] for icon in m["icons"]}
        assert "192x192" in sizes
        assert "512x512" in sizes

    def test_theme_color_matches_jens_actual_brand_color(self):
        """Not load-bearing for functionality, but a mismatched theme
        color would make the installed app's title bar/splash screen
        visibly clash with the app's own UI."""
        assert self._manifest()["theme_color"] == "#00b4d8"


class TestBaseTemplateReferencesManifest:
    def _base_html(self):
        return pathlib.Path("templates/base.html").read_text(errors="ignore")

    def test_manifest_link_present(self):
        assert 'rel="manifest" href="/static/manifest.webmanifest"' in self._base_html()

    def test_apple_touch_icon_present_for_ios_installability(self):
        """iOS Safari's "Add to Home Screen" doesn't use the web
        manifest spec at all — it's driven by this tag specifically."""
        content = self._base_html()
        assert 'rel="apple-touch-icon"' in content
        icon_path = None
        for line in content.splitlines():
            if 'rel="apple-touch-icon"' in line:
                start = line.index('href="') + len('href="')
                icon_path = line[start : line.index('"', start)]
                break
        assert icon_path, "apple-touch-icon link found but href couldn't be parsed"
        assert pathlib.Path(icon_path.lstrip("/")).exists(), f"{icon_path} referenced but missing on disk"

    def test_apple_mobile_web_app_capable_present(self):
        assert 'name="apple-mobile-web-app-capable" content="yes"' in self._base_html()

    def test_no_service_worker_registration_present(self):
        """Explicit guard for the deliberate decision documented in
        base.html and this module's docstring — a service worker
        accidentally added later (e.g. copy-pasted from an unrelated
        PWA tutorial) would reintroduce the stale-live-data risk this
        was specifically designed to avoid."""
        content = self._base_html()
        assert "serviceWorker.register" not in content
