"""
tests/test_content_layout.py
────────────────────────────
v5.13.0 — user-writable content moved from /opt/jen into
extensions.CONTENT_DIR (/var/lib/jen). Step 1 covers the constants, the
`/content/...` blueprint, the /favicon.ico precedence, and the app-side
`migrate_legacy_content()` copy. The installer/updater migration lives in
test_jen_update_root.py / test_docker_config.py (step 2).
"""

import hashlib
import os
import pathlib

import pytest

from jen import extensions
from jen.services import content as content_svc
from jen.services import plugins as plugins_svc

# ── CONTENT_DIR derivation ─────────────────────────────────────────────────


def _derive(environ: dict) -> str:
    jen_root = environ.get("JEN_ROOT", "/opt/jen")
    return environ.get("JEN_CONTENT_DIR") or (
        os.path.join(jen_root, "var") if "JEN_ROOT" in environ else "/var/lib/jen"
    )


class TestContentDirDerivation:
    def test_env_override_wins(self):
        assert _derive({"JEN_CONTENT_DIR": "/data/jen", "JEN_ROOT": "/x"}) == "/data/jen"

    def test_checkout_uses_jen_root_var(self):
        assert _derive({"JEN_ROOT": "/home/me/jen"}) == "/home/me/jen/var"

    def test_default_is_var_lib_jen(self):
        assert _derive({}) == "/var/lib/jen"

    def test_content_subdirs_are_under_content_dir(self):
        for attr in ("CONTENT_ICONS_DIR", "CONTENT_BRANDING_DIR", "CONTENT_BACKUP_DIR", "CONTENT_KEYS_DIR"):
            assert getattr(extensions, attr).startswith(extensions.CONTENT_DIR)


# ── the /content blueprint ────────────────────────────────────────────────


class TestContentRoutes:
    def test_icon_serves(self, client, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "CONTENT_ICONS_DIR", str(tmp_path))
        (tmp_path / "cisco.svg").write_text("<svg/>")
        r = client.get("/content/icons/cisco.svg")
        assert r.status_code == 200
        assert r.headers["Cache-Control"] == "public, max-age=3600"

    def test_icon_missing_is_404(self, client, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "CONTENT_ICONS_DIR", str(tmp_path))
        assert client.get("/content/icons/nope.svg").status_code == 404

    @pytest.mark.parametrize("bad", ["/content/icons/../x.svg", "/content/icons/x.txt", "/content/icons/x%2ey.svg"])
    def test_icon_rejects_bad_names(self, client, bad):
        assert client.get(bad).status_code == 404

    def test_branding_serves_nav_logo(self, client, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "CONTENT_BRANDING_DIR", str(tmp_path))
        (tmp_path / "nav_logo.png").write_bytes(b"PNG")
        assert client.get("/content/branding/nav_logo.png").status_code == 200

    def test_branding_rejects_anything_else(self, client, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "CONTENT_BRANDING_DIR", str(tmp_path))
        (tmp_path / "evil.png").write_bytes(b"x")
        assert client.get("/content/branding/evil.png").status_code == 404
        assert client.get("/content/branding/favicon.ico").status_code == 404  # served by /favicon.ico only


class TestFaviconPrecedence:
    def test_content_override_wins(self, client, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "CONTENT_BRANDING_DIR", str(tmp_path))
        monkeypatch.setattr(extensions, "FAVICON_PATH", str(tmp_path / "favicon.ico"))
        (tmp_path / "favicon.ico").write_bytes(b"CUSTOM-ICO")
        r = client.get("/favicon.ico")
        assert r.status_code == 200 and r.data == b"CUSTOM-ICO"

    def test_falls_back_to_shipped_default(self, client, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "FAVICON_PATH", str(tmp_path / "absent.ico"))
        r = client.get("/favicon.ico")
        assert r.status_code == 200 and len(r.data) > 0  # the shipped static/favicon.ico

    def test_204_when_neither_exists(self, client, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "FAVICON_PATH", str(tmp_path / "absent.ico"))
        monkeypatch.setattr(extensions, "FAVICON_DEFAULT_PATH", str(tmp_path / "also-absent.ico"))
        assert client.get("/favicon.ico").status_code == 204


# ── shipped-favicon hash guard ────────────────────────────────────────────


def test_shipped_favicon_sha256_is_current():
    real = hashlib.sha256(pathlib.Path("static/favicon.ico").read_bytes()).hexdigest()
    assert real == extensions.SHIPPED_FAVICON_SHA256, "update SHIPPED_FAVICON_SHA256 in extensions.py"


# ── migrate_legacy_content ────────────────────────────────────────────────


@pytest.fixture
def legacy(tmp_path, monkeypatch):
    """A fake old /opt/jen tree + a fresh empty CONTENT_DIR."""
    root = tmp_path / "opt"
    content = tmp_path / "var"
    (root / "static" / "icons" / "custom").mkdir(parents=True)
    (root / "backups").mkdir()
    (root / "plugins").mkdir()
    monkeypatch.setattr(extensions, "JEN_ROOT", str(root))
    monkeypatch.setattr(extensions, "CONTENT_DIR", str(content))
    monkeypatch.setattr(extensions, "CONTENT_ICONS_DIR", str(content / "icons"))
    monkeypatch.setattr(extensions, "CONTENT_BRANDING_DIR", str(content / "branding"))
    monkeypatch.setattr(extensions, "CONTENT_BACKUP_DIR", str(content / "backups"))
    monkeypatch.setattr(extensions, "CONTENT_PLUGIN_DIR", str(content / "plugins"))
    monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(content / "plugins-enabled"))
    monkeypatch.setattr(extensions, "CONTENT_KEYS_DIR", str(content / "keys"))
    monkeypatch.setattr(extensions, "FAVICON_PATH", str(content / "branding" / "favicon.ico"))
    monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(root / "plugins-bundled"))
    return root, content


class TestMigrateLegacyContent:
    def test_copies_icons_backups_navlogo(self, legacy):
        root, content = legacy
        (root / "static" / "icons" / "custom" / "acme.svg").write_text("<svg/>")
        (root / "backups" / "jen-2026.json.gz").write_bytes(b"gz")
        (root / "static" / "nav_logo.png").write_bytes(b"png")
        content_svc.migrate_legacy_content()
        assert (content / "icons" / "acme.svg").read_text() == "<svg/>"
        assert (content / "backups" / "jen-2026.json.gz").exists()
        assert (content / "branding" / "nav_logo.png").exists()

    def test_never_clobbers_existing(self, legacy):
        root, content = legacy
        (root / "static" / "icons" / "custom" / "acme.svg").write_text("OLD")
        (content / "icons").mkdir(parents=True)
        (content / "icons" / "acme.svg").write_text("NEW")
        content_svc.migrate_legacy_content()
        assert (content / "icons" / "acme.svg").read_text() == "NEW"

    def test_favicon_only_when_customized(self, legacy):
        root, content = legacy
        # identical to the shipped default → not migrated
        default = pathlib.Path("static/favicon.ico").read_bytes()
        (root / "static" / "favicon.ico").write_bytes(default)
        content_svc.migrate_legacy_content()
        assert not (content / "branding" / "favicon.ico").exists()
        # different → migrated
        (root / "static" / "favicon.ico").write_bytes(b"a-custom-favicon")
        content_svc.migrate_legacy_content()
        assert (content / "branding" / "favicon.ico").read_bytes() == b"a-custom-favicon"

    def test_idempotent(self, legacy):
        root, content = legacy
        (root / "static" / "icons" / "custom" / "acme.svg").write_text("<svg/>")
        content_svc.migrate_legacy_content()
        content_svc.migrate_legacy_content()  # no error, no duplicate
        assert (content / "icons" / "acme.svg").exists()

    def test_enabled_marker_relocates_for_bundled_and_installed(self, legacy):
        root, content = legacy
        (root / "plugins" / "ipam").mkdir()
        (root / "plugins" / "ipam" / ".enabled").write_text("")
        (root / "plugins" / "thirdparty").mkdir()
        (root / "plugins" / "thirdparty" / "manifest.json").write_text('{"id":"thirdparty"}')
        (root / "plugins" / "thirdparty" / ".enabled").write_text("")
        content_svc.migrate_legacy_content()
        assert (content / "plugins-enabled" / "ipam").exists()  # bundled: marker moved
        assert (content / "plugins-enabled" / "thirdparty").exists()
        assert (content / "plugins" / "thirdparty" / "manifest.json").exists()  # non-shipped dir copied
        assert not (content / "plugins" / "ipam").exists()  # shipped dir NOT copied

    def test_keys_relocate(self, legacy):
        root, content = legacy
        (root / ".secret_key").write_text("k" * 40)
        (root / ".mfa_key").write_text("m" * 44)
        content_svc.migrate_legacy_content()
        assert (content / "keys" / ".secret_key").read_text() == "k" * 40
        assert (content / "keys" / ".mfa_key").exists()


# ── discover_plugins merge precedence ─────────────────────────────────────


class TestDiscoverPluginsMerge:
    def test_content_copy_wins_over_bundled(self, tmp_path, monkeypatch):
        bundled = tmp_path / "bundled"
        content = tmp_path / "content"
        for base, ver in ((bundled, "1.0.0"), (content, "2.0.0")):
            d = base / "ipam"
            d.mkdir(parents=True)
            (d / "manifest.json").write_text(f'{{"id":"ipam","name":"IPAM","version":"{ver}"}}')
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(bundled))
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(content))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))
        found = {p["id"]: p for p in plugins_svc.discover_plugins()}
        assert found["ipam"]["version"] == "2.0.0"
        assert found["ipam"]["bundled"] is False

    def test_bundled_only_is_marked_bundled(self, tmp_path, monkeypatch):
        bundled = tmp_path / "bundled"
        (bundled / "ipam").mkdir(parents=True)
        (bundled / "ipam" / "manifest.json").write_text('{"id":"ipam","name":"IPAM","version":"1.0.0"}')
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(bundled))
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(tmp_path / "absent"))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))
        found = {p["id"]: p for p in plugins_svc.discover_plugins()}
        assert found["ipam"]["bundled"] is True

    def test_uninstall_bundled_only_disables(self, tmp_path, monkeypatch):
        bundled = tmp_path / "bundled"
        (bundled / "ipam").mkdir(parents=True)
        (bundled / "ipam" / "manifest.json").write_text('{"id":"ipam"}')
        monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", str(bundled))
        monkeypatch.setattr(extensions, "PLUGIN_DIR", str(tmp_path / "content"))
        monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "en"))
        plugins_svc.enable_plugin("ipam")
        assert plugins_svc._is_enabled("ipam")
        ok, msg = plugins_svc.uninstall_plugin("ipam")
        assert ok and "built-in" in msg and not plugins_svc._is_enabled("ipam")
