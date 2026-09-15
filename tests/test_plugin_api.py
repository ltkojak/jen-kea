"""
tests/test_plugin_api.py
────────────────────────
v5.34.0 (Q33) — `jen.plugin_api`, the one import surface a plugin may
use, and the manifest `plugin_api` gate.

DB-free: `python -m pytest --noconftest tests/test_plugin_api.py -k "Surface or Gate or Guard"`.
"""

import pathlib
import re

import pytest

from jen import plugin_api

REPO = pathlib.Path(__file__).resolve().parent.parent


class TestSurface:
    def test_version_is_one(self):
        assert plugin_api.PLUGIN_API_VERSION == 1

    def test_every_name_in_all_exists_and_is_the_real_object(self):
        """Re-exports, not copies: monkeypatching the internal in a test
        must affect what a plugin sees."""
        from jen.models import db as _db
        from jen.models import user as _user
        from jen.services import access, alerts, background, csv_safe, fingerprint, plugins, subnet_context

        same = {
            "jen_db": _db.jen_db,
            "kea_db": _db.kea_db,
            "kea6_db": _db.kea6_db,
            "get_jen_db": _db.get_jen_db,
            "get_kea_db": _db.get_kea_db,
            "audit": _user.audit,
            "get_global_setting": _user.get_global_setting,
            "set_global_setting": _user.set_global_setting,
            "assert_subnet_access": access.assert_subnet_access,
            "get_accessible_subnet_map": access.get_accessible_subnet_map,
            "is_admin_or_above": access.is_admin_or_above,
            "is_superadmin": access.is_superadmin,
            "admin_required": access.admin_required,
            "superadmin_required": access.superadmin_required,
            "viewer_or_above": access.viewer_or_above,
            "send_alert": alerts.send_alert,
            "register_periodic": background.register_periodic,
            "unregister_periodic": background.unregister_periodic,
            "periodic_jobs": background.periodic_jobs,
            "safe_row": csv_safe.safe_row,
            "safe_cell": csv_safe.safe_cell,
            "classify_device": fingerprint.classify_device,
            "installed_plugins": plugins.discover_plugins,
            "is_systemd_host": plugins.is_systemd_host,
            "subnet_context": subnet_context.subnet_context,
            "classify_address": subnet_context.classify_address,
            "in_pool": subnet_context.in_pool,
            "dhcp4_config": subnet_context.dhcp4_config,
        }
        for name in plugin_api.__all__:
            assert hasattr(plugin_api, name), name
        for name, obj in same.items():
            assert name in plugin_api.__all__, f"{name} missing from __all__"
            assert getattr(plugin_api, name) is obj, f"{name} is a copy, not a re-export"
        assert callable(plugin_api.subnet_map) and callable(plugin_api.jen_version)

    def test_all_is_sorted_and_complete(self):
        """A new name goes into __all__ (that's the published contract),
        and __all__ stays alphabetical so diffs are readable."""
        names = list(plugin_api.__all__)
        assert names == sorted(names)
        public = {n for n in dir(plugin_api) if not n.startswith("_") and n not in ("extensions",)}
        assert public == set(names), public ^ set(names)

    def test_import_does_no_work(self):
        """Importing the surface must not touch the database, config, or
        network — it is imported at plugin load, inside create_app()."""
        src = (REPO / "jen" / "plugin_api.py").read_text(encoding="utf-8")
        body = re.sub(r'""".*?"""', "", src, flags=re.DOTALL)
        body = re.sub(r"#.*", "", body)  # comments show usage examples; only code counts
        for forbidden in ("jen_db()", "kea_db()", "requests.", "urlopen", "subprocess"):
            assert forbidden not in body, forbidden


class TestManifestGate:
    def test_absent_or_current_is_ok(self):
        from jen.services.plugins import plugin_api_ok

        assert plugin_api_ok({}) is True
        assert plugin_api_ok({"plugin_api": 1}) is True
        assert plugin_api_ok({"plugin_api": "1"}) is True
        assert plugin_api_ok({"plugin_api": 0}) is True

    def test_newer_than_offered_is_refused(self):
        from jen.services.plugins import plugin_api_ok

        assert plugin_api_ok({"plugin_api": plugin_api.PLUGIN_API_VERSION + 1}) is False

    @pytest.mark.parametrize("bad", ["two", None, [], {}])
    def test_malformed_is_treated_as_undeclared(self, bad):
        from jen.services.plugins import plugin_api_ok

        assert plugin_api_ok({"plugin_api": bad}) is True

    def test_loader_skips_a_plugin_that_needs_a_newer_api(self, monkeypatch):
        from jen.services import plugins as svc

        loaded = []
        monkeypatch.setattr(svc, "_load_plugin", lambda app, m: loaded.append(m["id"]))
        monkeypatch.setattr(svc, "run_plugin_migrations", lambda m: (True, "", 0))
        monkeypatch.setattr("jen.models.user.get_global_setting", lambda *a, **k: None)
        monkeypatch.setattr("jen.models.user.set_global_setting", lambda *a, **k: None)
        manifests = [
            {"id": "old", "version": "1", "enabled": True, "version_ok": True, "api_ok": True},
            {"id": "future", "version": "1", "enabled": True, "version_ok": True, "api_ok": False, "plugin_api": 99},
        ]
        monkeypatch.setattr(svc, "discover_plugins", lambda: manifests)
        svc.load_plugins(app=None)
        assert loaded == ["old"]


ALLOWED_PLUGIN_IMPORTS = {"jen.plugin_api"}
# Until ipam v1.5.1 / network-discovery v1.1.1 land on the surface (the
# plugin releases that follow this Jen release), the bundled copies still
# import the internals they always did. Step 3 of Q33 empties this set.
TRANSITIONAL_ALLOWED = {
    "jen.models.db",
    "jen.models",
    "jen.services.access",
    "jen.services.alerts",
    "jen.services.background",
    "jen.services.csv_safe",
    "jen.services.fingerprint",
    "jen.services.plugins",
    "jen.services.subnet_context",
    "jen",
}

_IMPORT_RE = re.compile(
    r"^\s*(?:from\s+(jen(?:\.[A-Za-z_.]+)?)\s+import|import\s+(jen(?:\.[A-Za-z_.]+)?))", re.MULTILINE
)


class TestBundledPluginsImportGuard:
    def _imports(self, path):
        text = path.read_text(encoding="utf-8")
        return {m.group(1) or m.group(2) for m in _IMPORT_RE.finditer(text)}

    @pytest.mark.parametrize("plugin_id", ["ipam", "network-discovery"])
    def test_bundled_plugin_imports_only_the_surface_or_transitional_internals(self, plugin_id):
        found = self._imports(REPO / "plugins" / plugin_id / "plugin.py")
        assert found, plugin_id
        stray = found - ALLOWED_PLUGIN_IMPORTS - TRANSITIONAL_ALLOWED
        assert not stray, f"{plugin_id} imports outside the plugin surface: {sorted(stray)}"

    def test_everything_the_bundled_plugins_use_is_offered_by_the_surface(self):
        """The transitional list only buys time: every attribute the
        plugins pull from an internal module must already be re-exported,
        so the switch is a pure import rewrite."""
        rx = re.compile(r"^\s*from\s+(jen[A-Za-z_.]*)\s+import\s+([A-Za-z_]+)", re.MULTILINE)
        missing = []
        for plugin_id in ("ipam", "network-discovery"):
            text = (REPO / "plugins" / plugin_id / "plugin.py").read_text(encoding="utf-8")
            for mod, name in rx.findall(text):
                if mod == "jen.plugin_api":
                    continue
                if mod == "jen.models" and name == "user":
                    continue  # `_user.audit(...)` → audit()
                if mod == "jen" and name == "extensions":
                    continue  # SUBNET_MAP → subnet_map()
                if name == "discover_plugins":
                    name = "installed_plugins"
                if name not in plugin_api.__all__:
                    missing.append((plugin_id, mod, name))
        assert not missing, missing
