"""
tests/test_plugin_loading.py
─────────────────────────────
v5.60.1 (Q89) — every bundled plugin's `register(app)` must actually
run without raising, against a real, fully-built Jen app. Host
Watchdog 1.0.0 proved nothing checked this: its periodic tick was
registered below Jen's own `PERIODIC_MIN_MINUTES` floor,
`register_periodic()` raised, and `jen/services/plugins.py::_load_plugin`'s
per-plugin `try/except` quietly swallowed it — Jen started, logged one
line, and Watchdog simply never loaded: no nav item, no routes, no
probing, on any box, on any version, since it shipped. Nobody noticed
because `tests/e2e/conftest.py` only ever enabled `ipam` and
`network-discovery`, so three of the five bundled plugins had never
once had their own `register()` actually called by any test.

Needs the real database (plugin migrations run at load time) — a
normal conftest test, not `--noconftest`.
"""

import logging
import os

import jen.services.plugins as plugins_svc
from jen import extensions


def test_every_bundled_plugin_registers(app, monkeypatch, tmp_path, caplog):
    """Enable every bundled plugin, build a fresh app, and confirm every
    one of them actually ends up loaded — not just that discover_plugins()
    can see its manifest."""
    monkeypatch.setattr(extensions, "PLUGIN_DIR_BUNDLED", os.path.join(extensions.JEN_ROOT, "plugins"))
    monkeypatch.setattr(extensions, "CONTENT_PLUGINS_ENABLED_DIR", str(tmp_path / "plugins-enabled"))

    shipped = plugins_svc.shipped_plugin_ids()
    assert shipped, "no bundled plugins found — PLUGIN_DIR_BUNDLED points at the wrong tree"
    for plugin_id in shipped:
        plugins_svc.enable_plugin(plugin_id)

    saved_loaded = dict(plugins_svc._loaded_plugins)
    plugins_svc._loaded_plugins.clear()
    try:
        import jen as jen_pkg

        with caplog.at_level(logging.WARNING, logger="jen.services.plugins"):
            jen_pkg.create_app()

        loaded_ids = set(plugins_svc._loaded_plugins)
        assert loaded_ids == shipped, (
            f"not every bundled plugin registered — missing {shipped - loaded_ids}, unexpected {loaded_ids - shipped}"
        )

        failed = [r.message for r in caplog.records if "Failed to load plugin" in r.message]
        assert not failed, f"plugin(s) logged a load failure: {failed}"
    finally:
        plugins_svc._loaded_plugins.clear()
        plugins_svc._loaded_plugins.update(saved_loaded)
