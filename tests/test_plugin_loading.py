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
normal conftest test, not `--noconftest`. Building a real app also
runs every bundled plugin's migrations for real (DDL against jen_db,
which MySQL/MariaDB can't roll back transactionally) and stamps
`plugin_migrated_ok:<id>` in `settings` — both undone in `finally` by
diffing `SHOW TABLES` and deleting the settings rows this test wrote,
so a later test (e.g. test_plugin_migrations.py::TestRealShippedManifests,
which wants to apply those same migrations itself against a pristine
DB) never sees this test's leftovers.
"""

import logging
import os

import jen.services.plugins as plugins_svc
from jen import extensions
from jen.models.db import jen_db


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

    with jen_db() as db, db.cursor() as cur:
        cur.execute("SHOW TABLES")
        tables_before = {next(iter(r.values())) for r in cur.fetchall()}

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
        with jen_db() as db, db.cursor() as cur:
            cur.execute("SHOW TABLES")
            tables_after = {next(iter(r.values())) for r in cur.fetchall()}
            for table in tables_after - tables_before:
                cur.execute(f"DROP TABLE IF EXISTS `{table}`")
            for plugin_id in shipped:
                cur.execute(
                    "DELETE FROM settings WHERE setting_key IN (%s, %s)",
                    (f"plugin_migrated_ok:{plugin_id}", f"plugin_migration_failed:{plugin_id}"),
                )
