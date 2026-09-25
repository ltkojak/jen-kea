"""
tests/e2e/pages.py
───────────────────
v5.65.3 (Q92) — the plugin pages the phone/desktop screenshot job visits, DERIVED from the
bundled plugins instead of listed by hand.

`tests/e2e/test_mobile.py` used to name five plugin pages in a comment that said "every
bundled plugin's own page is covered"; Wake and Presence were never in it, so their pages
were never opened by the overflow, tap-target or screenshot passes. Now every directory
under `plugins/` contributes:

* its `nav` entries (manifest.json): each `endpoint` ("blueprint.function") is resolved to
  a URL path by reading plugin.py — the Blueprint's `url_prefix` plus the rule of the
  function's `@<bp>.route(...)`. Static (AST), because the list is needed at import time, before
  any app exists; the resolution is the same one `url_for` would give, and a nav endpoint that
  needs URL arguments is an error, not a silent skip;
* an optional `screenshot_pages` list in the manifest (`[{"name": ..., "path": ...}]`) for a
  second page a plugin wants captured;
* the second pages of the two plugins that predate that key, kept here (EXTRA_PAGES) so their
  manifests, which are synced from the plugin repositories, are not edited from this tree.

Pure: `tests/test_e2e_pages.py` covers it without a browser.
"""

from __future__ import annotations

import ast
import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
PLUGINS_DIR = ROOT / "plugins"

# Artifact names that predate the derivation (the screenshots are reviewed by name).
NAME_ALIASES = {"network-discovery": "discovery"}

# Second pages of plugins whose own manifest has no `screenshot_pages` (yet).
EXTRA_PAGES = {
    "ipam": [("plugin-ipam-subnet", "/network/ipam/subnet/kea/1")],
    "network-discovery": [("plugin-discovery-results", "/network/discovery/results/1")],
}


def _literal(node):
    return ast.literal_eval(node) if isinstance(node, ast.expr) else None


def _blueprints(tree) -> dict[str, tuple[str, str]]:
    """{variable: (blueprint name, url_prefix)} for every `x = Blueprint("name", ..., url_prefix="/p")`."""
    out = {}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and getattr(node.value.func, "id", "") == "Blueprint"
            and node.value.args
        ):
            prefix = ""
            for kw in node.value.keywords:
                if kw.arg == "url_prefix":
                    prefix = _literal(kw.value) or ""
            for target in node.targets:
                if isinstance(target, ast.Name):
                    out[target.id] = (_literal(node.value.args[0]), prefix)
    return out


def endpoint_path(plugin_py: pathlib.Path, endpoint: str) -> str:
    """The URL path for `endpoint` ("blueprint.function") in a plugin's plugin.py."""
    tree = ast.parse(plugin_py.read_text(encoding="utf-8"), filename=str(plugin_py))
    blueprints = _blueprints(tree)
    bp_name, _, func_name = endpoint.partition(".")
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) or node.name != func_name:
            continue
        for dec in node.decorator_list:
            if (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Attribute)
                and dec.func.attr == "route"
                and isinstance(dec.func.value, ast.Name)
                and blueprints.get(dec.func.value.id, ("", ""))[0] == bp_name
            ):
                rule = _literal(dec.args[0])
                if "<" in rule:
                    raise ValueError(f"{endpoint} takes URL arguments ({rule}) - list it under screenshot_pages")
                prefix = blueprints[dec.func.value.id][1]
                return (prefix + rule).rstrip("/") or "/"
    raise ValueError(f"{plugin_py.parent.name}: nav endpoint {endpoint!r} has no @route in plugin.py")


def plugin_pages(plugins_dir: pathlib.Path = PLUGINS_DIR) -> list[tuple[str, str]]:
    """[(screenshot name, path)] for every plugin directory under `plugins_dir`."""
    pages: list[tuple[str, str]] = []
    for manifest_path in sorted(plugins_dir.glob("*/manifest.json")):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        plugin_id = manifest["id"]
        short = NAME_ALIASES.get(plugin_id, plugin_id)
        nav = manifest.get("nav") or []
        for i, item in enumerate(nav):
            path = endpoint_path(manifest_path.parent / "plugin.py", item["endpoint"])
            pages.append((f"plugin-{short}" if i == 0 else f"plugin-{short}-{i + 1}", path))
        for extra in manifest.get("screenshot_pages") or []:
            pages.append((extra["name"], extra["path"]))
        pages.extend(EXTRA_PAGES.get(plugin_id, []))
    return pages
