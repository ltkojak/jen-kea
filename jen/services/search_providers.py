"""
jen/services/search_providers.py
──────────────────────────────────
v5.57.0 (Q73) — register_search_provider(), the plugin-API v3 hook that
adds a card of results to /search (templates/search_results.html) after
the core sections. Registered once per plugin at load time.

Defence in depth (the Q55 rule): even though `fn` is handed the caller's
own accessible_subnet_ids, run_search_providers() drops any returned row
whose subnet_id the caller cannot access, and — for a restricted caller —
any row with subnet_id None, rather than trusting the plugin to have
filtered correctly.
"""

import logging
import time

logger = logging.getLogger(__name__)

MAX_ROWS = 20
BUDGET_SECONDS = 1.0

_PROVIDERS: dict[str, dict] = {}  # plugin_id -> {"title", "fn"}


def register_search_provider(plugin_id: str, *, title: str, fn) -> None:
    """`fn(query, accessible_subnet_ids, all_subnets) -> list[dict]`, each
    row `{"title", "subtitle", "href", "subnet_id"}`. Re-registering the
    same plugin_id replaces its earlier provider."""
    if not callable(fn):
        raise TypeError("fn must be callable")
    _PROVIDERS[plugin_id] = {"title": title, "fn": fn}


def registered_search_providers() -> dict:
    return dict(_PROVIDERS)


def run_search_providers(query: str, accessible_subnet_ids, all_subnets: bool) -> list[dict]:
    """One entry per registered provider, in registration order:
    {"plugin_id", "title", "rows", "unavailable"}. A provider that
    raises is logged and marked unavailable rather than breaking the
    page; one over its time budget is logged but its rows still show —
    called in the request thread (no separate worker), so the budget is
    advisory, not a preemptive cutoff."""
    accessible = set(accessible_subnet_ids)
    out = []
    for plugin_id, entry in _PROVIDERS.items():
        unavailable = False
        start = time.monotonic()
        try:
            raw_rows = entry["fn"](query, accessible_subnet_ids, all_subnets) or []
        except Exception as e:
            logger.error(f"search provider {plugin_id!r} raised: {e}")
            unavailable = True
            raw_rows = []
        else:
            elapsed = time.monotonic() - start
            if elapsed > BUDGET_SECONDS:
                logger.warning(f"search provider {plugin_id!r} took {elapsed:.2f}s, over the {BUDGET_SECONDS}s budget")
        rows = []
        for row in raw_rows[:MAX_ROWS]:
            sid = row.get("subnet_id")
            if sid is None:
                if not all_subnets:
                    continue
            elif sid not in accessible:
                continue
            rows.append(row)
        out.append({"plugin_id": plugin_id, "title": entry["title"], "rows": rows, "unavailable": unavailable})
    return out
