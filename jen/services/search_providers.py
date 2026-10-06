"""
jen/services/search_providers.py
──────────────────────────────────
v5.57.0 (Q73) — register_search_provider(), the plugin-API v3 hook that
adds a card of results to /search (templates/search_results.html) after
the core sections. Registered once per plugin at load time. Since v5.68.0-beta.11 (Q146) a provider is run by `provider_budget`:
the page stops waiting after BUDGET_SECONDS and shows "unavailable (over 1 s)", and the number of calls outstanding is capped.

Defence in depth (the Q55 rule): even though `fn` is handed the caller's
own accessible_subnet_ids, run_search_providers() drops any returned row
whose subnet_id the caller cannot access, and — for a restricted caller —
any row with subnet_id None, rather than trusting the plugin to have
filtered correctly.
"""

import logging

from jen.services import provider_budget

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
    {"plugin_id", "title", "rows", "unavailable", "reason"}. A provider that
    raises is logged and marked unavailable rather than breaking the
    page; one that has not answered within BUDGET_SECONDS is unavailable
    ("over 1 s") and the page goes on without it, and when too many calls
    are already outstanding it is not run at all ("busy") - see
    `provider_budget`."""
    accessible = set(accessible_subnet_ids)
    calls = [
        (plugin_id, lambda fn=entry["fn"]: fn(query, accessible_subnet_ids, all_subnets))
        for plugin_id, entry in _PROVIDERS.items()
    ]
    titles = {plugin_id: entry["title"] for plugin_id, entry in _PROVIDERS.items()}
    out = []
    for result in provider_budget.run_bounded("search", calls, BUDGET_SECONDS):
        plugin_id = result["label"]
        unavailable = result["state"] != "ok"
        raw_rows = (result["value"] or []) if not unavailable else []
        if result["state"] == "error":
            logger.error(f"search provider {plugin_id!r} raised: {result['error']}")
        # v5.65.8 (Q97 j): filter by the caller's subnets FIRST and truncate afterwards. It used to
        # truncate to MAX_ROWS before the re-filter, so a restricted caller whose rows were 21 and later
        # saw "No results". A malformed row (not a dict) is skipped, not allowed to raise here, outside
        # the provider's own try, where it blanked every provider's card.
        rows = []
        for row in raw_rows if isinstance(raw_rows, (list, tuple)) else []:
            if not isinstance(row, dict):
                logger.warning(f"search provider {plugin_id!r} returned a non-dict row; skipped")
                continue
            sid = row.get("subnet_id")
            if sid is None:
                if not all_subnets:
                    continue
            elif sid not in accessible:
                continue
            rows.append(row)
            if len(rows) >= MAX_ROWS:
                break
        out.append(
            {
                "plugin_id": plugin_id,
                "title": titles[plugin_id],
                "rows": rows,
                "unavailable": unavailable,
                "reason": result["reason"],
            }
        )
    return out
