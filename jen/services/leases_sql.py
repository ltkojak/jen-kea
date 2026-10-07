"""
jen/services/leases_sql.py
──────────────────────────
v5.68.0-beta.18 (Q153) - what "this lease is current" means, ONCE, for every query in the tree.

Kea keeps a lease row at `state = 0` past its `expire` until reclamation removes it, so `state = 0` alone calls an expired lease "the
current lease". Q145 (beta.10) defined the predicate and applied it to the three modules its audit had grepped; the same mistake was in
twenty-five more places (the default Leases view, every per-subnet count, the delete safety check, the API summary, Reports, the
snapshot that feeds the history and the forecast, the alert lease map, the device scan, DDNS, the setup wizard and three bundled
plugins). A fix to a definition is a fix to every use, so the definition lives here and `tests/test_active_lease.py` refuses, over
the WHOLE tree, a query that spells `state = 0` against `lease4`/`lease6` any other way.

  ACTIVE_LEASE4 / ACTIVE_LEASE6   the predicate for a query over ONE table with no alias (a constant: interpolate it, it is not input)
  active_lease4(alias) / 6        the same with `alias.` in front of both columns, for a query that aliases the table or joins
  NOT_ACTIVE_LEASE4 / 6           its negation (an "expired" row: reclaimed OR past its expiry)

Historical views (the Leases page with "show expired", the delete-stale housekeeping) deliberately do not use it; the few that
spell `state` themselves are listed, each with its reason, in `tests/test_active_lease.py::HISTORICAL`.

No Flask, no database: importable from anywhere, including `jen.plugin_api` (which re-exports the two constants for plugins).
"""

ACTIVE_LEASE4 = "state = 0 AND expire > NOW()"
ACTIVE_LEASE6 = "state = 0 AND expire > NOW()"
NOT_ACTIVE_LEASE4 = f"NOT ({ACTIVE_LEASE4})"
NOT_ACTIVE_LEASE6 = f"NOT ({ACTIVE_LEASE6})"


def _qualified(alias: str) -> str:
    prefix = f"{alias}." if alias else ""
    return f"{prefix}state = 0 AND {prefix}expire > NOW()"


def active_lease4(alias: str = "") -> str:
    """The ACTIVE_LEASE4 predicate with both columns qualified by `alias` (a table alias written by the caller, never user input)."""
    return _qualified(alias)


def active_lease6(alias: str = "") -> str:
    return _qualified(alias)


def not_active_lease4(alias: str = "") -> str:
    return f"NOT ({_qualified(alias)})"


def not_active_lease6(alias: str = "") -> str:
    return f"NOT ({_qualified(alias)})"
