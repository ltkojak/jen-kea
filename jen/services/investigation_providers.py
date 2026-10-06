"""
jen/services/investigation_providers.py
────────────────────────────────────────
v5.68.0-beta.4 (Q139) — register_investigation_provider(), the plugin-API hook that adds one card per plugin to the
Investigation page's Overview ("What else Jen knows"), after the core facts. Mirrored on search_providers.py: a registry keyed
by plugin id, registered once per plugin at load time, and a provider that raises is logged and shown as "unavailable" rather than
breaking the page. Since v5.68.0-beta.11 (Q146) a provider is run by `provider_budget`, which enforces the 1.0 s budget (the page
stops waiting; a provider that is not done shows "unavailable (over 1 s)") and caps how many calls can be outstanding.

What a provider is handed is the ALREADY-AUTHORIZED view of the client (`client_subject.authorize`): it never resolves the
client itself and sees only what the caller may. Defence in depth, the Q55 rule - the plugin's own filtering is never trusted
alone: the card is validated and normalised here (`_card`), a restricted caller is refused any link that is not a path inside
Jen, and the caller's own subnet scope is passed beside the subject so the provider can put it in its own query.
"""

import copy
import logging
import re

from jen.services import provider_budget

logger = logging.getLogger(__name__)

BUDGET_SECONDS = 1.0
MAX_ROWS = 20
MAX_SUMMARY = 300
MAX_TEXT = 200
STATUSES = ("ok", "warn", "none")

_PROVIDERS: dict[str, dict] = {}  # plugin_id -> {"title", "fn"}


def register_investigation_provider(plugin_id: str, *, title: str, fn) -> None:
    """`fn(subject, accessible_subnet_ids, all_subnets) -> dict | None`. `subject` is a read-only copy of the resolved
    `ClientSubject` (mac, ip, hostname, duid, subnet_ids, leases4/reservations/... - the caller's own authorized view). The
    card is `{"summary": one sentence, "rows": [{"label", "value", "href"?}], "href": the plugin's own page for this client,
    "status": "ok" | "warn" | "none"}`; `None` means "nothing to say" and renders nothing. Re-registering the same plugin_id
    replaces its earlier provider."""
    if not callable(fn):
        raise TypeError("fn must be callable")
    _PROVIDERS[plugin_id] = {"title": title, "fn": fn}


def registered_investigation_providers() -> dict:
    return dict(_PROVIDERS)


def _internal_href(value) -> str:
    """A link a provider hands back is a path inside Jen ('/plugin/...'), never an address of someone else's: anything that is
    not a single-slash path (a scheme, '//host', a backslash, a control character) is dropped."""
    if not isinstance(value, str) or not value.startswith("/") or value.startswith("//"):
        return ""
    if "\\" in value or re.search(r"[\x00-\x1f\x7f]", value):
        return ""
    return value[: MAX_TEXT * 2]


def _text(value, limit: int) -> str:
    return "" if value is None else str(value)[:limit]


def _card(raw) -> dict | None:
    """Validate and normalise one provider answer. Returns the card, or raises ValueError for something that is not one."""
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise ValueError("a card is a dict or None")
    summary = _text(raw.get("summary"), MAX_SUMMARY).strip()
    status = raw.get("status", "ok")
    if status not in STATUSES:
        status = "ok"
    rows = []
    raw_rows = raw.get("rows") or []
    for row in raw_rows if isinstance(raw_rows, (list, tuple)) else []:
        if not isinstance(row, dict):
            continue
        label = _text(row.get("label"), MAX_TEXT).strip()
        value = _text(row.get("value"), MAX_TEXT).strip()
        if not label and not value:
            continue
        entry = {"label": label, "value": value}
        href = _internal_href(row.get("href"))
        if href:
            entry["href"] = href
        rows.append(entry)
        if len(rows) >= MAX_ROWS:
            break
    if not summary and not rows:
        return None
    return {"summary": summary, "rows": rows, "href": _internal_href(raw.get("href")), "status": status}


def run_investigation_providers(subject, accessible_subnet_ids, all_subnets: bool) -> list[dict]:
    """One entry per registered provider that has something to say (or failed), in registration order:
    {"plugin_id", "title", "card", "unavailable", "reason"}. A provider answering None renders nothing and is not listed. A
    provider that raises (or answers something that is not a card) is logged and listed as unavailable; one that has not answered
    within BUDGET_SECONDS is listed as unavailable with reason "over 1 s" and the page goes on without it (`provider_budget`
    runs the calls concurrently, so the whole page waits for the budget once, not once per provider); when too many calls are
    already outstanding a provider is not run and the reason is "busy"."""
    accessible = set(accessible_subnet_ids or ())
    if not all_subnets and not accessible:
        return []
    # a deep copy per call: the provider gets the caller's view to READ, and cannot change what the next provider (or the page)
    # sees by editing a list or dict inside it
    calls = [
        (
            plugin_id,
            lambda fn=entry["fn"]: fn(copy.deepcopy(subject), accessible_subnet_ids, all_subnets),
        )
        for plugin_id, entry in _PROVIDERS.items()
    ]
    titles = {plugin_id: entry["title"] for plugin_id, entry in _PROVIDERS.items()}
    out = []
    for result in provider_budget.run_bounded("investigation", calls, BUDGET_SECONDS):
        plugin_id = result["label"]
        card = None
        reason = result["reason"]
        unavailable = result["state"] != "ok"
        if result["state"] == "error":
            e = result["error"]
            logger.error(f"investigation provider {plugin_id!r} raised: {type(e).__name__}: {e}")
        elif not unavailable:
            try:
                card = _card(result["value"])
            except ValueError as e:
                logger.error(f"investigation provider {plugin_id!r} raised: {type(e).__name__}: {e}")
                unavailable = True
        if card is None and not unavailable:
            continue
        out.append(
            {
                "plugin_id": plugin_id,
                "title": titles[plugin_id],
                "card": card,
                "unavailable": unavailable,
                "reason": reason,
            }
        )
    return out


def warnings_line(results: list[dict]) -> list[dict]:
    """The warn-status cards as [{"title", "summary"}], for the one-line answer at the top of the Overview."""
    return [
        {"title": r["title"], "summary": r["card"]["summary"]}
        for r in results
        if r.get("card") and r["card"]["status"] == "warn" and r["card"]["summary"]
    ]
