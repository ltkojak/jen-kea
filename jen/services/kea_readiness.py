"""
jen/services/kea_readiness.py
─────────────────────────────
v5.38.0 (Q37) — the pure half of the Health Center's "Kea 3.2 readiness"
group: the table of config keys Kea has removed or renamed on the way
to 3.2, a walker that finds them in a `Dhcp4` config map, and the
version arithmetic the checks share. The checks themselves (which read
Jen's config and the live server status) live in jen/services/health.py
as `kea32_*`.

Only *reports*. Nothing here changes a config — the existing
"Kea version supported" check keeps the *status* (is this Kea still
talking to Jen?); readiness adds the *plan* (what to do before you
upgrade).
"""

from __future__ import annotations

# Each entry: the key as it appears in a config, where Kea accepted it,
# the version that deprecated it, what replaced it, and the one-line hint
# the Health row shows. `container` narrows the match to keys found
# inside that parent key (the dhcp-ddns block), None means anywhere.
REMOVED_KEYS: list[dict] = [
    {
        "key": "require-client-classes",
        "container": None,
        "since": "2.7.4",
        "replacement": "evaluate-additional-classes",
        "hint": "Kea 3.0 reads the old name with a deprecation warning; Jen writes the new one on save (Client Classes → Edit)",
    },
    {
        "key": "only-if-required",
        "container": None,
        "since": "2.7.4",
        "replacement": "only-in-additional-list",
        "hint": "on a client class; Jen writes the new spelling on save",
    },
    {
        "key": "client-class",
        "container": None,
        "since": "2.7.4",
        "replacement": "client-classes (a list)",
        "hint": "the singular guard spelling; Jen writes the list form on save",
    },
    {
        "key": "reservation-mode",
        "container": None,
        "since": "1.9.1",
        "replacement": "reservations-global / reservations-in-subnet / reservations-out-of-pool",
        "hint": "removed in Kea 2.x; edit kea-dhcp4.conf by hand (Servers → Config history shows what Jen has pushed)",
    },
    {
        "key": "qualifying-suffix",
        "container": "dhcp-ddns",
        "since": "1.7.7",
        "replacement": "ddns-qualifying-suffix (global / subnet)",
        "hint": "moved out of the dhcp-ddns block; set it on the DDNS page",
    },
    {
        "key": "override-no-update",
        "container": "dhcp-ddns",
        "since": "1.7.7",
        "replacement": "ddns-override-no-update",
        "hint": "moved out of the dhcp-ddns block; set it on the DDNS page",
    },
    {
        "key": "override-client-update",
        "container": "dhcp-ddns",
        "since": "1.7.7",
        "replacement": "ddns-override-client-update",
        "hint": "moved out of the dhcp-ddns block; set it on the DDNS page",
    },
    {
        "key": "replace-client-name",
        "container": "dhcp-ddns",
        "since": "1.7.7",
        "replacement": "ddns-replace-client-name",
        "hint": "moved out of the dhcp-ddns block; set it on the DDNS page",
    },
    {
        "key": "generated-prefix",
        "container": "dhcp-ddns",
        "since": "1.7.7",
        "replacement": "ddns-generated-prefix",
        "hint": "moved out of the dhcp-ddns block; set it on the DDNS page",
    },
    {
        "key": "hostname-char-set",
        "container": "dhcp-ddns",
        "since": "1.7.7",
        "replacement": "hostname-char-set (global / subnet)",
        "hint": "moved out of the dhcp-ddns block",
    },
    {
        "key": "hostname-char-replacement",
        "container": "dhcp-ddns",
        "since": "1.7.7",
        "replacement": "hostname-char-replacement (global / subnet)",
        "hint": "moved out of the dhcp-ddns block",
    },
]

_BY_KEY = {e["key"]: e for e in REMOVED_KEYS}


def _label(node: dict, key: str, index: int) -> str:
    """A readable path segment for a list element: subnet4[id 3],
    client-classes['pxe'], pools[0]."""
    if key == "subnet4" and node.get("id") is not None:
        return f"subnet4[id {node['id']}]"
    if key in ("client-classes", "shared-networks", "peers") and node.get("name"):
        return f"{key}[{node['name']!r}]"
    return f"{key}[{index}]"


def scan_removed_keys(dhcp4_cfg: dict | None) -> list[dict]:
    """Every occurrence of a REMOVED_KEYS entry in the config, as
    `{"key", "path", "since", "replacement", "hint"}`, in document
    order. `path` is dotted from `Dhcp4`. Pure; a None/empty config
    yields []."""
    out: list[dict] = []

    def walk(node, path: str, container: str | None):
        if isinstance(node, dict):
            for k, v in node.items():
                entry = _BY_KEY.get(k)
                if entry is not None and entry["container"] == (container if entry["container"] else None):
                    out.append(
                        {
                            "key": k,
                            "path": f"{path}.{k}" if path else k,
                            "since": entry["since"],
                            "replacement": entry["replacement"],
                            "hint": entry["hint"],
                        }
                    )
                walk(v, f"{path}.{k}" if path else k, k)
        elif isinstance(node, list):
            for i, item in enumerate(node):
                seg = _label(item, path.rsplit(".", 1)[-1], i) if isinstance(item, dict) else f"[{i}]"
                parent = path.rsplit(".", 1)[0] if "." in path else ""
                walk(item, f"{parent}.{seg}" if parent else seg, container)

    walk(dhcp4_cfg or {}, "Dhcp4", None)
    return out


def minor_of(version: tuple | None) -> str | None:
    """(3, 0, 1) -> "3.0"; None -> None."""
    if not version or len(version) < 2:
        return None
    return f"{version[0]}.{version[1]}"


def summarize(checks: list) -> dict:
    """The Settings → Kea one-liner from the readiness group's Check rows:
    `{"ready": bool, "actions": n, "checked": n}` — `actions` counts warn
    + fail; `checked` counts everything that wasn't skipped."""
    actions = sum(1 for c in checks if c.status in ("warn", "fail"))
    checked = sum(1 for c in checks if c.status != "skip")
    return {"ready": actions == 0 and checked > 0, "actions": actions, "checked": checked}
