"""
jen/services/kea_classes.py
────────────────────────────
v5.19.0 (Q13) — pure functions for Kea's `Dhcp4.client-classes`: turning
a guided rule builder into a Kea classification expression, resolving
the 2.7.4→3.0 attachment-key rename, finding what references a class,
and recognising Kea's built-in classes (never authored by Jen).

Pure — no I/O, no Flask. `dhcp4_cfg` throughout is the inner `Dhcp4` map
(`config["Dhcp4"]`), matching kea_config_view.py's convention.
"""

from __future__ import annotations

import copy
import re

# ── Built-in classes (never authored) ───────────────────────────────────────

_BUILTIN_EXACT = frozenset({"ALL", "KNOWN", "UNKNOWN", "DROP", "BOOTP"})
_BUILTIN_PREFIXES = ("VENDOR_CLASS_", "HA_", "AFTER_", "SPAWN_")


def is_builtin(name: str) -> bool:
    if name in _BUILTIN_EXACT:
        return True
    return any(name.startswith(p) for p in _BUILTIN_PREFIXES)


# ── Attachment key rename (Kea 2.7.4 → 3.0) ─────────────────────────────────
#
# Guard: "client-classes" (list, 2.7.4+) / "client-class" (singular
# string, older). Additional: "evaluate-additional-classes" (2.7.4+) /
# "require-client-classes" (older — already a list under the old name;
# only the guard's *shape* changed on rename, singular -> list). Only:
# "only-in-additional-list" (2.7.4+) / "only-if-required" (older) — a
# class-level flag, independent of the two above but renamed at the same
# Kea version, so it's tracked as the same spelling-family here.

NEW_GUARD, OLD_GUARD = "client-classes", "client-class"
NEW_ADDITIONAL, OLD_ADDITIONAL = "evaluate-additional-classes", "require-client-classes"
NEW_ONLY, OLD_ONLY = "only-in-additional-list", "only-if-required"


def _has_any(containers, *keys) -> bool:
    return any(isinstance(c, dict) and any(k in c for k in keys) for c in containers)


def _scope_containers(dhcp4_cfg: dict) -> list[dict]:
    """Every dict that can itself carry a guard/additional attachment:
    every subnet (top-level and nested in a shared network), every pool
    of every subnet, and every shared network."""
    from jen.services import kea_config_view as _view

    out = []
    for s, _sn in _view.iter_subnet4(dhcp4_cfg):
        out.append(s)
        out.extend(p for p in (s.get("pools") or []) if isinstance(p, dict))
    out.extend(_view.shared_networks4_raw(dhcp4_cfg))
    return out


def attachment_keys(dhcp4_cfg: dict, version: tuple | None = None) -> dict:
    """{"guard", "additional", "only"} — the key names to WRITE. Reading
    always checks both spellings (see _guard_classes/_additional_classes
    below); this only decides which one a *write* uses: whichever
    spelling the config already has anywhere (subnets, pools, shared
    networks, classes) wins; if the config uses neither, write the new
    names when `version >= (2, 7, 4)`, else the old ones. `version` is
    an (X, Y, Z) tuple (kea.parse_kea_version()'s return shape) or None
    when the running Kea's version couldn't be determined — treated
    conservatively as "assume old", the widest-compatible choice."""
    containers = _scope_containers(dhcp4_cfg)
    classes = [c for c in (dhcp4_cfg.get("client-classes") or []) if isinstance(c, dict)]

    new_seen = _has_any(containers, NEW_GUARD, NEW_ADDITIONAL) or _has_any(classes, NEW_ONLY)
    old_seen = _has_any(containers, OLD_GUARD, OLD_ADDITIONAL) or _has_any(classes, OLD_ONLY)

    if new_seen and not old_seen:
        use_new = True
    elif old_seen and not new_seen:
        use_new = False
    elif old_seen and new_seen:
        use_new = True  # mixed config — prefer the forward-compatible spelling
    else:
        use_new = version is not None and version >= (2, 7, 4)

    return (
        {"guard": NEW_GUARD, "additional": NEW_ADDITIONAL, "only": NEW_ONLY}
        if use_new
        else {"guard": OLD_GUARD, "additional": OLD_ADDITIONAL, "only": OLD_ONLY}
    )


def _guard_classes(container: dict) -> list[str]:
    """Class names this container guards on, reading BOTH spellings
    regardless of which one is actually present."""
    if not isinstance(container, dict):
        return []
    v = container.get(NEW_GUARD)
    if isinstance(v, list):
        return [c for c in v if isinstance(c, str)]
    v2 = container.get(OLD_GUARD)
    return [v2] if isinstance(v2, str) else []


def _additional_classes(container: dict) -> list[str]:
    """Class names evaluated as 'additional' for this container, reading
    both spellings — always a list under either name."""
    if not isinstance(container, dict):
        return []
    for key in (NEW_ADDITIONAL, OLD_ADDITIONAL):
        v = container.get(key)
        if isinstance(v, list):
            return [c for c in v if isinstance(c, str)]
    return []


def references(dhcp4_cfg: dict, class_name: str) -> list[str]:
    """Every place `class_name` is referenced: a subnet/pool/shared-network
    guard or additional-classes attachment, or another class's expression
    via member(). Human-readable labels, e.g. 'subnet 10',
    'pool 10.0.0.10 - 10.0.0.99 of subnet 10', 'shared network guest',
    'class printer-vlan (member)'."""
    from jen.services import kea_config_view as _view

    out: list[str] = []
    for s, _sn in _view.iter_subnet4(dhcp4_cfg):
        label = f"subnet {s.get('id')}"
        if class_name in _guard_classes(s) or class_name in _additional_classes(s):
            out.append(label)
        for p in s.get("pools") or []:
            if not isinstance(p, dict):
                continue
            if class_name in _guard_classes(p) or class_name in _additional_classes(p):
                out.append(f"pool {p.get('pool')} of {label}")
    for sn in _view.shared_networks4_raw(dhcp4_cfg):
        if class_name in _guard_classes(sn) or class_name in _additional_classes(sn):
            out.append(f"shared network {sn.get('name')}")
    for c in dhcp4_cfg.get("client-classes") or []:
        if not isinstance(c, dict) or c.get("name") == class_name:
            continue
        test = c.get("test") or ""
        if f"member('{class_name}')" in test or f'member("{class_name}")' in test:
            out.append(f"class {c.get('name')} (member)")
    return out


# ── Guided rule builder ──────────────────────────────────────────────────────
#
# field -> (Kea accessor or None for member, kind, allowed ops). "contains"
# is deliberately not offered anywhere — Kea's substring() needs a known
# start position, so only equals/starts_with are expressible for the
# string-ish fields, and only equals for anything hex/mac/member.

FIELDS = {
    "vendor_class": {"kea": "option[60].hex", "kind": "string", "ops": ("equals", "starts_with")},
    "user_class": {"kea": "option[77].hex", "kind": "string", "ops": ("equals", "starts_with")},
    "hostname": {"kea": "option[12].text", "kind": "string", "ops": ("equals", "starts_with")},
    "mac": {"kea": "pkt4.mac", "kind": "mac", "ops": ("equals",)},
    "mac_oui": {"kea": "substring(pkt4.mac,0,3)", "kind": "oui", "ops": ("equals",)},
    "client_id": {"kea": "option[61].hex", "kind": "hex", "ops": ("equals",)},
    "circuit_id": {"kea": "relay4[1].hex", "kind": "string", "ops": ("equals",)},
    "remote_id": {"kea": "relay4[2].hex", "kind": "hex", "ops": ("equals",)},
    "member": {"kea": None, "kind": "member", "ops": ("equals",)},
}

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _hexify(value: str, label: str, exact_bytes: int | None = None) -> str:
    body = re.sub(r"[:\-\s]", "", value or "")
    if not body or not _HEX_RE.match(body) or len(body) % 2:
        raise ValueError(f"{label}: must be an even-length hex string (e.g. 00:11:22:33:44:55)")
    if exact_bytes is not None and len(body) != exact_bytes * 2:
        raise ValueError(f"{label}: must be exactly {exact_bytes} bytes ({exact_bytes * 2} hex digits)")
    return "0x" + body.lower()


def _stringify(value: str, label: str) -> tuple[str, str]:
    """(stripped value, its Kea single-quoted literal) — raises if empty
    or if it contains a quote (Kea string literals have no escape)."""
    value = (value or "").strip()
    if not value:
        raise ValueError(f"{label}: a value is required")
    if "'" in value:
        raise ValueError(f"{label}: cannot contain a single quote — Kea string literals have no escape sequence")
    return value, f"'{value}'"


def _rule_expression(rule: dict) -> str:
    field = rule.get("field")
    op = rule.get("op", "equals")
    value = rule.get("value", "")
    meta = FIELDS.get(field)
    if meta is None:
        raise ValueError(f"unknown field {field!r}")
    if op not in meta["ops"]:
        raise ValueError(f"op {op!r} is not valid for field {field!r}")

    if meta["kind"] == "member":
        stripped, _lit = _stringify(value, "member")
        return f"member('{stripped}')"

    kea = meta["kea"]
    if meta["kind"] == "string":
        stripped, lit = _stringify(value, field)
        if op == "starts_with":
            return f"substring({kea},0,{len(stripped)}) == {lit}"
        return f"{kea} == {lit}"
    if meta["kind"] == "mac":
        return f"{kea} == {_hexify(value, field, exact_bytes=6)}"
    if meta["kind"] == "oui":
        return f"{kea} == {_hexify(value, field, exact_bytes=3)}"
    if meta["kind"] == "hex":
        return f"{kea} == {_hexify(value, field)}"
    raise ValueError(f"unhandled field kind for {field!r}")  # pragma: no cover — every kind above is handled


def build_expression(rules: list[dict], combinator: str = "all", negate: bool = False) -> str:
    """A Kea classification expression from guided rule rows. Raises
    ValueError (a user-facing, already-safe message) on an empty rule
    list, an unknown field/op, or a value that can't be expressed
    (a quote in a string field, invalid/wrong-length hex)."""
    if combinator not in ("all", "any"):
        raise ValueError(f"unknown combinator {combinator!r}")
    if not rules:
        raise ValueError("at least one rule is required")
    clauses = [_rule_expression(r) for r in rules]
    if len(clauses) == 1:
        body = clauses[0]
    else:
        joiner = " and " if combinator == "all" else " or "
        body = joiner.join(f"({c})" for c in clauses)
    return f"not ({body})" if negate else body


# ── Assembling a class dict for kea_config_edit.upsert_class4 ───────────────


def merge_class_fields(
    existing: dict | None,
    name: str,
    test: str,
    user_context: dict | None = None,
    next_server: str | None = None,
    server_hostname: str | None = None,
    boot_file_name: str | None = None,
    only_key: str | None = None,
    only_additional: bool = False,
) -> dict:
    """Build the complete class dict to hand to upsert_class4 — carrying
    forward `existing`'s fields the class-edit form doesn't own (its
    option-data, principally) while replacing everything the form does
    own. `existing` is None for a brand-new class."""
    merged = copy.deepcopy(existing) if isinstance(existing, dict) else {}
    merged["name"] = name
    merged["test"] = test
    if user_context is not None:
        merged["user-context"] = user_context
    else:
        merged.pop("user-context", None)
    for field, value in (
        ("next-server", next_server),
        ("server-hostname", server_hostname),
        ("boot-file-name", boot_file_name),
    ):
        if value:
            merged[field] = value
        else:
            merged.pop(field, None)
    if only_key:
        merged.pop(NEW_ONLY, None)
        merged.pop(OLD_ONLY, None)
        if only_additional:
            merged[only_key] = True
    return merged
