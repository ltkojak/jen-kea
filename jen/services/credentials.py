"""
jen/services/credentials.py
───────────────────────────
v5.69.0-beta.11 (Q180, CRED-004) - ONE definition of which secret Jen sends to which endpoint.

Beta.7 to beta.10 each fixed one form of the same defect: a secret reaching a host its owner never named, through a fallback written in a different place each time
(the extra-server derivation's default of the primary's password, `AppConfig.apply()`'s `[kea6]`, `[d2]` and `[kea6_db]` falling back to `[kea]`'s, the endpoint
resolver's "its own, else the server's" chain). This module is the rule, pure (a parser in, a dict out, no I/O), and every consumer asks it:

    A secret is used at its OWN endpoint, or inherited by another daemon ON THE SAME HOST (`auth.same_host`: another port of that host is the same box).
    An endpoint on a different host with no secret of its own has NONE - never its neighbour's.

A blank `api_pass =` is an explicit "no credential" (none); an ABSENT key is "inherit, if the host is the same". The same reading everywhere.

`Endpoint.source` is "own", "inherited:<name>" or "none". `Endpoint.withheld` is the name of the endpoint whose secret WOULD have been inherited had the host been the
same: it is what lets `kea._endpoint_for` tell "this endpoint has no credential because none was ever set" (a Kea with no authentication: send nothing extra) from "this one
was refused its neighbour's" (send nothing at all, and say why).

Also here: `materialise` (a legacy extra server that inherited the primary's password across hosts since 5.10 is converted ONCE, audibly) and `move_refusal`
(the check `AppConfig._write_parser` runs on every write: a saved password does not follow an endpoint to a new host, and does not appear on a second host, unless it was typed
in this request).
"""

from __future__ import annotations

import logging
import re
from collections import namedtuple

logger = logging.getLogger(__name__)

# source: "own" | "inherited:<name>" | "none"; withheld: the endpoint whose secret was NOT inherited because the host differs ("" otherwise)
Endpoint = namedtuple("Endpoint", "name url user password source withheld", defaults=("",))

#: the marker `materialise` and the "share" box write beside a copied password
SHARED_MARKER = "api_pass_shared"


def _has(parser, section: str, key: str) -> bool:
    return parser.has_section(section) and parser.has_option(section, key)


def _get(parser, section: str, key: str, fallback: str = "") -> str:
    return parser.get(section, key, fallback=fallback, raw=True) if parser.has_section(section) else fallback


def _same_host(a: str, b: str) -> bool:
    from jen.services import auth as _auth

    return _auth.same_host(a, b)


def _db_url(parser, section: str, host: str, fallback_port: str = "3306") -> str:
    host = (host or "").strip()
    if not host:
        return ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # a bare IPv6 literal: the port must not fuse into it
    port = (_get(parser, section, "port", fallback_port) or fallback_port).strip()
    return f"{host}:{port}"


def _inherit(name, url, user, own_present, own_value, parent: Endpoint) -> Endpoint:
    """One endpoint's credential: its own (blank = none, on purpose), else `parent`'s when this endpoint is on the parent's host, else none - with `withheld` set when the
    parent HAD a secret that was refused."""
    if own_present:
        return Endpoint(name, url, user, own_value, "own" if own_value else "none")
    if parent.password and url:
        if _same_host(parent.url, url):
            return Endpoint(name, url, user, parent.password, f"inherited:{parent.name}")
        return Endpoint(name, url, user, "", "none", parent.name)
    return Endpoint(name, url, user, "", "none")


def server_numbers(parser) -> list[int]:
    nums = []
    for section in parser.sections():
        m = re.fullmatch(r"kea_server_(\d+)", section)
        if m and int(m.group(1)) >= 2:
            nums.append(int(m.group(1)))
    return sorted(nums)


def resolve(parser) -> dict[str, Endpoint]:
    """Every place Jen sends a Kea or database credential, with the credential it WILL send and where it came from (CRED-004, Q180). The one rule: a secret is used at its
    own endpoint, or inherited by another daemon ON THE SAME HOST (`same_host`; another port of that host is the same box). An endpoint on a different host with no secret
    of its own has NONE - never its neighbour's. Names: "kea", "kea6", "d2", "kea_db", "kea6_db", "jen_db", "server_<N>", "server_<N>_v6", "server_<N>_d2".

    Lenient on purpose (a fresh install, a hand-made file, a parser built for a comparison): a missing section or option is a blank, never an error, and values are read raw
    (a `%` in a password is a `%`)."""
    mode = _get(parser, "kea", "connection_mode", "ca").strip().lower()
    direct = mode == "direct"
    out: dict[str, Endpoint] = {}

    kea_url, kea_user, kea_pass = (
        _get(parser, "kea", "api_url"),
        _get(parser, "kea", "api_user"),
        _get(parser, "kea", "api_pass"),
    )
    kea = out["kea"] = Endpoint("kea", kea_url, kea_user, kea_pass, "own" if kea_pass else "none")

    # [kea6] and [d2]: in ca mode an absent api_url is the Control Agent's (one CA proxies every daemon); in direct mode there is no fallback
    for name in ("kea6", "d2"):
        url = _get(parser, name, "api_url") if _has(parser, name, "api_url") else ("" if direct else kea_url)
        user = _get(parser, name, "api_user") if _has(parser, name, "api_user") else kea_user
        out[name] = _inherit(name, url, user, _has(parser, name, "api_pass"), _get(parser, name, "api_pass"), kea)

    kea_db_host, kea_db_user, kea_db_pass = (
        _get(parser, "kea_db", "host"),
        _get(parser, "kea_db", "user"),
        _get(parser, "kea_db", "password"),
    )
    kea_db = out["kea_db"] = Endpoint(
        "kea_db", _db_url(parser, "kea_db", kea_db_host), kea_db_user, kea_db_pass, "own" if kea_db_pass else "none"
    )
    h6 = _get(parser, "kea6_db", "host") if _has(parser, "kea6_db", "host") else kea_db_host
    u6 = _get(parser, "kea6_db", "user") if _has(parser, "kea6_db", "user") else kea_db_user
    out["kea6_db"] = _inherit(
        "kea6_db",
        _db_url(parser, "kea6_db", h6, _get(parser, "kea_db", "port", "3306") or "3306"),
        u6,
        _has(parser, "kea6_db", "password"),
        _get(parser, "kea6_db", "password"),
        kea_db,
    )
    jen_pass = _get(parser, "jen_db", "password")
    out["jen_db"] = Endpoint(
        "jen_db",
        _db_url(parser, "jen_db", _get(parser, "jen_db", "host")),
        _get(parser, "jen_db", "user"),
        jen_pass,
        "own" if jen_pass else "none",
    )

    for n in server_numbers(parser):
        sec = f"kea_server_{n}"
        url = _get(parser, sec, "api_url")
        user = _get(parser, sec, "api_user") if _has(parser, sec, "api_user") else kea_user
        srv = out[f"server_{n}"] = _inherit(
            f"server_{n}", url, user, _has(parser, sec, "api_pass"), _get(parser, sec, "api_pass"), kea
        )
        for suffix, url_key, user_key, pass_key in (
            ("v6", "api6_url", "api6_user", "api6_pass"),
            ("d2", "api_d2_url", "api_d2_user", "api_d2_pass"),
        ):
            eurl = _get(parser, sec, url_key) if _has(parser, sec, url_key) else ("" if direct else url)
            euser = _get(parser, sec, user_key) if _has(parser, sec, user_key) else srv.user
            out[f"server_{n}_{suffix}"] = _inherit(
                f"server_{n}_{suffix}", eurl, euser, _has(parser, sec, pass_key), _get(parser, sec, pass_key), srv
            )
    return out


def label(name: str) -> str:
    """The words a person reads for an endpoint name."""
    fixed = {
        "kea": "Kea API",
        "kea6": "Kea6 API",
        "d2": "D2 API",
        "kea_db": "Kea database",
        "kea6_db": "Kea6 database",
        "jen_db": "Jen database",
    }
    if name in fixed:
        return fixed[name]
    m = re.fullmatch(r"server_(\d+)(?:_(v6|d2))?", name)
    if m:
        return f"additional server {m.group(1)}" + {"v6": " (IPv6)", "d2": " (D2)", None: ""}[m.group(2)]
    return name


def host_of(url: str) -> str:
    from jen.services import auth as _auth

    parts = _auth._endpoint_parts(url)
    return parts[1] if parts else (url or "").strip()


def move_refusal(before: dict, after: dict, typed=frozenset()) -> str:
    """The sentence when a write would send a saved password somewhere its owner never named, else "" (CRED-004; asked ONCE, by `AppConfig._write_parser`, for every write of
    Jen's configuration - never per form). `before` and `after` are `resolve()` of the file as it is and as it would be; `typed` is the set of endpoint names whose password was
    TYPED in this request (a route says so; the setup wizard, an installer and a test say so for theirs).

    Two shapes, both only for a password that was not typed:
      (a) an endpoint whose password VALUE is unchanged but whose HOST changed - the saved password followed the endpoint to a new place;
      (b) a password VALUE that now appears on two endpoints on different hosts, when that pair did not already exist unchanged - the same secret on a second host.
    A write that touches neither (a rename, an HA mode, a password rotation at the same host) is never asked."""
    typed = frozenset(typed or ())
    for name, a in after.items():
        # only a secret an endpoint OWNS can move with it: an inherited one is its parent's, and the parent is judged as itself
        if a.source != "own" or name in typed or not a.url:
            continue
        b = before.get(name)
        if b is not None and b.password == a.password and b.url and not _same_host(b.url, a.url):
            return (
                f"The {label(name)} moved to a different host ({host_of(a.url)}) with its saved password: "
                "type the password for the new place - a saved password is never sent to one it was not typed for."
            )
    shown = [(n, e) for n, e in after.items() if e.password and e.url and e.source == "own"]
    for i, (n1, e1) in enumerate(shown):
        for n2, e2 in shown[i + 1 :]:
            if e1.password != e2.password or _same_host(e1.url, e2.url) or n1 in typed or n2 in typed:
                continue
            b1, b2 = before.get(n1), before.get(n2)
            if (
                b1 is not None
                and b2 is not None
                and b1.password == e1.password
                and b2.password == e2.password
                and b1.url
                and b2.url
                and _same_host(b1.url, e1.url)
                and _same_host(b2.url, e2.url)
            ):
                continue  # this pair already existed, unchanged: not something this write did
            return (
                f"The {label(n1)} ({host_of(e1.url)}) and the {label(n2)} ({host_of(e2.url)}) would now use the same saved password on different hosts: "
                "type each one's own password - a saved password is never sent to a host it was not typed for."
            )
    return ""


def password_key(name: str) -> tuple[str, str]:
    """(section, option) that holds an endpoint's own password - the inverse of `resolve`'s reading."""
    fixed = {
        "kea": ("kea", "api_pass"),
        "kea6": ("kea6", "api_pass"),
        "d2": ("d2", "api_pass"),
        "kea_db": ("kea_db", "password"),
        "kea6_db": ("kea6_db", "password"),
        "jen_db": ("jen_db", "password"),
    }
    if name in fixed:
        return fixed[name]
    m = re.fullmatch(r"server_(\d+)(?:_(v6|d2))?", name)
    if not m:
        raise KeyError(name)
    return f"kea_server_{m.group(1)}", {None: "api_pass", "v6": "api6_pass", "d2": "api_d2_pass"}[m.group(2)]


def pending_conversions(parser) -> list[str]:
    """The endpoints the 5.10-to-5.69.0-beta.10 inheritance would have given a password that CRED-004 no longer does: each has a url, no password key and a parent with a password
    on a different host (`withheld`). Servers' own endpoints come before their IPv6 and D2 ones, which inherit from them."""
    return [n for n, e in resolve(parser).items() if e.withheld and e.url and n != "kea"]


def materialise(app_config, audit=None, today: str = "") -> list[str] | None:
    """Convert a legacy configuration ONCE, audibly (CRED-004, Q180 U2). Until beta.11 an extra server - and Kea6, D2, the Kea6 database and a server's IPv6 and D2 endpoints - with
    no password of its own inherited its parent's whatever host it was on (HA peers since 5.10), and the resolver no longer does. For each endpoint that has a url, no password key
    and a parent with a password on a DIFFERENT host (`pending_conversions`), the parent's CURRENT password is written into its section with a `<key>_shared = 1` marker, one audit
    row (`CONFIG_MIGRATION`) and one INFO line each. A server's own API password is converted before its IPv6 and D2 ones, which inherit from it.

    ONCE: `create_app` calls this only while the install-level marker `credentials_materialised` is unset, and sets it when this returns a list (`None` = it did not run: a request
    context, or a failure - never fatal, retried at the next start). A section a superadmin leaves without a key afterwards is left alone: that is their answer, not a legacy
    state. Idempotent in itself (a section that has the key is untouched)."""
    try:
        from flask import has_request_context

        if has_request_context():
            return None
        done: list[str] = []

        def _apply(p):
            for _ in range(3):  # parent before child: a server's API password, then its IPv6 and D2
                batch = [n for n in pending_conversions(p) if n not in done]
                if not batch:
                    return
                res = resolve(p)
                for name in batch[:]:
                    parent = res[name].withheld
                    if not res[parent].password:
                        continue
                    section, option = password_key(name)
                    if p.has_section(section) and not p.has_option(section, option):
                        p.set(section, option, res[parent].password)
                        p.set(section, f"{option}_shared", "1")
                        done.append(name)

        probe = app_config._read_parser()
        if not pending_conversions(probe):
            return []
        app_config.mutate(_apply, typed=set(resolve(probe)))
        for name in done:
            section, option = password_key(name)
            logger.info(
                f"credentials: [{section}] {option}: the parent's password was copied into it (it no longer follows the parent's) {today}".rstrip()
            )
            if audit is not None:
                try:
                    audit(
                        "CONFIG_MIGRATION",
                        section,
                        f"{section}: the parent's {option} materialised; it no longer follows the parent's",
                    )
                except Exception as e:  # the audit row is a record, not a gate
                    logger.warning(f"credentials: could not audit the conversion of [{section}]: {type(e).__name__}")
        return done
    except Exception as e:
        logger.warning(f"credentials: the legacy conversion did not run: {type(e).__name__}: {e}")
        return None
