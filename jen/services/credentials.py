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

# source: "own" | "inherited:<name>" | "none"; withheld: the endpoint whose secret was NOT inherited because the host differs ("" otherwise);
# url_own (v5.69.0-beta.13, Q182, X1): True when the address is the endpoint's OWN value (its key is present in its section), False when it is DERIVED from its parent's (an absent
# key in CA mode) - the writer's mode-switch exemption reads it without the parser
Endpoint = namedtuple("Endpoint", "name url user password source withheld url_own", defaults=("", True))

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


def _user(
    own_present: bool,
    own_value: str,
    parent: Endpoint,
    url: str,
    own_password: str = "",
    no_auth: bool = False,
) -> str:
    """An endpoint's username under the one reading (v5.69.0-beta.12, Q181): a value is its own, a PRESENT-BLANK key is "no user", and an ABSENT key is the parent's - on the same
    host, or alongside a password the endpoint OWNS (the operator typed a password for it, and the account name it was typed with is the parent's unless said otherwise: the forms
    still offer "inherited" for a blank user). An endpoint with no password of its own on a different host has no user - a name is not a secret, but it is half of the credential, and
    there is no credential to carry it.

    v5.69.0-beta.13 (Q182, X2): `no_auth` is True for an HTTP endpoint whose password key is PRESENT and BLANK - the endpoint said "no authentication" - and an absent user beside it is no
    user: nothing is sent, not an empty Basic header carrying the parent's name. (A database keeps its user beside a blank password: a connection always names one.)"""
    if own_present:
        return own_value
    if no_auth:
        return ""
    if parent.user and url and (own_password or _same_host(parent.url, url)):
        return parent.user
    return ""


def _inherit(name, url, user, own_present, own_value, parent: Endpoint, url_own: bool = True) -> Endpoint:
    """One endpoint's credential: its own (blank = none, on purpose), else `parent`'s when this endpoint is on the parent's host, else none - with `withheld` set when the
    parent HAD a secret that was refused."""
    if own_present:
        return Endpoint(name, url, user, own_value, "own" if own_value else "none", "", url_own)
    if parent.password and url:
        if _same_host(parent.url, url):
            return Endpoint(name, url, user, parent.password, f"inherited:{parent.name}", "", url_own)
        return Endpoint(name, url, user, "", "none", parent.name, url_own)
    return Endpoint(name, url, user, "", "none", "", url_own)


def server_numbers(parser) -> list[int]:
    nums = []
    for section in parser.sections():
        m = re.fullmatch(r"kea_server_(\d+)", section)
        if m and int(m.group(1)) >= 2:
            nums.append(int(m.group(1)))
    return sorted(nums)


def resolve(parser) -> dict[str, Endpoint]:
    """Every place Jen sends a Kea or database credential, with the url, user and password it WILL send and where the password came from (CRED-004, Q180; Q181 for url and
    user). The one rule: a secret is used at its own endpoint, or inherited by another daemon ON THE SAME HOST (`same_host`; another port of that host is the same box). An
    endpoint on a different host with no secret of its own has NONE - never its neighbour's. Names: "kea", "kea6", "d2", "kea_db", "kea6_db", "jen_db", "server_<N>",
    "server_<N>_v6", "server_<N>_d2".

    THE THREE READINGS, the same for url, user and password (v5.69.0-beta.12, Q181 - what this returns is what the transport sends, and nothing downstream may change it):
      * a VALUE is the endpoint's own;
      * a PRESENT-BLANK key is explicit: "no endpoint of its own" (url), "no user", "no password" - never a request to fall back;
      * an ABSENT key inherits: the url from the parent endpoint in CA mode (one Control Agent proxies every daemon) and nothing in direct mode (every daemon has its own
        socket); the password from the parent's on the same host only, else none; the user from the parent's on the same host or alongside a password the endpoint owns, else none.

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
        user = _user(
            _has(parser, name, "api_user"),
            _get(parser, name, "api_user"),
            kea,
            url,
            _get(parser, name, "api_pass"),
            no_auth=_has(parser, name, "api_pass") and not _get(parser, name, "api_pass"),
        )
        out[name] = _inherit(
            name,
            url,
            user,
            _has(parser, name, "api_pass"),
            _get(parser, name, "api_pass"),
            kea,
            _has(parser, name, "api_url"),
        )

    kea_db_host, kea_db_user, kea_db_pass = (
        _get(parser, "kea_db", "host"),
        _get(parser, "kea_db", "user"),
        _get(parser, "kea_db", "password"),
    )
    kea_db = out["kea_db"] = Endpoint(
        "kea_db", _db_url(parser, "kea_db", kea_db_host), kea_db_user, kea_db_pass, "own" if kea_db_pass else "none"
    )
    h6 = _get(parser, "kea6_db", "host") if _has(parser, "kea6_db", "host") else kea_db_host
    url6 = _db_url(parser, "kea6_db", h6, _get(parser, "kea_db", "port", "3306") or "3306")
    out["kea6_db"] = _inherit(
        "kea6_db",
        url6,
        _user(
            _has(parser, "kea6_db", "user"),
            _get(parser, "kea6_db", "user"),
            kea_db,
            url6,
            _get(parser, "kea6_db", "password"),
        ),
        _has(parser, "kea6_db", "password"),
        _get(parser, "kea6_db", "password"),
        kea_db,
        _has(parser, "kea6_db", "host"),
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
        user = _user(
            _has(parser, sec, "api_user"),
            _get(parser, sec, "api_user"),
            kea,
            url,
            _get(parser, sec, "api_pass"),
            no_auth=_has(parser, sec, "api_pass") and not _get(parser, sec, "api_pass"),
        )
        srv = out[f"server_{n}"] = _inherit(
            f"server_{n}", url, user, _has(parser, sec, "api_pass"), _get(parser, sec, "api_pass"), kea
        )
        for suffix, url_key, user_key, pass_key in (
            ("v6", "api6_url", "api6_user", "api6_pass"),
            ("d2", "api_d2_url", "api_d2_user", "api_d2_pass"),
        ):
            eurl = _get(parser, sec, url_key) if _has(parser, sec, url_key) else ("" if direct else url)
            euser = _user(
                _has(parser, sec, user_key),
                _get(parser, sec, user_key),
                srv,
                eurl,
                _get(parser, sec, pass_key),
                no_auth=_has(parser, sec, pass_key) and not _get(parser, sec, pass_key),
            )
            out[f"server_{n}_{suffix}"] = _inherit(
                f"server_{n}_{suffix}",
                eurl,
                euser,
                _has(parser, sec, pass_key),
                _get(parser, sec, pass_key),
                srv,
                _has(parser, sec, url_key),
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


#: the endpoints that ride the Control Agent in CA mode (one proxy for every daemon): a switch of the connection mode re-points them wholesale, by the superadmin's own act
RIDES_THE_CONTROL_AGENT = re.compile(r"kea6|d2|server_\d+_(?:v6|d2)")


#: Y4 (v5.69.0-beta.14, Q183): a test sets this to a list and every `continue` in `move_refusal` appends the name of the matrix row it cites, so a test can prove a row REACHES the
#: exemption it names (existence of the row is not reach). None in production: one `is not None` per skip.
_trace = None


def _hit(row: str) -> None:
    if _trace is not None:
        _trace.append(row)


def _parent_of(name: str) -> str:
    """The endpoint whose address a derived (absent-key) address follows: the primary for Kea6 and D2, a server for its own IPv6 and D2."""
    if name in ("kea6", "d2"):
        return "kea"
    m = re.fullmatch(r"(server_\d+)_(?:v6|d2)", name)
    return m.group(1) if m else ""


def _re_pointed_by_the_mode_alone(name: str, a, before: dict, after: dict) -> bool:
    """X1 (v5.69.0-beta.13, Q182): the connection-mode switch exempts ONLY what the mode itself moves - a daemon whose address is DERIVED (its url key absent: `url_own` False) from a
    parent whose host did not change. An address of its own, or a Control Agent on a NEW host, is judged as any move: typed, or refused.

    Y1 (v5.69.0-beta.14, Q183): and only a daemon whose password ALREADY WENT to the parent's host - it had an address before, and that address was on the parent's host. A password
    that was typed for another host and then lost its address (the key removed, which is allowed: nothing is sent to an endpoint with no address) is given the Control Agent's address
    by the flip, and that is a first address like any other."""
    if a.url_own or not RIDES_THE_CONTROL_AGENT.fullmatch(name):
        return False
    parent = _parent_of(name)
    b, b_parent, a_parent = before.get(name), before.get(parent), after.get(parent)
    if b is None or not b.url or b_parent is None or not _same_host(b.url, b_parent.url):
        return False
    return bool(a_parent is not None and _same_host(b_parent.url, a_parent.url))


def move_refusal(before: dict, after: dict, typed=frozenset(), mode_changed: bool = False) -> str:
    """The sentence when a write would send a saved password somewhere its owner never named, else "" (CRED-004; asked ONCE, by `AppConfig._write_parser`, for every write of
    Jen's configuration - never per form). `before` and `after` are `resolve()` of the file as it is and as it would be; `typed` is the set of endpoint names whose password was
    TYPED in this request (a route says so; the setup wizard, an installer and a test say so for theirs).

    Three shapes, all only for a password that was not typed:
      (a) an endpoint whose password VALUE is unchanged but whose HOST changed - or that had NO address and was given one (Q181) - the saved password followed the endpoint to a
          new place; an endpoint that had no password gains an address freely, and a section new in this write has its password in `typed` by construction;
      (b) a password VALUE that now appears on two endpoints on different hosts, when that pair did not already exist unchanged - the same secret on a second host;
      (c) (Y2, v5.69.0-beta.14) an endpoint whose own password VALUE differs from what it was - or that is new with one - and whose name is not in `typed`: a value changes only when
          someone typed it for that endpoint. Every route types what it sets; what this catches is a `mutate` (a plugin's, a test's) that COPIES a value into an endpoint.
    A write that touches none (a rename, an HA mode, a password rotation at the same host, typed) is never asked."""
    typed = frozenset(typed or ())
    for name, a in after.items():
        # only a secret an endpoint OWNS can move with it: an inherited one is its parent's, and the parent is judged as itself
        if a.source != "own":
            _hit("a_new_server_with_no_key_on_another_host")
            continue  # row: a_new_server_with_no_key_on_another_host
        if name in typed:
            _hit("the_same_move_with_the_password_typed")
            continue  # row: the_same_move_with_the_password_typed
        b = before.get(name)
        if a.password and (b is None or b.password != a.password):
            return f"The {label(name)}'s password was written without being typed for it: a saved password changes only when it is typed for that endpoint."
        if not a.url:
            _hit("a_saved_password_with_no_address_is_not_a_write_to_judge")
            continue  # row: a_saved_password_with_no_address_is_not_a_write_to_judge
        if mode_changed and _re_pointed_by_the_mode_alone(name, a, before, after):
            _hit("a_mode_switch_with_derived_urls_on_the_same_control_agent")
            continue  # row: a_mode_switch_with_derived_urls_on_the_same_control_agent
        if b is not None and b.password == a.password:
            if not b.url:
                # v5.69.0-beta.12 (Q181): a saved password's FIRST address is a move too - it was never sent anywhere, and the address it is given now is a place it was not typed for
                return (
                    f"The {label(name)} has a saved password and is being given its first address ({host_of(a.url)}): "
                    "type the password for it - a saved password is never sent to a place it was not typed for."
                )
            if not _same_host(b.url, a.url):
                return (
                    f"The {label(name)} moved to a different host ({host_of(a.url)}) with its saved password: "
                    "type the password for the new place - a saved password is never sent to one it was not typed for."
                )
    shown = [(n, e) for n, e in after.items() if e.password and e.url and e.source == "own"]
    for i, (n1, e1) in enumerate(shown):
        for n2, e2 in shown[i + 1 :]:
            if e1.password != e2.password:
                _hit("a_rotation_with_kea6_and_d2_pinned")
                continue  # row: a_rotation_with_kea6_and_d2_pinned
            if _same_host(e1.url, e2.url):
                _hit("two_own_passwords_equal_on_the_same_host")
                continue  # row: two_own_passwords_equal_on_the_same_host
            if n1 in typed or n2 in typed:
                _hit("the_same_server_with_the_share_box_ticked")
                continue  # row: the_same_server_with_the_share_box_ticked
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
                _hit("an_existing_pair_sharing_a_password_is_not_this_writes_doing")
                continue  # row: an_existing_pair_sharing_a_password_is_not_this_writes_doing
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


def user_key(name: str) -> tuple[str, str]:
    """(section, option) that holds an endpoint's own USER - the sibling of `password_key`."""
    section, option = password_key(name)
    return section, {
        "api_pass": "api_user",
        "api6_pass": "api6_user",
        "api_d2_pass": "api_d2_user",
        "password": "user",
    }[option]


#: the two server keys that 5.68.0 read a BLANK as "inherit" for (`kea._endpoint_for`'s `or` chain): in a file that has not been converted, a present-blank value is the same as an absent key
LEGACY_BLANK_KEYS = ("api6_pass", "api_d2_pass")


def _without_legacy_blanks(parser):
    """A copy of `parser` with the legacy present-blank keys (`LEGACY_BLANK_KEYS` of a `[kea_server_N]`) removed: what 5.68.0 meant by them."""
    import configparser

    q = configparser.ConfigParser(interpolation=None)
    for section in parser.sections():
        q.add_section(section)
        legacy = re.fullmatch(r"kea_server_\d+", section) is not None
        for key, value in parser.items(section, raw=True):
            if legacy and key in LEGACY_BLANK_KEYS and value == "":
                continue
            q.set(section, key, value)
    return q


def shared_copies(parser) -> set[str]:
    """The endpoints whose password is a COPY of the parent's, made once and not following it (Y3, v5.69.0-beta.14): the `<password key>_shared = 1` marker the conversion, the "share"
    box and the direct-socket routes write beside the copy - for `api_pass` of a server, Kea6 or D2, `api6_pass` and `api_d2_pass` of a server, and `[kea6_db] password`. The Servers & HA
    rows and the Kea6 / D2 / Kea6-database cards read it ("shared copy"); `clear_shared` is how a password that is typed again stops being one."""
    out = set()
    for name in resolve(parser):
        try:
            section, option = password_key(name)
        except KeyError:
            continue
        if _has(parser, section, option) and _get(parser, section, f"{option}_shared") == "1":
            out.add(name)
    return out


def clear_shared(parser, name: str) -> None:
    """Drop an endpoint's `_shared` marker: its password was typed (or removed, or made explicitly blank) in this save, so it is its own and no longer a copy."""
    section, option = password_key(name)
    if parser.has_section(section) and parser.has_option(section, f"{option}_shared"):
        parser.remove_option(section, f"{option}_shared")


def pending_conversions(parser, legacy: bool | None = None) -> list[str]:
    """The endpoints the 5.10-to-5.69.0-beta.10 inheritance would have given a password that CRED-004 no longer does: each has a url, no password key and a parent with a password
    on a different host (`withheld`). Servers' own endpoints come before their IPv6 and D2 ones, which inherit from them.

    v5.69.0-beta.13 (Q182, X5d): in a file WITHOUT the credential-model marker (`legacy`, the default for such a file) a present-blank `api6_pass` / `api_d2_pass` of a server is what 5.68.0
    called "inherit", so it is pending too; with the marker a blank is a blank (an explicit "no password")."""
    if legacy is None:
        legacy = model_marker(parser) == "absent"
    if legacy:
        parser = _without_legacy_blanks(parser)
    return [n for n, e in resolve(parser).items() if e.withheld and e.url and n != "kea"]


#: the marker, in the file it describes (v5.69.0-beta.12, Q181): `[jen] credential_model = explicit` says "every endpoint's password in this file is its own, or deliberately absent" -
#: written by the installer and the setup wizard on a fresh install, and by `materialise` in the SAME atomic write as the copies it makes. A file without it is a legacy file.
MODEL_SECTION, MODEL_KEY, MODEL_VALUE = "jen", "credential_model", "explicit"


def beta11_flag():
    """The settings-table row beta.11 wrote when it converted (`credentials_materialised`): True / False, or None when the settings table cannot be READ - which is not "absent". An
    unreadable table must not read as "not converted" (a section a superadmin left keyless on purpose after beta.11's conversion would be filled in), so the caller does nothing this
    start and tries again at the next."""
    try:
        from jen.models.db import jen_db

        with jen_db() as db, db.cursor() as cur:
            cur.execute("SELECT setting_value FROM settings WHERE setting_key = %s", ("credentials_materialised",))
            row = cur.fetchone()
    except Exception as e:
        logger.warning(
            f"credentials: the settings table could not be read ({type(e).__name__}); the conversion waits for the next start"
        )
        return None
    return bool(row) and str(row["setting_value"]).strip().strip('"') == "1"


def forget_beta11_flag() -> None:
    """The bridge has done its work once the marker is in the file: drop the row, so a pre-beta.11 config copied back by hand later converts instead of being marked unconverted."""
    try:
        from jen.models.db import jen_db

        with jen_db() as db, db.cursor() as cur:
            cur.execute("DELETE FROM settings WHERE setting_key = %s", ("credentials_materialised",))
            db.commit()
    except Exception as e:
        logger.warning(
            f"credentials: could not drop the beta.11 conversion row ({type(e).__name__}); it is harmless and is retried at the next start"
        )


def model_marker(parser) -> str:
    """The marker as a VALUE (v5.69.0-beta.13, Q182, X3): "absent" (no `[jen] credential_model` key: a legacy file), "explicit" (the value Jen writes, whitespace ignored) or "invalid"
    (the key is there with anything else - a typo, an empty value). An invalid marker is neither: Jen cannot tell whether every password in the file is its own, so it converts
    nothing and says so (`materialise`, the Doctor's `credential-model-invalid`, Health)."""
    if not _has(parser, MODEL_SECTION, MODEL_KEY):
        return "absent"
    return "explicit" if _get(parser, MODEL_SECTION, MODEL_KEY).strip() == MODEL_VALUE else "invalid"


def has_model_marker(parser) -> bool:
    """True when the marker says `explicit` (the file is converted or was born converted)."""
    return model_marker(parser) == "explicit"


def materialise(app_config, audit=None, today: str = "", already_converted: bool = False) -> list[str] | None:
    """Convert a legacy configuration ONCE, audibly (CRED-004, Q180 U2, Q181 V3). Until beta.11 an extra server - and Kea6, D2, the Kea6 database and a server's IPv6 and D2
    endpoints - with no password of its own inherited its parent's whatever host it was on (HA peers since 5.10), and the resolver no longer does. For each endpoint that has a url,
    no password key and a parent with a password on a DIFFERENT host (`pending_conversions`), the parent's CURRENT password is written into its section with a `<key>_shared = 1`
    marker, one audit row (`CONFIG_MIGRATION`) and one INFO line each. A server's own API password is converted before its IPv6 and D2 ones, which inherit from it.

    ONCE, and the marker lives IN THE FILE it describes: `[jen] credential_model = explicit` is written in the same `mutate` - one atomic replace - as the copies, so the marker and the
    copies exist together or not at all; a file that has it is never converted again, whatever database it is paired with (a restored older database changes nothing; a restored
    pre-beta.11 config has no marker and converts, correctly, with its audit rows; a fresh hand-made config is converted only if it has a passwordless peer on another host).
    `already_converted` is the one-release bridge: an install that converted under beta.11 (its settings-table row says so) gets the marker WITHOUT a second round of copies.

    Returns the names converted ([] when there was nothing to do or the marker alone was written), or None when it did not run: a request context (a request is judged by the
    identity guards), or a failure - never fatal; a read-only file logs ONE error naming it and is retried at the next start."""
    try:
        from flask import has_request_context

        if has_request_context():
            return None
        probe = app_config._read_parser()
        state = model_marker(probe)
        if state == "explicit":
            return []
        if state == "invalid":
            logger.error(
                f"credentials: [{MODEL_SECTION}] {MODEL_KEY} = {_get(probe, MODEL_SECTION, MODEL_KEY)!r} in {getattr(app_config, 'path', 'jen.config')} is not a value Jen knows - nothing was converted. "
                f"Set it to {MODEL_VALUE!r} if every password in the file is its own, or remove the line to convert a legacy file"
            )
            return None
        done: list[str] = []

        def _apply(p):
            if model_marker(p) != "absent":
                return  # a second process (or an installer) wrote it between the probe and now: nothing to convert, nothing to write
            if not p.has_section(MODEL_SECTION):
                p.add_section(MODEL_SECTION)
            p.set(MODEL_SECTION, MODEL_KEY, MODEL_VALUE)
            # X5a (Q182): the bridge marks THIS file only when it has nothing to convert - the settings row described the database's old file, and a restored pre-beta.11 file with
            # passwordless peers on other hosts converts them. The marker above is already set, so what is pending is read as a legacy file (legacy=True)
            # (second pass, P2-2: a file whose database says beta.11 converted is not a 5.68.0 file - beta.11's own forms wrote `api6_pass =` for "no authentication" - so its blanks are
            # answers, and the legacy-blank reading applies only when the bridge does not)
            legacy = not already_converted
            if already_converted and not pending_conversions(p, legacy=False):
                return
            for _ in range(3):  # parent before child: a server's API password, then its IPv6 and D2
                batch = [n for n in pending_conversions(p, legacy=legacy) if n not in done]
                if not batch:
                    return
                res = resolve(_without_legacy_blanks(p) if legacy else p)
                for name in batch[:]:
                    parent = res[name].withheld
                    if not res[parent].password:
                        continue
                    section, option = password_key(name)
                    blank_legacy = (
                        legacy
                        and p.has_section(section)
                        and option in LEGACY_BLANK_KEYS
                        and re.fullmatch(r"kea_server_\d+", section) is not None
                        and p.has_option(section, option)
                        and p.get(section, option, raw=True) == ""
                    )
                    if p.has_section(section) and (not p.has_option(section, option) or blank_legacy):
                        p.set(section, option, res[parent].password)
                        p.set(section, f"{option}_shared", "1")
                        # the USER it sent too (Q181): the old inheritance carried the parent's user with the password, and the resolver now inherits a user on the same host only -
                        # a copied password without its user would fail the endpoint's Basic authentication
                        u_section, u_option = user_key(name)
                        if res[parent].user and not p.has_option(u_section, u_option):
                            p.set(u_section, u_option, res[parent].user)
                        done.append(name)

        try:
            app_config.mutate(_apply, typed=set(resolve(probe)))
        except OSError as e:
            logger.error(
                f"credentials: could not write the credential model into {getattr(app_config, 'path', 'jen.config')} ({type(e).__name__}: {e}) - "
                "a legacy additional server may lose its borrowed password until the file is writable; retried at the next start"
            )
            return None
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
