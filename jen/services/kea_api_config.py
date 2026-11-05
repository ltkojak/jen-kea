"""
jen/services/kea_api_config.py
──────────────────────────────
Q212 (7.0.0-beta.1) - a Kea server's configuration changed over the daemon's OWN API: `config-get`, `config-hash-get`, `config-test`, `config-set`, `config-write`.
No SSH, no restart. This is the ONE module that sends `config-set`, `config-write` or `config-hash-get` (a source test pins it, `tests/test_kea_host.py`), it posts only through
`jen.services.kea.kea_command` (so `credentials.resolve` chooses every credential and nothing here can name a host), and it imports nothing that speaks SSH.

Every function answers the HostResult shape the file path already answers (`kea_host._from_helper_test`): `{"ok", "code", "detail", "via": "api", "sha256"?}` - so the
change set, the restore and the import dispatch on the transport and read nothing new. `code` is one of:

    ok | conflict | testerror | guard | set-failed | write-failed | unverified | unknown | noanswer | investigation-on | nokey | noservice

`needs_hands` (a bool, beside the code) is set when the daemon may be in a state Jen cannot name: the line a person reads says both digests.

**A file or a daemon that cannot be read is not a difference; a write's own guards decide** (Q217, AB8). `apply` step (8) and `api_daemon_differs` both cite this: a write the daemon's own digest proved
is `ok` with a note when the file cannot be read back; only a file that WAS read and does not carry what the daemon runs is `unverified`.

What this module knows of Kea, from the rows of `tests/kea_compat/test_config_write.py` (docs/ARCHITECTURE.md 3.17):
  - `config-get` is not redacted (database passwords in plain text): a reply is NEVER logged, nor is a `config-set` payload; this module logs command names and digests only.
  - the digest is under `arguments.hash` on `config-get`, `config-set` and `config-hash-get`; Jen cannot compute it, so it is only ever compared with another digest the daemon gave.
  - Kea has NO compare-and-set (a stale `config-set` is accepted): `apply` compares first, and the daemon's own `config-get` afterward is the record.
  - a refused `config-set` leaves the old configuration serving - but ISC says the server can also stop; so a refusal is followed by a question, never assumed.
  - `config-write` (no filename) persists what runs, in place; a change a restart would lose did not stand.
"""

from __future__ import annotations

import copy
import json
import logging
import pathlib
import re

from jen.services import config_revisions as _rev
from jen.services import kea as _kea
from jen.services import kea_host as _host

logger = logging.getLogger(__name__)

# dhcp4 only in 7.0.0-beta.1. ISC's own dhcp4 image has no kea-dhcp6 binary, so Q211's row 10 ("the same over dhcp6") could not be built against a real daemon (run 41703269176: `exec:
# "kea-dhcp6": executable file not found`); dhcp6 joins D2 on the file path in this beta, and `kea_changeset._transport` says so for every service this module does not serve.
SERVICE_KEY = {"dhcp4": "Dhcp4"}

# Kea cuts a control connection at 10 s (not configurable); one second more than that is the whole wait, and a test narrows it.
COMMAND_TIMEOUT = 15
# `config-write` writes what runs and is idempotent: it is re-sent when no answer came, never when Kea answered.
WRITE_ATTEMPTS = 3

PENDING = "pending"

TRANSPORTS = ("api", "file", "off")


def declared_transport(server: dict) -> str:
    """The server's `config_transport` setting, in ONE place (the change set, the file path's choke point and the capability badge all read it here): `api | file | off`. ABSENT (or blank) is exactly
    today's behavior - `file` when the server has an SSH host, `off` when it has none (an API-only server was never a write target and stays one until its operator switches it). A value that is not
    one of the three, spelled exactly, reads as `off`: `API`, `yes` and `ssh` are mistakes, and a mistake never grants a write path."""
    raw = server.get("config_transport")
    if raw is None or str(raw).strip() == "":
        return "file" if server.get("ssh_host") else "off"
    value = str(raw).strip()
    return value if value in TRANSPORTS else "off"


def _name(server: dict) -> str:
    return server.get("name") or server.get("ssh_host") or f"Server {server.get('id')}"


def _result(ok: bool, code: str, detail: str = "", sha256: str | None = None, **extra) -> dict:
    out = {"ok": ok, "code": code, "via": "api"}
    if detail:
        out["detail"] = detail
    if sha256:
        out["sha256"] = sha256
    out.update(extra)
    return out


def _cmd(server: dict, service: str, command: str, arguments: dict | None = None, timeout=None) -> dict:
    """The one sender: `kea_command` with this module's wait. Logs the command's name and its result code, never an argument or a reply."""
    reply = _kea.kea_command(command, service, arguments, server=server, timeout=timeout or COMMAND_TIMEOUT)
    logger.debug("kea_api_config: %s on %s -> result %s", command, _name(server), reply.get("result"))
    return reply


def _answered(reply: dict) -> bool:
    """Kea sent this reply (a refusal included); False for one Jen fabricated for a transport fault - read by the `transport` key, never by the sentence."""
    return "transport" not in reply


def _ok(reply: dict) -> bool:
    return _answered(reply) and reply.get("result") == 0


def _text(reply: dict) -> str:
    return str(reply.get("text") or "").strip()[:300]


def _digest(reply: dict) -> str | None:
    value = (reply.get("arguments") or {}).get("hash") if isinstance(reply.get("arguments"), dict) else None
    return value if isinstance(value, str) and value else None


def _section(cfg: dict | None, service: str) -> dict:
    return (cfg or {}).get(SERVICE_KEY.get(service, ""), {}) or {}


# Kea renders some singular keys of a file as lists in `config-get` (docs/ARCHITECTURE.md 3.17: `hosts-database` comes back as `hosts-databases`, `control-socket` as `control-sockets`). The table's SOURCE is a
# compat row (`tests/kea_compat/test_config_write.py::test_11_what_config_get_renames`, Q216 BF4): a row and this table that disagree are settled by the row, and the table is edited.
RENAMED_KEYS = {"hosts-database": "hosts-databases", "control-socket": "control-sockets"}

# The ONE kind of string Kea re-renders: a pool "a - b" is reported as "a-b" (compat run 41712142556). The spacing rule is for a string AT one of these paths (indexes blanked; a shared network's
# subnets are the same shape one level down) and nowhere else: a `user-context.pool` and a top-level `pool` compare exactly. A path the compat row reports that is not one of these is a new entry
# here, named, never a wider rule (Q216 BF5, Q217 AB15).
SPACE_INSENSITIVE_PATHS = frozenset({"subnet4[].pools[].pool", "subnet6[].pools[].pool", "subnet6[].pd-pools[].prefix"})
_INDEX = re.compile(r"\[\d+\]")


def _space_insensitive(path: str) -> bool:
    blank = _INDEX.sub("[]", path)
    return any(blank == known or blank.endswith("." + known) for known in SPACE_INSENSITIVE_PATHS)


# Keys of `interfaces-config` that `config-get` OMITS when they hold their default (compat row 11, Kea 3.0.5, 3.2.1 and 3.3.3: a file carrying `service-sockets-require-all: false` and
# `service-sockets-max-retries: 0` comes back without them). A file that carries one at its default is carried by a daemon that does not report it; any other value is a difference.
OMITTED_AT_DEFAULT = {"service-sockets-require-all": False, "service-sockets-max-retries": 0}


_MISSING = object()


def _walk(running: object, candidate: object, under: str | None = None, path: str = ""):
    """THE one walk (Q217 BG3 b): `None` when the configuration the daemon RUNS carries everything the candidate said, else `(path, candidate_leaf, running_leaf)` for the FIRST thing it does not -
    the path built as the walk descends (`Dhcp4.subnet4[2].pools[0].pool`; the caller prefixes the section). `config-get` returns the daemon's configuration with Kea's own defaults written out (45 keys
    at the top of `Dhcp4`, 13 per subnet and one per pool - docs/ARCHITECTURE.md 3.17, row 08), so a candidate Jen built is a SUBSET of what the daemon reports after it takes it: every key present with
    an equal value, lists the same length and elementwise the same. Equality would never hold for a subnet Jen just added. Used with a check of the BEFORE state FIRST, never alone: a candidate that only
    deletes is a subset of the configuration it came from. `under` is the key a value sits below: a candidate key Kea renames (`RENAMED_KEYS`) is carried by the list that took its place, and a string
    is compared without its spaces only under a `pool` key."""
    if isinstance(candidate, dict):
        if not isinstance(running, dict):
            return (path, candidate, running)
        for k, v in candidate.items():
            here = f"{path}.{k}" if path else k
            if k in running:
                found = _walk(running[k], v, k, here)
                if found is not None:
                    return found
                continue
            renamed = running.get(RENAMED_KEYS.get(k, ""))
            if isinstance(renamed, list) and len(renamed) == 1:
                found = _walk(
                    renamed[0], v, k, here
                )  # (the list Kea reports in the key's place: descend, so a difference is named at its own path, never as the whole object)
                if found is None:
                    continue
                return found
            if isinstance(renamed, list):
                return (
                    here,
                    v,
                    renamed,
                )  # (Q218 BH5 c, AC16) the daemon runs MORE (or fewer) than the one the file says: named by its count, never "nothing"
            if (
                under == "interfaces-config"
                and k in OMITTED_AT_DEFAULT
                and v == OMITTED_AT_DEFAULT[k]
                and type(v) is type(OMITTED_AT_DEFAULT[k])
            ):
                continue
            return (here, v, _MISSING)
        return None
    if isinstance(candidate, list):
        if not isinstance(running, list):
            return (path, candidate, running)
        if len(running) != len(candidate):
            return (path, candidate, running)
        for i, (r, c) in enumerate(zip(running, candidate, strict=True)):
            found = _walk(r, c, under, f"{path}[{i}]")
            if found is not None:
                return found
        return None
    if isinstance(running, str) and isinstance(candidate, str):
        if _space_insensitive(path):
            same = running.replace(" ", "") == candidate.replace(" ", "")
        else:
            same = running == candidate
        return None if same else (path, candidate, running)
    if isinstance(running, bool) or isinstance(candidate, bool):  # (AB3) Python says True == 1: Kea does not
        return None if type(running) is type(candidate) and running == candidate else (path, candidate, running)
    return None if running == candidate else (path, candidate, running)


def _carries(running: object, candidate: object, under: str | None = None) -> bool:
    """Does the configuration the daemon RUNS carry everything the candidate said? `first_difference` answers the same question with the path; this is its negation, so they cannot disagree."""
    return _walk(running, candidate, under) is None


def first_difference(running: object, candidate: object, under: str | None = None, path: str = "") -> str:
    """The FIRST path of `candidate` that `running` does not carry (`""` when it is carried): the one walk, as a path."""
    found = _walk(running, candidate, under, path)
    return "" if found is None else (found[0] or "/")


class DefaultsSet(frozenset):
    """Kea's written-out default key paths for one minor version (`load_vector`), with `populated`: the paths whose default is a NON-EMPTY list (`host-reservation-identifiers`), that list, and
    `scalars`: the value the daemon wrote out for a scalar path (Q218 D1), `None` for a vector recorded before values were (the path rule then stands, as before)."""

    populated: dict = {}
    scalars: dict | None = None


def _same_scalar(a: object, b: object) -> bool:
    """Equal as JSON scalars: a boolean is never a number (Python says True == 1, Kea does not)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return type(a) is type(b) and a == b


def _is_default(path: str, value: object, defaults: frozenset, chain: tuple = ()) -> bool:
    """Is a key the daemon runs and the file does not say one of Kea's own written-out defaults? (Q217 row 1 of the second pass; Q218 D1.) Its path must be in the vector AND its VALUE must be what a
    default is: an empty list, an object whose every child is itself a default, the recorded list for a list that Kea defaults to non-empty - so a populated `option-data`, `reservations`, `relay` or
    `shared-networks` deleted from the file is a difference, never "a default" - and a SCALAR only when it is the value the daemon wrote out for that path (`defaults.scalars`) or the value of the
    same-named key in an enclosing scope of the running configuration (Kea inherits an omitted scalar from the scope above it: a subnet's `valid-lifetime` is the global one). A scalar the operator
    DELETED from the file while the daemon runs another value is a difference: a `config-write` would put it back. `chain` is the running objects from the section down to the one that holds this
    key. A vector with no recorded scalar values (`scalars is None`) judges a scalar by its path alone - the limit `docs/ARCHITECTURE.md` 3.17 names for a vector not yet re-recorded."""
    blank = _INDEX.sub("[]", path)
    if blank not in defaults:
        return False
    if isinstance(value, dict):
        return all(_is_default(f"{path}.{k}", v, defaults, chain + (value,)) for k, v in value.items())
    if isinstance(value, list):
        return not value or getattr(defaults, "populated", {}).get(blank) == value
    scalars = getattr(defaults, "scalars", None)
    if scalars is None:
        return True
    key = re.split(r"[.\[\]]+", path)[-1]
    for scope in reversed(chain[:-1]):
        if isinstance(scope, dict) and key in scope:
            return _same_scalar(
                scope[key], value
            )  # (Q219, AD1) Kea inherits an omitted scalar from the NEAREST scope above that carries it: that scope decides, never a value some recording saw
    return blank in scalars and _same_scalar(scalars[blank], value)


def _lacks(running: object, candidate: object, defaults: frozenset, path: str = "", scope: tuple = ()):
    """THE reverse walk (Q217 AB6): `None` when everything the daemon RUNS is either in the file or one of Kea's own written-out defaults (`defaults`: key paths with indexes blanked, relative to the
    section), else `(path, _MISSING, running_leaf)` for the FIRST key the daemon runs that the file does not say - a key DELETED from the file (a `hooks-libraries` entry, a subnet's option) reads as
    "the file says nothing" and the next `config-write` would destroy the deletion. Run only after `_walk` passed (lists are the same length then). A key Kea renames is matched by its alias."""
    if isinstance(running, dict) and isinstance(candidate, dict):
        accounted = set()
        for k, v in candidate.items():
            here = f"{path}.{k}" if path else k
            if k in running:
                accounted.add(k)
                found = _lacks(running[k], v, defaults, here, scope + (running,))
                if found is not None:
                    return found
                continue
            alias = RENAMED_KEYS.get(k, "")
            renamed = running.get(alias)
            if isinstance(renamed, list) and len(renamed) == 1:
                accounted.add(alias)
                found = _lacks(renamed[0], v, defaults, here, scope + (running,))
                if found is not None:
                    return found
        for k, v in running.items():
            if k in accounted:
                continue
            here = f"{path}.{k}" if path else k
            if _is_default(here, v, defaults, scope + (running,)):
                continue
            return (here, _MISSING, v)
        return None
    if isinstance(running, list) and isinstance(candidate, list) and len(running) == len(candidate):
        for i, (r, c) in enumerate(zip(running, candidate, strict=True)):
            found = _lacks(r, c, defaults, f"{path}[{i}]", scope)
            if found is not None:
                return found
    return None


def file_in_daemon(
    file_cfg: dict | None, live_cfg: dict | None, service: str, defaults: frozenset | None = None
) -> bool:
    """Is the FILE the daemon's configuration, in both directions? Everything the file says is carried by what the daemon runs (a file Jen authored, or an older Kea-written one, is a subset of the
    daemon's configuration with its defaults written out - fix row 7: equality never held for an authored file) AND, when `defaults` is known (Kea's own written-out key paths for the daemon's
    minor version, `defaults_for`), every key the daemon runs that is not one of those defaults is in the file: a key deleted from the file is a difference, not an agreement (Q217 AB6). Without
    `defaults` only the first direction can be asked."""
    running, said = _section(live_cfg, service), _section(file_cfg, service)
    if not _carries(running, said):
        return False
    return defaults is None or _lacks(running, said, defaults) is None


def _secret_path(path: str) -> bool:
    """Is any segment of `path` a key whose VALUE is a secret? (`hosts-databases[0].password` is on a path Jen prints.) The one definition is `secret_keys.is_secret_key` (LEAK-001)."""
    from jen.services.secret_keys import is_secret_key

    return any(is_secret_key(segment) for segment in re.split(r"[.\[\]]+", path) if segment)


def _is_container(value: object) -> bool:
    return isinstance(value, (dict, list))


def _kind(value: object) -> str:
    """What a value IS, never what it says: the shape of a container, the type of a scalar (`nothing` for a key that is absent)."""
    if value is _MISSING:
        return "nothing"
    if isinstance(value, (dict, list)):
        return _leaf(value)
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, str):
        return "a string"
    return "a null" if value is None else "a value"


def _leaf(value: object) -> str:
    if value is _MISSING:
        return "nothing"
    if isinstance(value, dict):
        return f"an object with {len(value)} keys"  # (a container is never printed: it may hold a secret the path does not name)
    if isinstance(value, list):
        return f"a list of {len(value)}"
    text = json.dumps(value, sort_keys=True, default=str)
    return text if len(text) <= 60 else text[:59] + "…"


def difference_text(
    file_cfg: dict | None, live_cfg: dict | None, service: str, defaults: frozenset | None = None
) -> str:
    """Where the file and the daemon differ, in a sentence an operator can act on: `at <path>: the file says <a>, the daemon <b>` (each leaf cut to 60 characters, and the values replaced by an
    ellipsis when any segment of the path names a secret) - or `""` when the file is the daemon's (`file_in_daemon`, both directions). The path is prefixed with the section (`Dhcp4.`)."""
    section = SERVICE_KEY.get(service, service)
    running, said = _section(live_cfg, service), _section(file_cfg, service)
    found = _walk(running, said, None, section)
    if found is None and defaults is not None:
        found = _lacks(running, said, defaults)
        if found is not None:
            found = (f"{section}.{found[0]}", found[1], found[2])
    if found is None:
        return ""
    path, mine, theirs = found
    if _secret_path(path):
        return f"at {path}: the file and the daemon differ (the values are not shown)"
    key = re.split(r"[.\[\]]+", path)[-1] if path else ""
    if key in RENAMED_KEYS and isinstance(theirs, list) and mine is not _MISSING:
        return f"at {path}: the file says one {key}, the daemon runs {len(theirs)} {RENAMED_KEYS[key]}"  # (Q218 BH5 c)
    if _is_container(mine) != _is_container(theirs):
        # (Q218 BH5 b, AC15) a difference of KIND is named at the parent, and the scalar on one side may sit where the other side keeps a secret one level below: a container prints its shape and the scalar only its type
        return f"at {path}: the file says {_kind(mine)}, the daemon {_kind(theirs)}"
    return f"at {path}: the file says {_leaf(mine)}, the daemon {_leaf(theirs)}"


# ── Kea's written-out defaults, per minor version (Q217 AB6) ─────────────────────────────────────────────────────────────
# `config-get` writes Kea's defaults out, so "the daemon runs a key the file does not say" is a deletion only when that key is NOT one of them. The set is the daemon's own answer, never a guess:
# `tests/kea_compat/test_config_write.py` row 12 sends a rich minimal configuration, reads `config-get`, and records every key path that appeared and was not sent; the recorded file is committed
# under `jen/data/` (keys only, one per Kea minor, dhcp4) and the row FAILS when the daemon's answer differs from it, so a Kea release that adds a default is caught by the weekly run.
KEA_DEFAULTS_DIR = pathlib.Path(__file__).resolve().parent.parent / "data"
_VERSION = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")
_VECTOR_NAME = re.compile(r"kea_defaults_(\d+)\.(\d+)\.json")


def vector_path(major: int, minor: int) -> pathlib.Path:
    return KEA_DEFAULTS_DIR / f"kea_defaults_{major}.{minor}.json"


def load_vector(version: str, directory: pathlib.Path | None = None) -> tuple[frozenset | None, str]:
    """`(paths, vector_name)` for a Kea version text: the vector of its own major.minor, else the nearest LOWER minor of the same major (a newer Kea that has not been recorded yet), else
    `(None, "")` - nothing is known about its defaults and the reverse compare is not asked (Q217 AB6)."""
    m = _VERSION.search(version or "")
    if not m:
        return None, ""
    major, minor = int(m.group(1)), int(m.group(2))
    directory = directory or KEA_DEFAULTS_DIR
    best = None
    try:
        for entry in directory.iterdir():
            f = _VECTOR_NAME.fullmatch(entry.name)
            if f and int(f.group(1)) == major and int(f.group(2)) <= minor:
                key = int(f.group(2))
                if best is None or key > best[0]:
                    best = (key, entry)
    except OSError:
        return None, ""
    if best is None:
        return None, ""
    try:
        data = json.loads(best[1].read_text(encoding="utf-8"))
        raw_paths, raw_populated, raw_scalars = data["paths"], data.get("populated", {}), data.get("scalars")
        if (
            not isinstance(raw_paths, list)
            or not all(isinstance(p, str) for p in raw_paths)
            or not isinstance(raw_populated, dict)
            or not all(isinstance(v, list) for v in raw_populated.values())
            or (
                raw_scalars is not None
                and not (
                    isinstance(raw_scalars, dict)
                    and all(isinstance(v, (str, int, float, bool)) or v is None for v in raw_scalars.values())
                )
            )
        ):
            raise ValueError(
                "the vector's shape is not `paths: [str]`, `populated: {str: list}`, `scalars: {str: scalar}`"
            )  # (Q218 BH5 d, AC23; D1)
        paths = DefaultsSet(raw_paths)
        paths.populated = {str(k): v for k, v in raw_populated.items()}
        paths.scalars = None if raw_scalars is None else {str(k): v for k, v in raw_scalars.items()}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        logger.warning("kea_api_config: the defaults vector %s cannot be read", best[1].name)
        return None, ""  # a vector that cannot be read asks nothing: the first direction still decides
    return paths, f"{major}.{best[0]}"


def daemon_version(server: dict, service: str = "dhcp4") -> str:
    """The daemon's own version text from `version-get` (`3.0.1`), or `""` when it did not answer."""
    reply = _cmd(server, service, "version-get")
    if not _ok(reply):
        return ""
    args = reply.get("arguments") if isinstance(reply.get("arguments"), dict) else {}
    m = _VERSION.search(str(args.get("extended") or reply.get("text") or ""))
    return m.group(0) if m else ""


def defaults_for(server: dict, service: str = "dhcp4") -> tuple[frozenset | None, dict]:
    """`(paths, facts)` for the daemon on `server`: its defaults vector (dhcp4 only; recorded per minor) and `{"version", "vector", "exact"}`. `paths` is None when the version is unknown or no vector
    covers it, and the facts say which (the card reads them)."""
    facts = {"version": "", "vector": "", "exact": False}
    if service != "dhcp4":
        return None, facts
    version = daemon_version(server, service)
    facts["version"] = version
    paths, name = load_vector(version)
    facts["vector"] = name
    m = _VERSION.search(version)
    facts["exact"] = bool(paths is not None and m and name == f"{m.group(1)}.{m.group(2)}")
    return paths, facts


def compare(server: dict, service: str, file_cfg: dict | None, live_cfg: dict | None) -> tuple[bool, str]:
    """`(same, where)` - the first place a file and a daemon differ, as a sentence, and NOTHING ELSE (Q219): since beta.5 this model of Kea's written-out defaults decides no write. `file_proof` asks the host
    and the daemon themselves (when was the file written, when did the daemon last load a configuration, what did Jen last render, what did the Plan prove); this walk only names a path for the sentence,
    best effort, and `file_proof` is its one caller (`TestTheModuleIsTheOneSender`). `where` is "" when the walk finds no difference."""
    defaults, _facts = defaults_for(server, service)
    where = difference_text(file_cfg, live_cfg, service, defaults=defaults)
    return where == "", where


def _canonical(cfg: dict | None, service: str) -> str:
    """The service's own section in the stored canonical form (key order and Kea's formatting do not matter; the `hash` beside it is never part of it)."""
    return _rev.canonical({SERVICE_KEY[service]: _section(cfg, service)})


def _body(cfg: dict, service: str) -> dict:
    """What `config-set` / `config-test` take: the service's section only."""
    key = SERVICE_KEY[service]
    return {key: cfg[key]}


def _split(reply: dict, service: str) -> tuple[dict | None, str | None]:
    """(cfg, digest) of a `config-get` reply that Kea answered with result 0 - the service's own key REQUIRED and the digest stripped out of the cfg - or (None, None)."""
    key = SERVICE_KEY[service]
    args = reply.get("arguments") if isinstance(reply.get("arguments"), dict) else {}
    if not _ok(reply) or key not in args:
        return None, None
    return {k: v for k, v in args.items() if k != "hash"}, _digest(reply)


def _get(server: dict, service: str, timeout=None) -> tuple[dict | None, str | None, str]:
    """`config-get`: (cfg, digest, "") or (None, None, <why>). A reply without a digest is a FAILED read - never `config-hash-get` as a substitute (the two are not the same instant)."""
    if service not in SERVICE_KEY:
        return None, None, f"{service} is not configured over the API"
    reply = _cmd(server, service, "config-get", timeout=timeout)
    if not _answered(reply):
        return None, None, _text(reply) or f"{_name(server)} did not answer"
    if reply.get("result") != 0:
        return None, None, _text(reply) or f"{_name(server)} refused config-get"
    cfg, digest = _split(reply, service)
    if cfg is None:
        return None, None, f"{_name(server)} answered config-get without a {SERVICE_KEY[service]} section (nokey)"
    if not digest:
        return None, None, f"{_name(server)} answered config-get without a digest"
    return cfg, digest, ""


def hash(server: dict, service: str = "dhcp4", timeout=None) -> str | None:
    """`config-hash-get`: the daemon's current digest, or None when it did not answer one."""
    if service not in SERVICE_KEY:
        return None
    reply = _cmd(server, service, "config-hash-get", timeout=timeout)
    return _digest(reply) if _ok(reply) else None


def _capture(server: dict, service: str, cfg: dict, digest: str) -> None:
    """The file path's own capture rule, for `kea` rows (Q212, BB1 e): no `kea` row yet -> a baseline; a digest unlike the latest `kea` row's -> `external` (a hand `config-set` on the daemon
    shows in Config history the way a hand edit of the file does). A `raw` row is never compared with a `kea` digest, and a PENDING row is not a baseline."""
    sid = server.get("id")
    if sid is None:
        return
    try:
        if _rev.pending(sid, service) is not None:
            return  # a pending change is not a baseline: the daemon runs its candidate (`latest_of_kind` no longer returns a pending or a damaged row, Q218 BH2 e)
        last = _rev.latest_of_kind(sid, service, "kea")
        if last is None:
            _rev.record(
                sid,
                service,
                cfg,
                digest,
                "initial baseline - first config Jen read from the daemon",
                hash_kind="kea",
                source="baseline",
            )
        elif last.get("sha256") and last["sha256"] != digest:
            _rev.record(sid, service, cfg, digest, "changed outside Jen", hash_kind="kea", source="external")
    except Exception as e:  # a failed history write never fails the read it rode on
        logger.warning("kea_api_config: capture failed for server %s/%s: %s", sid, service, type(e).__name__)


def read(
    server: dict,
    service: str,
    *,
    errors: list | None = None,
    timeout: int | None = None,
    capture: bool = True,
    helper_only: bool = False,  # accepted so the dispatch in `kea_host.read_config` is kwarg-compatible; an API read has no helper
    notes: list | None = None,
) -> tuple[dict | None, str | None]:
    """`(cfg, digest)` from the daemon's own `config-get`, or `(None, None)` with a sentence appended to `errors`. The digest comes from the reply, beside the service's section, and is
    STRIPPED from `cfg` before anything reads it.

    A pending change of Jen's own (BB9 c: Jen died between `config-set` and the verify) is CLASSIFIED by content on this read and the line it earns goes to `notes`; a read never settles it (Q216,
    AA19: a read that reconciles is a write path - it sent `config-write` and changed the store from a GET, outside the change lock). Settlement is `settle_pending`, under the lock."""
    cfg, digest, why = _get(server, service, timeout)
    if cfg is None:
        if errors is not None:
            errors.append(why)
        return None, None
    try:
        _classify_pending(server, service, cfg, digest, notes)
    except _rev.RevisionStoreUnreadable:
        if notes is not None:
            notes.append(unreadable_sentence(server))
    if capture:
        _capture(server, service, cfg, digest)
    return cfg, digest


PROOF_HOWS = ("rendering", "planned", "loaded", "no-file", "unreadable", "none")
NO_PLANNED_SENTENCE = "the file on {host} cannot be proved against the file this change was planned over; restart Kea there to load the file as it stands, then Settle it now"


def _utc(ts: int) -> str:
    """A time as the proof prints it (Q219, Decided 1): UTC, to the second."""
    from datetime import datetime, timezone

    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _proof(
    ok: bool,
    how: str,
    *,
    sha256: str | None = None,
    mtime: int | None = None,
    loaded_at: int | None = None,
    started_at: int | None = None,
    where: str = "",
    why: str = "",
) -> dict:
    return {
        "ok": ok,
        "how": how,
        "sha256": sha256,
        "mtime": mtime,
        "loaded_at": loaded_at,
        "started_at": started_at,
        "where": where,
        "why": why,
    }


def _int_or_none(value) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def file_proof(server: dict, service: str = "dhcp4", *, planned_sha: str | None = None, capture: bool = True) -> dict:
    """THE one definition of "the file on the host is one the daemon has loaded, or Jen rendered, or the Plan proved" (Q219, CFG-004): the question every `config-write` asks before it replaces a file.
    It reads the file ONCE (`kea_host.read_config_proof`: the content, its sha256 and - from a helper at build 22 - the file's mtime and the host's `now` and the daemon's own `status-get`, all from the
    host's one clock), then, in this order, the first that holds decides:
      (R) `rendering` - the file's sha256 is the newest `rendering` row's: the file Kea itself wrote after a change over the API;
      (P) `planned`   - `planned_sha` is the file's sha256: byte for byte the file the Plan proved before any `config-set`;
      (L) `loaded`    - the daemon last loaded a configuration at or after the file was written (`mtime <= now - reload`), the file is in the daemon one way (a reload that did not take is not a
                        load), and no `pending` change is on record (then the daemon's last commit is Jen's own `config-set` and the time proves nothing).
    A file that cannot be read is `unreadable` (never overwritten, CFG-005); a server with no SSH host has no file (`no-file`, ok). None of (R), (P), (L) is `none`, with the TIMES in `why` - and a path
    in `where`, best effort, from the one walk that names it (`compare`): a model of Kea's defaults never decides. `capture=False` is for a caller that only reads."""
    if not _has_ssh(server) or service not in SERVICE_KEY:
        return _proof(True, "no-file")
    host = server.get("name") or server.get("ssh_host") or "the host"
    file_cfg, sha, times = _host.read_config_proof(server, service, capture=capture)
    if file_cfg is None:
        return _proof(
            False,
            "unreadable",
            why=f"the file on {host} could not be read, so a write cannot be proved against it (check the SSH connection)",
        )
    sid = server.get("id")
    mtime = _int_or_none((times or {}).get("mtime"))
    now = _int_or_none((times or {}).get("now"))
    daemon = (times or {}).get("daemon") if isinstance((times or {}).get("daemon"), dict) else None
    reload_s = _int_or_none((daemon or {}).get("reload"))
    uptime_s = _int_or_none((daemon or {}).get("uptime"))
    loaded_at = now - reload_s if now is not None and reload_s is not None else None
    started_at = now - uptime_s if now is not None and uptime_s is not None else None
    facts = {"sha256": sha, "mtime": mtime, "loaded_at": loaded_at, "started_at": started_at}

    rendering = _rev.latest_rendering(sid, service) if sid is not None else None  # (R)
    if rendering and sha and rendering.get("sha256") == sha:
        return _proof(True, "rendering", **facts)
    if planned_sha and sha and planned_sha == sha:  # (P)
        return _proof(True, "planned", **facts)

    pending_row, pending_unreadable = None, False  # (L) - the record is read ONCE
    if sid is not None:
        try:
            pending_row = _rev.pending(sid, service)
        except _rev.RevisionStoreUnreadable:
            pending_unreadable = True
    live = None
    if (
        mtime is not None
        and loaded_at is not None
        and mtime <= loaded_at
        and pending_row is None
        and not pending_unreadable
    ):
        live, _digest, _why = _get(server, service)
        if live is not None and file_in_daemon(file_cfg, live, service):
            return _proof(True, "loaded", **facts)

    where = ""
    try:
        if live is None:
            live, _digest, _why = _get(server, service)
        if live is not None:
            where = compare(server, service, file_cfg, live)[1]
    except (
        Exception
    ) as e:  # naming a path never decides anything: the proof is already `none` (S10: it fails closed here)
        logger.warning("kea_api_config: file_proof could not name a path for %s: %s", sid, type(e).__name__)
    at = f" ({where})" if where else ""
    way_out = "restart Kea there (or `config-reload`) to load it, or discard it from the server's Write mode card"
    written = (
        f"the file on {host} was written at {_utc(mtime)}"
        if mtime is not None
        else f"the file on {host} is not one Jen rendered or proved"
    )
    if times is None:
        why = f"{written}; the daemon's own load time needs helper build 22 on {host} - press Update helper{at}"
    elif daemon is None or loaded_at is None:
        why = f"{written}; the daemon's own load time could not be read on {host} ({(times or {}).get('socket_note') or 'no answer'}){at}"
    elif planned_sha:
        why = (
            f"the file on {host} is not the file this change was planned over (written at {_utc(mtime)}, the daemon last loaded its configuration at {_utc(loaded_at)}); "
            f"the daemon has not loaded that edit - {way_out}"  # (no path: against a daemon that runs the change, the first difference is the change itself)
        )
    elif pending_row is not None or pending_unreadable:
        why = (
            f"{written} and the daemon last loaded its configuration at {_utc(loaded_at)}; an earlier change on {host} is unresolved, so the daemon's load time proves nothing - "
            f"settle it first (Settle it now on the server's Write mode card)"
        )
    elif mtime is not None and mtime > loaded_at:
        why = f"{written} and the daemon last loaded its configuration at {_utc(loaded_at)}; the daemon has not loaded that edit{at} - {way_out}"
    else:
        why = f"{written}, before the daemon's last load at {_utc(loaded_at)}, but the daemon does not run it{at} - {way_out}"
    return _proof(False, "none", where=where, why=why, **facts)


def _ask_the_file(
    server: dict, service: str, *, planned_sha: str | None = None, discard: bool = False, capture: bool = True
) -> tuple[dict | None, dict]:
    """CFG-005 - the question every `config-write` asks first, and the whole of it: `file_proof`. `(refusal, proof)`: `refusal` is `None` when the write may go, else `{"ok": False, "code": "unloaded-edit", ...}`
    whose `detail` is the proof's `why`; `proof` is what was asked (a caller with no Plan keeps its `sha256`). A server with no SSH host has no file to ask. `discard` is the one way past a `none`, and a caller passes it only when `discard_file_edit` was given on THIS act; a
    file that cannot be read is never overwritten, with or without it. The read is a CAPTURING one by default: an edit is a row in Config history before it can be lost."""
    proof = file_proof(server, service, planned_sha=planned_sha, capture=capture)
    if proof["ok"] or (discard and proof["how"] == "none"):
        return None, proof
    return _result(False, "unloaded-edit", proof["why"]), proof


def record_rendering_after_write(
    server: dict, service: str, summary: str, *, cfg: dict | None = None, raw: str | None = None
) -> bool:
    """The file Kea itself just rendered is a `raw` row of source `rendering` in Config history - ALWAYS that source (Q219, Decided 14): it is what `file_proof`'s (R) reads, and a file Jen wrote over
    SSH whose restart failed is never one. Without it the NEXT capturing read finds a file the store has not seen and records Jen's own write as `external`. `cfg` and `raw` are the file as the caller
    already read it (apply's step 8: the bytes that were verified); with none the file is read now. A server with no SSH host, a read that fails and a helper that answers no raw hash record nothing."""
    sid = server.get("id")
    if sid is None or not _has_ssh(server):
        return False
    if cfg is None or not raw:
        cfg, raw = _host.read_config_versioned(server, service, capture=False)
    if cfg is None or not raw or str(raw).startswith(_host._CANONICAL_SENTINEL_PREFIX):
        return False
    return _rev.record(sid, service, cfg, raw, summary, hash_kind="raw", source="rendering") is not None


def _send_write(server: dict, service: str, attempts: int) -> tuple[dict | None, bool, bool]:
    """THE sender of `config-write` (CFG-005; the only `_cmd(..., "config-write")` in the tree, held by `TestTheModuleIsTheOneSender`): re-sent when no answer came, up to `attempts` times (it is
    idempotent: it writes what runs). `(last reply, answered 0, an earlier attempt got NO answer - it may have written)`. Nothing calls this without having asked the file first."""
    reply, silent = None, False
    for _ in range(attempts):
        reply = _cmd(server, service, "config-write")
        if _ok(reply) or _answered(reply):
            break
        silent = True
    return reply, _ok(reply or {}), silent and _answered(reply or {})


def write_file(server: dict, service: str = "dhcp4", *, planned_sha: str | None = None, discard: bool = False) -> dict:
    """`config-write` of what runs, no filename - the switch's and the settlement's own call, and the ONE place that sends it outside `apply`'s step (6) (CFG-005, Q218 BH1, Q219). The file must be one
    `file_proof` accepts: Jen's own rendering, the file the Plan proved (`planned_sha`, the settlement's - the row's `file_sha256`), or one the daemon has loaded; `discard` writes over a `none` the
    capturing read has just put in Config history, and over nothing else. `ok`, `write-failed` (Kea's own words), `noanswer`, or `unloaded-edit` with NOTHING sent."""
    if service not in SERVICE_KEY:
        return _result(False, "noservice", f"{service} is not configured over the API")
    refusal, _proof = _ask_the_file(server, service, planned_sha=planned_sha, discard=discard)
    if refusal is not None:
        return refusal
    reply, ok, _maybe = _send_write(server, service, 1)
    if ok:
        return _result(True, "ok")
    if not _answered(reply):
        return _result(False, "noanswer", _text(reply))
    return _result(False, "write-failed", _text(reply) or "config-write was refused")


def test(server: dict, service: str, cfg: dict) -> dict:
    """`config-test` of a candidate (advisory: Kea's own validation before anything is set). `ok`, `testerror` (Kea's words) or `noanswer`."""
    if service not in SERVICE_KEY:
        return _result(False, "noservice", f"{service} is not configured over the API")
    reply = _cmd(server, service, "config-test", _body(cfg, service))
    if _ok(reply):
        return _result(True, "ok")
    if not _answered(reply):
        return _result(False, "noanswer", _text(reply))
    return _result(False, "testerror", _text(reply) or "config-test refused the configuration")


# ── the API-only guard (step 2) ───────────────────────────────────────────────────────────────────────────────────────


GUARD_SENTENCE = (
    "a change to the control socket, a hook library or its parameters, or TLS material goes through the file path"
)


def _hooks(sec: dict) -> list:
    """The `hooks-libraries` list AS VALUES - each entry's `library` and its `parameters`, in order (Q216 AA4): an HA peer's address or a lease_cmds setting is a hook's `parameters`, and a restore
    of a revision from before such a change would otherwise be sent over the API with the paths and the order unchanged."""
    return list(sec.get("hooks-libraries") or [])


def _api_only_guard(service: str, running: dict | None, candidate: dict) -> str:
    """The candidate's `control-sockets`, `hooks-libraries` (each entry as a value: the library AND its parameters, in order) and every TLS path Jen's own certificate files appear at must equal the running configuration's: a change to
    the socket the command arrives on is never sent over that socket, and a hook library or a certificate is host material the file path checks (`tlsmissing`) and this path cannot. This is what
    makes the direct-socket callers, the restore and the import safe over the API without each writer knowing the rule."""
    from jen.services import kea_authoring as _auth
    from jen.services import kea_tls as _tls

    before, after = _section(running, service), _section(candidate, service)
    for key in ("control-sockets", "control-socket"):
        if (before.get(key) or None) != (after.get(key) or None):
            return GUARD_SENTENCE
    if _hooks(before) != _hooks(after):
        return GUARD_SENTENCE
    tls = _tls.remote_tls_paths(service)
    if sorted(_auth.referenced_tls_paths(running or {}, tls)) != sorted(_auth.referenced_tls_paths(candidate, tls)):
        return GUARD_SENTENCE
    return ""


# ── the pending record (step 3) and its reconciliation ────────────────────────────────────────────────────────────────────


PENDING_SETTLE_SECONDS = 120  # an apply finishes inside its commands' waits; a pending row younger than this belongs to one in flight and no reader may settle it (fix row 3)


def _row_age_seconds(row: dict) -> float:
    """Seconds since a revision row was written (UTC); 0-age cannot be told apart from "unknown", so an unreadable stamp counts as old."""
    from datetime import datetime, timezone

    stamp = row.get("created_at")
    try:
        when = stamp if isinstance(stamp, datetime) else datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return PENDING_SETTLE_SECONDS + 1
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - when).total_seconds()


def unreadable_sentence(server: dict) -> str:
    return f"the record of an earlier change on {_name(server)} cannot be read; nothing is sent until it can"


def record_unreadable(server: dict, service: str = "dhcp4") -> str:
    """A refusal sentence when the record of pending changes cannot be READ, else "" (Q216, AA11): `None` from the store means nothing is pending, and a store that could not be asked is not that."""
    sid = server.get("id")
    if sid is None or service not in SERVICE_KEY:
        return ""
    try:
        _rev.pending(sid, service)
    except _rev.RevisionStoreUnreadable:
        return unreadable_sentence(server)
    return ""


DAMAGED_SENTENCE = "the record of an earlier change on {name} is damaged; Settle it now compares digests and removes it"


def _pending_candidate(row: dict, service: str = "dhcp4") -> dict | None:
    """THE one place a pending row's body is parsed (Q217 AB10-AB12): the candidate configuration it holds, or `None` when the row is DAMAGED - a body that is not JSON, not an object, or whose
    service section is empty or missing. A damaged row is never "live" and never "nothing pending": it blocks, and `settle_pending` compares digests and removes it."""
    try:
        parsed = json.loads(row["config"])
    except (TypeError, ValueError, KeyError):
        return None
    section = _section(parsed, service) if isinstance(parsed, dict) else None
    if not isinstance(section, dict) or not section:
        return None  # (Q218 BH2 f) a service section that is a list, a string, a number or a boolean is no configuration: damaged, never "unresolved" for ever
    return parsed


def _file_waits(server: dict, service: str, row: dict) -> str:
    """READ ONLY (no capture, no write): what a settlement of this LIVE pending row would wait on - `""` when its `config-write` would overwrite nothing the proof does not accept, else the sentence the
    settlement itself would print (the proof's, or the row's having no planned file: a row an earlier release wrote). A server with no SSH host has no file."""
    if not _has_ssh(server):
        return ""
    if not row.get("file_sha256"):
        return NO_PLANNED_SENTENCE.format(host=server.get("name") or server.get("ssh_host") or "the host")
    refusal, _proof = _ask_the_file(server, service, planned_sha=row["file_sha256"], capture=False)
    return "" if refusal is None else str(refusal.get("detail") or "")


def pending_note(server: dict, service: str = "dhcp4") -> str:
    """The line the read says about a pending change (`_classify_pending`), for the card to print above *Settle it now* (Q218 BH1 e): `""` when nothing is pending, the daemon did not answer or the record
    cannot be read. A read: nothing is sent and no row changes."""
    cfg, digest, _why = _get(server, service)
    if cfg is None:
        return ""
    notes: list[str] = []
    try:
        _classify_pending(server, service, cfg, digest, notes)
    except _rev.RevisionStoreUnreadable:
        return ""
    return notes[0] if notes else ""


def _classify_pending(server: dict, service: str, cfg: dict, digest: str, notes: list | None) -> None:
    """What a pending row would be settled as, said in a line - and nothing else: no command is sent, no row changes (a read is not a write path, Q216 AA19). Raises `RevisionStoreUnreadable`."""
    sid = server.get("id")
    if sid is None or service not in SERVICE_KEY or notes is None:
        return
    row = _rev.pending(sid, service)
    if row is None:
        return
    candidate = _pending_candidate(row, service)
    if candidate is None:
        notes.append(DAMAGED_SENTENCE.format(name=_name(server)))
        return
    at = str(row.get("created_at") or "an earlier time")
    if _row_age_seconds(row) < PENDING_SETTLE_SECONDS:
        notes.append(f"a change of {at} is in progress; it is not settled until it has had {PENDING_SETTLE_SECONDS} s")
    elif row.get("sha256") and digest == row["sha256"]:
        notes.append(
            f"a change of {at} never reached the daemon; its record is removed at the next change or when you settle it"
        )
    elif _carries(_section(cfg, service), _section(candidate, service)):
        waits = _file_waits(
            server, service, row
        )  # (Q218 BH1 e, Q219) the settlement's own question, asked as a read: the card says what it waits on
        notes.append(
            f"a change of {at} is live and its file write waits: {waits}"
            if waits
            else f"a change of {at} is live and its file write is not proved yet; the next change finishes it, or you can settle it from the server's card"
        )
    else:
        notes.append(
            f"a change of {at} is unresolved: the daemon runs {digest}, which is neither the state before it ({row.get('sha256') or 'unknown'}) nor the change; resolve it from Config history"
        )


def settle_pending(server: dict, service: str = "dhcp4") -> tuple[list[str], bool]:
    """Settle a pending row by content NOW - the two places that may (Q216 AA19), both under `kea_changeset.change_lock`: this, called by the card's "settle" route, and `pending_block`, asked by the
    Plan of a change set and by `apply`. `(lines, settled)`: the lines say what happened, `settled` is True only when a row was finished or removed (Q217 AB13)."""
    notes: list[str] = []
    cfg, digest, why = _get(server, service)
    if cfg is None:
        return [f"{_name(server)} did not answer ({why}); nothing was settled"], False
    try:
        _cfg, _digest, settled = _reconcile_pending(server, service, cfg, digest, notes)
    except _rev.RevisionStoreUnreadable:
        return [unreadable_sentence(server)], False
    return notes or ["there is no pending change to settle"], settled


def _reconcile_pending(
    server: dict, service: str, cfg: dict, digest: str, notes: list | None
) -> tuple[dict, str, bool]:
    """If Jen died between `config-set` and the verify, the next change finds a `pending` row and settles it by CONTENT (Jen cannot compute Kea's digest, so a digest alone cannot say
    whose configuration runs): equal to the candidate -> that change is live, `config-write` is sent (idempotent) and verified, the row becomes `jen`; its digest equal to the row's BEFORE
    digest -> nothing landed, the row is deleted; neither -> the row stays and the line names both digests; no answer -> the row stays. A DAMAGED row (`_pending_candidate`) is removed when the
    daemon's digest is the row's BEFORE digest and otherwise marked `damaged` with the daemon's digest named - never "live". Returns `(cfg, digest, settled)`: the configuration the daemon runs NOW
    and whether a row was finished or removed. A WRITER: never from a read - the caller holds the change lock. Raises `RevisionStoreUnreadable`."""
    sid = server.get("id")
    if sid is None or service not in SERVICE_KEY:
        return cfg, digest, False
    row = _rev.pending(sid, service)
    if row is None:
        return cfg, digest, False
    at = str(row.get("created_at") or "an earlier time")
    candidate = _pending_candidate(row, service)
    if candidate is None:
        if row.get("sha256") and digest == row["sha256"]:
            done = _rev.discard(row["id"])
            if notes is not None:
                notes.append(
                    f"a change of {at} never reached the daemon (its record was damaged); the record was removed"
                    if done
                    else f"a change of {at} never reached the daemon (its record was damaged), and the record could not be removed - try again"
                )
        else:
            done = _rev.mark_damaged(row["id"])
            if notes is not None:
                notes.append(
                    f"the record of a change of {at} is damaged and the daemon runs {digest}; restore from Config history if that is not what you expect"
                    if done
                    else f"the record of a change of {at} is damaged and could not be marked - try again (the daemon runs {digest})"
                )
        return cfg, digest, bool(done)
    if _row_age_seconds(row) < PENDING_SETTLE_SECONDS:
        if notes is not None:
            notes.append(
                f"a change of {at} is in progress; it is not settled until it has had {PENDING_SETTLE_SECONDS} s"
            )
        return cfg, digest, False
    if row.get("sha256") and digest == row["sha256"]:
        done = _rev.discard(row["id"])
        if notes is not None:
            notes.append(
                f"a change of {at} never reached the daemon; its record was removed"
                if done
                else f"a change of {at} never reached the daemon, and its record could not be removed - try again"
            )
        return cfg, digest, bool(done)
    if _carries(_section(cfg, service), _section(candidate, service)):
        # (second pass, row 5) the settlement's `config-write` is a write of this server's file: it asks what every other writer asks first - the investigation marker and the host's restore window
        from jen.services import investigation_logging as _inv

        waits = _host.guard_kea_write(server, cfg, service) or (
            _inv.restore_window(server) if service == "dhcp4" else ""
        )
        if waits:
            if notes is not None:
                notes.append(f"a change of {at} is live and its file write waits: {waits}")
            return cfg, digest, False
        # (Q218 BH1 b, Q219) the file is asked BEFORE it is replaced, and the question is the proof: the file is byte for byte the one the Plan proved (the row's `file_sha256`), or Jen's own
        # rendering. A row that carries none (an earlier release wrote it) cannot be proved, and a settlement that cannot prove the file never overwrites it
        if _has_ssh(server) and not row.get("file_sha256"):
            if notes is not None:
                notes.append(
                    f"a change of {at} is live and its file write waits: "
                    + NO_PLANNED_SENTENCE.format(host=server.get("name") or server.get("ssh_host") or "the host")
                )
            return cfg, digest, False
        wrote = write_file(server, service, planned_sha=row.get("file_sha256"))
        if wrote.get("code") == "unloaded-edit":
            if notes is not None:
                notes.append(f"a change of {at} is live and its file write waits: {wrote.get('detail')}")
            return cfg, digest, False
        again, digest2, _ = _get(server, service)
        if wrote.get("ok") and again is not None and digest2:
            finished = _rev.finish(row["id"], source="jen", sha256=digest2, cfg=again)
            record_rendering_after_write(server, service, f"settled a change of {at}")  # (Q218 D8)
            if not finished:  # (Q218 BH2 a) the third store write of this function: a False is no settlement
                if notes is not None:
                    notes.append(
                        f"a change of {at} is live and its file was written, but its record could not be finished - try again (the daemon runs {digest2})"
                    )
                return again, digest2, False
            if notes is not None:
                notes.append(f"a change of {at} was finished now")
            return again, digest2, True
        if notes is not None:
            notes.append(
                f"a change of {at} is live but its file write is not proved ({wrote.get('detail') or 'no answer'}); the daemon runs {digest}"
            )
        return cfg, digest, False
    if notes is not None:
        notes.append(
            f"a change of {at} is unresolved: the daemon runs {digest}, which is neither the state before it ({row.get('sha256') or 'unknown'}) nor the change; resolve it from Config history"
        )
    return cfg, digest, False


def _stale_pending(server: dict, service: str) -> str:
    """For a restore (Q219): `""` when no pending record is on file, `"stale"` when one is and the daemon does NOT carry its change (it never reached the daemon, the body is damaged, or the daemon runs neither
    state) - the record is removed, so the restore's own can be written - `"live"` when the daemon carries it (or it is younger than a change takes), and `"unknown"` when the daemon could not be asked."""
    sid = server.get("id")
    if sid is None:
        return ""
    row = _rev.pending(sid, service)
    if row is None:
        return ""
    candidate = _pending_candidate(row, service)
    if candidate is not None:
        cfg, digest, _why = _get(server, service)
        if cfg is None:
            return "unknown"
        if _row_age_seconds(row) < PENDING_SETTLE_SECONDS:
            return "live"
        if not (row.get("sha256") and digest == row["sha256"]) and _carries(
            _section(cfg, service), _section(candidate, service)
        ):
            return "live"
    _rev.discard_pending(sid, service)
    return "stale"


def pending_block(server: dict, service: str) -> str:
    """A sentence when a pending change is on record and the daemon is in neither of its states (read, reconcile, and nothing settled it); else "". `apply` refuses on it (a restore, which is
    the operator's way out, passes `source="restore"` and is not stopped). A DAMAGED row blocks with the same sentence the read gives; only `settle_pending` removes it."""
    sid = server.get("id")
    if sid is None:
        return ""
    try:
        row = _rev.pending(sid, service)
        if row is None:
            return ""
        if _pending_candidate(row, service) is None:
            return DAMAGED_SENTENCE.format(name=_name(server))
        notes: list = []
        cfg, digest, why = _get(server, service)
        if cfg is None:
            return f"an earlier change on {_name(server)} is unresolved and the daemon did not answer ({why})"
        _reconcile_pending(server, service, cfg, digest, notes)
        if _rev.pending(sid, service) is None:
            return ""
    except _rev.RevisionStoreUnreadable:
        return unreadable_sentence(
            server
        )  # (Q216 AA11) a store that cannot be asked is a refusal, never "nothing is pending"
    return notes[-1] if notes else f"an earlier change on {_name(server)} is unresolved; resolve it from Config history"


# ── apply: the nine steps, in this order and no other ─────────────────────────────────────────────────────────────────────


def _unproved(code: str, detail: str, **extra) -> dict:
    return _result(False, code, detail, needs_hands=True, **extra)


def _undo(server: dict, service: str, before_cfg: dict | None, before_hash: str) -> bool:
    """Put the previous configuration back over the API and PROVE it: the daemon's own `config-get` afterward equals it (or carries the digest it had)."""
    if before_cfg is None:
        return False
    reply = _cmd(server, service, "config-set", _body(before_cfg, service))
    if not _ok(reply) and _answered(
        reply
    ):  # a refusal; a transport fault is ASKED about below, never assumed (the forward set's rule)
        return False
    got, digest, _why = _get(server, service)
    return got is not None and (digest == before_hash or _canonical(got, service) == _canonical(before_cfg, service))


def _after_a_set_failure(server: dict, service: str, expect_hash: str, reply: dict) -> dict:
    """`config-set` was refused by Kea: ISC's rule is that the old configuration keeps serving, and Jen asks the daemon rather than assume it."""
    now = hash(server, service)
    if now == expect_hash:
        return _result(False, "set-failed", _text(reply) or "config-set was refused")
    if now is None:
        return _unproved(
            "noanswer",
            f"{_name(server)} refused the change and then did not answer; the daemon may have stopped serving - a restart reloads its file, which this change never touched",
        )
    return _unproved(
        "unverified",
        f"{_name(server)} refused the change but now runs a configuration with digest {now}, not the {expect_hash} it had; "
        "the daemon may have stopped serving - a restart reloads its file, which this change never touched",
        before_hash=expect_hash,
        after_hash=now,
    )


def _after_a_set_without_an_answer(
    server: dict, service: str, cfg: dict, before_cfg: dict | None, expect_hash: str
) -> tuple[str | None, dict | None]:
    """`config-set` got no answer: only the daemon's own `config-get` can say whose configuration runs, compared CANONICALLY with the candidate. (h1, None) to continue; (None, result) to stop."""
    got, digest, why = _get(server, service)
    if got is None:
        return None, _unproved(
            "noanswer",
            f"{_name(server)} did not answer the change or the question that followed it ({why}); the daemon may or may not carry it",
        )
    if before_cfg is not None and _canonical(got, service) == _canonical(before_cfg, service):
        return None, _result(
            False, "set-failed", "config-set got no answer and the daemon still runs the previous configuration"
        )
    if _carries(_section(got, service), _section(cfg, service)):
        return digest, None
    return None, _unproved(
        "unverified",
        f"{_name(server)} did not answer config-set and now runs a configuration that is neither the change nor the one before it (digest {digest}, before {expect_hash})",
        before_hash=expect_hash,
        after_hash=digest,
    )


def _write_with_retries(server: dict, service: str) -> tuple[dict | None, bool, bool]:
    """`config-write` of `apply`'s step (6), re-sent when no answer came: `_send_write` with `WRITE_ATTEMPTS`. `apply` asks the file (`_ask_the_file`) immediately before it."""
    return _send_write(server, service, WRITE_ATTEMPTS)


def _has_ssh(server: dict) -> bool:
    return bool(server.get("ssh_host"))


def apply(
    server: dict,
    service: str,
    cfg: dict,
    expect_hash: str | None,
    summary: str,
    source: str = "jen",
    *,
    before_cfg: dict | None = None,
    planned_sha: str | None = None,
) -> dict:
    """Write `cfg` to the daemon over its own API: compare, set, write, verify - the HostResult of the file path's `apply_config`. `expect_hash` is the digest read with the configuration
    this change was built from (the Plan read); `before_cfg` is that configuration (the undo's target and the API-only guard's reference; read here when a caller has none). `planned_sha` (Q219) is the
    sha256 of the FILE the Plan proved before any `config-set`: the pending row carries it, and step (6) checks the file is still that one. A caller with no Plan (a restore, an import) proves the
    file itself before anything is sent (`guard`, nothing sent, when it cannot); a rollback has none and rests on Jen's own rendering.

    The sequence, in this order and no other:
      (1) `guard_kea_write` (INV-005: the investigation marker) - a refusal is `guard`, nothing sent.
      (2) the API-only guard - a socket, a hook library or a TLS path that differs from the running configuration's is `guard`.
      (3) the pending record is written (the candidate, with the BEFORE digest and the file the Plan proved), so a reader can settle a half-applied change by content.
      (4) `config-hash-get` equals `expect_hash` or `conflict` (nothing sent); no `expect_hash` at all is `conflict` too - a compare that is not asked for is not a compare (Q216 BF3).
      (5) `config-set` -> h1. A refusal: ask the daemon; a missing answer: ask `config-get` and compare canonically.
      (6) the file is still the one the Plan proved or Jen's own rendering (`file_proof`; the daemon's last commit is Jen's own `config-set`, so a load time proves nothing here), else `unverified`
          with the record kept; then `config-write` (re-sent on a missing answer); a refusal undoes the set (`write-failed`); no answer is never `ok`.
      (7) `config-get` carries h1, or `unverified` (NOT undone: a different digest may be someone else's change).
      (8) where SSH exists the helper reads the FILE and the daemon's `config-get` must carry everything it says.
      (9) the revision recorded (the pending row, finished in place), `{"ok": True, "code": "ok", "sha256": h1}`.
    """
    if service not in SERVICE_KEY:
        return _result(False, "noservice", f"{service} is not configured over the API in this release")
    sid = server.get("id")

    refusal = _host.guard_kea_write(server, cfg, service)  # (1)
    if refusal:
        return _result(False, "guard", refusal)
    if source != "rollback":
        # (1a) BB9 d: never inside the window in which the HOST restores logging - a rollback undoes a change that stood, and is not a new write over the restore
        from jen.services import (
            investigation_logging as _inv,
        )  # lazy: that module imports the change set, which imports this one

        window = _inv.restore_window(server) if service == "dhcp4" else ""
        if window:
            return _result(False, "investigation-on", window)
    # (1b) no write without the probe's facts, the operator's consent and a daemon that is not known to refuse its file
    gated = probe_gate(server, source)
    if gated:
        return _result(False, "guard", gated)

    if before_cfg is None:
        before_cfg, before_digest, why = _get(server, service)
        if before_cfg is None:
            return _result(False, "noanswer", f"the running configuration of {_name(server)} could not be read ({why})")
        expect_hash = expect_hash or before_digest
    if (
        not expect_hash
    ):  # (Q216 BF3) the digest compare is the only compare the API has: a call that brings none sends nothing
        return _result(False, "conflict", "no digest to compare against - read the daemon first")
    guarded = _api_only_guard(service, before_cfg, cfg)  # (2)
    if guarded:
        return _result(False, "guard", guarded)
    unreadable = record_unreadable(server, service)
    if unreadable:
        return _result(
            False, "unreadable", unreadable
        )  # (Q217 AB9) nothing was sent and nobody's hands are needed: the record has to be readable again
    if source == "restore":
        # (Q219 BI2 b, AD5) a restore never plants a second pending row (the store refuses one): over a LIVE record - the daemon runs a change whose file write is owed - it asks for the settlement first;
        # over a stale one (the daemon runs neither state, the change never reached it, the body is damaged) the restore IS the way out, as it has always been, and supersedes it
        stale = _stale_pending(server, service)
        if stale == "live":
            return _unproved(
                "unverified",
                f"settle the unresolved change on {_name(server)} first - Settle it now on its Write mode card",
            )
        if stale == "unknown":
            return _unproved(
                "unverified",
                f"an earlier change on {_name(server)} is unresolved and the daemon did not answer, so a restore cannot be placed over it",
            )
    else:
        blocked = pending_block(server, service)
        if blocked:
            return _unproved("unverified", blocked)
    if planned_sha is None and source != "rollback" and _has_ssh(server):
        # (Q219) a caller with no Plan (a restore, an import) proves the file itself, BEFORE anything is sent: the proof is true now, while no pending row makes the daemon's last commit Jen's own
        refusal, proof = _ask_the_file(server, service)
        if refusal is not None:
            return _result(False, "guard", refusal["detail"])
        planned_sha = proof["sha256"]

    pending_id = None
    if sid is not None:  # (3)
        try:
            pending_id = _rev.record(
                sid,
                service,
                cfg,
                expect_hash or "",
                summary,
                hash_kind="kea",
                source=PENDING,
                file_sha256=planned_sha if _has_ssh(server) else None,
            )
        except Exception as e:  # (Q219 BI2 c, AD9) a store that RAISES is the same refusal as one that answers None
            logger.warning("kea_api_config: the pending record could not be written: %s", type(e).__name__)
            pending_id = None
        if (
            pending_id is None
        ):  # (Q218 BH2 b) a change nobody can find the record of is never sent: the daemon would run it with nothing on file to settle it by
            return _result(
                False,
                "unreadable",
                "the record of this change could not be written to Config history; nothing was sent - the database refused the row, or an earlier change on this server is still on record",
            )

    def _drop_pending():
        if pending_id is not None:
            _rev.discard(pending_id)

    now = hash(server, service)  # (4)
    if now is None:
        _drop_pending()
        return _result(False, "noanswer", f"{_name(server)} did not answer the digest question; nothing was sent")
    if expect_hash and now != expect_hash:
        _drop_pending()
        return _result(
            False,
            "conflict",
            f"the daemon on {_name(server)} runs digest {now}, not the {expect_hash} this change was built from",
            before_hash=expect_hash,
            after_hash=now,
        )

    reply = _cmd(server, service, "config-set", _body(cfg, service))  # (5)
    if _ok(reply):
        h1 = _digest(reply) or hash(server, service)
        if not h1:
            return _unproved(
                "unverified", f"{_name(server)} accepted the change but returned no digest; it may be live"
            )
    elif _answered(reply):
        outcome = _after_a_set_failure(server, service, expect_hash or now, reply)
        if not outcome.get("needs_hands"):
            _drop_pending()
        return outcome
    else:
        h1, stop = _after_a_set_without_an_answer(server, service, cfg, before_cfg, expect_hash or now)
        if stop is not None:
            if not stop.get("needs_hands"):
                _drop_pending()
            return stop

    if _has_ssh(
        server
    ):  # (6) the file `config-write` is about to replace is still the one the Plan proved (or Jen's own rendering): else an edit the daemon never loaded
        refusal, _proof = _ask_the_file(server, service, planned_sha=planned_sha)
        if refusal is not None:
            return _unproved(  # the daemon took the change and the file waits: nothing is undone, and the pending row STAYS - `_reconcile_pending` settles it by content
                "unverified",
                f"live in the daemon on {_name(server)}, not yet in its file: {refusal.get('detail')}; the record of the change stays",
                before_hash=expect_hash or now,
                after_hash=h1,
            )
    wrote, wrote_ok, maybe_written = _write_with_retries(server, service)  # (6)
    unwritten = ""
    if not wrote_ok:
        if wrote is not None and _answered(wrote):
            remember_refusal(
                server, _text(wrote)
            )  # BB9 a: a fleet does not undo the same change on every edit; cleared only by evidence
            proved_back = _undo(server, service, before_cfg, expect_hash or now)
            if proved_back and maybe_written:
                return _unproved(
                    "write-failed",
                    f"{_text(wrote) or 'config-write was refused'}; an earlier attempt got no answer and may have written the file, so it may carry a change the daemon no longer runs",
                    after_hash=h1,
                )
            if proved_back:
                _drop_pending()
                return _result(False, "write-failed", _text(wrote) or "config-write was refused")
            return _unproved(
                "write-failed",
                f"{_text(wrote) or 'config-write was refused'}; the change could not be proved undone - the daemon may run it without the file carrying it",
                after_hash=h1,
            )
        unwritten = "the file may not carry this change"

    got, digest, why = _get(server, service)  # (7)
    if got is None or digest != h1:
        return _unproved(
            "unverified",
            f"{_name(server)} did not confirm the change ({why or f'its digest is {digest}, not the {h1} the set returned'}); the daemon's own answer is the record and nothing was undone",
            before_hash=expect_hash or now,
            after_hash=digest,
        )

    raw_sha = None
    note = ""
    if _has_ssh(server):  # (8)
        file_cfg, raw_sha = _host.read_config_versioned(server, service, capture=False)
        if file_cfg is None and not unwritten:
            # (Q217 AB8) the daemon proved the write (its digest is the set's); a file that cannot be READ BACK is not a difference - a write's own guards decide
            note = f"the file on {_name(server)} could not be read back; Config history carries what the daemon runs"
            raw_sha = None
        elif file_cfg is None or not file_in_daemon(
            file_cfg, got, service
        ):  # Kea's own rendering carries everything the daemon runs (Q219, Decided 16)
            return _unproved(
                "unverified",
                f"the file on {_name(server)} does not carry what the daemon runs"
                + (f" ({unwritten})" if unwritten else ""),
                before_hash=expect_hash or now,
                after_hash=h1,
            )
    elif unwritten:
        return _unproved("unverified", f"{_name(server)}: {unwritten}", after_hash=h1)

    finished = True
    if pending_id is not None:  # (9)
        finished = _rev.finish(pending_id, source=source, sha256=h1, cfg=got)
        if finished:
            _rev.discard_pending(
                sid, service
            )  # (fix row 2) an unresolved row an earlier crash left is superseded by a change that stood
    if raw_sha and sid is not None:
        record_rendering_after_write(server, service, summary or f"{source} {service}", cfg=got, raw=raw_sha)
    if not finished:
        # (Q218 BH2 c) the pending row is the ONE record of what the daemon runs: it is not discarded, and the change is not "ok" - the next change, or Settle it now, finishes it by content
        return _unproved(
            "unverified",
            "the change is live and its file written, but its record could not be finished; the next change, or Settle it now, finishes it by content",
            before_hash=expect_hash or now,
            after_hash=h1,
        )
    return _result(True, "ok", sha256=h1, **({"note": note} if note else {}))


def revert(
    server: dict, service: str, cfg: dict, expect_hash: str | None, summary: str, *, before_cfg: dict | None = None
) -> dict:
    """`apply` with `source="rollback"`: put a configuration this module wrote back, guarded by the digest that write returned."""
    return apply(server, service, copy.deepcopy(cfg), expect_hash, summary, source="rollback", before_cfg=before_cfg)


def record_daemon_after_file_change(server: dict, service: str, summary: str, source: str = "jen") -> bool:
    """A change reached this server by the FILE path (its daemon was restarted on the new file): record what the daemon runs NOW as a `kea` row, from `config-get`, so the next API write
    does not read this one as somebody else's change. Best effort and never raises: a daemon that does not answer records nothing, and the next read captures it as it would any hand edit."""
    sid = server.get("id")
    if sid is None or service not in SERVICE_KEY:
        return False
    cfg, digest, _why = _get(server, service)
    if cfg is None:
        return False
    return (
        _rev.record(sid, service, cfg, digest, summary or f"{source} {service}", hash_kind="kea", source=source)
        is not None
    )


def api_daemon_differs(server: dict, service: str) -> str:
    """The choke point's question for a FILE-path write onto a server whose transport is `api` (Q212, BB2 e): does the file the writer is about to replace carry what the daemon runs? A sentence
    naming both digests when BOTH answered and differ - the next logging toggle would otherwise erase an `unverified` apply or a hand `config-set` - else "". A file or a daemon that cannot be read
    is not a difference (the write's own guards decide), so a host whose daemon is down can still be put back."""
    if declared_transport(server) != "api" or service not in SERVICE_KEY:
        return ""
    live, digest, _why = _get(server, service)
    if live is None:
        return ""
    sid = server.get("id")
    try:
        last = _rev.latest_of_kind(sid, service, "kea") if sid is not None else None
        in_flight = sid is not None and _rev.pending(sid, service) is not None
    except Exception as e:  # a history read never decides this question: containment below is the fallback
        logger.warning("kea_api_config: api_daemon_differs could not read the history of %s: %s", sid, type(e).__name__)
        last, in_flight = None, False
    if not in_flight and last is not None and last.get("sha256") and last["sha256"] != digest:
        # (Q216 AA - the blind spot) a hand `config-set` of a key the FILE omits (one of the 45 defaults `config-get` writes out) is invisible to containment; the DIGEST of the last configuration Jen
        # recorded for this daemon is the check, and containment is the fallback for a server with no `kea` row yet (docs/ARCHITECTURE.md 3.17 says that is its limit)
        return (
            f"the daemon on {_name(server)} runs a configuration that is not the one Jen last recorded for it (the daemon {digest[:12]}, Jen's record {str(last['sha256'])[:12]}); "
            "restore or resolve it from Config history first"
        )
    proof = file_proof(
        server, service, capture=False
    )  # (Q219, Decided 16) the daemon's own clock, not a model of its defaults
    if proof["how"] != "none":
        return ""  # a file that cannot be read is not a difference either: the write's own guards decide
    return (
        f"the daemon on {_name(server)} runs a configuration its file does not carry ({proof['why']}; the daemon {digest[:12]}, the file {str(proof['sha256'] or 'unknown')[:12]}); "
        "restore or resolve it from Config history first"
    )


# ── the stored probe: the facts are the gate (Q212, BB3 c/d) ──────────────────────────────────────────────────────────────


PROBE_KEY = "config_transport_probe:{}"
PROBE_MAX_AGE_DAYS = 7
PROBE_SENTENCE = "run the readiness check on the server's Write mode card first"


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def stored_probe(server_id) -> dict | None:
    """The stored result of the last probe of this server (`settings` key `config_transport_probe:<id>`), or None. It is what `capabilities.derive` reads and what the card renders - a
    settings read, never a Kea call."""
    if server_id is None:
        return None
    from jen.models import user as _user

    try:
        raw = _user.get_global_setting(PROBE_KEY.format(server_id))
        data = json.loads(raw) if raw else None
    except (TypeError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def store_probe(server_id, data: dict) -> bool:
    from jen.models import user as _user

    return bool(_user.set_global_setting(PROBE_KEY.format(server_id), json.dumps(data, sort_keys=True)))


def _age_days(iso: str | None) -> float | None:
    from datetime import datetime, timezone

    try:
        when = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - when).total_seconds() / 86400


def _bound(server: dict) -> str:
    """Which endpoint a stored probe was read from: a hash of the API url and the SSH host (never stored in the clear). Server ids are reused (the next free number) and `api_url` can be re-pointed,
    so consent given to one Kea must not carry to another that inherits its number (fix row 6)."""
    import hashlib

    return hashlib.sha256(f"{server.get('api_url') or ''}|{server.get('ssh_host') or ''}".encode()).hexdigest()[:16]


CONSENTS = ("consent_rendering", "consent_unauthenticated", "discard_file_edit", "confirm_no_include")
# A stored result with no `consents` list (beta.1's shape) has accepted the file rewrite - and, for a server with no SSH, the structural confirmation that no later fact can change - and nothing
# else (Q217 AB2): an endpoint that has lost its authentication, or a file that no longer matches, blocks until the card's step 3 is ticked again.
LEGACY_CONSENTS = ("consent_rendering", "confirm_no_include")


def consent_gap(name: str, facts: dict | None, consents, *, has_ssh: bool, strict: bool = True) -> tuple[str, str]:
    """(sentence, needs): the FIRST thing that stands between these `facts` and an operator's named `consents` - "" when nothing does. THE one definition of whether the operator's consents cover the facts (Q216
    AA1): the switch's rules of BB8 moved here verbatim, asked by the switch, by `probe(consent=True)` and - for the facts a refresh brought - by the gate. `needs` is the consent field that would answer
    the sentence (or the helper grant, `allow_config_write`). With `strict=False` a fact that is ABSENT from a stored result (an older release wrote none; a test stores three keys) is not an unknown one."""
    facts = facts or {}
    consents = set(consents or ())

    def known(key):
        return strict or key in facts

    if not facts.get("config_api"):
        return (
            f"{name}: the daemon could not be read over its API ({facts.get('read_error') or 'no answer'}); nothing was changed",
            "",
        )
    if facts.get("test_ok") is False:
        return (
            f"{name}: the daemon did not accept its own configuration in a config-test ({facts.get('test_detail') or 'refused'}); nothing was changed",
            "",
        )
    if facts.get("include"):
        return (
            f"{name}: the file carries an include ({', '.join(facts['include'])}); the daemon reports the merged configuration and config-write renders one flat file, so Live API is not recommended here",
            "",
        )
    if has_ssh and (
        (known("agree") and facts.get("agree") is None)
        or (known("include") and facts.get("include") is None)
        or (known("write") and not isinstance(facts.get("write"), dict))
    ):
        return (
            f"{name}: SSH is configured but the host's facts could not be read (is the helper installed at build 19 or later, and does SSH answer?), so the file could not be compared with the daemon; nothing was changed",
            "",
        )
    if not has_ssh and "confirm_no_include" not in consents:
        return (
            f"{name} has no SSH host, so Jen cannot see its file: confirm that the file carries no include and no edit the daemon has not loaded, then switch again",
            "confirm_no_include",
        )
    if has_ssh and facts.get("agree") is False and "discard_file_edit" not in consents:
        return (
            f"{name}: the file on the host carries a configuration the daemon is not running - restart Kea first, or tick 'discard the file's edit' (the switch makes the file the daemon's configuration)",
            "discard_file_edit",
        )
    write = facts.get("write")
    if has_ssh and isinstance(write, dict) and write.get("may_write") is False:
        return (
            f"{name}: the daemon's account ({write.get('account') or 'unknown'}) may not write its file ({write.get('mode')}); press Allow the daemon to write its file, then switch again",
            "allow_config_write",
        )
    if "consent_rendering" not in consents:
        return (
            f"{name}: Kea writes its file in its own form - comments and key order are not kept (a 1,932-byte file became 4,769). This is the one moment they are lost: tick the confirmation to go on",
            "consent_rendering",
        )
    if facts.get("auth") == "none" and "consent_unauthenticated" not in consents:
        return (
            f"{name}: this endpoint has no authentication; anything that can reach it can change this daemon's configuration. Confirm that, then switch again",
            "consent_unauthenticated",
        )
    return "", ""


def consents_called_for(facts: dict | None, *, has_ssh: bool) -> list[str]:
    """The consents the FACTS call for, in the order `consent_gap` names them (Q217 BG2): the card's row 3 and the gate's table are one list (a test walks `consent_gap` one refusal at a time and
    compares). `consent_rendering` is asked of every switch."""
    facts = facts or {}
    out = []
    if not has_ssh:
        out.append("confirm_no_include")
    if has_ssh and facts.get("agree") is False:
        out.append("discard_file_edit")
    out.append("consent_rendering")
    if facts.get("auth") == "none":
        out.append("consent_unauthenticated")
    return out


def consent_allowed(name: str, facts: dict | None, consents, *, has_ssh: bool, strict: bool = True) -> str:
    """`consent_gap`'s sentence alone: "" when the named consents cover the facts."""
    return consent_gap(name, facts, consents, has_ssh=has_ssh, strict=strict)[0]


def probe_gate(server: dict, source: str = "jen") -> str:
    """NO API write without it: a sentence for a server whose stored result is absent, older than 7 days, has `config_api` false, carries no `consented_at` (the operator's named consent, from
    the card), carries a fact the consent given does not cover (a refresh found an include, or the endpoint lost its authentication - Q216 AA12), or remembers a refused write (BB9 a); "" otherwise. A
    server added through Settings with `api` written by the save route therefore cannot be written to until its operator has read the probe's facts once: the probe is a click, the facts are the gate."""
    stored = stored_probe(server.get("id"))
    if not stored:
        return PROBE_SENTENCE
    if not stored.get("bound"):
        # (Q218 BH3 d, AC6) a stored result that names no endpoint cannot say which Kea it was read from: it is checked again, never taken for the current one
        return f"{_name(server)} was checked before this version recorded which Kea it was - {PROBE_SENTENCE.replace('first', 'again')}"
    if stored["bound"] != _bound(server):
        return f"{_name(server)} now points at a different Kea than the one that was checked - {PROBE_SENTENCE.replace('first', 'again')}"
    age = _age_days(stored.get("at"))
    if age is None or age > PROBE_MAX_AGE_DAYS:
        return f"the last check of {_name(server)} is older than {PROBE_MAX_AGE_DAYS} days - {PROBE_SENTENCE.replace('first', 'again')}"
    if not stored.get("config_api"):
        return f"the daemon on {_name(server)} could not be read over its API at the last check - {PROBE_SENTENCE.replace('first', 'again')}"
    if not stored.get("consented_at"):
        return f"changes over the API to {_name(server)} have not been allowed yet - read the facts and allow them from the server's card"
    # the consent on record covers the facts it was given for; a stored result from before the consents were recorded (7.0.0-beta.1) counts as having been given all of them
    given = stored.get("consents", LEGACY_CONSENTS)
    uncovered = consent_allowed(_name(server), stored, given, has_ssh=_has_ssh(server), strict=False)
    if uncovered:
        prefix = f"{_name(server)}: "
        return (
            uncovered[len(prefix) :] if uncovered.startswith(prefix) else uncovered
        )  # (the caller names the server: "❌ kea-d: ...")
    return (
        "" if source in ("rollback", "restore") else refusal_sentence(server)
    )  # a rollback puts back a change that DID stand on this server, and a restore is the way out of a REFUSED write (Q216 AA14, Q219 BI2 d): a remembered refusal must not stop either. A restart of Kea (or a reload of its configuration) is the way out of an UNLOADED edit - the attention note names which


def refusal_sentence(server: dict) -> str:
    """BB9 a: after a `write-failed` the stored result carries `refused` (Kea's own text) and a change set refuses to PLAN against the server, so a fleet does not undo the same change on every edit."""
    stored = stored_probe(server.get("id"))
    if stored and stored.get("refused"):
        return f"the daemon on {_name(server)} may not write its file ({stored['refused']}); fix it, then run the readiness check on the server's Write mode card"
    return ""


def remember_refusal(server: dict, text: str) -> bool:
    """Record Kea's own refusal of `config-write` in the stored result. Cleared only by evidence (`probe` with the helper's `config-write-check` saying the account may write, or the operator's
    "I have fixed it" with its audit row) - never by a probe that proves nothing."""
    sid = server.get("id")
    if sid is None:
        return False
    stored = stored_probe(sid) or {"at": _now_iso()}
    stored["refused"] = (text or "config-write was refused")[:300]
    return store_probe(sid, stored)


def clear_refusal(server_id) -> bool:
    stored = stored_probe(server_id)
    if not stored or "refused" not in stored:
        return True
    stored.pop("refused", None)
    return store_probe(server_id, stored)


def _endpoint_facts(server: dict, service: str) -> dict:
    """How the endpoint is authenticated and whether it is reached over TLS - read from what `credentials.resolve` gave the server dict, never sent anywhere. Kea draws no line between a client that reads
    and one that writes (RBAC is subscriber-only), so the credential that reads is the credential that writes and NOTHING new is created on Kea."""
    endpoint = _kea._endpoint_for(server, service)
    if isinstance(endpoint, dict):
        return {"auth": "unknown", "tls": None}
    url, user, pwd = endpoint
    tls = str(url).lower().startswith("https://")
    if user or pwd:
        auth = "password"
    elif tls and _kea._tls_client_cert():
        auth = "client certificate"
    else:
        auth = "none"
    return {"auth": auth, "tls": tls}


PROBE_REFRESH_AFTER_HOURS = 24


def refresh_probe(server: dict, service: str = "dhcp4") -> bool:
    """Keep the FACTS fresh without asking the operator again (Q216 AA12): re-run the probe for a server whose operator has consented, leaving `consented_at` and `consents` exactly as they are while `bound`
    is unchanged. True when the stored facts were replaced. A daemon (or a host's helper) that does not answer keeps the previous facts and their age - reachability is runtime (BB2 b) - and a fact that
    now stands outside the consent given closes the gate with its own sentence (`probe_gate`)."""
    sid = server.get("id")
    stored = stored_probe(sid)
    if not stored or not stored.get("consented_at") or service not in SERVICE_KEY:
        return False
    if not stored.get("bound") or stored["bound"] != _bound(server):
        return False  # a re-pointed server is for its operator to check again - and so is a result that names no endpoint (Q218 BH3 d): the refresh never binds a consent to a Kea nobody checked
    cfg, _digest, _why = _get(server, service)
    if cfg is None:
        return False
    fresh = probe(server, service, persist=False)
    if _has_ssh(server) and (
        fresh.get("include") is None or fresh.get("agree") is None or not isinstance(fresh.get("write"), dict)
    ):
        return False  # (second pass, row 4) the host did not answer this time - or its file could not be read: what was known stays known, never an unknown that closes the gate
    latest = (
        stored_probe(sid) or {}
    )  # (row 10) re-read just before the write: a consent or a refusal given while the facts were being read is the operator's, not ours to discard
    for key in ("consented_at", "consents", "refused"):
        if key in latest:
            fresh[key] = latest[key]
        else:
            fresh.pop(key, None)
    return store_probe(sid, fresh)


def refresh_if_stale(server: dict, service: str = "dhcp4") -> bool:
    """The change set's Plan: facts older than a day are refreshed before the gate is asked."""
    stored = stored_probe(server.get("id"))
    age = _age_days((stored or {}).get("at"))
    if not stored or age is None or age * 24 < PROBE_REFRESH_AFTER_HOURS:
        return False
    return refresh_probe(server, service)


def probe(server: dict, service: str = "dhcp4", *, consent: bool = False, consents=(), persist: bool = True) -> dict:
    """The facts an operator reads before the first change over the API, from a GUARDED `config-get` (never `config-hash-get`, which the Control Agent also answers), a `config-test` of the running
    configuration, how the endpoint is authenticated, and - where SSH exists - the helper's `config-write-check` and a compare of the file with the daemon. Stored (BB3 d) and returned.
    `consent` records the operator's named consent (`consented_at`, and the `consents` it was given with) ONLY when `consent_allowed` answers "" for the consents the caller carries - the switch's terms
    exactly (Q216 AA1). `persist=False` returns the facts without storing them (the refresh decides)."""
    sid = server.get("id")
    prev = stored_probe(sid) or {}
    out = {"at": _now_iso(), "service": service, "bound": _bound(server)}
    if prev.get("bound") != out["bound"]:
        prev = {}  # a different endpoint - or a result that names none (Q218 BH3 d): nothing carries over (consent, a remembered refusal)
    cfg, _digest, why = _get(server, service)
    out["config_api"] = cfg is not None
    if cfg is None:
        out["read_error"] = why
    else:
        tested = test(server, service, cfg)
        out["test_ok"] = bool(tested["ok"])
        if not tested["ok"]:
            out["test_detail"] = tested.get("detail", "")
    out.update(_endpoint_facts(server, service))
    out["authored"] = False
    if sid is not None:
        try:
            out["authored"] = any(
                r.get("source") in ("jen", "authoring") for r in _rev.list_revisions(sid, service, limit=500)
            )
        except Exception as e:  # a history read never fails the probe
            logger.warning("kea_api_config: probe could not read the history of %s: %s", sid, type(e).__name__)
    refused = prev.get("refused")
    if _has_ssh(server):
        check = _host.config_write_check(server, service)
        out["write"] = (
            {
                "may_write": bool(check.get("may_write")),
                "owner_uid": check.get("owner_uid"),
                "owner_gid": check.get("owner_gid"),
                "mode": check.get("mode"),
                "account": (check.get("account") or {}).get("name") if check.get("account") else "root",
                "daemon_is_root": bool(check.get("daemon_is_root")),
            }
            if check.get("ok")
            else {"unavailable": check.get("detail") or check.get("code")}
        )
        out["include"] = list(check.get("includes") or []) if check.get("ok") else None
        if not check.get("ok"):
            # (Q217 BG3 a) SSH EXISTS here: the helper did not answer. The card names that cause (a helper below build 19, SSH down), never "without SSH"
            out["include_unavailable"] = str(check.get("detail") or check.get("code") or "the helper did not answer")[
                :300
            ]
        out["agree"] = None
        out["proof"] = None
        out["file_written_at"] = None
        out["daemon_loaded_at"] = None
        if cfg is not None:
            # (Q219) the facts are the proof's: `agree` is True when the file is Jen's own rendering, the one the Plan proved or one the daemon has loaded, False when it is none of them, None when it
            # cannot be read. While a change is pending the proof is asked against the file it planned over (Decided 5).
            planned = None
            if sid is not None:
                try:
                    planned = (_rev.pending(sid, service) or {}).get("file_sha256")
                except _rev.RevisionStoreUnreadable:
                    planned = None
            proof = file_proof(server, service, planned_sha=planned, capture=False)
            out["proof"] = proof["how"]
            out["file_written_at"] = proof["mtime"]
            out["daemon_loaded_at"] = proof["loaded_at"]
            if proof["how"] in ("rendering", "planned", "loaded"):
                out["agree"] = True
            elif proof["how"] == "none":
                out["agree"] = False
                out["agree_at"] = proof["where"] or proof["why"]
        if check.get("ok") and check.get("may_write"):
            refused = None  # evidence: the host says the daemon's account may write its file
    else:
        out["write"] = "unknown until the first change - Jen undoes a change whose write fails"
        out["include"] = None  # cannot be known without the host; the switch asks the operator to confirm there is none
        out["agree"] = None
    if refused:
        out["refused"] = refused
    if prev.get("consented_at"):
        out["consented_at"] = prev["consented_at"]
        if "consents" in prev:
            out["consents"] = prev["consents"]
    if consent:
        given = sorted(set(consents or ()) & set(CONSENTS))
        gap = consent_allowed(_name(server), out, given, has_ssh=_has_ssh(server))
        if not gap:
            out["consented_at"] = _now_iso()
            out["consents"] = given
        else:
            out["consent_refused"] = gap
    if persist:
        store_probe(sid, out)
    return out
