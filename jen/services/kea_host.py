"""
jen/services/kea_host.py
────────────────────────
v5.11.0 — the single client for every Kea-host operation.

Prefers `jen-kea-helper` (the fixed-function root helper at
/usr/local/sbin/jen-kea-helper, one sudoers line — see
docs/ARCHITECTURE.md §3.3). Falls back to the pre-5.11.0 `sudo python3`
path for a host that does not have the helper yet, with:
  * a one-per-server warning flash per request, and
  * a persisted per-server status (`kea_helper_status` in the settings
    table) so pages and the admin banner never SSH just to render.

Every high-level call returns a `HostResult` dict:
    {"ok": bool, "code": str, "detail": str, "via": "helper"|"legacy", …}
`code` is drawn from the vocabulary the routes already switch on:
`ok`, `preview-ok`, `nochange`, `exists`, `notfound`, `idexists`,
`testerror`, `missingbinary`, `tlsmissing`, `error`.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import re
import shlex
from datetime import datetime, timezone

from flask import flash, g, has_request_context

import jen.services.kea6 as __kea6
import jen.services.kea_authoring as __authoring

logger = logging.getLogger(__name__)

# Mirrors jen-update-root.py's own GITHUB_REPO — used only to build the by-hand helper-download
# one-liner below (v5.65.13, Q102), never for anything that reaches over the network itself.
_GITHUB_REPO = "ltkojak/jen-kea"

# v5.66.0-beta.2 (Q104, item g) — byte-identical to the same-named constant in
# jen-update-root.py and jen-kea-helper (tests/test_kea_host.py diffs all three the same way
# tests/test_kea_helper.py already diffs the first two). Jen's own copy exists so
# verify_helper_signature() below can check a helper signature LOCALLY, before ever sending
# it to a Kea host, and so the by-hand download one-liner can embed it directly — a rotation
# adds the new key here too, in the same commit as the other two copies.
RELEASE_SIGNERS = "release@jen ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFXk5NbQwUy85pHCzLfOwPisL0JGLCOrHuRjRZSf25vD"
_RELEASE_SIGNATURE_IDENTITY = "release@jen"
_HELPER_SIGNATURE_NAMESPACE = "jen-kea-helper"

HELPER_PATH = "/usr/local/sbin/jen-kea-helper"
JEN_HELPER_MIN_VERSION = 1
# v5.16.0 — the version Jen wants for atomic-guarded writes + external
# change capture. A host below this still works; the Settings → Kea SSH
# table shows an "upgrade available" hint and nothing else changes.
JEN_HELPER_WANT_VERSION = 2
# v5.23.0 (Q19) — the version D2 support needs. Deliberately NOT folded
# into JEN_HELPER_WANT_VERSION: D2 is an optional subsystem most installs
# never touch, so bumping the general "upgrade available" threshold to 3
# would nag every operator instead of only the ones who open the DDNS
# page's D2 tabs. Checked there specifically (d2_supported below), not by
# the Settings → Kea SSH table.
D2_HELPER_MIN_VERSION = 3
_HELPER_STATUS_KEY = "kea_helper_status"

# stderr fragments that mean "the helper isn't callable here" rather than
# "the helper ran and failed".
_MISSING_RE = re.compile(r"password is required|command not found|no such file", re.IGNORECASE)


class HelperMissing(Exception):
    """The helper isn't installed, or the sudoers line is absent, on this host."""


class HelperError(Exception):
    """The helper ran but returned nothing usable."""


# ── low-level transport ─────────────────────────────────────────────────────


def helper_call(server: dict, op: str, payload: dict | None = None, timeout: int = 60) -> dict:
    """One SSH round trip: `sudo -n jen-kea-helper <op>` with a JSON
    object on stdin, a JSON object back on stdout. Returns the parsed
    object (whatever its exit code). Raises HelperMissing when the helper
    or its sudoers grant is absent, HelperError on any other garbage.

    `sudo -n` is load-bearing: without it, a missing sudoers rule blocks
    on the password prompt instead of failing fast."""
    ssh = __kea6._connect_ssh(server)
    try:
        stdin, stdout, stderr = ssh.exec_command(f"sudo -n {HELPER_PATH} {shlex.quote(op)}", timeout=timeout)
        try:
            stdin.write(json.dumps(payload or {}))
            stdin.channel.shutdown_write()
        except (OSError, AttributeError):
            pass
        out = stdout.read().decode("utf-8", "replace").strip()
        err = stderr.read().decode("utf-8", "replace").strip()
    finally:
        with contextlib.suppress(Exception):
            ssh.close()

    if out:
        try:
            parsed = json.loads(out)
            if isinstance(parsed, dict):
                return parsed
        except ValueError:
            pass
    if _MISSING_RE.search(err):
        raise HelperMissing(err)
    raise HelperError(err or "no JSON from helper")


# ── per-server status ──────────────────────────────────────────────────────


def _user():
    import jen.models.user as __user

    return __user


def helper_status() -> dict:
    """`{"<server id>": {"version": 1|null, "checked": "<iso>"}}` from the
    settings table. Never SSHes."""
    try:
        raw = _user().get_global_setting(_HELPER_STATUS_KEY, "{}")
        data = json.loads(raw) if raw else {}
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError):
        return {}


def record_helper_status(server_id, version, build=None, legacy_grant: bool | None = None) -> None:
    """Called after every helper attempt: `version` is the integer
    reported by a `version` op, an int carried forward for any other
    successful op, or None for HelperMissing. `build` (v5.66.0-beta.2,
    Q104) is `helper_build` from the same response envelope when the
    host is already on v7+ — None (the default, matching `legacy_grant`'s
    own convention) leaves whatever was last recorded rather than
    clobbering it with "unknown", since most callers have no reason to
    SSH just to check. `legacy_grant` (v5.20.0) records whether the old
    NOPASSWD: /usr/bin/python3 sudoers grant is still present on this
    host — True/False updates it, None (the default — every caller
    except check_helper) leaves whatever was last recorded, since most
    callers have no reason to SSH just to check."""
    if server_id is None:
        return
    data = helper_status()
    prev = data.get(str(server_id), {})
    data[str(server_id)] = {
        "version": version,
        "build": build if build is not None else prev.get("build"),
        "checked": datetime.now(timezone.utc).isoformat(),
        "legacy_grant": legacy_grant if legacy_grant is not None else prev.get("legacy_grant"),
    }
    try:
        _user().set_global_setting(_HELPER_STATUS_KEY, json.dumps(data))
    except Exception as e:
        logger.warning(f"could not persist kea_helper_status: {e}")


def _known_version(server_id):
    return helper_status().get(str(server_id), {}).get("version")


def _known_build(server_id):
    return helper_status().get(str(server_id), {}).get("build")


def d2_supported(server_id) -> bool:
    """True iff the last-recorded helper version for this server is known
    to be >= D2_HELPER_MIN_VERSION. False (not None) when nothing has been
    recorded yet — a page gating the D2 tabs on this should treat "unknown"
    the same as "not yet confirmed," matching JEN_HELPER_MIN_VERSION's own
    fail-closed default elsewhere in this module."""
    v = _known_version(server_id)
    return isinstance(v, int) and v >= D2_HELPER_MIN_VERSION


_D2_NEEDS_HELPER = "D2 needs jen-kea-helper v3+ on this host — install or update it from Settings → Kea → SSH."

# v5.29.0 (Q29) — the version `install-tls` (https control-socket
# material) needs. Same reasoning as D2_HELPER_MIN_VERSION: only the
# https setup path needs it, so it gates that path (tls_supported)
# rather than nagging every host through JEN_HELPER_WANT_VERSION.
TLS_HELPER_MIN_VERSION = 4
# v5.64.0 (Q83) — `tail-log` (Trace) arrived in helper v5 (bounded deque);
# jen.services.capabilities derives the `trace` capability from this.
TRACE_HELPER_MIN_VERSION = 5
# v5.29.1 — the HELPER_VERSION of the jen-kea-helper file this install
# ships (tests/test_kea_host.py pins it to the file). Distinct from
# JEN_HELPER_WANT_VERSION on purpose: WANT drives the amber "upgrade
# available" nag (kept at 2 — D2 and https are optional), SHIPPED drives
# whether the Settings → Kea → SSH table OFFERS the Update helper button
# at all. v5.29.0 gated the https socket option on v4 but the button only
# appeared below WANT, so a v3 host had no way to get there from the UI.
JEN_HELPER_SHIPPED_VERSION = 7  # v7 (v5.66.0-beta.2, Q104): PATH hardening + preflight/rollback
# v5.66.0-beta.2 (Q104) — HELPER_BUILD of the jen-kea-helper file this install ships
# (tests/test_kea_host.py pins it to the file, the same way JEN_HELPER_SHIPPED_VERSION is).
# A helper below v7 never reports a build at all (record_helper_status's "build" stays
# whatever it last was, usually None) — comparisons that matter fall back to version alone
# in that case; see install_helper()'s already-check and helper_version_label() below.
JEN_HELPER_SHIPPED_BUILD = 9  # v5.66.0-beta.7 (Q109): protocol/build checked independently, _bin_dir_ok
# v5.66.0 (Q103) — the version whose "Update helper" click needs no legacy grant at all: at
# or above this, install_helper() takes the signed path (helper_signature() + the `update`
# op) instead of the pre-5.11.0 sudo-python3 engine. A host below this still gets one last
# legacy-grant hop to reach v6 — after that, never again.
SIGNED_UPDATE_HELPER_MIN_VERSION = 6


def helper_version_label(
    version, shipped: int | None = None, build: int | None = None, shipped_build: int | None = None
) -> str:
    """One host's version as every page words it: "v4 (v5 available)", or "v5"
    when it is current, "not recorded" when Jen has never seen it answer.
    v5.66.0-beta.2 (Q104) — `build`/`shipped_build` are optional: a v7+ host that
    reports one reads "v7 (build 7)" when current, or "v7 (build 3, build 7
    available)" when it's behind on build only (same protocol version, older
    file) — a case `version` alone can't distinguish from "fully current"."""
    shipped = JEN_HELPER_SHIPPED_VERSION if shipped is None else shipped
    shipped_build = JEN_HELPER_SHIPPED_BUILD if shipped_build is None else shipped_build
    if not isinstance(version, int):
        return "not recorded"
    if version < shipped:
        return f"v{version} (v{shipped} available)"
    if isinstance(build, int):
        if build < shipped_build:
            return f"v{version} (build {build}, build {shipped_build} available)"
        return f"v{version} (build {build})"
    return f"v{version}"


def helper_version_phrase(versions, shipped: int | None = None) -> str:
    """The fleet phrasing shared by the Health "helper installed" row, the Kea
    3.2 readiness row and (per host, via helper_version_label) the Settings →
    Kea → SSH card: "1/1 host(s) on helper v4 (v5 available)". Hosts group by
    version; hosts Jen has never seen answer are counted apart."""
    versions = list(versions)
    total = len(versions)
    if not total:
        return ""
    shipped = JEN_HELPER_SHIPPED_VERSION if shipped is None else shipped
    parts = []
    for v in sorted({v for v in versions if isinstance(v, int)}):
        n = sum(1 for x in versions if x == v)
        parts.append(f"{n}/{total} host(s) on helper {helper_version_label(v, shipped)}")
    unknown = sum(1 for x in versions if not isinstance(x, int))
    if unknown:
        parts.append(f"{unknown}/{total} host(s) with no helper recorded")
    return "; ".join(parts)


_TLS_NEEDS_HELPER = (
    "https setup needs jen-kea-helper v4+ on this host — update it from Settings → Kea → SSH "
    "(the http option works with any helper version)."
)


def tls_supported(server_id) -> bool:
    """True iff the last-recorded helper version for this server is known
    to be >= TLS_HELPER_MIN_VERSION; False when unknown (fail closed,
    like d2_supported)."""
    v = _known_version(server_id)
    return isinstance(v, int) and v >= TLS_HELPER_MIN_VERSION


def _record_from_resp(server_id, resp: dict) -> None:
    """v5.16.0 — learn the real helper version from any op's response
    envelope (`helper_version`, added to every v2 response), falling back
    to the last-known value or the minimum. Replaces the old
    `record_helper_status(id, _known_version(id) or MIN)` pattern that
    could only ever record the minimum outside a `version` op."""
    v = None
    if isinstance(resp, dict) and resp.get("helper_version") is not None:
        with contextlib.suppress(TypeError, ValueError):
            v = int(resp["helper_version"])
    record_helper_status(server_id, v or _known_version(server_id) or JEN_HELPER_MIN_VERSION)


# ── legacy-path warning ────────────────────────────────────────────────────


def _flag_legacy(server: dict) -> None:
    """Record the server as helper-less and flash ONE warning per server
    per request."""
    record_helper_status(server.get("id"), None)
    name = server.get("name") or server.get("ssh_host") or "?"
    if not has_request_context():
        return
    seen = getattr(g, "_kea_legacy_flashed", None)
    if seen is None:
        seen = g._kea_legacy_flashed = set()
    if name in seen:
        return
    seen.add(name)
    flash(
        f"{name} is using the legacy root `python3` path — install the Kea host helper from Settings → Kea → SSH.",
        "warning",
    )


def _legacy_suffix(result: dict) -> dict:
    if result.get("via") == "legacy" and result.get("detail"):
        result["detail"] = f"{result['detail']} (legacy path)"
    return result


# ── legacy engine ─────────────────────────────────────────────────────────


def _legacy_python3(server: dict, script: str, timeout: int = 30) -> tuple[str, str, int]:
    """`echo <b64> | base64 -d | sudo python3` — the pre-5.11.0 path.

    v5.28.0 (Q24, B1) — returns the remote command's real exit status
    too, read AFTER stdout/stderr (paramiko's `recv_exit_status()`
    blocks until the channel actually closes). Every caller used to
    trust the script's own stdout token unconditionally — a remote
    command that died before ever running the script (a dropped
    connection mid-command, `sudo` itself failing) could still leave
    old, stale output sitting in a buffer that read as success."""
    import base64

    ssh = __kea6._connect_ssh(server)
    try:
        enc = base64.b64encode(script.encode()).decode()
        _stdin, stdout, stderr = ssh.exec_command(f"echo {enc} | base64 -d | sudo python3", timeout=timeout)
        out = stdout.read().decode("utf-8", "replace").strip()
        err = stderr.read().decode("utf-8", "replace").strip()
        return out, err, stdout.channel.recv_exit_status()
    finally:
        with contextlib.suppress(Exception):
            ssh.close()


def _legacy_ssh(server: dict, command: str, timeout: int = 30) -> tuple[str, str, int]:
    """v5.28.0 (Q24, B1) — see _legacy_python3's docstring; same fix."""
    ssh = __kea6._connect_ssh(server)
    try:
        _stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
        out = stdout.read().decode("utf-8", "replace").strip()
        err = stderr.read().decode("utf-8", "replace").strip()
        return out, err, stdout.channel.recv_exit_status()
    finally:
        with contextlib.suppress(Exception):
            ssh.close()


def _parse_legacy_script_out(out: str, err: str, via: str, rc: int = 0) -> dict:
    """Map the old script's stdout tokens onto a HostResult.

    v5.28.0 (Q24, B1) — an "ok"/"preview-ok" token is only trusted when
    the remote command's own exit status was actually 0. Before this,
    a real bug: `service_action()`'s legacy path appended an
    unconditional trailing marker token after `cmd1 || cmd2`, which
    printed regardless of whether BOTH systemctl attempts failed, so
    Jen could report "Kea restarted successfully" when it did not.
    Every other token (exists, missingbinary, testerror, tlsmissing,
    the generic fallback) already
    carried enough information in its own text and is unaffected by
    rc — those are the script's own considered refusal, not a
    connection/sudo failure masquerading as one."""
    if out in ("ok", "preview-ok"):
        if rc == 0:
            return {"ok": True, "code": out, "via": via}
        return {"ok": False, "code": "error", "detail": err or f"exited {rc}", "via": via}
    if out == "exists":
        return {"ok": False, "code": "exists", "detail": "config already exists", "via": via}
    if out.startswith("missingbinary:"):
        b = out[len("missingbinary:") :]
        return {"ok": False, "code": "missingbinary", "binary": b, "detail": b, "via": via}
    if out.startswith("testerror:"):
        return {"ok": False, "code": "testerror", "detail": out[len("testerror:") :], "via": via}
    if out.startswith("tlsmissing:"):
        p = out[len("tlsmissing:") :]
        return {"ok": False, "code": "tlsmissing", "path": p, "detail": p, "via": via}
    return {"ok": False, "code": "error", "detail": err or out or "unknown error", "via": via}


# ── helper-response → HostResult ──────────────────────────────────────────


def _from_helper_test(resp: dict, ok_code: str) -> dict:
    if resp.get("ok"):
        out = {"ok": True, "code": ok_code, "via": "helper"}
        if "backup" in resp:
            out["backup"] = resp["backup"]
        if "sha256" in resp:
            out["sha256"] = resp["sha256"]
        return out
    err = resp.get("error")
    if err == "testerror":
        return {"ok": False, "code": "testerror", "detail": resp.get("detail", ""), "via": "helper"}
    if err == "missingbinary":
        b = resp.get("binary", "kea")
        return {"ok": False, "code": "missingbinary", "binary": b, "detail": b, "via": "helper"}
    if err == "tlsmissing":
        p = resp.get("path", "")
        return {"ok": False, "code": "tlsmissing", "path": p, "detail": p, "via": "helper"}
    if err == "exists":
        return {"ok": False, "code": "exists", "detail": "config already exists", "via": "helper"}
    if err == "conflict":
        return {
            "ok": False,
            "code": "conflict",
            "sha256": resp.get("sha256", ""),
            "detail": "the config on the host changed since you started",
            "via": "helper",
        }
    return {"ok": False, "code": "error", "detail": resp.get("detail") or err or "helper refused", "via": "helper"}


# ── high-level API ────────────────────────────────────────────────────────


def _conf_path(server, service):
    return __authoring.conf_path_for(server, service)


_CANONICAL_SENTINEL_PREFIX = "canonical:"


def _canonical_sentinel(cfg: dict) -> str:
    """v5.28.0 (Q24, B2) — a synthetic sha-like string standing in for
    "no raw hash available" (a v1 helper or the legacy path never
    return one), computed from the same canonical-JSON form
    config_revisions.py already uses for diffing. This is deliberately
    NOT sent to a v2 helper's `apply-config` — it isn't a real sha256
    of the raw file and the helper would (correctly) reject it as a
    mismatch — `apply_config()` recognizes the prefix and routes it to
    `_jen_side_conflict()` instead of the payload."""
    from jen.services import config_revisions as _rev

    return _CANONICAL_SENTINEL_PREFIX + hashlib.sha256(_rev.canonical(cfg).encode()).hexdigest()


def read_config_versioned(server: dict, service: str) -> tuple[dict | None, str | None]:
    """(parsed config, sha256-of-raw-bytes or a canonical sentinel).

    v5.28.0 (Q24, B2) — a v1 helper or the legacy path returns no raw
    sha; this used to return `None` for it, which meant a caller's
    `expect_sha256=None` disabled the concurrency guard entirely until
    `apply_config()` fell back to a best-effort check — one that, for a
    v1 helper, ran AFTER the write had already happened. It now
    returns `_canonical_sentinel(cfg)` instead: every caller's
    `expect_sha256=` argument always has something to guard a write
    with, and `apply_config()` checks it BEFORE writing regardless of
    helper version. A genuine read failure still returns (None, None).

    v5.16.0 — when the SHA is known and differs from the newest recorded
    revision's, the on-host file was hand-edited since Jen last wrote it:
    record it as an `external` revision so the history stays complete.
    v5.20.0 — the first time Jen ever sees a host's config (no revision
    recorded yet), or the first time it sees one with a RAW hash after
    only ever having a canonical one (a v1→v2 helper upgrade), that read
    is recorded as a `baseline`, never `external` — there is nothing to
    have changed relative to, and doing so also arms the optimistic-
    concurrency guard from the very first write instead of leaving it
    unguarded until Jen happens to write something first."""
    path = _conf_path(server, service)
    cfg: dict | None = None
    sha: str | None = None
    try:
        resp = helper_call(server, "read-config", {"service": service, "path": path})
        _record_from_resp(server.get("id"), resp)
        if resp.get("ok"):
            cfg = resp.get("config")
            sha = resp.get("sha256")
    except HelperMissing:
        _flag_legacy(server)
        ssh = __kea6._connect_ssh(server)
        try:
            cfg = __authoring.read_remote_json(ssh, path)
        finally:
            with contextlib.suppress(Exception):
                ssh.close()
    except HelperError as e:
        logger.warning(f"read-config helper error on {server.get('name')}: {e}")
        return None, None

    if cfg is None:
        return None, None

    # _capture_baseline_or_external_change must see the RAW sha (None
    # on v1/legacy) — it branches on that, not on the sentinel below.
    _capture_baseline_or_external_change(server.get("id"), service, cfg, sha)
    if not sha:
        sha = _canonical_sentinel(cfg)
    return cfg, sha


def read_config(server: dict, service: str) -> dict | None:
    """The parsed Kea config for `service` on `server`, or None if it's
    missing or unreadable. Thin wrapper over read_config_versioned()."""
    return read_config_versioned(server, service)[0]


def _capture_baseline_or_external_change(server_id, service: str, cfg: dict, sha: str | None) -> None:
    """v5.16.0 (external-change capture) + v5.20.0 (baseline + hash_kind).

    `sha` known (helper v2): no revision recorded yet -> `baseline`
    ("raw"); a revision exists but isn't "raw" yet (a v1->v2 helper
    upgrade) -> `baseline` again, NOT `external` — the file didn't
    change, Jen just gained the ability to hash it properly; the sha
    differs from the latest recorded ONE THAT IS ALREADY "raw" -> a
    genuine `external` change. `sha` unknown (v1/legacy): only the very
    first contact records anything (a "canonical" baseline, so
    `_jen_side_conflict`'s best-effort compare has something to compare
    against) — there's no raw hash to detect a later external change
    with, unchanged from before."""
    if server_id is None:
        return
    try:
        from jen.services import config_revisions as _rev

        last = _rev.latest(server_id, service)
        if sha:
            if last is None:
                _rev.record(
                    server_id,
                    service,
                    cfg,
                    sha,
                    "initial baseline — first config Jen saw on this host",
                    source="baseline",
                    hash_kind="raw",
                )
            elif last.get("hash_kind") != "raw":
                _rev.record(
                    server_id,
                    service,
                    cfg,
                    sha,
                    "baseline re-established (helper v2)",
                    source="baseline",
                    hash_kind="raw",
                )
            elif last.get("sha256") and last["sha256"] != sha:
                _rev.record(server_id, service, cfg, sha, "changed outside Jen", source="external", hash_kind="raw")
        elif last is None:
            canon_sha = hashlib.sha256(_rev.canonical(cfg).encode()).hexdigest()
            _rev.record(
                server_id,
                service,
                cfg,
                canon_sha,
                "initial baseline — first config Jen saw on this host (no raw hash: helper v1 / legacy)",
                source="baseline",
                hash_kind="canonical",
            )
    except Exception as e:
        logger.warning(f"config-revision baseline/external-change capture failed for server {server_id}/{service}: {e}")


def _tls_list(tls_paths):
    return [[p, kind] for (p, kind) in (tls_paths or [])]


def test_config(server: dict, service: str, cfg: dict, tls_paths=()) -> dict:
    path = _conf_path(server, service)
    try:
        resp = helper_call(
            server,
            "test-config",
            {"service": service, "path": path, "config": cfg, "tls_paths": _tls_list(tls_paths)},
        )
        _record_from_resp(server.get("id"), resp)
        if service == "d2" and not resp.get("ok") and resp.get("error") == "not-allowed":
            return {"ok": False, "code": "error", "detail": _D2_NEEDS_HELPER, "via": "helper"}
        return _from_helper_test(resp, "preview-ok")
    except HelperMissing:
        _flag_legacy(server)
        # v5.23.0 — D2 has no legacy engine: render_author_config_script's
        # binary/unit logic below only knows dhcp4/dhcp6 (anything not
        # "dhcp4" is treated as dhcp6), so a d2 call falling through here
        # would silently run kea-dhcp6 -t against D2's own config content.
        if service == "d2":
            return {"ok": False, "code": "error", "detail": _D2_NEEDS_HELPER, "via": "legacy"}
        script = __authoring.render_author_config_script(
            service, path, cfg, allow_overwrite=True, dry_run=True, tls_paths=list(tls_paths or [])
        )
        out, err, rc = _legacy_python3(server, script)
        return _legacy_suffix(_parse_legacy_script_out(out, err, "legacy", rc))
    except HelperError as e:
        return {"ok": False, "code": "error", "detail": str(e), "via": "helper"}


def _jen_side_conflict(server: dict, service: str, expected: str) -> dict | None:
    """Pre-write concurrency check for a v1 / legacy host, which gives
    no raw sha. Re-reads the live config and computes the SAME
    canonical sentinel `_canonical_sentinel()` computes on a read —
    never trusting whatever `read_config_versioned()` itself happens to
    return this time, since the live host could have gained a real raw
    sha between the original read and this call (a mid-flight helper
    upgrade) and a format mismatch there must never look like a
    conflict. A mismatch against `expected` (the sentinel the caller
    read earlier) means someone else changed the config since then —
    "is what I read still what's there", the same semantics a v2
    helper's raw-sha check gives, just computed here instead of
    atomically under the helper's own file lock. Returns a conflict or
    error HostResult (and flashes once), or None to proceed.

    v5.28.0 (Q24, B2) — this is now called BEFORE any write, for every
    helper version and the legacy path alike (previously: a v1 helper
    was checked only AFTER `apply-config` had already overwritten the
    file; the legacy path already checked first). It also no longer
    special-cases "no revision recorded yet" as automatically safe —
    `expected` is always something the caller genuinely read, not a
    possibly-absent history entry, so there's always something real to
    compare against.

    v5.28.1 (Q26, A2) — a failed reread now fails CLOSED. This used to
    return None ("can't verify — let the write proceed, -t will catch
    anything wrong") but `-t` only validates the CANDIDATE's syntax; it
    has no way to know whether the live file changed since Jen's
    original read, which is the one thing this whole guard exists to
    check. An unreachable host here means the guard simply can't run —
    refusing is the only honest answer."""
    _flash_no_atomic_guard(server)
    current, _sha = read_config_versioned(server, service)
    if current is None:
        name = server.get("name") or server.get("ssh_host") or "?"
        return {
            "ok": False,
            "code": "error",
            "detail": f"Could not verify the current configuration on {name} — no changes were written.",
            "via": "jen",
        }
    if _canonical_sentinel(current) != expected:
        name = server.get("name") or server.get("ssh_host") or "?"
        return {
            "ok": False,
            "code": "conflict",
            "detail": f"the config on {name} changed since you started",
            "via": "jen",
        }
    return None


def _flash_no_atomic_guard(server: dict) -> None:
    if not has_request_context():
        return
    seen = getattr(g, "_kea_noguard_flashed", None)
    if seen is None:
        seen = g._kea_noguard_flashed = set()
    name = server.get("name") or server.get("ssh_host") or "?"
    if name in seen:
        return
    seen.add(name)
    flash(f"No atomic guard on {name}: helper v1 / legacy — the write proceeded on a best-effort check.", "warning")


def apply_config(
    server: dict,
    service: str,
    cfg: dict,
    tls_paths=(),
    allow_overwrite: bool = True,
    expect_sha256: str | None = None,
    summary: str | None = None,
    source: str = "jen",
) -> dict:
    """Write `cfg` to the host. `expect_sha256` is a value from an
    earlier `read_config_versioned()` call — a raw sha (v2 helper), a
    canonical sentinel (v1 helper or legacy — see `_canonical_sentinel`),
    or "" for "must not exist" — or None to skip the guard entirely. On
    success (any path) the applied config is recorded as a revision
    with `summary` and `source` (`source="restore"` when re-applying a
    prior revision from the history page).

    v5.28.0 (Q24, B2) — a canonical sentinel is checked HERE, before
    ANY write (helper or legacy), via `_jen_side_conflict()`. This
    replaces two separate checks that both ran only for a subset of
    hosts, one of them dangerously late: a v1 helper's check used to
    run only AFTER `apply-config` had already overwritten the file
    (the helper ignores `expect_sha256` it doesn't understand and just
    reports success — Jen's own conflict check then ran too late to
    prevent the overwrite it was supposed to guard against). The
    legacy path's check already ran first; it's unchanged in spirit,
    just moved up to sit beside the helper case. A raw sha (v2 helper)
    is unaffected — it still goes straight into the payload and the
    helper enforces it atomically under its own file lock."""
    if expect_sha256 is not None and expect_sha256.startswith(_CANONICAL_SENTINEL_PREFIX):
        conflict = _jen_side_conflict(server, service, expect_sha256)
        if conflict is not None:
            return conflict
        expect_sha256 = None  # a sentinel is never real — never sent to the helper

    path = _conf_path(server, service)
    payload = {
        "service": service,
        "path": path,
        "config": cfg,
        "tls_paths": _tls_list(tls_paths),
        "allow_overwrite": allow_overwrite,
    }
    if expect_sha256 is not None:
        payload["expect_sha256"] = expect_sha256

    result = None
    try:
        resp = helper_call(server, "apply-config", payload)
        _record_from_resp(server.get("id"), resp)
        if service == "d2" and not resp.get("ok") and resp.get("error") == "not-allowed":
            return {"ok": False, "code": "error", "detail": _D2_NEEDS_HELPER, "via": "helper"}
        result = _from_helper_test(resp, "ok")
    except HelperMissing:
        _flag_legacy(server)
        # v5.23.0 — see the identical guard in test_config(): D2 has no
        # legacy engine, and render_author_config_script's dhcp4/dhcp6-only
        # binary logic would otherwise silently run kea-dhcp6 against D2's
        # config.
        if service == "d2":
            return {"ok": False, "code": "error", "detail": _D2_NEEDS_HELPER, "via": "legacy"}
        script = __authoring.render_author_config_script(
            service, path, cfg, allow_overwrite=allow_overwrite, dry_run=False, tls_paths=list(tls_paths or [])
        )
        out, err, rc = _legacy_python3(server, script)
        result = _legacy_suffix(_parse_legacy_script_out(out, err, "legacy", rc))
    except HelperError as e:
        return {"ok": False, "code": "error", "detail": str(e), "via": "helper"}

    if result.get("ok"):
        _record_revision_after_apply(server, service, cfg, result.get("sha256"), summary, source)
        # v5.28.1 (Q26, A3) — a v1/legacy write reports no raw sha, so a
        # caller (kea_changeset's rollback) that stores this "applied
        # sha" to guard a LATER write against would otherwise guard it
        # with None — no guard at all. Give it the same canonical
        # sentinel a read would produce, computed AFTER this write (the
        # revision recorded just above still gets the real None, since
        # `_record_revision_after_apply` branches on `if sha:` to pick
        # hash_kind — this only touches the RETURNED result).
        if not result.get("sha256"):
            result["sha256"] = _canonical_sentinel(cfg)
    return result


def _record_revision_after_apply(server, service, cfg, sha, summary, source):
    try:
        from jen.services import config_revisions as _rev

        # No SHA from the helper (v1 / legacy) → compute the canonical one
        # so the row still has something stable to compare and diff, and
        # record what kind of hash it is (v5.20.0) so a later reader never
        # compares a "raw" sha against a "canonical" one.
        if sha:
            hash_kind = "raw"
        else:
            sha = hashlib.sha256(_rev.canonical(cfg).encode()).hexdigest()
            hash_kind = "canonical"
        _rev.record(
            server.get("id"), service, cfg, sha, summary or f"{source} {service}", source=source, hash_kind=hash_kind
        )
    except Exception as e:
        logger.warning(f"config revision not recorded for server {server.get('id')}/{service}: {e}")


_SERVICE_UNIT_FAM = {"dhcp4": "dhcp4", "dhcp6": "dhcp6", "d2": "dhcp-ddns"}


def service_action(server: dict, service: str, action: str) -> dict:
    """action ∈ restart | enable | disable | status."""
    try:
        resp = helper_call(server, "service", {"service": service, "action": action})
        _record_from_resp(server.get("id"), resp)
        if resp.get("ok"):
            return {
                "ok": True,
                "code": "ok",
                "unit": resp.get("unit", ""),
                "state": resp.get("state", ""),
                "via": "helper",
            }
        err = resp.get("error")
        if service == "d2" and err == "not-allowed":
            return {"ok": False, "code": "error", "detail": _D2_NEEDS_HELPER, "via": "helper"}
        if err == "no-unit":
            fam = _SERVICE_UNIT_FAM.get(service, service)
            return {
                "ok": False,
                "code": "error",
                "detail": f"no kea-{fam}-server unit on this host",
                "via": "helper",
            }
        return {
            "ok": False,
            "code": "error",
            "detail": resp.get("detail") or err or "systemctl failed",
            "via": "helper",
        }
    except HelperMissing:
        _flag_legacy(server)
        # v5.23.0 — D2 has no legacy engine (see the identical guard in
        # test_config()/apply_config()); falling through below would
        # restart kea-dhcp6-server instead of D2's own unit.
        if service == "d2":
            return {"ok": False, "code": "error", "detail": _D2_NEEDS_HELPER, "via": "legacy"}
        # v5.28.0 (Q24, B1) — the real bug this fixes: the trailing
        # marker token this used to append ran UNCONDITIONALLY, even
        # when both systemctl attempts failed, so this used to report
        # "restarted successfully" on a host where Kea never actually
        # restarted. Success is now the compound command's own exit
        # status — `cmd1 || cmd2` exits 0 iff at least one of the two
        # systemctl attempts succeeded.
        fam = _SERVICE_UNIT_FAM.get(service, service)
        act = "enable --now" if action == "enable" else "disable --now" if action == "disable" else action
        out, err, rc = _legacy_ssh(
            server,
            f"sudo systemctl {act} kea-{fam}-server 2>/dev/null || "
            f"sudo systemctl {act} isc-kea-{fam}-server 2>/dev/null",
        )
        if rc == 0:
            return {"ok": True, "code": "ok", "unit": "", "state": "", "via": "legacy"}
        return _legacy_suffix(
            {"ok": False, "code": "error", "detail": err or out or f"systemctl exited {rc}", "via": "legacy"}
        )
    except HelperError as e:
        return {"ok": False, "code": "error", "detail": str(e), "via": "helper"}


def install_tls(server: dict, service: str, files: dict) -> dict:
    """v5.29.0 (Q29, C2) — push one daemon's https material to the Kea
    host: `files` is exactly {"ca.crt", "server.crt", "server.key"} →
    PEM str (what kea_tls.issue_server_cert() returns); the helper
    writes them under /etc/kea/tls/<service>/ and nowhere else. Helper
    only — there is deliberately NO legacy fallback: this op exists so
    key material never rides a generated root script, and a host
    without a v4 helper gets {"code": "helper-required"} with the
    message the https option shows. Returns a HostResult with
    `paths` (the three remote paths) on success."""
    try:
        resp = helper_call(server, "install-tls", {"service": service, "files": files})
        _record_from_resp(server.get("id"), resp)
        if resp.get("ok"):
            return {
                "ok": True,
                "code": "ok",
                "paths": resp.get("paths", {}),
                "owner": resp.get("owner", ""),
                "via": "helper",
            }
        err = resp.get("error")
        if err == "unknown-op":  # a v1–v3 helper: the op doesn't exist there
            return {"ok": False, "code": "helper-required", "detail": _TLS_NEEDS_HELPER, "via": "helper"}
        if err == "symlink":
            return {
                "ok": False,
                "code": "error",
                "detail": f"{resp.get('path')} on the Kea host is a symlink — the helper refuses to write through it",
                "via": "helper",
            }
        if err == "bad-pem":
            return {
                "ok": False,
                "code": "error",
                "detail": f"the helper rejected {resp.get('file')} as not PEM",
                "via": "helper",
            }
        return {"ok": False, "code": "error", "detail": resp.get("detail") or err or "helper refused", "via": "helper"}
    except HelperMissing:
        _flag_legacy(server)
        return {"ok": False, "code": "helper-required", "detail": _TLS_NEEDS_HELPER, "via": "legacy"}
    except HelperError as e:
        return {"ok": False, "code": "error", "detail": str(e), "via": "helper"}


def tail_log(server: dict, path: str, lines: int = 200, timeout: int | None = None, helper_only: bool = False) -> dict:
    """Last `lines` of a log on the Kea host. `timeout` bounds the SSH round trip (default: the
    helper's 60 s / the legacy path's 30 s) — Trace passes a short one so a hung host
    cannot hold a request worker."""
    try:
        resp = helper_call(server, "tail-log", {"path": path, "lines": lines}, timeout=timeout or 60)
        _record_from_resp(server.get("id"), resp)
        if resp.get("ok"):
            return {"ok": True, "code": "ok", "lines": resp.get("lines", []), "via": "helper"}
        if resp.get("error") == "missing":
            return {"ok": False, "code": "missing", "detail": "log file not found", "via": "helper"}
        return {"ok": False, "code": "error", "detail": resp.get("detail") or resp.get("error") or "", "via": "helper"}
    except HelperMissing:
        _flag_legacy(server)
        if helper_only:
            # Trace: the legacy `sudo tail -200` grant cannot serve 1000 lines
            # anyway, and a partial log would read as a complete one.
            return {
                "ok": False,
                "code": "no-helper",
                "detail": "the Kea host helper is not installed on this host",
                "via": "helper",
            }
        # v5.28.0 (Q24, B1) — rc replaces the old "err and not out"
        # stdout/stderr-shape guess.
        out, err, rc = _legacy_ssh(server, f"sudo tail -{int(lines)} {shlex.quote(path)}", timeout=timeout or 30)
        if rc != 0:
            if "No such file" in err or "No such file" in out:
                return {"ok": False, "code": "missing", "detail": "log file not found", "via": "legacy"}
            return _legacy_suffix(
                {"ok": False, "code": "error", "detail": err or out or f"tail exited {rc}", "via": "legacy"}
            )
        return {"ok": True, "code": "ok", "lines": out.splitlines(), "via": "legacy"}
    except HelperError as e:
        return {"ok": False, "code": "error", "detail": str(e), "via": "helper"}


def install_package(server: dict, service: str) -> dict:
    try:
        resp = helper_call(server, "install-package", {"service": service}, timeout=300)
        _record_from_resp(server.get("id"), resp)
        return {
            "ok": bool(resp.get("ok")),
            "code": "ok" if resp.get("ok") else "error",
            "detail": resp.get("output", ""),
            "output": resp.get("output", ""),
            "via": "helper",
        }
    except HelperMissing:
        _flag_legacy(server)
        package = f"kea-{service}-server" if service in ("dhcp4", "dhcp6") else "kea-dhcp4-server"
        out, err, rc = _legacy_ssh(
            server,
            f"sudo apt-get update -qq 2>&1 && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {package} 2>&1",
            timeout=300,
        )
        combined = (out + "\n" + err).strip()
        tail = "\n".join(combined.splitlines()[-15:])
        # v5.28.0 (Q24, B1) — rc replaces the old "E:"/"Unable to
        # locate" text sniffing (apt's own real exit status, not a
        # guess at what its output looks like when it fails).
        ok = rc == 0
        return {"ok": ok, "code": "ok" if ok else "error", "detail": tail, "output": tail, "via": "legacy"}
    except HelperError as e:
        return {"ok": False, "code": "error", "detail": str(e), "output": str(e), "via": "helper"}


# ── helper deployment (used by the settings route) ────────────────────────


def check_helper(server: dict) -> dict:
    """Run `version`, record the status — including whether the legacy
    python3 grant is still present (v5.20.0), so Health Center can warn
    about it without SSHing at render time — return the parsed result.
    `install_helper()`'s own `check_helper()` calls get this for free.
    v5.66.0-beta.2 (Q104) — also records `helper_build` from the same
    response envelope, when the host is on v7+ and answers one."""
    grant = legacy_grant_present(server)
    try:
        resp = helper_call(server, "version", {})
        version = resp.get("helper_version") if resp.get("ok") else None
        build = resp.get("helper_build") if resp.get("ok") else None
        record_helper_status(server.get("id"), version, build=build, legacy_grant=grant)
        return {"ok": bool(version), "version": version, "build": build, "via": "helper"}
    except HelperMissing:
        record_helper_status(server.get("id"), None, legacy_grant=grant)
        return {"ok": False, "version": None, "code": "missing"}
    except HelperError as e:
        record_helper_status(server.get("id"), None, legacy_grant=grant)
        return {"ok": False, "version": None, "code": "error", "detail": str(e)}


def effective_ssh_user(server: dict) -> str:
    """The SSH user Jen actually connects to `server` as. v5.65.13 (Q102) — a maintainer report
    traced to two derivations of this disagreeing: `kea6.py::_connect_ssh` used to read
    `server.get("ssh_user", extensions.KEA_SSH_USER)`, a dict DEFAULT that never fires because
    `config.py` always sets the key (to `""` when unset), while `install_helper`/
    `remove_legacy_grant` here already used the correct `server.get("ssh_user") or
    extensions.KEA_SSH_USER`. Server 1 is unaffected (both read `[kea_ssh] user`); an EXTRA server
    with no explicit SSH user connected as the empty string while its sudoers script and status
    line named the intended global default — one function now, used everywhere the SSH user is
    needed."""
    from jen import extensions

    return server.get("ssh_user") or extensions.KEA_SSH_USER


def _sudo_l_summary(listing: str) -> str:
    """Pure: given the raw text of a full `sudo -n -l` (never `-l <cmd>` — see legacy_grant_status's
    docstring for why that specific form is uninformative here), pull out the python3 rule(s) with
    their tags and the first LATER line granting ALL without NOPASSWD - the pair that distinguishes
    "a rule after jen-kea overrides it" from "the line is genuinely missing". Returns "" when no
    python3 rule is findable at all (an unrecognised sudo -l format, or the probe produced
    nothing) - the caller falls back to sudo's own refusal reason alone."""
    lines = [line.strip() for line in (listing or "").splitlines() if line.strip()]
    python3_indices = [i for i, line in enumerate(lines) if "python3" in line]
    if not python3_indices:
        return ""
    python3_lines = [lines[i] for i in python3_indices]
    later_blanket = next(
        (line for line in lines[max(python3_indices) + 1 :] if "ALL" in line and "NOPASSWD" not in line),
        None,
    )
    summary = "python3 rule(s) on this host: " + "; ".join(python3_lines)
    if later_blanket:
        summary += f" — a LATER rule may override it: {later_blanket}"
    return summary


def legacy_grant_status(server: dict) -> dict:
    """Is the old `NOPASSWD: /usr/bin/python3` grant usable right now, and if not, WHY — sudo's
    own first stderr line, not just a boolean. v5.65.13 (Q102, a maintainer report): a bare `rc !=
    0` used to mean only "no", with no way to tell a genuinely missing grant from sudo refusing a
    CORRECT one for an unrelated reason — a later rule in /etc/sudoers.d overriding it (matched in
    file-read order, last match wins), `Defaults requiretty`/`use_pty` on a hardened box (Jen's SSH
    session has no PTY), or a plain transport failure (wrong host, key rejected). The operator was
    told to add a line they already had.

    Returns `{"ok": bool, "rc": int, "reason": str, "user_at_host": str, "summary": str}`:
    `reason` is sudo's own first stderr line (or the transport exception's own message);
    `user_at_host` names exactly who Jen probed as, so a wrong-box paste is visible at once;
    `summary` (only populated when the probe failed) is `_sudo_l_summary()` of a FULL `sudo -n -l`
    — correction from this Q's own first draft: `sudo -n -l /usr/bin/python3` is NOT the right
    probe, because `-l <cmd>`'s `listpw` default is `any` — it asks for no password, and so prints
    the command as runnable, as long as ANY of the user's rules carries NOPASSWD (the helper's own
    rule always does), even when THIS command specifically would need one."""
    user = effective_ssh_user(server)
    user_at_host = f"{user}@{server.get('ssh_host', '')}"
    try:
        out, err, rc = _legacy_ssh(server, "sudo -n /usr/bin/python3 -c 'print(1)'", timeout=15)
    except Exception as e:
        reason = f"{type(e).__name__}: {e}"
        logger.warning(f"legacy_grant_status: {user_at_host}: {reason}")
        return {"ok": False, "rc": -1, "reason": reason, "user_at_host": user_at_host, "summary": ""}
    if rc == 0:
        return {"ok": True, "rc": 0, "reason": "", "user_at_host": user_at_host, "summary": ""}
    reason_source = err or out
    reason = reason_source.splitlines()[0] if reason_source else f"sudo exited {rc}"
    summary = ""
    try:
        list_out, list_err, _list_rc = _legacy_ssh(server, "sudo -n -l", timeout=15)
        summary = _sudo_l_summary(list_out or list_err or "")
    except Exception:
        pass  # the reason above already carries the useful part; the listing is a bonus
    logger.warning(f"legacy_grant_status: {user_at_host}: sudo refused ({reason!r}); rc={rc}")
    return {"ok": False, "rc": rc, "reason": reason, "user_at_host": user_at_host, "summary": summary}


def legacy_grant_present(server: dict) -> bool:
    """Is the old `NOPASSWD: /usr/bin/python3` grant still there? Used to
    decide whether the in-app 'Install helper' button can work.

    v5.65.13 (Q102) — thin boolean wrapper over legacy_grant_status(), kept for callers (helper
    status recording, the Health row) that only ever needed the yes/no."""
    return legacy_grant_status(server)["ok"]


def remove_legacy_grant(server: dict) -> dict:
    """v5.49.0 (Q51) — remove /etc/sudoers.d/jen-kea on `server`, using
    the grant itself (it removes itself). Returns {"ok", "code":
    removed|absent|refused|no-helper|error, "detail"}.

    Jen-side gate first: the helper must already answer with a version
    >= JEN_HELPER_MIN_VERSION, so a host is never left with no working
    path. There is deliberately NO opposite operation: writing the grant
    back would be Jen handing itself root (docs/ARCHITECTURE.md §3.3) —
    granting stays by hand.

    Like every legacy-engine caller (v5.28.0), an `ok:` token only counts
    when the remote exit status was 0."""
    chk = check_helper(server)
    v = chk.get("version")
    if not isinstance(v, int) or v < JEN_HELPER_MIN_VERSION:
        return {
            "ok": False,
            "code": "no-helper",
            "detail": "the helper is not answering on this host — install it first; "
            "removing the legacy grant now would leave Jen with no root path",
        }
    script = __authoring.render_remove_legacy_grant_script(effective_ssh_user(server))
    try:
        out, err, rc = _legacy_python3(server, script, timeout=30)
    except Exception as e:
        return {"ok": False, "code": "error", "detail": str(e)}
    if rc == 0 and out in ("ok:removed", "ok:absent"):
        check_helper(server)  # the recorded legacy_grant flag flips to False
        return {"ok": True, "code": out[3:], "detail": ""}
    if out.startswith("refused:"):
        return {"ok": False, "code": "refused", "detail": out[len("refused:") :]}
    return {"ok": False, "code": "error", "detail": err or out or f"remote command exited {rc}"}


def _helper_source():
    """The jen-kea-helper text shipped with this install."""
    import os

    from jen import extensions

    path = os.path.join(extensions.JEN_ROOT, "jen-kea-helper")
    with open(path) as f:
        return f.read()


def _helper_source_bytes() -> bytes:
    """The jen-kea-helper file shipped with this install, as RAW BYTES — never text-decoded
    (v5.66.0, Q103). The signed `update` op sends these bytes to the Kea host, and they must
    be byte-identical to what release.yml actually signed; `_helper_source()` (text mode)
    stays as it was for the legacy engine, which embeds the source as a Python string literal
    inside a generated script rather than sending it verbatim."""
    import os

    from jen import extensions

    path = os.path.join(extensions.JEN_ROOT, "jen-kea-helper")
    with open(path, "rb") as f:
        return f.read()


_HELPER_SIG_MAX = 8 * 1024
_HELPER_SIG_FETCH_TIMEOUT = 10
_HELPER_SIG_VERIFY_TIMEOUT = 10


def verify_helper_signature(candidate: bytes, sig: bytes) -> bool:
    """v5.66.0-beta.2 (Q104, item g) — confirm `sig` is a genuine `jen-kea-helper`-namespace
    signature over these EXACT `candidate` bytes, issued by RELEASE_SIGNERS. The same check
    jen-kea-helper's own `update` op performs on the Kea host, run here FIRST so a stale,
    corrupted, or mismatched local signature is caught before Jen ever spends a round trip
    sending it — mirrors jen-update-root.py's verify_release_signature() (a byte-identical
    RELEASE_SIGNERS, a throwaway temp dir for both files, the same subprocess shape). Never
    raises: a missing ssh-keygen, a timeout, or any other transport hiccup is just "not
    verified", never an exception the caller has to handle specially."""
    import subprocess
    import tempfile
    from pathlib import Path

    try:
        with tempfile.TemporaryDirectory() as tmp:
            signers_path = Path(tmp) / "allowed_signers"
            sig_path = Path(tmp) / "jen-kea-helper.sig"
            signers_path.write_text(RELEASE_SIGNERS)
            sig_path.write_bytes(sig)
            result = subprocess.run(  # nosec B603 B607 — fixed argv, no shell, a throwaway temp dir
                [
                    "ssh-keygen",
                    "-Y",
                    "verify",
                    "-f",
                    str(signers_path),
                    "-I",
                    _RELEASE_SIGNATURE_IDENTITY,
                    "-n",
                    _HELPER_SIGNATURE_NAMESPACE,
                    "-s",
                    str(sig_path),
                ],
                input=candidate,
                capture_output=True,
                timeout=_HELPER_SIG_VERIFY_TIMEOUT,
            )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def _local_helper_signature(candidate: bytes) -> bytes | None:
    """The sibling file `JEN_ROOT/jen-kea-helper.sig`, written by jen-update-root.py on every
    self-update from v5.66.0 on — read bounded (v5.66.0-beta.2, Q104: the old read here had no
    cap at all) and verified against `candidate` before being trusted. Returns None (never
    raises) for "absent", "oversize", or "doesn't verify against these bytes" alike — the
    caller can't tell those apart and doesn't need to; it just falls through to a fetch."""
    import os

    from jen import extensions

    sig_path = os.path.join(extensions.JEN_ROOT, "jen-kea-helper.sig")
    try:
        with open(sig_path, "rb") as f:
            data = f.read(_HELPER_SIG_MAX + 1)
    except OSError:
        return None
    if not data or len(data) > _HELPER_SIG_MAX:
        return None
    if not verify_helper_signature(candidate, data):
        return None
    return data


def _fetch_helper_signature(candidate: bytes) -> bytes | None:
    """This release's own GitHub asset — a hand-installed tarball, a Docker image built from
    source, and a dev checkout all lack the sibling file, and (v5.66.0-beta.2, Q104) so does a
    box whose local copy no longer verifies (a corrupted sibling file, or a signature left over
    from before a key rotation). Over https, the fixed GitHub releases/download prefix only,
    read bounded to _HELPER_SIG_MAX, and verified the same way the local copy is before being
    trusted. Returns None for a routine "not available" case (network error, oversize response,
    doesn't verify); never raises, so the caller words one clean refusal either way."""
    import urllib.request

    from jen import JEN_VERSION

    url = f"https://github.com/{_GITHUB_REPO}/releases/download/v{JEN_VERSION}/jen-kea-helper.sig"
    try:
        req = urllib.request.Request(url)  # nosec B310 — https, a fixed github.com download prefix only
        with urllib.request.urlopen(req, timeout=_HELPER_SIG_FETCH_TIMEOUT) as resp:  # nosec B310
            data = resp.read(_HELPER_SIG_MAX + 1)
    except Exception:
        return None
    if not data or len(data) > _HELPER_SIG_MAX:
        return None
    if not verify_helper_signature(candidate, data):
        return None
    return data


def helper_signature(candidate: bytes) -> bytes | None:
    """The release signature for the jen-kea-helper file this install would send in a signed
    update (v5.66.0, Q103). v5.66.0-beta.2 (Q104, item g) — now PRE-VERIFIED against
    `candidate` (the exact bytes about to be sent) before either copy is trusted, not just
    fetched and handed over blindly: prefers the local sibling file if it verifies, falls back
    to a fresh fetch from this release's own GitHub asset if it doesn't (or is absent). Returns
    None only when neither source produces a signature that verifies against these exact
    bytes; never raises, so the caller words one clean refusal either way."""
    local = _local_helper_signature(candidate)
    if local is not None:
        return local
    return _fetch_helper_signature(candidate)


def _source_version(source: str) -> int:
    """HELPER_VERSION as declared by the helper text about to be copied —
    the only honest "what will the host report afterwards" number."""
    m = re.search(r"^HELPER_VERSION = (\d+)$", source, re.M)
    return int(m.group(1)) if m else JEN_HELPER_SHIPPED_VERSION


def _source_build(source: str) -> int:
    """HELPER_BUILD as declared by the helper text about to be copied — v5.66.0-beta.2
    (Q104), beside _source_version() for the same reason: the only honest "what will the
    host report afterwards" number, this time for the build ordering that survives a
    helper-only fix which doesn't bump HELPER_VERSION."""
    m = re.search(r"^HELPER_BUILD = (\d+)$", source, re.M)
    return int(m.group(1)) if m else JEN_HELPER_SHIPPED_BUILD


def _helper_self_test_command() -> str:
    """v5.66.0-beta.7 (Q109, item b) — the piece the by-hand line used to skip: the automatic
    signed-update path already preflights a candidate by running its OWN `version` op and
    checking the reply before installing it (Q104, item preflight/rollback); the by-hand line
    went straight from `ssh-keygen -Y verify` to `sudo install` with no equivalent. This runs
    the just-downloaded candidate's `version` op and exits non-zero unless the JSON reply says
    `ok: true` with EXACTLY the version/build this release's own source declares (baked in as
    literals here — V and B are read from _source_version()/_source_build() of the file this
    install ships, the same "what will the host report afterwards" numbers install_helper()
    itself targets)."""
    source = _helper_source()
    target_version = _source_version(source)
    target_build = _source_build(source)
    check = (
        "import json,sys;d=json.load(sys.stdin);"
        f'sys.exit(0 if d.get("ok") is True and d.get("helper_version")=={target_version} '
        f'and d.get("helper_build")=={target_build} else 1)'
    )
    return f"/usr/bin/python3 -I jen-kea-helper version </dev/null | /usr/bin/python3 -c '{check}'"


def _helper_verify_and_install_command() -> str:
    """The verify-then-selftest-then-install tail shared by `_helper_download_command()` (the
    online one-liner, below) and the offline/local case (a tarball install already has both
    `jen-kea-helper` and `jen-kea-helper.sig` sitting side by side — see docs/admin-guide.md
    and docs/runbooks.md § 3): both are this exact same suffix, run in the directory holding
    both files. `_helper_self_test_command()` (v5.66.0-beta.7, Q109, item b) now runs BETWEEN
    the signature verify and the install — the by-hand path used to skip the self-test the
    automatic signed-update path already performs."""
    return (
        f"printf '%s\\n' '{RELEASE_SIGNERS}' > allowed_signers && "
        f"ssh-keygen -Y verify -f allowed_signers -I {_RELEASE_SIGNATURE_IDENTITY} "
        f"-n {_HELPER_SIGNATURE_NAMESPACE} -s jen-kea-helper.sig < jen-kea-helper && "
        f"{_helper_self_test_command()} && "
        "sudo install -o root -g root -m 0755 jen-kea-helper /usr/local/sbin/jen-kea-helper"
    )


def _helper_download_command() -> str:
    """The ONE by-hand fallback anywhere in this app for installing jen-kea-helper — and
    (v5.66.0-beta.2, Q104, item b) now a VERIFIED one-liner, never an unverified copy. The old
    wording (v5.65.13, Q102: `curl ... -o /tmp/jen-kea-helper && sudo install ...`) fetched a
    release asset over plain https and installed it with no check at all — anyone who could
    intercept or spoof that one connection controlled what ran as root on the Kea host. This
    fetches BOTH the helper and its signature from this release's own GitHub asset, verifies
    the signature against the same embedded RELEASE_SIGNERS jen_update_root.py and
    jen-kea-helper itself carry — by hand, but the EXACT same `ssh-keygen -Y verify` check
    verify_helper_signature() runs in Python — self-tests the downloaded candidate (v5.66.0-
    beta.7, Q109, item b) — and only then installs it. A bad signature (a corrupted download, a
    stripped mirror, tampering in transit) makes ssh-keygen exit non-zero, and a candidate that
    doesn't self-report what it just verified as makes the self-test exit non-zero — either way
    the `&&` chain means "nothing gets installed", never "install anyway"."""
    from jen import JEN_VERSION

    base = f"https://github.com/{_GITHUB_REPO}/releases/download/v{JEN_VERSION}"
    return (
        'd="$(mktemp -d)" && cd "$d" && '
        f"curl -fsSLO {base}/jen-kea-helper && "
        f"curl -fsSLO {base}/jen-kea-helper.sig && "
        f"{_helper_verify_and_install_command()}"
    )


def _send_helper_update(server: dict, candidate: bytes, sig: bytes) -> dict:
    """Build the `update` op payload and send it — split out of _install_helper_signed
    (v5.66.0-beta.2, Q104) so a bad-signature retry with a freshly fetched signature can call
    it a second time without duplicating the base64/payload plumbing. May raise HelperMissing
    or HelperError, exactly as helper_call() itself does; the caller handles both."""
    import base64

    payload = {
        "helper_b64": base64.b64encode(candidate).decode(),
        "signature_b64": base64.b64encode(sig).decode(),
    }
    return helper_call(server, "update", payload, timeout=60)


def _install_helper_signed(server: dict, target: int, target_build: int, current: int) -> dict:
    """v5.66.0 (Q103) — helper >= SIGNED_UPDATE_HELPER_MIN_VERSION: update through the signed
    `update` op instead of the legacy engine. No sudoers grant is asked for or needed — the op
    itself verifies a release-key signature and a strictly higher HELPER_VERSION before it ever
    replaces itself; this function's only job is to supply the candidate bytes and the matching
    signature, and to word whatever the op refuses.

    v5.66.0-beta.2 (Q104, item g) — the signature is now pre-verified locally (helper_signature())
    before it's ever sent, so a `bad-signature` reply from the HOST right after a LOCALLY-sourced
    signature is unexpected enough to be worth one retry with a freshly fetched signature before
    reporting failure — it can only mean the sibling file, though cryptographically valid a
    moment ago, is somehow not what this exact release ships (e.g. a stale file left over from a
    key rotation the host's own trust hasn't caught up to yet)."""
    name = server.get("name", "this host")
    try:
        candidate = _helper_source_bytes()
    except OSError as e:
        return {"ok": False, "version": current, "code": "no-source", "detail": str(e)}

    local_sig = _local_helper_signature(candidate)
    used_local = local_sig is not None
    sig = local_sig if used_local else _fetch_helper_signature(candidate)
    if sig is None:
        # v5.66.0-beta.7 (Q109, item b) — this is one of the four cases that DOES offer the
        # by-hand line: nothing on the WIRE was ever refused here, Jen simply couldn't put
        # together a signature to send (offline, or a corrupted/rotated-away sibling file) —
        # the exact "copy both files, verify, self-test, install" the by-hand command does,
        # which a tarball install can already do straight from its own tree with no network.
        return {
            "ok": False,
            "version": current,
            "code": "no-signature",
            "detail": (
                "the signature shipped with this install does not match its helper — "
                "reinstall Jen from the release tarball, or copy the helper by hand (a tarball "
                "install already has both jen-kea-helper and jen-kea-helper.sig side by side, "
                f"so this works fully offline too): {_helper_download_command()}"
            ),
        }

    try:
        resp = _send_helper_update(server, candidate, sig)
    except (HelperMissing, HelperError) as e:
        return {"ok": False, "version": current, "code": "error", "detail": str(e)}

    if used_local and not resp.get("ok") and resp.get("error") == "bad-signature":
        fetched = _fetch_helper_signature(candidate)
        if fetched is not None:
            try:
                resp = _send_helper_update(server, candidate, fetched)
            except (HelperMissing, HelperError) as e:
                return {"ok": False, "version": current, "code": "error", "detail": str(e)}

    if resp.get("ok"):
        recheck = check_helper(server)
        real = recheck.get("version")
        real_build = recheck.get("build")
        # op_update's own preflight/postflight already guaranteed the installed file's
        # version/build equal exactly what it verified — this re-check exists to catch a
        # discrepancy in Jen's OWN view (a stale SSH round trip), not to re-derive "newer".
        build_ok = real_build is None or real_build == target_build
        if real == target and build_ok:
            return {"ok": True, "version": real, "code": "upgraded", "detail": ""}
        return {
            "ok": False,
            "version": real,
            "code": "stale",
            "detail": (
                f"the copy did not take — the host still reports helper v{real if real is not None else '?'}, "
                f"expected v{target}"
            ),
        }

    by_hand = _helper_download_command()
    reason = resp.get("error") or "error"
    wording = {
        # v5.66.0-beta.2 (Q104, item b) — the ONE bad-signature retry above already tried a
        # freshly fetched signature; a second refusal means the release itself is the problem,
        # not this host's copy of anything — and a by-hand install would fail the exact same
        # verification, so it's never offered as a way around it.
        "bad-signature": (
            f"{name} refused the signature on this release's helper — that points at a problem with the "
            f"release itself, not this host. Do not install it by hand: the same signature would fail "
            f"there too. Reinstall Jen from the release tarball and retry; if it persists, please report it."
        ),
        "no-ssh-keygen": f"{name} has no ssh-keygen (openssh-client) — install it there and retry.",
        "not-newer": f"{name} already reports v{current}, which is not older than this release's helper — nothing to do.",
        # v5.66.0-beta.7 (Q109, item b) — symlink and unparseable used to offer a by-hand
        # install as a way around the refusal; neither is a case where installing around it is
        # safe. A pre-planted symlink at the installed path may mean something else on the
        # host is already interfering with it, and an unparseable readback means the host's own
        # copy of a release Jen already trusts didn't behave as declared — both need a human to
        # look at the host, not another unattended write to it.
        "symlink": (
            f"the installed path on {name} is a symlink, not a plain file — nothing was changed. "
            f"Investigate it by hand before retrying; do not install over it."
        ),
        "unparseable": (
            f"{name}'s own copy of this release's helper could not be read back — nothing was changed. "
            f"This should not happen; please report it rather than installing over it."
        ),
        "preflight-failed": (
            f"{name} refused to install this release's helper: it does not run cleanly there ({resp.get('detail', '')}) "
            f"— the currently-installed helper was left untouched. Please report this."
        ),
        "postflight-failed": (
            f"{name} rolled the update back on its own: the newly-installed helper did not answer correctly "
            f"({resp.get('detail', '')}) — the previous helper is restored and working. Please report this."
        ),
        # v5.66.0-beta.4 (Q106) — HELPER_BUILD 8: update() refuses BEFORE writing anything when
        # there is nothing installed to update, instead of installing with no way back.
        "not-installed": (
            f"{name} has no helper at /usr/local/sbin/jen-kea-helper to update — install it by hand instead: {by_hand}"
        ),
        # v5.66.0-beta.4 (Q106) — the rollback after a postflight failure is now unconditional;
        # THIS is what fires when that rollback itself fails (disk full, permissions changed
        # mid-flight) — the host may be left with the broken candidate live and the old bytes
        # stranded at .prev, so both paths are named and this needs hands immediately.
        "rollback-failed": (
            f"{name} failed to update AND failed to roll back ({resp.get('detail', '')}) — this needs hands "
            f"on the host right now: check {resp.get('path', '/usr/local/sbin/jen-kea-helper')} and its saved "
            f"copy at {resp.get('prev_path', '/usr/local/sbin/jen-kea-helper.prev')} by hand before retrying."
        ),
    }
    code = reason if reason in wording else "error"
    # v5.66.0-beta.7 (Q109, item b) — an unrecognized refusal is exactly the "investigate,
    # don't install around it" case: this app has never seen the host say this before, so
    # installing over it by hand would be a guess, not a fix.
    detail = wording.get(
        reason, f'the signed update was refused on {name}: "{reason}" — nothing was changed; please report it.'
    )
    return {"ok": False, "version": current, "code": code, "detail": detail}


def install_helper(server: dict) -> dict:
    """Deploy (or upgrade) jen-kea-helper onto `server`. Returns
    {"ok": bool, "version": int|None, "code": str, "detail": str}.

    v5.19.1 — this used to short-circuit "already" at
    JEN_HELPER_MIN_VERSION, so a v1 host answered "already installed"
    forever and the "Update helper" button was a no-op. It now targets
    JEN_HELPER_WANT_VERSION, and never trusts the remote script's own
    echoed version number for the final answer — it re-runs
    check_helper() after the copy and reports what the host actually
    says, because a copy that silently didn't take (wrong path, stale
    cache, a second file shadowing it) should never be recorded as a
    successful upgrade.

    v5.66.0 (Q103) — a host already at SIGNED_UPDATE_HELPER_MIN_VERSION takes the signed
    `update` path (`_install_helper_signed`) and never touches the legacy engine at all; the
    legacy `sudo python3` path below is now reached only to get a host TO v6 in the first
    place (a fresh install, or the v5→v6 hop) — the one place it is still used deliberately."""
    try:
        source = _helper_source()
    except OSError as e:
        return {"ok": False, "version": None, "code": "no-source", "detail": str(e)}
    # v5.29.2 — the target is the version of the file being copied, not
    # WANT: WANT (2) is the "upgrade available" nag threshold, and gating
    # the copy on it meant a v3 host got "already installed" back from the
    # Update helper button that v5.29.1 had just put in front of it.
    target = _source_version(source)
    target_build = _source_build(source)

    chk = check_helper(server)
    current = chk.get("version")
    current_build = chk.get("build")
    # v5.66.0-beta.2 (Q104) — compare builds too when the host actually reports one (v7+):
    # same VERSION, lower BUILD is a real update to offer (a helper-only fix, no protocol
    # change), not "already". A host below v7 never reports a build, so this falls back to
    # version alone exactly as it always did.
    # v5.66.0-beta.7 (Q109) — the two checks are now INDEPENDENT, mirroring op_update's own
    # fix: a lexicographic (current, current_build) >= (target, target_build) tuple compare
    # had the identical gap the helper's own not-newer check had — a HIGHER target version
    # with a not-newer build read as "not already" (current tuple < target tuple, since
    # version dominates lexicographic order) and would have been offered as an update the
    # helper's own op_update would then have refused as build-not-newer. "Already" now means
    # either side alone already disqualifies the target from being a real update.
    if isinstance(current, int):
        if isinstance(current_build, int):
            already = target < current or target_build <= current_build
        else:
            already = current >= target
        if already:
            return {"ok": True, "version": current, "code": "already", "detail": ""}

    if isinstance(current, int) and current >= SIGNED_UPDATE_HELPER_MIN_VERSION:
        return _install_helper_signed(server, target, target_build, current)

    status = legacy_grant_status(server)
    if not status["ok"]:
        # v5.65.13 (Q102) — a maintainer report traced to this exact spot: a plain "no legacy
        # grant" was the ONLY answer this route ever gave, even when the grant genuinely existed
        # and sudo refused it for an unrelated reason. The wording now says what sudo actually
        # said, and steers by which reason it was.
        # v5.66.0 (Q103) — this branch is now reached only below SIGNED_UPDATE_HELPER_MIN_VERSION,
        # so the wording says so: this is the LAST time this host will ever need the grant.
        name = server.get("name", "this host")
        by_hand = _helper_download_command()
        reason_lower = status["reason"].lower()
        if current is None:
            detail = (
                f"no legacy python3 grant to install through (probed as {status['user_at_host']}: sudo said "
                f'"{status["reason"]}") — needed once, to reach helper v{SIGNED_UPDATE_HELPER_MIN_VERSION}; '
                "every update after that is signed and needs no grant"
            )
        elif "tty" in reason_lower or "terminal" in reason_lower:
            detail = (
                f"helper v{current} is installed but v{target} needs the legacy python3 grant for this one "
                f"last hop (from v{SIGNED_UPDATE_HELPER_MIN_VERSION}, updates are signed and need no grant), "
                f'and Jen runs sudo without a terminal on {name}: sudo said "{status["reason"]}" — remove '
                f"requiretty/use_pty for this SSH user, or copy the helper by hand: {by_hand}"
            )
        else:
            override_note = f" ({status['summary']})" if status["summary"] else ""
            detail = (
                f"helper v{current} is installed but v{target} needs the legacy python3 grant for this one "
                f"last hop (from v{SIGNED_UPDATE_HELPER_MIN_VERSION}, updates are signed and need no grant), "
                f'and sudo refused it on {name}: "{status["reason"]}" — a rule later in /etc/sudoers.d may be '
                f"overriding the jen-kea line; check with `sudo -l`{override_note}, or copy the helper by "
                f"hand: {by_hand}"
            )
        return {"ok": False, "version": current, "code": "no-path", "detail": detail}

    script = __authoring.render_install_helper_script(source, effective_ssh_user(server), target)
    # v5.28.0 (Q24, B1) — _legacy_python3 now returns a 3-tuple; this
    # function's own success signal is unaffected (it already
    # independently re-verifies via a fresh check_helper() call below
    # rather than trusting this script's stdout alone).
    out, err, _rc = _legacy_python3(server, script, timeout=60)
    if out.startswith("ok:"):
        recheck = check_helper(server)
        real = recheck.get("version")
        if isinstance(real, int) and real >= target:
            code = "upgraded" if current is not None else "installed"
            return {"ok": True, "version": real, "code": code, "detail": ""}
        return {
            "ok": False,
            "version": real,
            "code": "stale",
            "detail": (
                f"the copy did not take — the host still reports helper v{real if real is not None else '?'}, "
                f"expected v{target}"
            ),
        }
    if out.startswith("sudoerror:"):
        return {"ok": False, "version": current, "code": "sudoerror", "detail": out[len("sudoerror:") :]}
    if out.startswith("writeerror:"):
        return {"ok": False, "version": current, "code": "writeerror", "detail": out[len("writeerror:") :]}
    return {"ok": False, "version": current, "code": "error", "detail": err or out or "helper install failed"}
