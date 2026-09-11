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

HELPER_PATH = "/usr/local/sbin/jen-kea-helper"
JEN_HELPER_MIN_VERSION = 1
# v5.16.0 — the version Jen wants for atomic-guarded writes + external
# change capture. A host below this still works; the Settings → Kea SSH
# table shows an "upgrade available" hint and nothing else changes.
JEN_HELPER_WANT_VERSION = 2
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


def record_helper_status(server_id, version) -> None:
    """Called after every helper attempt: `version` is the integer
    reported by a `version` op, an int carried forward for any other
    successful op, or None for HelperMissing."""
    if server_id is None:
        return
    data = helper_status()
    data[str(server_id)] = {"version": version, "checked": datetime.now(timezone.utc).isoformat()}
    try:
        _user().set_global_setting(_HELPER_STATUS_KEY, json.dumps(data))
    except Exception as e:
        logger.warning(f"could not persist kea_helper_status: {e}")


def _known_version(server_id):
    return helper_status().get(str(server_id), {}).get("version")


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


def _legacy_python3(server: dict, script: str, timeout: int = 30) -> tuple[str, str]:
    """`echo <b64> | base64 -d | sudo python3` — the pre-5.11.0 path."""
    import base64

    ssh = __kea6._connect_ssh(server)
    try:
        enc = base64.b64encode(script.encode()).decode()
        _stdin, stdout, stderr = ssh.exec_command(f"echo {enc} | base64 -d | sudo python3", timeout=timeout)
        return stdout.read().decode("utf-8", "replace").strip(), stderr.read().decode("utf-8", "replace").strip()
    finally:
        with contextlib.suppress(Exception):
            ssh.close()


def _legacy_ssh(server: dict, command: str, timeout: int = 30) -> tuple[str, str]:
    ssh = __kea6._connect_ssh(server)
    try:
        _stdin, stdout, stderr = ssh.exec_command(command, timeout=timeout)
        return stdout.read().decode("utf-8", "replace").strip(), stderr.read().decode("utf-8", "replace").strip()
    finally:
        with contextlib.suppress(Exception):
            ssh.close()


def _parse_legacy_script_out(out: str, err: str, via: str) -> dict:
    """Map the old script's stdout tokens onto a HostResult."""
    if out in ("ok", "preview-ok"):
        return {"ok": True, "code": out, "via": via}
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


def read_config_versioned(server: dict, service: str) -> tuple[dict | None, str | None]:
    """(parsed config, sha256-of-raw-bytes). The SHA is None on a v1
    helper or the legacy path — Jen then falls back to a canonical-JSON
    compare for the concurrency guard, and skips external-change capture.

    v5.16.0 — when the SHA is known and differs from the newest recorded
    revision's, the on-host file was hand-edited since Jen last wrote it:
    record it as an `external` revision so the history stays complete."""
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

    if cfg is not None and sha:
        _capture_external_change(server.get("id"), service, cfg, sha)
    return cfg, sha


def read_config(server: dict, service: str) -> dict | None:
    """The parsed Kea config for `service` on `server`, or None if it's
    missing or unreadable. Thin wrapper over read_config_versioned()."""
    return read_config_versioned(server, service)[0]


def _capture_external_change(server_id, service: str, cfg: dict, sha: str) -> None:
    if server_id is None:
        return
    try:
        from jen.services import config_revisions as _rev

        last = _rev.latest(server_id, service)
        if last is not None and last.get("sha256") and last["sha256"] != sha:
            _rev.record(server_id, service, cfg, sha, "changed outside Jen", source="external")
    except Exception as e:
        logger.warning(f"external-change capture failed for server {server_id}/{service}: {e}")


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
        return _from_helper_test(resp, "preview-ok")
    except HelperMissing:
        _flag_legacy(server)
        script = __authoring.render_author_config_script(
            service, path, cfg, allow_overwrite=True, dry_run=True, tls_paths=list(tls_paths or [])
        )
        out, err = _legacy_python3(server, script)
        return _legacy_suffix(_parse_legacy_script_out(out, err, "legacy"))
    except HelperError as e:
        return {"ok": False, "code": "error", "detail": str(e), "via": "helper"}


def _jen_side_conflict(server: dict, service: str, cfg: dict) -> dict | None:
    """Best-effort concurrency check for a v1 / legacy host, which gives
    no SHA. Re-read the live file and compare its canonical JSON against
    the newest recorded revision; a mismatch means someone else changed
    it. Returns a conflict HostResult (and flashes once) or None to
    proceed. `cfg` is the config Jen is about to write (unused for the
    compare — the reference is the last *recorded* config, not the
    incoming one)."""
    from jen.services import config_revisions as _rev

    _flash_no_atomic_guard(server)
    last = _rev.latest(server.get("id"), service)
    if last is None:
        return None  # nothing to compare against — first write for this server/service
    current, _sha = read_config_versioned(server, service)
    if current is None:
        return None  # can't read it back — let the write proceed and be validated by -t
    if _rev.canonical(current) != _rev.canonical(json.loads(last["config"])):
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
    """Write `cfg` to the host. `expect_sha256` (a SHA from an earlier
    read, or "" for "must not exist") makes the write conditional — the
    v2 helper enforces it atomically under a file lock; a v1 / legacy
    host gets a best-effort canonical-JSON compare instead. On success
    (any path) the applied config is recorded as a revision with
    `summary` and `source` (`source="restore"` when re-applying a prior
    revision from the history page)."""
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
        # A v1 helper ignores expect_sha256 → fall back to the Jen-side check.
        if (
            expect_sha256 is not None
            and (resp.get("helper_version") or JEN_HELPER_MIN_VERSION) < JEN_HELPER_WANT_VERSION
            and resp.get("error") != "conflict"
        ):
            conflict = _jen_side_conflict(server, service, cfg)
            if conflict is not None:
                return conflict
        result = _from_helper_test(resp, "ok")
    except HelperMissing:
        _flag_legacy(server)
        if expect_sha256 is not None:
            conflict = _jen_side_conflict(server, service, cfg)
            if conflict is not None:
                return conflict
        script = __authoring.render_author_config_script(
            service, path, cfg, allow_overwrite=allow_overwrite, dry_run=False, tls_paths=list(tls_paths or [])
        )
        out, err = _legacy_python3(server, script)
        result = _legacy_suffix(_parse_legacy_script_out(out, err, "legacy"))
    except HelperError as e:
        return {"ok": False, "code": "error", "detail": str(e), "via": "helper"}

    if result.get("ok"):
        _record_revision_after_apply(server, service, cfg, result.get("sha256"), summary, source)
    return result


def _record_revision_after_apply(server, service, cfg, sha, summary, source):
    try:
        from jen.services import config_revisions as _rev

        # No SHA from the helper (v1 / legacy) → compute the canonical one
        # so the row still has something stable to compare and diff.
        sha = sha or hashlib.sha256(_rev.canonical(cfg).encode()).hexdigest()
        _rev.record(server.get("id"), service, cfg, sha, summary or f"{source} {service}", source=source)
    except Exception as e:
        logger.warning(f"config revision not recorded for server {server.get('id')}/{service}: {e}")


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
        if err == "no-unit":
            return {
                "ok": False,
                "code": "error",
                "detail": f"no kea-{service}-server unit on this host",
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
        fam = "dhcp4" if service == "dhcp4" else "dhcp6"
        act = "enable --now" if action == "enable" else "disable --now" if action == "disable" else action
        out, err = _legacy_ssh(
            server,
            f"sudo systemctl {act} kea-{fam}-server 2>/dev/null || "
            f"sudo systemctl {act} isc-kea-{fam}-server 2>/dev/null; echo done",
        )
        if out.endswith("done"):
            return {"ok": True, "code": "ok", "unit": "", "state": "", "via": "legacy"}
        return _legacy_suffix(
            {"ok": False, "code": "error", "detail": err or out or "systemctl failed", "via": "legacy"}
        )
    except HelperError as e:
        return {"ok": False, "code": "error", "detail": str(e), "via": "helper"}


def tail_log(server: dict, path: str, lines: int = 200) -> dict:
    try:
        resp = helper_call(server, "tail-log", {"path": path, "lines": lines})
        _record_from_resp(server.get("id"), resp)
        if resp.get("ok"):
            return {"ok": True, "code": "ok", "lines": resp.get("lines", []), "via": "helper"}
        if resp.get("error") == "missing":
            return {"ok": False, "code": "missing", "detail": "log file not found", "via": "helper"}
        return {"ok": False, "code": "error", "detail": resp.get("detail") or resp.get("error") or "", "via": "helper"}
    except HelperMissing:
        _flag_legacy(server)
        out, err = _legacy_ssh(server, f"sudo tail -{int(lines)} {shlex.quote(path)}")
        if "No such file" in err or "No such file" in out:
            return {"ok": False, "code": "missing", "detail": "log file not found", "via": "legacy"}
        if err and not out:
            return _legacy_suffix({"ok": False, "code": "error", "detail": err, "via": "legacy"})
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
        out, err = _legacy_ssh(
            server,
            f"sudo apt-get update -qq 2>&1 && sudo DEBIAN_FRONTEND=noninteractive apt-get install -y {package} 2>&1",
            timeout=300,
        )
        combined = (out + "\n" + err).strip()
        tail = "\n".join(combined.splitlines()[-15:])
        ok = "E:" not in combined and "Unable to locate" not in combined
        return {"ok": ok, "code": "ok" if ok else "error", "detail": tail, "output": tail, "via": "legacy"}
    except HelperError as e:
        return {"ok": False, "code": "error", "detail": str(e), "output": str(e), "via": "helper"}


# ── helper deployment (used by the settings route) ────────────────────────


def check_helper(server: dict) -> dict:
    """Run `version`, record the status, return the parsed result."""
    try:
        resp = helper_call(server, "version", {})
        version = resp.get("helper_version") if resp.get("ok") else None
        record_helper_status(server.get("id"), version)
        return {"ok": bool(version), "version": version, "via": "helper"}
    except HelperMissing:
        record_helper_status(server.get("id"), None)
        return {"ok": False, "version": None, "code": "missing"}
    except HelperError as e:
        record_helper_status(server.get("id"), None)
        return {"ok": False, "version": None, "code": "error", "detail": str(e)}


def legacy_grant_present(server: dict) -> bool:
    """Is the old `NOPASSWD: /usr/bin/python3` grant still there? Used to
    decide whether the in-app 'Install helper' button can work."""
    try:
        out, _err = _legacy_ssh(server, "sudo -n /usr/bin/python3 -c 'print(1)' 2>&1", timeout=15)
        return out.strip() == "1"
    except Exception:
        return False


def _helper_source():
    """The jen-kea-helper text shipped with this install."""
    import os

    from jen import extensions

    path = os.path.join(extensions.JEN_ROOT, "jen-kea-helper")
    with open(path) as f:
        return f.read()


def install_helper(server: dict) -> dict:
    """Deploy (or upgrade) jen-kea-helper onto `server` — the one place
    the legacy `sudo python3` path is still used deliberately. Returns
    {"ok": bool, "version": int|None, "code": str, "detail": str}.

    v5.19.1 — this used to short-circuit "already" at
    JEN_HELPER_MIN_VERSION, so a v1 host answered "already installed"
    forever and the "Update helper" button was a no-op. It now targets
    JEN_HELPER_WANT_VERSION, and never trusts the remote script's own
    echoed version number for the final answer — it re-runs
    check_helper() after the copy and reports what the host actually
    says, because a copy that silently didn't take (wrong path, stale
    cache, a second file shadowing it) should never be recorded as a
    successful upgrade."""
    from jen import extensions

    try:
        source = _helper_source()
    except OSError as e:
        return {"ok": False, "version": None, "code": "no-source", "detail": str(e)}

    chk = check_helper(server)
    current = chk.get("version")
    if isinstance(current, int) and current >= JEN_HELPER_WANT_VERSION:
        return {"ok": True, "version": current, "code": "already", "detail": ""}

    if not legacy_grant_present(server):
        if current is None:
            detail = "no legacy python3 grant to install through"
        else:
            detail = (
                f"helper v{current} is installed but v{JEN_HELPER_WANT_VERSION} needs the legacy python3 grant "
                "to be re-added for one run, or copy it by hand: sudo install -o root -g root -m 0755 "
                "./jen-kea-helper /usr/local/sbin/jen-kea-helper"
            )
        return {"ok": False, "version": current, "code": "no-path", "detail": detail}

    ssh_user = server.get("ssh_user") or extensions.KEA_SSH_USER
    script = __authoring.render_install_helper_script(source, ssh_user, JEN_HELPER_WANT_VERSION)
    out, err = _legacy_python3(server, script, timeout=60)
    if out.startswith("ok:"):
        recheck = check_helper(server)
        real = recheck.get("version")
        if isinstance(real, int) and real >= JEN_HELPER_WANT_VERSION:
            code = "upgraded" if current is not None else "installed"
            return {"ok": True, "version": real, "code": code, "detail": ""}
        return {
            "ok": False,
            "version": real,
            "code": "stale",
            "detail": (
                f"the copy did not take — the host still reports helper v{real if real is not None else '?'}, "
                f"expected v{JEN_HELPER_WANT_VERSION}"
            ),
        }
    if out.startswith("sudoerror:"):
        return {"ok": False, "version": current, "code": "sudoerror", "detail": out[len("sudoerror:") :]}
    if out.startswith("writeerror:"):
        return {"ok": False, "version": current, "code": "writeerror", "detail": out[len("writeerror:") :]}
    return {"ok": False, "version": current, "code": "error", "detail": err or out or "helper install failed"}
