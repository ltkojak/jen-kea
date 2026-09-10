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
    return {"ok": False, "code": "error", "detail": resp.get("detail") or err or "helper refused", "via": "helper"}


# ── high-level API ────────────────────────────────────────────────────────


def _conf_path(server, service):
    return __authoring.conf_path_for(server, service)


def read_config(server: dict, service: str) -> dict | None:
    """The parsed Kea config for `service` on `server`, or None if it's
    missing or unreadable."""
    path = _conf_path(server, service)
    try:
        resp = helper_call(server, "read-config", {"service": service, "path": path})
        record_helper_status(server.get("id"), _known_version(server.get("id")) or JEN_HELPER_MIN_VERSION)
        if resp.get("ok"):
            return resp.get("config")
        return None
    except HelperMissing:
        _flag_legacy(server)
        ssh = __kea6._connect_ssh(server)
        try:
            return __authoring.read_remote_json(ssh, path)
        finally:
            with contextlib.suppress(Exception):
                ssh.close()
    except HelperError as e:
        logger.warning(f"read-config helper error on {server.get('name')}: {e}")
        return None


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
        record_helper_status(server.get("id"), _known_version(server.get("id")) or JEN_HELPER_MIN_VERSION)
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


def apply_config(server: dict, service: str, cfg: dict, tls_paths=(), allow_overwrite: bool = True) -> dict:
    path = _conf_path(server, service)
    try:
        resp = helper_call(
            server,
            "apply-config",
            {
                "service": service,
                "path": path,
                "config": cfg,
                "tls_paths": _tls_list(tls_paths),
                "allow_overwrite": allow_overwrite,
            },
        )
        record_helper_status(server.get("id"), _known_version(server.get("id")) or JEN_HELPER_MIN_VERSION)
        return _from_helper_test(resp, "ok")
    except HelperMissing:
        _flag_legacy(server)
        script = __authoring.render_author_config_script(
            service, path, cfg, allow_overwrite=allow_overwrite, dry_run=False, tls_paths=list(tls_paths or [])
        )
        out, err = _legacy_python3(server, script)
        return _legacy_suffix(_parse_legacy_script_out(out, err, "legacy"))
    except HelperError as e:
        return {"ok": False, "code": "error", "detail": str(e), "via": "helper"}


def service_action(server: dict, service: str, action: str) -> dict:
    """action ∈ restart | enable | disable | status."""
    try:
        resp = helper_call(server, "service", {"service": service, "action": action})
        record_helper_status(server.get("id"), _known_version(server.get("id")) or JEN_HELPER_MIN_VERSION)
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
        record_helper_status(server.get("id"), _known_version(server.get("id")) or JEN_HELPER_MIN_VERSION)
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
        record_helper_status(server.get("id"), _known_version(server.get("id")) or JEN_HELPER_MIN_VERSION)
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
    """Deploy jen-kea-helper onto `server` — the one place the legacy
    `sudo python3` path is still used deliberately. Returns
    {"ok": bool, "version": int|None, "code": str, "detail": str}."""
    from jen import extensions

    try:
        source = _helper_source()
    except OSError as e:
        return {"ok": False, "version": None, "code": "no-source", "detail": str(e)}

    # Already there and current? Don't need the legacy grant then.
    chk = check_helper(server)
    if chk.get("version") and chk["version"] >= JEN_HELPER_MIN_VERSION:
        return {"ok": True, "version": chk["version"], "code": "already", "detail": ""}

    if not legacy_grant_present(server):
        return {"ok": False, "version": None, "code": "no-path", "detail": "no legacy python3 grant to install through"}

    ssh_user = server.get("ssh_user") or extensions.KEA_SSH_USER
    script = __authoring.render_install_helper_script(source, ssh_user, JEN_HELPER_MIN_VERSION)
    out, err = _legacy_python3(server, script, timeout=60)
    if out.startswith("ok:"):
        try:
            version = int(out[3:].strip() or 0)
        except ValueError:
            version = JEN_HELPER_MIN_VERSION
        record_helper_status(server.get("id"), version)
        return {"ok": True, "version": version, "code": "installed", "detail": ""}
    if out.startswith("sudoerror:"):
        return {"ok": False, "version": None, "code": "sudoerror", "detail": out[len("sudoerror:") :]}
    if out.startswith("writeerror:"):
        return {"ok": False, "version": None, "code": "writeerror", "detail": out[len("writeerror:") :]}
    return {"ok": False, "version": None, "code": "error", "detail": err or out or "helper install failed"}
