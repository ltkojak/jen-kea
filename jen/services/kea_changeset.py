"""
jen/services/kea_changeset.py
──────────────────────────────
v5.28.0 (Q24, C1) — a shared multi-server "change set" for every
push-a-config-edit-to-every-SSH-server flow (subnets, shared networks,
DDNS naming, D2 domains/keys). Read → mutate → PREFLIGHT every target
→ commit sequentially → revert already-committed targets if a later
one fails → restart.

This replaces an identical read/mutate/apply/restart loop that used to
be duplicated (and drifting) across subnets.py and ddns.py: each
server was handled independently, so server A could succeed and
server B could fail with no attempt to undo A — "Kea A = new config,
Kea B = old config", sometimes with Jen's own SUBNET_MAP updated to
match neither. Preflighting every target with `kea_host.test_config()`
before the first real write, and reverting on a later failure, closes
that gap. This module never touches Jen's own metadata (SUBNET_MAP,
audit log) — callers do that only when `ChangeSetResult.status` is
not in `NOT_APPLIED` ("aborted", "rolled_back", "rollback_failed";
see kea_changeset's callers in subnets.py/ddns.py/infrastructure.py):
"ok", "nothing" and "noservers" all mean nothing was left
half-written, so a metadata write is safe in each of those cases.

v5.65.1 (Q90) — a restart that fails after the config was written no
longer leaves the new config on disk and the daemon down. Every target
is put back on its previous config and restarted again: "rolled_back"
when that worked everywhere (the change did not happen — same rule as
"aborted"), "rollback_failed" when a revert or the second restart did
not (a mixed or stopped state that needs a person). The old
"restart_failed" status is retired: it rested on "the config is still
live and valid", which is false when the daemon cannot start from the
config it was just handed. And nothing in here raises any more: an SSH
failure in the preflight, the commit, the revert or the restart is a
recorded failure, so a transport error can no longer skip the revert
and leave the first server on the new config.

Pure orchestration over `kea_host` — no Flask imports. Callers build
the flash lines from `ChangeSetResult.lines` themselves; this module
never calls `flash()`.
"""

import logging
from dataclasses import dataclass, field

from jen import extensions
from jen.services import events as _events
from jen.services import kea_host as _host

logger = logging.getLogger(__name__)

# Matches jen/services/kea_authoring.py's _CONF_FILENAMES — d2's file is
# kea-dhcp-ddns.conf, not "kea-d2.conf".
_CONF_FILENAMES = {"dhcp4": "kea-dhcp4.conf", "dhcp6": "kea-dhcp6.conf", "d2": "kea-dhcp-ddns.conf"}


@dataclass
class Target:
    """One server that will (or did) receive the mutated config."""

    server: dict
    name: str
    before_cfg: dict
    before_sha: str | None
    after_cfg: dict | None = None
    code: str = "ok"
    applied_sha: str | None = None
    note: str = ""


@dataclass
class ChangeSetResult:
    # "ok" | "nothing" | "noservers" | "aborted" | "rolled_back" | "rollback_failed"
    status: str
    last_code: str  # the last mutate code seen — callers map it to their own message
    lines: list[tuple[str, str]] = field(default_factory=list)  # ("success"|"warning"|"error", text), in order
    restart_failures: list[str] = field(default_factory=list)  # server names whose restart failed
    # servers a person has to look at: the ones a failed revert / second restart left wrong
    needs_hands: list[str] = field(default_factory=list)
    # the servers an "ok" run actually changed and restarted (v5.65.8): what record_outcome checks
    # before it lets a run clear a rollback_failed banner
    covered: list[str] = field(default_factory=list)


# The statuses after which the change did NOT happen (or is half-applied): callers must not write
# Jen's own metadata (SUBNET_MAP, audit "done" lines) for these.
NOT_APPLIED = ("aborted", "rolled_back", "rollback_failed")

_DETAIL_TAIL = 300


def _safe(fn, *args, **kwargs) -> dict:
    """Call a kea_host operation; a raised exception (paramiko refusing the
    connection, a socket timeout ...) becomes a not-ok result instead of
    escaping — kea_host.apply_config / test_config / service_action catch only
    the helper's own errors, so a dead sshd used to raise straight through
    Phase 3 with the first server already committed."""
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        logger.warning(f"kea_changeset: {getattr(fn, '__name__', 'call')} raised {type(e).__name__}: {e}")
        return {"ok": False, "code": "error", "detail": f"{type(e).__name__}: {e}"}


def _tail(text) -> str:
    text = str(text or "").strip()
    return text if len(text) <= _DETAIL_TAIL else "…" + text[-_DETAIL_TAIL:]


def _by_hand(names) -> str:
    return (
        f"{', '.join(names)} need attention: check the config on the host, restore the last good one from "
        "Servers → Config history, and restart Kea there by hand."
    )


def _default_conflict_phrase(name: str) -> str:
    return f"the config on {name} changed since you started"


def _failure_line(name: str, res: dict, daemon_label: str) -> str:
    """The existing per-code phrase every converted loop already used,
    for a `test_config`/`apply_config` result that came back not-ok.
    `conflict` is handled by the caller (see `conflict_phrase` below) —
    this never sees a conflict result."""
    code = res.get("code")
    if code == "missingbinary":
        return f"❌ {name}: {res.get('binary')} is not installed on this server — install it and try again."
    if code == "testerror":
        return (
            f"❌ {name}: config validation failed — {daemon_label} NOT restarted, "
            f"original config preserved. Error: {res.get('detail')}"
        )
    return f"❌ {name}: {res.get('detail', code)}"


def _run_change(
    service: str,
    mutate_fn,
    summary: str,
    *,
    servers: list[dict] | None = None,
    expected_sha_for=None,
    restart: bool = True,
    skip_codes=("notfound", "nochange"),
    code_messages: dict[str, str] | None = None,
    conflict_phrase=None,
    daemon_label: str = "Kea",
    tls_paths=(),
) -> ChangeSetResult:
    """Push one config mutation to every SSH-configured Kea server for
    `service` ("dhcp4" | "dhcp6" | "d2"), preflighting all of them
    before the first real write and reverting already-applied targets
    if a later one fails.

    `mutate_fn(cfg) -> (after_cfg, code)` — `code == "ok"` means apply
    this target; a code in `skip_codes` means skip this ONE target
    (the changeset continues with the rest, a line is still added,
    using `code_messages.get(code, code)` as the phrase after
    "{name}: " and rendered as a success-shaped "ℹ️ {name}: {phrase}"
    line — every current skip case (delete_subnet's "not in Kea's
    config", edit's "nothing to change", D2's "not found"/"still
    referenced") is exactly this shape: informational, not a failure,
    and never blocks the OTHER servers); any other code ABORTS THE
    WHOLE CHANGE SET before any write happens — a subnet ID that
    already exists on server B, say, must not let server A get created
    while B is skipped, leaving the two servers disagreeing.

    `expected_sha_for(server)` overrides the sha this function guards
    a write with (edit_subnet_post's form carries a `base_sha_<id>`
    per server, read when the FORM was opened, not now); defaults to
    the sha this function just read for that server.

    `code_messages` also supplies the phrase for the abort case (any
    non-ok, non-skip mutate code) — e.g. `{"exists": 'a shared network
    named "x" already exists'}` — matching the pre-Q24
    `_apply_dhcp4_change(mutate_fn, done_phrase, code_messages, ...)`
    signature exactly, so its existing callers' dicts keep working
    unchanged.

    `conflict_phrase(name) -> str` lets a caller supply its own exact
    wording for a `code == "conflict"` result (`_conflict_flash()` and
    its ddns.py equivalents live in the routes layer, not here); it
    defaults to a generic phrase.

    `tls_paths` (v5.29.0, Q29) — `[(remote_path, "file"), ...]` the
    mutated config references (an https control socket's trust-anchor,
    cert-file, key-file); passed through to both the preflight and the
    commit so the helper refuses with `tlsmissing` BEFORE the daemon is
    restarted into a config it can't load. The rollback re-applies the
    pre-change config, which referenced none of them.

    Never raises — a per-server exception during planning aborts the
    whole change set with that exception's text as the line, matching
    every converted loop's existing `except Exception as e:
    errors.append(f"❌ {name}: {e}")` shape exactly (so
    tests/test_no_raw_exception_leaks.py's allowlist state doesn't
    need a new entry — this is the identical pattern, just moved)."""
    code_messages = code_messages or {}
    conflict_phrase = conflict_phrase or _default_conflict_phrase

    candidates = servers if servers is not None else extensions.KEA_SERVERS
    ssh_servers = [s for s in candidates if s.get("ssh_host")]
    if not ssh_servers:
        return ChangeSetResult(status="noservers", last_code="noservers")

    lines: list[tuple[str, str]] = []
    targets: list[Target] = []
    last_code = "ok"

    # ── Phase 1: plan ────────────────────────────────────────────────
    for server in ssh_servers:
        name = server.get("name") or server.get("ssh_host") or "?"
        try:
            cfg, sha = _host.read_config_versioned(server, service)
            if cfg is None:
                conf_name = _CONF_FILENAMES.get(service, f"kea-{service}.conf")
                lines.append(("error", f"❌ {name}: {conf_name} not found on this server"))
                return ChangeSetResult("aborted", "notfound-conf", lines)

            after_cfg, code = mutate_fn(cfg)
            last_code = code
            if code == "ok":
                # before_sha doubles as "the sha this target's write is
                # guarded against" — expected_sha_for() overrides what
                # was actually just read (edit_subnet_post's form
                # carries a sha from when the form was OPENED, not now).
                expected = expected_sha_for(server) if expected_sha_for else sha
                targets.append(Target(server, name, cfg, expected, after_cfg, code))
                continue
            if code in skip_codes:
                lines.append(("success", f"ℹ️ {name}: {code_messages.get(code, code)}"))
                continue
            # Any other code aborts the whole change set before any write.
            lines.append(("error", f"❌ {name}: {code_messages.get(code, code)}"))
            return ChangeSetResult("aborted", code, lines)
        except Exception as e:
            lines.append(("error", f"❌ {name}: {e}"))
            return ChangeSetResult("aborted", "error", lines)

    if not targets:
        return ChangeSetResult("nothing", last_code, lines)

    # ── Phase 2: preflight every target before touching anything ─────
    preflight_failed = False
    for t in targets:
        res = _safe(_host.test_config, t.server, service, t.after_cfg, tls_paths=tls_paths)
        if not res.get("ok"):
            preflight_failed = True
            if res.get("code") == "conflict":
                lines.append(("error", f"❌ {t.name}: {conflict_phrase(t.name)}"))
            else:
                lines.append(("error", _failure_line(t.name, res, daemon_label)))
    if preflight_failed:
        lines.append(("error", "ℹ️ nothing was changed on any server"))
        return ChangeSetResult("aborted", "testerror", lines)

    # ── Phase 3: commit sequentially, revert on the first failure ────
    committed: list[Target] = []
    for t in targets:
        res = _safe(
            _host.apply_config,
            t.server,
            service,
            t.after_cfg,
            tls_paths=tls_paths,
            expect_sha256=t.before_sha,
            summary=summary,
        )
        if res.get("ok"):
            t.applied_sha = res.get("sha256")
            committed.append(t)
            continue

        # First failure — revert every already-committed target.
        if res.get("code") == "conflict":
            lines.append(("error", f"❌ {t.name}: {conflict_phrase(t.name)}"))
        else:
            lines.append(("error", _failure_line(t.name, res, daemon_label)))

        revert_failed = []  # the revert call itself failed: still on the NEW config
        restart_stuck = []  # the previous config is back but the daemon would not restart on it
        for done in reversed(committed):
            rres = _safe(
                _host.apply_config,
                done.server,
                service,
                done.before_cfg,
                expect_sha256=done.applied_sha,
                summary=f"rollback: {summary}",
                source="rollback",
            )
            if not rres.get("ok"):
                revert_failed.append(done.name)
                continue
            if restart:
                rres_restart = _safe(_host.service_action, done.server, service, "restart")
                if not rres_restart.get("ok"):
                    # v5.65.6 (Q95) - this was a warning line and the status stayed "aborted", which is
                    # never persisted: the Servers banner never showed it and the operator could miss
                    # that Kea is DOWN on a server that was rolled back. It is the same state as the
                    # restart-phase rollback below, so it gets the same treatment: an error line,
                    # rollback_failed, needs_hands, and the persisted banner.
                    restart_stuck.append(done.name)
                    lines.append(
                        (
                            "error",
                            f"❌ {done.name}: previous config restored but {daemon_label} did not restart on it "
                            f"({_tail(rres_restart.get('detail'))})",
                        )
                    )

        if revert_failed or restart_stuck:
            # v5.28.1 (Q26, A1) — name all three groups correctly.
            # `revert_failed` holds targets whose REVERT call itself
            # failed, meaning THEY still carry the new config — the
            # previous wording had this exactly backwards, telling an
            # operator reading it for recovery instructions the
            # opposite of reality.
            if revert_failed:
                still_new = revert_failed
                rolled_back = [d.name for d in committed if d.name not in revert_failed]
                untouched = t.name
                lines.append(
                    (
                        "error",
                        f"🛑 ROLLBACK FAILED — {', '.join(still_new)} still have the NEW config (their rollback "
                        f"failed); {', '.join(rolled_back) or '(none)'} were rolled back to the old config; "
                        f"{untouched} was never changed. Fix by hand: Servers → Config history → restore.",
                    )
                )
            if restart_stuck:
                lines.append(("error", "🛑 ROLLBACK FAILED — " + _by_hand(restart_stuck)))
            return ChangeSetResult(
                "rollback_failed", res.get("code", "error"), lines, needs_hands=revert_failed + restart_stuck
            )

        if committed:
            names = ", ".join(d.name for d in committed)
            lines.append(("error", f"↩️ reverted {len(committed)} server(s) that had already been updated: {names}"))
        return ChangeSetResult("aborted", res.get("code", "error"), lines)

    # ── Phase 4: restart (every apply succeeded) ──────────────────────
    # `config.applied` is emitted only once the change stands: a restart failure below
    # rolls it back, and a timeline entry saying it was applied would be false.
    if not restart:
        for t in targets:
            _events.emit("config.applied", server=t.name, detail=summary)
            lines.append(("success", f"✅ {t.name}: {summary}"))
        return ChangeSetResult("ok", "ok", lines, covered=[t.name for t in targets])

    restarts = {t.name: _safe(_host.service_action, t.server, service, "restart") for t in targets}
    failed = [t for t in targets if not restarts[t.name].get("ok")]
    if not failed:
        for t in targets:
            _events.emit("config.applied", server=t.name, detail=summary)
            lines.append(("success", f"✅ {t.name}: {summary}, {daemon_label} restarted"))
        return ChangeSetResult("ok", "ok", lines, covered=[t.name for t in targets])

    # A restart failed although the config passed preflight and was written: the daemon
    # cannot start from what it was just handed (and the restart already stopped the old
    # process). "The config is valid, restart it by hand" is not an honest state to leave a
    # server in, so EVERY target goes back to what it had and is restarted again — putting
    # only the failed one back would leave the servers disagreeing, the very state this
    # module exists to prevent.
    for t in failed:
        lines.append(
            (
                "error",
                f"❌ {t.name}: {daemon_label} did NOT restart on the new config ({_tail(restarts[t.name].get('detail'))})",
            )
        )
    stuck: list[str] = []
    for t in reversed(targets):
        rres = _safe(
            _host.apply_config,
            t.server,
            service,
            t.before_cfg,
            expect_sha256=t.applied_sha,
            summary=f"rollback: {summary}",
            source="rollback",
        )
        if not rres.get("ok"):
            stuck.append(t.name)
            lines.append(
                ("error", f"❌ {t.name}: could not put the previous config back ({_tail(rres.get('detail'))})")
            )
            continue
        again = _safe(_host.service_action, t.server, service, "restart")
        if not again.get("ok"):
            stuck.append(t.name)
            lines.append(
                (
                    "error",
                    f"❌ {t.name}: previous config restored but {daemon_label} did not restart on it "
                    f"({_tail(again.get('detail'))})",
                )
            )
    names = [t.name for t in failed]
    if stuck:
        lines.append(("error", "🛑 ROLLBACK FAILED — " + _by_hand(stuck)))
        return ChangeSetResult("rollback_failed", "restart-failed", lines, names, stuck)
    lines.append(
        (
            "error",
            f"↩️ rolled back: {', '.join(t.name for t in targets)} {'is' if len(targets) == 1 else 'are'} "
            f"on the previous config and {daemon_label} restarted; the change was NOT applied.",
        )
    )
    return ChangeSetResult("rolled_back", "restart-failed", lines, names)


# ── what a person must be told about (v5.65.1, Q90) ──────────────────────────
# A change set that ended "rolled_back" or "rollback_failed" is shown once, in the flash lines
# of the request that made it. The Servers page keeps it in front of the operator until they
# dismiss it (or a later change set succeeds), because a "rollback_failed" is a server that may
# be on the wrong config or stopped, and a flash is easy to miss.

ATTENTION_KEY = "changeset_attention"


def _ok_run_clears(raw: str, result: ChangeSetResult, service: str) -> bool:
    """May this clean run take the banner down? (v5.65.8, Q97.)

    A `rolled_back` note says every server was put back and is running, so any later clean run
    clears it. A `rollback_failed` note is the only persistent sign that a daemon may be STOPPED,
    and it used to be cleared by ANY ok run - a DDNS save, a single-server edit that never touched
    the server that needs hands. It now clears only when the run was for the same service and
    covered every server in `needs_hands` (a clean restart of each is proof it is running);
    otherwise it stays until an admin dismisses it."""
    import json

    try:
        note = json.loads(raw)
    except Exception:
        return True  # unreadable: nothing worth protecting
    if not isinstance(note, dict) or note.get("status") != "rollback_failed":
        return True
    if note.get("service") != service:
        return False
    needed = set(note.get("needs_hands") or [])
    return needed <= set(result.covered)


def record_outcome(result: ChangeSetResult, service: str, summary: str) -> None:
    """Remember a rolled-back / failed-rollback outcome for the Servers page; clear it after a
    clean run. Best-effort telemetry: never raises, never changes the result."""
    try:
        import json
        from datetime import datetime, timezone

        from jen.models import user as _user

        if result.status in ("rolled_back", "rollback_failed"):
            _user.set_global_setting(
                ATTENTION_KEY,
                json.dumps(
                    {
                        "status": result.status,
                        "service": service,
                        "summary": summary,
                        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        "failed_restart": list(result.restart_failures),
                        "needs_hands": list(result.needs_hands),
                        "lines": [text for kind, text in result.lines if kind == "error"][-6:],
                    }
                ),
            )
            # v5.65.8 (Q97): the audit log used to record only that someone DISMISSED the notice. A rollback
            # is an event in its own right (and a rollback_failed is a server that may be stopped).
            _user.audit(
                "CONFIG_ROLLBACK_FAILED" if result.status == "rollback_failed" else "CONFIG_ROLLED_BACK",
                service,
                f"{summary}"
                + (f"; needs attention: {', '.join(result.needs_hands)}" if result.needs_hands else "")
                + (f"; restart failed on: {', '.join(result.restart_failures)}" if result.restart_failures else ""),
            )
        elif result.status == "ok":
            noted = _user.get_global_setting(ATTENTION_KEY, "")
            if noted and _ok_run_clears(noted, result, service):
                _user.set_global_setting(ATTENTION_KEY, "")
    except Exception as e:
        logger.debug(f"kea_changeset: could not record the outcome: {e}")


def attention() -> dict | None:
    """The outcome record for the Servers page banner, or None."""
    try:
        import json

        from jen.models import user as _user

        raw = _user.get_global_setting(ATTENTION_KEY, "")
        data = json.loads(raw) if raw else None
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def clear_attention() -> None:
    try:
        from jen.models import user as _user

        _user.set_global_setting(ATTENTION_KEY, "")
    except Exception as e:
        logger.debug(f"kea_changeset: could not clear the outcome: {e}")


def apply_change(service: str, mutate_fn, summary: str, **kwargs) -> ChangeSetResult:
    """`_run_change` (documented above) plus `record_outcome`, so every caller's
    rolled-back / failed-rollback result reaches the Servers page without each route
    remembering to."""
    result = _run_change(service, mutate_fn, summary, **kwargs)
    record_outcome(result, service, summary)
    return result
