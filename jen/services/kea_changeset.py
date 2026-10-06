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

v5.68.0-beta.15 (Q150) — Author Kea Config goes through here too. It used to loop `for server in KEA_SERVERS` in its route,
calling `apply_config` per server with no expected sha, no preflight of the OTHER targets, no rollback, and Jen's own `[subnets]`
written when ANY server succeeded; with "overwrite" ticked it replaced whatever was on each host at commit time, whatever the
preview had shown. Two additions make the four phases fit it unchanged: a PER-TARGET CANDIDATE (`candidate_for(server, cfg)` -
the authored config for THAT server) and an "ABSENT IS THE EXPECTED STATE" target (`absent_is_expected=True`: a host with no config
file is a normal target whose expected sha is "" - what `apply_config`'s own `expect_sha256=""` already means - not a failure, and
its write may never overwrite a file that appeared in the meantime). A target that was absent is rolled back by REMOVING the file
Jen wrote (`kea_host.remove_config`, guarded by the sha Jen's own write produced), the only way "put it back as it was" is true.

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
    # v5.68.0-beta.15 (Q150): an ABSENT target (before_cfg is None, expected sha "") may only ever create the file; its own
    # tls material (an authored https control socket's cert/key/trust anchor) is per target, not one list for every server
    allow_overwrite: bool = True
    tls_paths: tuple = ()


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
        from jen.services.kea_host import missing_binary_text

        return f"❌ {name}: {missing_binary_text(res, advice=True)}."
    if code == "testerror":
        return (
            f"❌ {name}: config validation failed — {daemon_label} NOT restarted, "
            f"original config preserved. Error: {res.get('detail')}"
        )
    return f"❌ {name}: {res.get('detail', code)}"


def _restore_target(t: Target, service: str, summary: str) -> dict:
    """Put one already-committed target back as it was (v5.68.0-beta.15, Q150): the previous config re-applied, or - for a target that
    had no config file before - the file Jen wrote removed again, guarded by the sha that write produced. A result dict like
    `kea_host.apply_config`'s; never raises."""
    if t.before_cfg is None:
        return _safe(_host.remove_config, t.server, service, expect_sha256=t.applied_sha)
    return _safe(
        _host.apply_config,
        t.server,
        service,
        t.before_cfg,
        expect_sha256=t.applied_sha,
        summary=f"rollback: {summary}",
        source="rollback",
    )


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
    candidate_for=None,
    absent_is_expected: bool = False,
    tls_paths_for=None,
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

    `candidate_for(server, cfg) -> (after_cfg, code)` (v5.68.0-beta.15, Q150) replaces `mutate_fn` when the config each target
    receives is its OWN rather than one mutation of what it has: Author Kea Config builds a different file per server. `cfg` is the
    config read from that host, or None when `absent_is_expected` and the host has no config file. `absent_is_expected=True` makes
    a missing config file a normal target - expected sha "" (the helper's "must not exist"), `allow_overwrite=False` at commit, and
    rolled back by removing what Jen wrote - while a host that cannot be READ at all (SSH down, a helper that answers badly) still
    aborts: only a read that succeeded and found nothing is "absent". `tls_paths_for(server)` gives each target its own TLS files.

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
            read_errors: list[str] = []
            if absent_is_expected:  # only here is "nothing came back" ambiguous: say WHY it did not (an unreachable host is not an absent file)
                cfg, sha = _host.read_config_versioned(server, service, errors=read_errors)
            else:
                cfg, sha = _host.read_config_versioned(server, service)
            if cfg is None:
                if absent_is_expected and not read_errors:
                    cfg, sha = (
                        None,
                        "",
                    )  # the host answered and has no config file: the expected state of a target to author
                elif absent_is_expected:
                    lines.append(("error", f"❌ {name}: could not read its config — {read_errors[0]}"))
                    return ChangeSetResult("aborted", "error", lines)
                else:
                    conf_name = _CONF_FILENAMES.get(service, f"kea-{service}.conf")
                    lines.append(("error", f"❌ {name}: {conf_name} not found on this server"))
                    return ChangeSetResult("aborted", "notfound-conf", lines)

            after_cfg, code = candidate_for(server, cfg) if candidate_for else mutate_fn(cfg)
            last_code = code
            if code == "ok":
                # before_sha doubles as "the sha this target's write is
                # guarded against" — expected_sha_for() overrides what
                # was actually just read (edit_subnet_post's form
                # carries a sha from when the form was OPENED, not now).
                expected = expected_sha_for(server) if expected_sha_for else sha
                targets.append(
                    Target(
                        server,
                        name,
                        cfg,
                        expected,
                        after_cfg,
                        code,
                        allow_overwrite=cfg is not None,
                        tls_paths=tuple(tls_paths_for(server)) if tls_paths_for else tuple(tls_paths or ()),
                    )
                )
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
        res = _safe(_host.test_config, t.server, service, t.after_cfg, tls_paths=t.tls_paths)
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
            tls_paths=t.tls_paths,
            allow_overwrite=t.allow_overwrite,
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
            rres = _restore_target(done, service, summary)
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
        rres = _restore_target(t, service, summary)
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

# The banner's most incidents at once; the oldest clean-rollback notes go first when it is full.
_MAX_INCIDENTS = 20

# v5.66.0-beta.3 (Q105 a) — a `rollback_failed` incident is the only persistent record that a
# daemon may be STOPPED; losing one to make room for a newer note would be worse than the note
# never existing. The soft cap above is never enforced against one — if every incident on the
# list is an unresolved `rollback_failed`, the list is allowed to exceed it. This hard ceiling
# is the only real bound: twenty unresolved stopped daemons is a human's problem long before it
# is a storage one, but the stored note itself still can't be allowed to grow forever.
_INCIDENTS_HARD_CEILING = 200


def _incidents_of(raw) -> list[dict]:
    """The unresolved incidents in a stored note (v5.65.10, Q99). The note is `{"incidents": [...]}`; the
    single-note shape written by 5.65.1 to 5.65.9 (`{"status": ..., "service": ...}`) is read as a list of
    one, so a note recorded before an upgrade is neither lost nor misread."""
    import json

    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return []
    if not isinstance(data, dict):
        return []
    if isinstance(data.get("incidents"), list):
        return [i for i in data["incidents"] if isinstance(i, dict)]
    return [data] if data.get("status") else []


def _incident_cleared(incident: dict, result: ChangeSetResult, service: str) -> bool:
    """Does this clean run resolve `incident`? (v5.65.8, Q97; per incident since v5.65.10.)

    A `rolled_back` incident says every server was put back and is running, so any later clean run
    clears it. A `rollback_failed` incident is the only persistent sign that a daemon may be STOPPED: a
    clean run clears it only when it was for the same service and covered every server in its
    `needs_hands` (a clean restart of each is proof it is running); otherwise it stays until an admin
    dismisses it."""
    if incident.get("status") != "rollback_failed":
        return True
    if incident.get("service") != service:
        return False
    return set(incident.get("needs_hands") or []) <= set(result.covered)


def record_outcome(result: ChangeSetResult, service: str, summary: str) -> None:
    """Remember a rolled-back / failed-rollback outcome for the Servers page; resolve incidents after a
    clean run. Best-effort telemetry: never raises, never changes the result.

    v5.65.10 (Q99): the note is a LIST of unresolved incidents. It used to be one slot that every new
    rolled-back / failed-rollback result overwrote, so a `rolled_back` on kea-b replaced an unresolved
    `rollback_failed` on kea-a ("nothing was changed", and the next clean run cleared it while a daemon
    was still stopped), and a second `rollback_failed` replaced the first one's `needs_hands`. Now each
    outcome is appended; a clean run drops the incidents it covers and the key is cleared only when none
    is left."""
    try:
        import json
        from datetime import datetime, timezone

        from jen.models import user as _user

        if result.status in ("rolled_back", "rollback_failed"):
            incident = {
                "status": result.status,
                "service": service,
                "summary": summary,
                "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "failed_restart": list(result.restart_failures),
                "needs_hands": list(result.needs_hands),
                "lines": [text for kind, text in result.lines if kind == "error"][-6:],
            }
            incidents = _incidents_of(_user.get_global_setting(ATTENTION_KEY, ""))
            # the same trouble again (same kind, service and servers) refreshes its incident, it does not pile up
            same = (incident["status"], service, sorted(incident["needs_hands"]))
            incidents = [
                i for i in incidents if (i.get("status"), i.get("service"), sorted(i.get("needs_hands") or [])) != same
            ]
            incidents.append(incident)
            while len(incidents) > _MAX_INCIDENTS:
                # v5.65.10 (Q99) preferred evicting a resolved `rolled_back` note; v5.66.0-beta.3
                # (Q105 a) makes that literal: an unresolved `rollback_failed` is NEVER evicted to
                # stay under this soft cap — only the hard ceiling below can drop one.
                drop = next((i for i in incidents if i.get("status") != "rollback_failed"), None)
                if drop is None:
                    break
                incidents.remove(drop)
            if len(incidents) > _INCIDENTS_HARD_CEILING:
                logger.error(
                    f"kea_changeset: {len(incidents)} unresolved rollback_failed incidents on "
                    f"record — past the {_INCIDENTS_HARD_CEILING}-incident hard ceiling; the "
                    "oldest are being dropped from the stored note. Each one may mean a server "
                    "is still stopped; this many unresolved at once needs a human, not a bigger list."
                )
                del incidents[: len(incidents) - _INCIDENTS_HARD_CEILING]
            _user.set_global_setting(ATTENTION_KEY, json.dumps({"incidents": incidents}))
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
            if noted:
                left = [i for i in _incidents_of(noted) if not _incident_cleared(i, result, service)]
                _user.set_global_setting(ATTENTION_KEY, json.dumps({"incidents": left}) if left else "")
    except Exception as e:
        logger.debug(f"kea_changeset: could not record the outcome: {e}")


def attention() -> dict | None:
    """The unresolved incidents for the Servers page banner, `{"incidents": [...]}` oldest first, or None."""
    try:
        from jen.models import user as _user

        incidents = _incidents_of(_user.get_global_setting(ATTENTION_KEY, ""))
        return {"incidents": incidents} if incidents else None
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
