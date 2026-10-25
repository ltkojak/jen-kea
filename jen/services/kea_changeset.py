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
import os
from dataclasses import dataclass, field

from jen import extensions
from jen.services import events as _events
from jen.services import kea_host as _host
from jen.services.kea_authoring import conf_path_for as _conf_path_for

logger = logging.getLogger(__name__)


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
    # v5.69.0-beta.19 (Q188, AD9): the revert of this target FAILED, so its file still carries the NEW config. A route that put certificate material on the host before the change must not
    # reinstall the OLD material under the new entry.
    revert_failed: bool = False

    @property
    def key(self):
        """What identifies this target in every piece of bookkeeping (v5.69.0-beta.3, Q172): the server's id, which Jen assigns and keeps unique. The
        `name` is free text an operator types - two servers may carry the same one - so a dict, a set or an `in` test keyed by it merges two targets
        into one and a failed restart on the first is read as the second's success. The name is for the lines a person reads, never for the bookkeeping."""
        sid = self.server.get("id")
        return sid if sid is not None else self.name


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
    # the same two lists by server id (v5.69.0-beta.3, Q172): names are what a person reads, ids are what is compared - two servers may share a name
    needs_hands_ids: list = field(default_factory=list)
    covered_ids: list = field(default_factory=list)
    # the ids of the targets whose revert failed - they still carry the NEW config (`rollback_failed` also covers "the previous config is back but the daemon would not restart on it", which is NOT this)
    still_new_ids: list = field(default_factory=list)


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
    if code == "investigation-on":
        # v5.68.0-beta.28 (Q164): kea_host.apply_config refused a write that would erase the investigation-logging marker; nothing was sent to this host
        return f"❌ {name}: {res.get('detail')} (nothing was written to {name})"
    if code == "testerror":
        return (
            f"❌ {name}: config validation failed — {daemon_label} NOT restarted, "
            f"original config preserved. Error: {res.get('detail')}"
        )
    return f"❌ {name}: {res.get('detail', code)}"


def _restore_target(t: Target, service: str, summary: str, helper_only: bool = False) -> dict:
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
        **({"helper_only": True} if helper_only else {}),
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
    finalize=None,
    helper_only: bool = False,
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

    `helper_only=True` (v5.68.0-beta.16, Q151) is passed through to every `test_config` / `apply_config` the change makes (never the legacy
    script): a change whose rollback exists only in the helper must not be written through an engine that cannot roll back.

    `finalize(result)` (v5.68.0-beta.16, Q151) runs once every target has committed (and restarted, when `restart`): the place for what
    Jen does LOCALLY because of this change (Author Kea Config's `[subnets]` record). If it raises, the change did not stand: every
    target is put back exactly as for a failed restart, a revert that fails is `rollback_failed`, and the result is `rolled_back`
    with `last_code == "finalize-failed"` - never ok.

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
                    lines.append(("error", f"❌ {name}: its config could not be read ({read_errors[0]})"))
                    return ChangeSetResult("aborted", "error", lines)
                else:
                    conf_name = os.path.basename(
                        _conf_path_for(server, service)
                    )  # the file Jen looked for, which is the configured one
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
        res = _safe(
            _host.test_config,
            t.server,
            service,
            t.after_cfg,
            tls_paths=t.tls_paths,
            **({"helper_only": True} if helper_only else {}),
        )
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
            **({"helper_only": True} if helper_only else {}),
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

        revert_failed: list[Target] = []  # the revert call itself failed: still on the NEW config
        restart_stuck: list[Target] = []  # the previous config is back but the daemon would not restart on it
        for done in reversed(committed):
            rres = _restore_target(done, service, summary, helper_only)
            if not rres.get("ok"):
                revert_failed.append(done)
                continue
            if restart:
                rres_restart = _safe(_host.service_action, done.server, service, "restart")
                if not rres_restart.get("ok"):
                    # v5.65.6 (Q95) - this was a warning line and the status stayed "aborted", which is
                    # never persisted: the Servers banner never showed it and the operator could miss
                    # that Kea is DOWN on a server that was rolled back. It is the same state as the
                    # restart-phase rollback below, so it gets the same treatment: an error line,
                    # rollback_failed, needs_hands, and the persisted banner.
                    restart_stuck.append(done)
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
                failed_keys = {d.key for d in revert_failed}  # by id: two servers may share a name
                still_new = [d.name for d in revert_failed]
                rolled_back = [d.name for d in committed if d.key not in failed_keys]
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
                lines.append(("error", "🛑 ROLLBACK FAILED — " + _by_hand([d.name for d in restart_stuck])))
            needs = revert_failed + restart_stuck
            return ChangeSetResult(
                "rollback_failed",
                res.get("code", "error"),
                lines,
                needs_hands=[d.name for d in needs],
                needs_hands_ids=[d.key for d in needs],
                still_new_ids=[d.key for d in revert_failed],
            )

        if committed:
            names = ", ".join(d.name for d in committed)
            lines.append(("error", f"↩️ reverted {len(committed)} server(s) that had already been updated: {names}"))
        return ChangeSetResult("aborted", res.get("code", "error"), lines)

    # ── Phase 4: restart (every apply succeeded) ──────────────────────
    # `config.applied` is emitted only once the change stands: a restart failure below (or a finalize
    # failure, phase 5) rolls it back, and a timeline entry saying it was applied would be false.
    if restart:
        restarts = {
            t.key: _safe(_host.service_action, t.server, service, "restart") for t in targets
        }  # by id, never by the free-text name
        failed = [t for t in targets if not restarts[t.key].get("ok")]
        if failed:
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
                        f"❌ {t.name}: {daemon_label} did NOT restart on the new config "
                        f"({_tail(restarts[t.key].get('detail'))})",
                    )
                )
            stuck = _put_everything_back(
                targets, service, summary, daemon_label, lines, restart=True, helper_only=helper_only
            )
            names = [t.name for t in failed]
            if stuck:
                lines.append(("error", "🛑 ROLLBACK FAILED — " + _by_hand([s.name for s in stuck])))
                return ChangeSetResult(
                    "rollback_failed",
                    "restart-failed",
                    lines,
                    names,
                    [s.name for s in stuck],
                    needs_hands_ids=[s.key for s in stuck],
                    still_new_ids=[s.key for s in stuck if s.revert_failed],
                )
            lines.append(
                (
                    "error",
                    f"↩️ rolled back: {', '.join(t.name for t in targets)} {'is' if len(targets) == 1 else 'are'} "
                    f"on the previous config and {daemon_label} restarted; the change was NOT applied.",
                )
            )
            return ChangeSetResult("rolled_back", "restart-failed", lines, names)

    # ── Phase 5: finalize (v5.68.0-beta.16, Q151) ─────────────────────
    # Everything Jen does LOCALLY on the strength of this change (Author Kea Config's `[subnets]` record) joins the
    # transaction: it runs after every target committed, and an exception from it is a failure of the whole change,
    # exactly like a failed restart - every target is put back, a revert that fails is `rollback_failed` (an incident
    # on the Servers page), and the change is reported `rolled_back`, never ok. It used to run after the "ok" in the
    # route, where an OSError left Kea changed and Jen's map old and a Kea-valid, Jen-invalid name failed after every
    # server had already committed.
    if finalize is not None:
        try:
            finalize(
                ChangeSetResult(
                    "ok", "ok", list(lines), covered=[t.name for t in targets], covered_ids=[t.key for t in targets]
                )
            )
        except Exception as e:
            logger.warning(f"kea_changeset: finalize raised {type(e).__name__}: {e}")
            lines.append(
                (
                    "error",
                    f"❌ Jen could not record this change on its own side ({type(e).__name__}); "
                    "every server is being put back as it was.",
                )
            )
            stuck = _put_everything_back(
                targets, service, summary, daemon_label, lines, restart=restart, helper_only=helper_only
            )
            if stuck:
                lines.append(("error", "🛑 ROLLBACK FAILED — " + _by_hand([s.name for s in stuck])))
                return ChangeSetResult(
                    "rollback_failed",
                    "finalize-failed",
                    lines,
                    [],
                    [s.name for s in stuck],
                    needs_hands_ids=[s.key for s in stuck],
                    still_new_ids=[s.key for s in stuck if s.revert_failed],
                )
            lines.append(
                (
                    "error",
                    f"↩️ rolled back: {', '.join(t.name for t in targets)} "
                    f"{'is' if len(targets) == 1 else 'are'} on the previous config; the change was NOT applied.",
                )
            )
            return ChangeSetResult("rolled_back", "finalize-failed", lines, [t.name for t in targets])

    for t in targets:
        _events.emit("config.applied", server=t.name, detail=summary)
        lines.append(("success", f"✅ {t.name}: {summary}" + (f", {daemon_label} restarted" if restart else "")))
    return ChangeSetResult("ok", "ok", lines, covered=[t.name for t in targets], covered_ids=[t.key for t in targets])


def _put_everything_back(targets, service, summary, daemon_label, lines, *, restart, helper_only=False) -> list[Target]:
    """Put EVERY target back as it was (reverse order): the previous config re-applied, or the file Jen created removed again; with
    `restart` the daemon is restarted on it. Appends one error line per target that could not be put back. Returns the TARGETS that are
    stuck (a revert or the second restart that failed) - the caller names them for a person and keys them by id."""
    stuck: list[Target] = []
    for t in reversed(targets):
        rres = _restore_target(t, service, summary, helper_only)
        if not rres.get("ok"):
            t.revert_failed = True
            stuck.append(t)
            lines.append(
                ("error", f"❌ {t.name}: could not put the previous config back ({_tail(rres.get('detail'))})")
            )
            continue
        if not restart:
            continue
        again = _safe(_host.service_action, t.server, service, "restart")
        if not again.get("ok"):
            stuck.append(t)
            lines.append(
                (
                    "error",
                    f"❌ {t.name}: previous config restored but {daemon_label} did not restart on it "
                    f"({_tail(again.get('detail'))})",
                )
            )
    return stuck


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


class MalformedNote(ValueError):
    """The stored recovery note is text that is not a note (Q189, AE3). A read that must not turn it into "nothing is waiting" raises this; a write that would put a new incident over it refuses."""


_OUTCOME_STATUSES = ("rolled_back", "rollback_failed")
_OUTCOME_OPTIONAL_LISTS = ("needs_hands", "needs_hands_ids", "lines", "failed_restart")


def _is_server_id(value) -> bool:
    """A server id as Jen writes one: an int (not a bool) or a non-blank string (second pass, Q190: `server_id: false` and `[]` were 'a server id')."""
    return (isinstance(value, int) and not isinstance(value, bool)) or (isinstance(value, str) and bool(value.strip()))


def _is_timestamp(value) -> bool:
    """`at` as Jen writes it (an ISO-8601 time) - text that does not parse is not a time Jen wrote."""
    if not isinstance(value, str):
        return False
    from datetime import datetime

    try:
        datetime.fromisoformat(value.strip())
    except ValueError:
        return False
    return True


def recognised_incident(entry) -> bool:
    """Is `entry` an incident Jen wrote (Q190, AF3)? An ATTENTION incident is `kind == "attention"` with a known `category`, a `service` of dhcp4 / dhcp6 / d2, a `server_id` and a `summary` and
    `at` that are text. An OUTCOME incident (a rolled-back or failed-rollback change, and the single note of 5.65.x) is a `status` of `rolled_back` or `rollback_failed` with a `service` and an
    `at` that are text; `needs_hands`, `needs_hands_ids`, `lines` and `failed_restart` are optional, and when present are lists - a record from before ids were kept stays valid. Anything else is an
    entry Jen cannot read: it is KEPT (never cleared by a clean run, never written over) until a superadmin sets the note aside."""
    if not isinstance(entry, dict):
        return False
    if entry.get("kind") == ATTENTION_KIND:
        return (
            entry.get("category") in ATTENTION_CATEGORIES
            and entry.get("service") in ("dhcp4", "dhcp6", "d2")
            and _is_server_id(entry.get("server_id"))
            and isinstance(entry.get("summary"), str)
            and _is_timestamp(entry.get("at"))
        )
    return (
        entry.get("status") in _OUTCOME_STATUSES
        and isinstance(entry.get("service"), str)
        and _is_timestamp(entry.get("at"))
        and all(isinstance(entry[k], list) for k in _OUTCOME_OPTIONAL_LISTS if k in entry)
    )


def _incidents_of(raw, strict: bool = False) -> list[dict]:
    """The unresolved incidents in a stored note (v5.65.10, Q99). The note is `{"incidents": [...]}`; the
    single-note shape written by 5.65.1 to 5.65.9 (`{"status": ..., "service": ...}`) is read as a list of
    one, so a note recorded before an upgrade is neither lost nor misread.

    `strict` (Q189, AE3; Q190, AF3): the only shapes are (a) nothing - `None` or `""`, (b) a dict whose `incidents` is a list of RECOGNISED incidents (`recognised_incident`), (c) the 5.65.x
    single note, which is one recognised outcome incident. Anything else raises `MalformedNote` naming the entry's INDEX, never its text - a writer that read it as `[]` would write its new
    incident over text it never understood, and "a list of dicts" is not a shape: `{"incidents": [{}]}` was accepted, and a clean run deleted the empty entry as "resolved".
    Without `strict` the reader stays forgiving (the Servers banner reads the note on every page load): anything unreadable is no incidents, and an entry that is a dict is kept in the list
    (`_incident_cleared` keeps it, and the banner says an incident Jen cannot read is on record)."""
    import json

    if raw is None or raw == "":
        return []
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        if strict:
            raise MalformedNote("the incident note is not readable") from None
        return []
    if not isinstance(data, dict):
        if strict:
            raise MalformedNote("the incident note is not readable")
        return []
    if "incidents" in data and strict:
        listed = data["incidents"]
        if not isinstance(listed, list):
            raise MalformedNote("the incident note is not readable")
        for index, entry in enumerate(listed):
            if not recognised_incident(entry):
                raise MalformedNote(f"entry {index} of the incident note is not an incident Jen recognises")
        return list(listed)
    if isinstance(data.get("incidents"), list):
        return [i for i in data["incidents"] if isinstance(i, dict)]
    if strict:
        if data.get("status") and recognised_incident(data):
            return [data]  # the single note of 5.65.x is one outcome incident by the same rule
        raise MalformedNote("the incident note is not readable")
    if data.get("status"):
        return [data]
    return []


def _incident_servers(incident: dict) -> list[str]:
    """The servers an incident is about, as a sortable list of strings: their ids when the incident carries them (v5.69.0-beta.3, Q172), else the names."""
    return sorted(str(x) for x in (incident.get("needs_hands_ids") or incident.get("needs_hands") or []))


def _incident_cleared(incident: dict, result: ChangeSetResult, service: str) -> bool:
    """Does this clean run resolve `incident`? (v5.65.8, Q97; per incident since v5.65.10.)

    A `rolled_back` incident says every server was put back and is running, so any later clean run
    clears it. A `rollback_failed` incident is the only persistent sign that a daemon may be STOPPED: a
    clean run clears it only when it was for the same service and covered every server in its
    `needs_hands` (a clean restart of each is proof it is running); otherwise it stays until an admin
    dismisses it."""
    if not recognised_incident(incident):
        return False  # Q190 (AF3): FAIL CLOSED - an entry Jen cannot read is kept, never cleared by a clean run (an empty dict used to read as 'a rolled_back note' and be deleted)
    if incident.get("kind") == ATTENTION_KIND:
        return False  # Q187: an unproved recovery is cleared by a verified recovery of THAT server and service, or acknowledged - never by an unrelated change
    if incident.get("status") != "rollback_failed":
        return True
    if incident.get("service") != service:
        return False
    needs_ids = incident.get("needs_hands_ids")
    if needs_ids and result.covered_ids:  # compared by server id (v5.69.0-beta.3, Q172): two servers may share a name
        return set(needs_ids) <= set(result.covered_ids)
    return set(incident.get("needs_hands") or []) <= set(
        result.covered
    )  # an incident recorded before ids were kept, or a result built without them


def _with_attention(fn, strict: bool = True) -> bool:
    """Read-modify-write the incident note as ONE locked transaction (v5.69.0-beta.19, Q188, AD5). `fn(incidents: list[dict]) -> list[dict] | None` receives the incidents as the note holds them
    UNDER the row lock and returns the new list (None: leave the note alone); the note is the settings row `changeset_attention`, read `FOR UPDATE` and written in the same transaction, so two workers
    recording two incidents (or one recording while another acknowledges) both land. Returns False - never raises, never reports as done what is not - when the transaction could not complete.

    Q189 (AE3): the stored note is parsed STRICTLY. A value that is not a note makes the transaction refuse (nothing is written, False comes back) - it is never read as `[]` and written over.
    `strict=False` is the one sanctioned reset, used by `set_aside_unreadable_note` after the raw value has been copied to a key of its own."""
    import json

    from jen.models import user as _user

    def mutate(raw):
        new = fn(_incidents_of(raw, strict=strict))
        if new is None:
            return None
        return json.dumps({"incidents": new}) if new else ""

    try:
        return bool(_user.update_global_setting(ATTENTION_KEY, mutate))
    except Exception as e:
        logger.error(f"kea_changeset: the incident note transaction failed: {type(e).__name__}")
        return False


def record_outcome(result: ChangeSetResult, service: str, summary: str) -> bool:
    """Remember a rolled-back / failed-rollback outcome for the Servers page; resolve incidents after a
    clean run. Best-effort telemetry: never raises, never changes the result.

    v5.65.10 (Q99): the note is a LIST of unresolved incidents. It used to be one slot that every new
    rolled-back / failed-rollback result overwrote, so a `rolled_back` on kea-b replaced an unresolved
    `rollback_failed` on kea-a ("nothing was changed", and the next clean run cleared it while a daemon
    was still stopped), and a second `rollback_failed` replaced the first one's `needs_hands`. Now each
    outcome is appended; a clean run drops the incidents it covers and the key is cleared only when none
    is left. v5.69.0-beta.19 (Q188, AD5): through `_with_attention` - one locked transaction.

    Q189 (AE3): returns False when the note could not be updated (an unreadable stored note is refused, never overwritten); True otherwise."""
    done = True
    try:
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
                "needs_hands_ids": list(result.needs_hands_ids),
                "lines": [text for kind, text in result.lines if kind == "error"][-6:],
            }

            def add(incidents):
                # the same trouble again (same kind, service and servers) refreshes its incident, it does not pile up
                same = (incident["status"], service, _incident_servers(incident))
                incidents = [i for i in incidents if (i.get("status"), i.get("service"), _incident_servers(i)) != same]
                incidents.append(incident)
                while len(incidents) > _MAX_INCIDENTS:
                    # v5.65.10 (Q99) preferred evicting a resolved `rolled_back` note; v5.66.0-beta.3 (Q105 a) makes that literal: an unresolved `rollback_failed` is NEVER evicted to stay under this
                    # soft cap - only the hard ceiling below can drop one (Q187: nor is an unproved recovery, for the same reason: the daemon may be stopped)
                    drop = next(
                        (
                            i
                            for i in incidents
                            if i.get("status") != "rollback_failed" and i.get("kind") != ATTENTION_KIND
                        ),
                        None,
                    )
                    if drop is None:
                        break
                    incidents.remove(drop)
                if len(incidents) > _INCIDENTS_HARD_CEILING:
                    logger.error(
                        f"kea_changeset: {len(incidents)} unresolved incidents on record - past the {_INCIDENTS_HARD_CEILING}-incident hard ceiling; the oldest are being dropped from the "
                        "stored note (the newest 200 are kept). Each one may mean a server is still stopped; this many unresolved at once needs a human, not a bigger list."
                    )
                    del incidents[: len(incidents) - _INCIDENTS_HARD_CEILING]
                return incidents

            done = _with_attention(add)
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

            def clear(incidents):
                left = [i for i in incidents if not _incident_cleared(i, result, service)]
                return left if len(left) != len(incidents) else None

            done = _with_attention(clear)
    except Exception as e:
        logger.debug(f"kea_changeset: could not record the outcome: {e}")
        return False
    return done


# ── an unproved recovery is a persistent incident (v5.69.0-beta.18, Q187, AC3) ───────────────────────────────────────────────────────────────
# A direct-socket operation changes the Kea host and then Jen's own settings; when it fails, the route puts the host back - and says "undone" only when that is PROVED. What could not be
# proved (a restore that found the file already matching, a restart that did not verify, material that could not be reinstalled, a socket that never answered) is a state a flash and an audit
# row nobody reads do not keep in front of anyone. It is the same persistent note as `rolled_back` / `rollback_failed`, with a category, a server and a service, and it is cleared by
# a verified recovery of that server and service (a later successful operation on it that probed the endpoint) or acknowledged by a superadmin. It never carries a socket entry or a credential.

ATTENTION_KIND = "attention"
ATTENTION_CATEGORIES = {
    "remote-unknown": "Jen could not read what the daemon's control sockets were before the change, so it could not put them back.",
    "restored-restart-unverified": "The daemon's config file is back as it was, but Jen did not restart the daemon on it, so it may still be running the change.",
    "restart-failed": "The previous config was put back but the daemon did not restart on it, so it may be stopped or running the change.",
    "tls-not-restored": "The certificate Jen installed for the control socket could not be put back, so a restored socket may meet a certificate issued for another address.",
    "tls-local-stale": "The certificate on the Kea host is the one it had, but Jen's own copy of it may not be the one on the host: its expiry warning and the next recovery read that copy.",
    "restored-endpoint-unreachable": "The daemon's sockets and certificate were put back and it was restarted, but the endpoint Jen uses did not answer as the right daemon afterwards.",
    "probe-pending": "The new control socket was added but has not answered Jen yet. It stays in the daemon's config and Jen's settings are unchanged; run the setup again to probe it.",
    "aborted": "The recovery could not be applied, so the daemon may still carry the failed change.",
    "tls-superseded": "A server that is not dialled over https now may still run a certificate from a CA Jen has since replaced. When it is dialled over https again, remove its direct socket and set it up again.",
    "record-forgotten": "Jen's record of a certificate was forgotten on the operator's word while the daemon may still present it; its expiry is not watched. A later setup of the socket, or its removal, ends this.",
}


def _same_server(incident: dict, server_id) -> bool:
    return str(incident.get("server_id")) == str(
        server_id
    )  # (ids are compared as strings: a stored 1 and a posted "1" are one server)


def record_attention(
    server_id, service: str, operation: str, category: str, when=None, *, server_name: str = "", detail: str = ""
) -> bool:
    """Record an unproved recovery for the Servers page and Health (Q187, AC3). `category` is one of `ATTENTION_CATEGORIES`; `operation` is a short sentence about what was being done
    ("setup of the https control socket on 10.0.0.5:8014"), never a socket entry; `detail` is a fixed sentence. The same category for the same server and service refreshes its incident.
    Returns whether it was stored (a locked transaction since Q188) - the caller already told the person in a flash, so a failure here is logged at ERROR, never raised."""
    if category not in ATTENTION_CATEGORIES:
        raise ValueError(f"unknown attention category {category!r}")
    try:
        from datetime import datetime, timezone

        from jen.models import user as _user

        at = (when or datetime.now(timezone.utc)).isoformat(timespec="seconds")
        incident = {
            "kind": ATTENTION_KIND,
            "status": category,
            "category": category,
            "service": service,
            "server_id": server_id,
            "server_name": server_name,
            "summary": operation,
            "detail": detail or ATTENTION_CATEGORIES[category],
            "at": at,
            "needs_hands": [],
            "needs_hands_ids": [],
            "lines": [],
        }

        def add(incidents):
            kept = [
                i
                for i in incidents
                if not (
                    i.get("kind") == ATTENTION_KIND
                    and i.get("category") == category
                    and i.get("service") == service
                    and _same_server(i, server_id)
                )
            ]
            kept.append(incident)
            return kept

        if not _with_attention(add):
            logger.error(f"kea_changeset: the {category} incident for server {server_id} could not be stored")
            return False
        _user.audit(
            "DIRECT_SOCKET_INCIDENT",
            service,
            f"server={server_name or server_id} category={category}; {operation}"[:500],
        )
        return True
    except Exception as e:
        logger.error(
            f"kea_changeset: could not record the {category} incident for server {server_id}: {type(e).__name__}"
        )
        return False


def resolve_attention(server_id, service: str, *, categories=None) -> int:
    """A verified recovery of THAT server and service clears its recovery incidents (Q187, AC3): called by an operation that probed the endpoint and got the answer it needs. An incident of
    another server or service, and every `rolled_back` / `rollback_failed` incident, is left alone. Returns how many were cleared; best-effort."""
    cleared = [0]

    def clear(incidents):
        left = [
            i
            for i in incidents
            if not (
                i.get("kind") == ATTENTION_KIND
                and i.get("service") == service
                and _same_server(i, server_id)
                and (categories is None or i.get("category") in categories)
            )
        ]
        cleared[0] = len(incidents) - len(left)
        return left if cleared[0] else None

    try:
        if not _with_attention(clear):
            logger.error(f"kea_changeset: the recovery incidents of server {server_id} could not be cleared")
            return 0
        return cleared[0]
    except Exception as e:
        logger.error(
            f"kea_changeset: could not resolve the recovery incidents of server {server_id}: {type(e).__name__}"
        )
        return 0


def recovery_incidents(strict: bool = False) -> list[dict]:
    """The unresolved recovery incidents (Q187) - what Health shows. Never raises, unless `strict`: then a note that cannot be READ (the settings table unreachable, stored text that is not the
    note) raises ValueError instead of reading as "none" - Health says "unknown", not "ok". Strict reads the table itself (`get_global_setting(strict=True)`): the cache's cold-start default and
    its stale copy are exactly what must not answer "nothing is waiting" when the database is down."""
    if strict:
        from jen.models import user as _user

        try:
            raw = _user.get_global_setting(ATTENTION_KEY, "", strict=True)
        except Exception as e:
            raise ValueError(f"the incident note could not be read ({type(e).__name__})") from e
        incidents = _incidents_of(raw, strict=True)  # (raises MalformedNote for stored text that is not a note)
        return [i for i in incidents if i.get("kind") == ATTENTION_KIND]
    note = attention()
    return [i for i in (note or {}).get("incidents", []) if i.get("kind") == ATTENTION_KIND]


def acknowledge_recovery(server_id=None, service: str | None = None, category: str | None = None) -> int | None:
    """A superadmin's acknowledgement (Q187): clears the recovery incidents matching the filters (None = any) and returns how many. None means the note could not be written - the incidents are
    still shown, and the caller says so. The old `rolled_back` / `rollback_failed` incidents are not touched."""
    cleared = [0]

    def matches(i):
        return (
            i.get("kind") == ATTENTION_KIND
            and (server_id is None or _same_server(i, server_id))
            and (service is None or i.get("service") == service)
            and (category is None or i.get("category") == category)
        )

    def clear(incidents):
        left = [i for i in incidents if not matches(i)]
        cleared[0] = len(incidents) - len(left)
        return left if cleared[0] else None

    try:
        if not _with_attention(clear):
            logger.error("kea_changeset: the recovery incidents could not be cleared")
            return None
        return cleared[0]
    except Exception as e:
        logger.error(f"kea_changeset: could not acknowledge the recovery incidents: {type(e).__name__}")
        return None


def dismiss_rollback_notes() -> bool:
    """The Servers page's old Dismiss button (rolled_back / rollback_failed): leaves the recovery incidents, which a superadmin acknowledges (Q187). False when the note could not be updated (Q189)."""
    try:
        return _with_attention(lambda incidents: [i for i in incidents if i.get("kind") == ATTENTION_KIND])
    except Exception as e:
        logger.debug(f"kea_changeset: could not dismiss the rollback notes: {e}")
        return False


def _listed_count(raw) -> int:
    """How many entries the stored note LISTS, of any type (the lenient reader drops what is not a dict)."""
    import json

    try:
        data = json.loads(raw) if isinstance(raw, str) and raw else raw
    except Exception:
        return 0
    listed = data.get("incidents") if isinstance(data, dict) else None
    return len(listed) if isinstance(listed, list) else 0


def attention() -> dict | None:
    """The unresolved incidents for the Servers page banner, `{"incidents": [...], "unrecognised": n}` oldest first, or None. `incidents` holds only the entries Jen recognises (the banner renders
    those); `unrecognised` counts the dicts it does not (Q190, AF3) - the banner says an incident Jen cannot read is on record, with the set-aside for a superadmin."""
    try:
        from jen.models import user as _user

        raw = _user.get_global_setting(ATTENTION_KEY, "")
        entries = _incidents_of(raw)
        incidents = [i for i in entries if recognised_incident(i)]
        unrecognised = max(len(entries), _listed_count(raw)) - len(
            incidents
        )  # (an entry that is not even a dict is on record too)
        return {"incidents": incidents, "unrecognised": unrecognised} if entries or unrecognised else None
    except Exception:
        return None


def clear_attention() -> bool:
    try:
        return _with_attention(
            lambda incidents: []
        )  # (a locked transaction like every other writer of the note; an unreadable note is refused, not cleared)
    except Exception as e:
        logger.debug(f"kea_changeset: could not clear the outcome: {e}")
        return False


def note_state() -> str:
    """'ok' | 'malformed' | 'unavailable': can the stored recovery note be read as a note (Q189, AE3)? The Servers page offers a superadmin the set-aside only for 'malformed'."""
    try:
        recovery_incidents(strict=True)
        return "ok"
    except MalformedNote:
        return "malformed"
    except ValueError:
        return "unavailable"


def set_aside_unreadable_note() -> tuple[str, str, int]:
    """The ONE sanctioned reset of an unreadable recovery note (Q189, AE3), for a superadmin's explicit request: copy the raw stored value to the settings row
    `changeset_attention_set_aside_<utc timestamp>` (one locked `update_global_setting`), then clear the note through `_with_attention(strict=False)`. Returns `(status, key, length)`:
    'not-needed' (the note reads fine - nothing is touched), 'done', 'changed' (the stored value changed while it was being set aside: nothing was cleared, the copy is a spare) or 'failed' (the copy
    or the clear did not happen: the note is left as it was, and the copy, if made, is a spare).
    Never returns the text; the caller audits the length and the key."""
    from datetime import datetime, timezone

    from jen.models import user as _user

    try:
        raw = _user.get_global_setting(ATTENTION_KEY, "", strict=True)
    except Exception:
        return "failed", "", 0
    try:
        _incidents_of(raw, strict=True)
        return "not-needed", "", 0
    except MalformedNote:
        pass
    key = f"{ATTENTION_KEY}_set_aside_{datetime.now(timezone.utc):%Y%m%dT%H%M%S%fZ}"
    value = raw if isinstance(raw, str) else str(raw)
    cleared = [False]

    def clear_if_unchanged(current):
        # (second pass, finding 6) the clear happens in the same locked transaction that checks the value is still the one that was copied: a second superadmin's set-aside, or a real
        # incident recorded in between, is never wiped by a request that read the note a moment ago
        if current == value:
            cleared[0] = True
            return ""
        return None

    try:
        if not _user.update_global_setting(key, lambda current: value):
            return "failed", "", 0
        if not _user.update_global_setting(ATTENTION_KEY, clear_if_unchanged):
            return "failed", key, len(value)
    except Exception:
        return "failed", "", 0
    return ("done" if cleared[0] else "changed"), key, len(value)


def apply_change(service: str, mutate_fn, summary: str, **kwargs) -> ChangeSetResult:
    """`_run_change` (documented above) plus `record_outcome`, so every caller's
    rolled-back / failed-rollback result reaches the Servers page without each route
    remembering to."""
    result = _run_change(service, mutate_fn, summary, **kwargs)
    record_outcome(result, service, summary)
    return result
