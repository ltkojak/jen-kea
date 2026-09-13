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
audit log) — callers do that unless `ChangeSetResult.status` is
"aborted" or "rollback_failed" (see kea_changeset's callers in
subnets.py/ddns.py); "ok", "nothing" and "noservers" all mean nothing
was left half-written, so a metadata write is safe in each case.

Pure orchestration over `kea_host` — no Flask imports. Callers build
the flash lines from `ChangeSetResult.lines` themselves; this module
never calls `flash()`.
"""

import logging
from dataclasses import dataclass, field

from jen import extensions
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
    status: str  # "ok" | "nothing" | "noservers" | "aborted" | "rollback_failed"
    last_code: str  # the last mutate code seen — callers map it to their own message
    lines: list[tuple[str, str]] = field(default_factory=list)  # ("success"|"error", text), in display order
    restart_failures: list[str] = field(default_factory=list)  # server names whose restart failed (status stays "ok")


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


def apply_change(
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
        res = _host.test_config(t.server, service, t.after_cfg)
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
        res = _host.apply_config(t.server, service, t.after_cfg, expect_sha256=t.before_sha, summary=summary)
        if res.get("ok"):
            t.applied_sha = res.get("sha256")
            committed.append(t)
            continue

        # First failure — revert every already-committed target.
        if res.get("code") == "conflict":
            lines.append(("error", f"❌ {t.name}: {conflict_phrase(t.name)}"))
        else:
            lines.append(("error", _failure_line(t.name, res, daemon_label)))

        revert_failed = []
        for done in reversed(committed):
            rres = _host.apply_config(
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
                _host.service_action(done.server, service, "restart")

        if revert_failed:
            new_names = ", ".join(d.name for d in committed if d.name not in revert_failed)
            old_names = ", ".join(revert_failed)
            lines.append(
                (
                    "error",
                    f"🛑 ROLLBACK FAILED — {new_names or '(none)'} now have the new config, "
                    f"{old_names} the old one. Fix by hand: Servers → Config history → restore.",
                )
            )
            return ChangeSetResult("rollback_failed", res.get("code", "error"), lines)

        if committed:
            names = ", ".join(d.name for d in committed)
            lines.append(("error", f"↩️ reverted {len(committed)} server(s) that had already been updated: {names}"))
        return ChangeSetResult("aborted", res.get("code", "error"), lines)

    # ── Phase 4: restart (every apply succeeded) ──────────────────────
    restart_failures: list[str] = []
    if restart:
        for t in targets:
            rres = _host.service_action(t.server, service, "restart")
            if rres.get("ok"):
                lines.append(("success", f"✅ {t.name}: {summary}, {daemon_label} restarted"))
            else:
                lines.append(
                    ("success", f"✅ {t.name}: {summary} — restart {daemon_label} manually ({rres.get('detail')})")
                )
                restart_failures.append(t.name)
    else:
        for t in targets:
            lines.append(("success", f"✅ {t.name}: {summary}"))

    return ChangeSetResult("ok", "ok", lines, restart_failures)
