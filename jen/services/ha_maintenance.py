"""
jen/services/ha_maintenance.py
──────────────────────────────
v5.38.0 (Q37) — the pure half of the planned-maintenance flow on the
Servers page: which Jen server is the partner of the one being taken
down, and what the stepper should show next given both servers' HA
status. No Kea calls here; the route feeds in `kea_ha.ha_status()`
results (or None for an unreachable server) and acts on the answer.

The Kea semantics this encodes (hooks-ha, verified 2026-09-14):
`ha-maintenance-start` goes to the server that KEEPS serving (B). It
tells its partner (A) to enter `in-maintenance` and takes every scope
itself (`partner-in-maintenance`). Once A is actually shut down, B moves
to `partner-down` on its own; when A returns, Kea negotiates, syncs
leases and returns both to `hot-standby` / `load-balancing` with no
further command. `ha-maintenance-cancel` (to B) only works while B is
still `partner-in-maintenance`.
"""

from __future__ import annotations

from datetime import datetime, timezone

STEPS = ("preflight", "handover", "work", "back", "done")
PREFLIGHT_CHECK_IDS = ("kea_reachable", "kea_ha_state", "kea_time_sync", "kea_config_drift", "lease_snapshot_fresh")
HANDOVER_TIMEOUT_SECONDS = 60
NORMAL_STATES = ("hot-standby", "load-balancing")


def resolve_partner(down: dict, servers: list[dict], ha_configs: dict) -> tuple[dict | None, str]:
    """(partner server, "") or (None, reason). `ha_configs` is
    {server id: kea_ha.ha_config(...) or None} for every Jen server.
    The partner is the Jen server whose HA `this-server-name` equals
    the name A's own config lists as its one other peer."""
    from jen.services import kea_ha

    a_cfg = ha_configs.get(down.get("id"))
    if not a_cfg:
        return None, f"{down.get('name')} has no HA hook configured (libdhcp_ha.so with a high-availability block)."
    want = kea_ha.partner_name(a_cfg)
    if not want:
        return (
            None,
            f"{down.get('name')}'s HA config does not name exactly one partner — Jen cannot pick the other side.",
        )
    for s in servers:
        if s.get("id") == down.get("id"):
            continue
        cfg = ha_configs.get(s.get("id"))
        if cfg and cfg.get("this_server_name") == want:
            return s, ""
    return None, (
        f"Jen only knows one side of this pair — {down.get('name')}'s partner is '{want}' in Kea, "
        "and no server under Settings → Kea reports that name. Add the partner there first."
    )


def leases_shared(a_cfg: dict | None) -> bool:
    """True when the pair shares one lease database (Kea's
    `send-lease-updates` / `sync-leases` false), so there is no
    per-lease sync to watch for after the node returns."""
    if not a_cfg:
        return False
    return a_cfg.get("send_lease_updates") is False or a_cfg.get("sync_leases") is False


def _state(status: dict | None) -> str | None:
    """The local HA state out of a kea_ha.ha_status() result; None when
    the server was unreachable or reported no HA block."""
    if not status:
        return None
    return (status.get("local") or {}).get("state")


def _age(step_at: str | None, now: datetime) -> float:
    if not step_at:
        return 0.0
    try:
        return (now - datetime.fromisoformat(step_at)).total_seconds()
    except (TypeError, ValueError):
        return 0.0


def next_step(state: dict, status_down: dict | None, status_up: dict | None, now: datetime | None = None) -> dict:
    """What the stepper shows for `state` = {"step", "step_at", "down_name",
    "up_name", "leases_shared"} given both servers' current HA status.
    Returns {"step", "advance" (the step to move to, or None),
    "down_state", "up_state", "can_cancel", "timed_out", "tone"
    (ok | wait | warn | fail), "message"}."""
    now = now or datetime.now(timezone.utc)
    step = state.get("step", "preflight")
    a, b = state.get("down_name", "A"), state.get("up_name", "B")
    sa, sb = _state(status_down), _state(status_up)
    out = {
        "step": step,
        "advance": None,
        "down_state": sa,
        "up_state": sb,
        "can_cancel": sb == "partner-in-maintenance",
        "timed_out": False,
        "tone": "wait",
        "message": "",
    }
    if step == "preflight":
        out["tone"] = "ok" if sa in NORMAL_STATES and sb in NORMAL_STATES else "warn"
        out["message"] = (
            f"{a} is {sa or 'unreachable'}, {b} is {sb or 'unreachable'}. "
            f"Start the handover to have {b} take every scope while {a} goes quiet."
        )
        return out
    if step == "handover":
        if sb == "partner-in-maintenance" and sa == "in-maintenance":
            out["advance"] = "work"
            out["tone"] = "ok"
            out["message"] = f"{b} is serving everything ({sb}); {a} is in-maintenance and can be shut down."
            return out
        if _age(state.get("step_at"), now) > HANDOVER_TIMEOUT_SECONDS:
            out["timed_out"] = True
            out["tone"] = "fail"
            stuck = []
            if sb != "partner-in-maintenance":
                stuck.append(f"{b} is {sb or 'unreachable'}, not partner-in-maintenance")
            if sa != "in-maintenance":
                stuck.append(f"{a} is {sa or 'unreachable'}, not in-maintenance")
            out["message"] = (
                f"No handover after {HANDOVER_TIMEOUT_SECONDS}s: " + "; ".join(stuck) + ". "
                "Check both servers' Kea logs (the HA hook must reach its partner over the HA channel)"
                + (" — or cancel to return both to their previous states." if out["can_cancel"] else ".")
            )
            return out
        out["message"] = f"Waiting for Kea: {b} is {sb or 'unreachable'}, {a} is {sa or 'unreachable'}…"
        return out
    if step == "work":
        if sb == "partner-down" or sa is None:
            out["tone"] = "ok"
            out["message"] = (
                f"{a} is down; {b} is serving alone ({sb or '?'}). Do your work on {a} now. "
                "Cancel no longer applies — once you bring "
                f"{a} back, Kea re-synchronises on its own; click Back when it is up."
            )
        elif sb == "partner-in-maintenance":
            out["tone"] = "ok"
            out["message"] = (
                f"{a} is out of service ({sa}); {b} answers everything. Stop Kea on {a}, patch, reboot — "
                "or cancel to hand back without doing anything."
            )
        else:
            out["tone"] = "warn"
            out["message"] = f"Unexpected states: {a} is {sa or 'unreachable'}, {b} is {sb or 'unreachable'}."
        return out
    if step == "back":
        if sa in NORMAL_STATES and sb in NORMAL_STATES:
            out["advance"] = "done"
            out["tone"] = "ok"
            out["message"] = f"Both back to normal: {a} is {sa}, {b} is {sb}."
            return out
        if sa is None:
            out["message"] = f"Waiting for {a} to answer… {b} is {sb or 'unreachable'}."
        else:
            sync = "leases are shared; nothing to sync" if state.get("leases_shared") else "Kea syncs leases on its own"
            out["message"] = f"{a} is {sa}, {b} is {sb or 'unreachable'} — {sync}; waiting for both to report normal."
        return out
    out["tone"] = "ok"
    out["message"] = f"Maintenance of {a} finished. Repeat for {b} when you are ready."
    return out
