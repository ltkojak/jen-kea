"""
jen/services/packet_health.py
──────────────────────────────
Q42 — is Kea processing DHCPv4 traffic cleanly? Pure functions over
`server_stats` snapshot rows (written by
`jen.services.alerts.take_server_stats_snapshot`): turn raw, ever-
increasing Kea counters into per-window deltas, per-minute rates, and a
health verdict. No DB/network access here — callers fetch rows and pass
them in, which is what keeps this testable without a database.
"""

from datetime import timedelta

DEFAULT_THRESHOLDS = {
    # warn when drops+parse-failures exceed this % of pkt4-received
    "warn_drop_pct": 1.0,
    # fail when drops+parse-failures exceed this % of pkt4-received
    "fail_drop_pct": 10.0,
    # fail when NAKs exceed this % of ACKs
    "fail_nak_pct": 10.0,
    # the NAK ratio alone never warns or fails below this many NAKs in the
    # window (one stray NAK on a quiet server is not an incident)
    "min_naks": 10,
}


# v5.49.0-beta.3 (Q52) — the pkt4-* counters Kea 3.2 adds beyond the five
# classic ones. The NAMES below are the verified ones from the Q50
# kea-compat run's `pkt4-3.2.0.json` artifact (real kea-dhcp4 3.2.0 and
# 3.3.1 report identical lists; 3.0.3 reports none of these); the labels
# are plain-English readings of the names, no more. They are shown next to
# the classic counters and summarised in the Health detail — they do not
# change the ok/warn/fail thresholds, which stay on the classic counters.
DROP_REASON_LABELS = {
    "pkt4-admin-filtered": "Filtered by an administrator rule",
    "pkt4-duplicate": "Duplicate packet",
    "pkt4-limit-exceeded": "Limit exceeded",
    "pkt4-not-for-us": "Addressed to a different server",
    "pkt4-processing-failed": "Processing failed",
    "pkt4-queue-full": "Queue full",
    "pkt4-rfc-violation": "RFC violation",
    "pkt4-service-disabled": "Service disabled",
}


def deltas(rows):
    """rows: snapshots ordered oldest→newest, each
    `{"snapshot_time": datetime, "stats": {counter_name: int}}` (Kea's raw,
    monotonically-increasing statistic-get-all values). Returns one entry
    per consecutive pair: `{"ts", "seconds", "delta": {counter_name: int}}`.

    Kea's counters reset to 0 on restart, so a value that *dropped* between
    two snapshots isn't a negative delta — it means the counter restarted
    partway through the interval. Rather than under-count (or produce a
    nonsensical negative rate), treat the newer raw value as the whole
    delta: everything it counted happened since the restart, which is
    somewhere inside this interval.
    """
    out = []
    for prev, cur in zip(rows, rows[1:], strict=False):
        prev_stats = prev.get("stats") or {}
        cur_stats = cur.get("stats") or {}
        seconds = (cur["snapshot_time"] - prev["snapshot_time"]).total_seconds()
        delta = {}
        for key, cur_val in cur_stats.items():
            prev_val = prev_stats.get(key, 0)
            d = cur_val - prev_val
            delta[key] = cur_val if d < 0 else d
        out.append({"ts": cur["snapshot_time"], "seconds": seconds, "delta": delta})
    return out


def rates(deltas_list, window_minutes=60):
    """Sum the deltas whose timestamp falls within the trailing
    `window_minutes` (measured back from the latest delta's own
    timestamp — not wall-clock now, so this stays testable with fixed
    data) into per-key totals and per-minute rates.

    Returns `{"totals": {key: int}, "rates": {key: float}, "window_minutes":
    <actual minutes of data covered, <= window_minutes — shorter right
    after startup or a gap>}`.
    """
    if not deltas_list:
        return {"totals": {}, "rates": {}, "window_minutes": 0.0}

    latest_ts = deltas_list[-1]["ts"]
    cutoff = latest_ts - timedelta(minutes=window_minutes)
    included = [d for d in deltas_list if d["ts"] > cutoff]

    totals = {}
    elapsed_seconds = 0.0
    for d in included:
        elapsed_seconds += d["seconds"]
        for key, value in d["delta"].items():
            totals[key] = totals.get(key, 0) + value

    elapsed_minutes = elapsed_seconds / 60.0
    rates_per_min = {}
    if elapsed_minutes > 0:
        for key, value in totals.items():
            rates_per_min[key] = value / elapsed_minutes

    return {"totals": totals, "rates": rates_per_min, "window_minutes": elapsed_minutes}


def assess(rates_result, thresholds=None):
    """Turn a `rates()` result into `{"status", "notes": [str, ...]}`.

    status is one of "ok", "warn", "fail", or "no_traffic" — the last is
    informational, not a fault: a standby server in a hot-standby HA pair
    legitimately sees zero received packets the whole window.
    """
    t = {**DEFAULT_THRESHOLDS, **(thresholds or {})}
    totals = rates_result.get("totals", {})
    received = totals.get("pkt4-received", 0)

    if received == 0:
        return {"status": "no_traffic", "notes": ["no pkt4-received in this window — idle, or a hot-standby peer"]}

    drop = totals.get("pkt4-receive-drop", 0) + totals.get("pkt4-parse-failed", 0)
    drop_pct = (drop / received) * 100.0

    acks = totals.get("pkt4-ack-sent", 0)
    naks = totals.get("pkt4-nak-sent", 0)
    # NAKs as a share of ALL replies (ACK + NAK): with the old naks/acks form,
    # 50 NAKs and 0 ACKs scored 0% and read green.
    replies = acks + naks
    nak_pct = (naks / replies * 100.0) if replies else 0.0
    nak_significant = naks >= t["min_naks"]

    alloc_fail_total = sum(v for k, v in totals.items() if k.startswith("v4-allocation-fail"))

    status = "ok"
    if drop_pct > t["fail_drop_pct"] or (nak_significant and nak_pct > t["fail_nak_pct"]):
        status = "fail"
    elif drop_pct > t["warn_drop_pct"] or alloc_fail_total > 0:
        status = "warn"

    notes = []
    if drop:
        notes.append(f"drops + parse failures: {drop_pct:.1f}% of received ({drop}/{received})")
    if naks:
        if acks:
            notes.append(f"NAKs: {nak_pct:.1f}% of replies ({naks} NAK / {acks} ACK)")
        else:
            notes.append(f"{naks} NAK(s), 0 ACKs")
    if alloc_fail_total:
        notes.append(f"{alloc_fail_total} allocation failure(s)")
    reasons = [f"{label} {totals[key]}" for key, label in DROP_REASON_LABELS.items() if totals.get(key, 0) > 0]
    if reasons:
        notes.append("Kea 3.2 drop reasons: " + ", ".join(reasons))
    if not notes:
        notes.append("no drops, parse failures, NAKs, or allocation failures")

    return {"status": status, "notes": notes}
