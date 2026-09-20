"""
tests/test_packet_health.py
────────────────────────────
Q42 — pure tests for jen/services/packet_health.py. No DB, no Kea: these
exercise deltas()/rates()/assess() directly against constructed rows, so
they run with --noconftest (see CLAUDE.md's "Local verification").
"""

from datetime import datetime, timedelta

from jen.services.packet_health import assess, deltas, rates


def _row(minutes_ago, **stats):
    return {"snapshot_time": datetime(2026, 1, 1, 12, 0, 0) + timedelta(minutes=minutes_ago), "stats": stats}


class TestDeltas:
    def test_basic_increase(self):
        rows = [
            _row(0, **{"pkt4-received": 100, "pkt4-ack-sent": 90}),
            _row(30, **{"pkt4-received": 160, "pkt4-ack-sent": 140}),
        ]
        out = deltas(rows)
        assert len(out) == 1
        assert out[0]["delta"] == {"pkt4-received": 60, "pkt4-ack-sent": 50}
        assert out[0]["seconds"] == 30 * 60
        assert out[0]["ts"] == rows[1]["snapshot_time"]

    def test_restart_reset_uses_newer_raw_value(self):
        # Kea restarted between snapshots: pkt4-received dropped from 500
        # to 20 — the whole 20 happened since the restart, not -480.
        rows = [
            _row(0, **{"pkt4-received": 500}),
            _row(30, **{"pkt4-received": 20}),
        ]
        out = deltas(rows)
        assert out[0]["delta"]["pkt4-received"] == 20

    def test_multiple_rows_yield_one_fewer_delta(self):
        rows = [_row(0, **{"pkt4-received": 0}), _row(10, **{"pkt4-received": 10}), _row(20, **{"pkt4-received": 25})]
        out = deltas(rows)
        assert len(out) == 2
        assert out[0]["delta"]["pkt4-received"] == 10
        assert out[1]["delta"]["pkt4-received"] == 15

    def test_key_absent_from_prior_row_treated_as_zero(self):
        # e.g. a fresh Kea 3.2 box's new drop-reason counter appearing for
        # the first time — shouldn't blow up or be dropped.
        rows = [_row(0, **{"pkt4-received": 10}), _row(10, **{"pkt4-received": 20, "pkt4-queue-full": 3})]
        out = deltas(rows)
        assert out[0]["delta"]["pkt4-queue-full"] == 3

    def test_empty_and_single_row_yield_no_deltas(self):
        assert deltas([]) == []
        assert deltas([_row(0, **{"pkt4-received": 1})]) == []


class TestRates:
    def test_sums_and_converts_to_per_minute(self):
        d = [{"ts": datetime(2026, 1, 1, 12, 30), "seconds": 30 * 60, "delta": {"pkt4-received": 60}}]
        r = rates(d, window_minutes=60)
        assert r["totals"] == {"pkt4-received": 60}
        assert r["window_minutes"] == 30
        assert r["rates"]["pkt4-received"] == 2.0

    def test_excludes_deltas_outside_the_trailing_window(self):
        base = datetime(2026, 1, 1, 12, 0)
        d = [
            {"ts": base, "seconds": 30 * 60, "delta": {"pkt4-received": 1000}},  # outside a 30-min window
            {"ts": base + timedelta(minutes=30), "seconds": 30 * 60, "delta": {"pkt4-received": 30}},
        ]
        r = rates(d, window_minutes=30)
        assert r["totals"] == {"pkt4-received": 30}

    def test_empty_deltas_yield_zeroed_result(self):
        r = rates([], window_minutes=60)
        assert r == {"totals": {}, "rates": {}, "window_minutes": 0.0}


class TestAssess:
    def test_ok_when_clean(self):
        r = {"totals": {"pkt4-received": 1000, "pkt4-ack-sent": 900}}
        result = assess(r)
        assert result["status"] == "ok"

    def test_no_traffic_is_informational_not_a_fault(self):
        r = {"totals": {}}
        result = assess(r)
        assert result["status"] == "no_traffic"

    def test_warn_when_drops_exceed_one_percent(self):
        # 20 drops / 1000 received = 2% > warn(1%), <= fail(10%)
        r = {"totals": {"pkt4-received": 1000, "pkt4-receive-drop": 20}}
        result = assess(r)
        assert result["status"] == "warn"

    def test_warn_on_any_allocation_failure(self):
        r = {"totals": {"pkt4-received": 1000, "v4-allocation-fail-subnet": 1}}
        result = assess(r)
        assert result["status"] == "warn"

    def test_fail_when_drops_exceed_ten_percent(self):
        r = {"totals": {"pkt4-received": 100, "pkt4-receive-drop": 15}}
        result = assess(r)
        assert result["status"] == "fail"

    def test_fail_when_naks_exceed_ten_percent_of_acks(self):
        r = {"totals": {"pkt4-received": 1000, "pkt4-ack-sent": 100, "pkt4-nak-sent": 20}}
        result = assess(r)
        assert result["status"] == "fail"

    def test_fifty_naks_and_no_acks_is_a_failure(self):
        """v5.49.0-beta.2 (audit H) - the old naks/acks ratio scored 0% here."""
        r = {"totals": {"pkt4-received": 1000, "pkt4-nak-sent": 50}}
        assert assess(r)["status"] == "fail"

    def test_one_stray_nak_stays_ok_and_is_noted(self):
        r = {"totals": {"pkt4-received": 1000, "pkt4-nak-sent": 1}}
        result = assess(r)
        assert result["status"] == "ok"
        assert any("1 NAK" in n for n in result["notes"])

    def test_nak_ratio_needs_the_minimum_count_to_alert(self):
        # 5 NAKs / 5 ACKs is 50% of replies but below min_naks (10)
        r = {"totals": {"pkt4-received": 1000, "pkt4-ack-sent": 5, "pkt4-nak-sent": 5}}
        assert assess(r)["status"] == "ok"
        assert assess(r, thresholds={"min_naks": 1})["status"] == "fail"

    def test_custom_thresholds_override_defaults(self):
        r = {"totals": {"pkt4-received": 1000, "pkt4-receive-drop": 5}}
        assert assess(r)["status"] == "ok"
        assert assess(r, thresholds={"warn_drop_pct": 0.1})["status"] == "warn"


class TestKea32DropReasons:
    """v5.49.0-beta.3 (Q52) - the names come from the kea-compat run's
    pkt4-3.2.0.json artifact (real kea-dhcp4 3.2.0), not from the ARM."""

    VERIFIED_3_2_EXTRAS = {
        "pkt4-admin-filtered",
        "pkt4-duplicate",
        "pkt4-lease-query-received",
        "pkt4-lease-query-response-active-sent",
        "pkt4-lease-query-response-unassigned-sent",
        "pkt4-lease-query-response-unknown-sent",
        "pkt4-limit-exceeded",
        "pkt4-not-for-us",
        "pkt4-processing-failed",
        "pkt4-queue-full",
        "pkt4-rfc-violation",
        "pkt4-service-disabled",
    }

    def test_every_named_reason_is_a_verified_3_2_counter(self):
        from jen.services.packet_health import DROP_REASON_LABELS

        assert set(DROP_REASON_LABELS) <= self.VERIFIED_3_2_EXTRAS
        assert all(DROP_REASON_LABELS.values())

    def test_reasons_appear_in_the_notes_but_do_not_change_status(self):
        r = {"totals": {"pkt4-received": 1000, "pkt4-queue-full": 3, "pkt4-rfc-violation": 2}}
        result = assess(r)
        assert result["status"] == "ok"
        assert any("Queue full 3" in n and "RFC violation 2" in n for n in result["notes"])

    def test_zero_reasons_add_no_note(self):
        r = {"totals": {"pkt4-received": 1000, "pkt4-queue-full": 0}}
        assert not any("drop reasons" in n for n in assess(r)["notes"])
