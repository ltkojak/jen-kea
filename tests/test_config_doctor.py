"""
tests/test_config_doctor.py
─────────────────────────────
v5.40.0 (Q41) — jen/services/config_doctor.py is pure, so every test
here calls diagnose() directly against a fabricated Dhcp4 config; no
DB, no Kea, no Flask.
"""

import pytest

from jen.services import config_doctor as doctor

ALL_CHECK_IDS = {
    "pools_overlap",
    "pool_outside_subnet",
    "reservation_outside_subnet",
    "reservation_inside_pool",
    "duplicate_reservation_identifier",
    "duplicate_reservation_address",
    "class_unreferenced",
    "class_unknown_member",
    "class_unreachable",
    "contradictory_pool_guards",
    "subnet_without_pools_or_reservations",
    "lease_timers",
    "global_option_shadowed_everywhere",
    "shared_network_asymmetry",
    "ha_peer_semantic_diff",
    "removed_keys",
}


def _ids(findings):
    return {f["id"] for f in findings}


class TestCleanConfig:
    def test_a_sane_config_yields_nothing(self):
        cfg = {
            "valid-lifetime": 3600,
            "renew-timer": 900,
            "rebind-timer": 1800,
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "10.10.0.0/24",
                    "pools": [{"pool": "10.10.0.10 - 10.10.0.200"}],
                }
            ],
        }
        assert doctor.diagnose(cfg, hosts=[]) == []

    def test_none_config_yields_nothing(self):
        assert doctor.diagnose(None) == []

    def test_empty_config_yields_nothing(self):
        assert doctor.diagnose({}) == []


# ── the subnet/pool/reservation/class shaped checks, one fixture ────────────


@pytest.fixture
def kitchen_sink_cfg():
    return {
        "valid-lifetime": 3600,
        "renew-timer": 900,
        "rebind-timer": 1800,
        "client-classes": [
            {"name": "cls_red", "test": "option[60].hex == 'RED'"},
            {"name": "cls_not_red", "test": "not (option[60].hex == 'RED')"},
            {"name": "cls_unused", "test": "option[60].hex == 'UNUSED'"},
            {"name": "cls_bad_member", "test": "member('ghost_class')"},
            {"name": "cls_unreachable", "test": "option[60].hex == 'AAA' and option[60].hex == 'BBB'"},
        ],
        "subnet4": [
            {
                # pools_overlap: two overlapping ranges in the same subnet.
                "id": 1,
                "subnet": "10.0.1.0/24",
                "pools": [
                    {"pool": "10.0.1.10 - 10.0.1.50"},
                    {"pool": "10.0.1.40 - 10.0.1.60"},
                ],
            },
            {
                # pool_outside_subnet: the pool spills past the /24.
                "id": 2,
                "subnet": "10.0.2.0/24",
                "pools": [{"pool": "10.0.2.240 - 10.0.3.10"}],
            },
            {
                # reservation_inside_pool (warn, reservations-out-of-pool)
                # + reservation_outside_subnet (a second reservation whose
                # address isn't even in this /24).
                "id": 3,
                "subnet": "10.0.3.0/24",
                "reservations-out-of-pool": True,
                "pools": [{"pool": "10.0.3.10 - 10.0.3.50"}],
            },
            {
                # duplicate_reservation_identifier + duplicate_reservation_address.
                "id": 4,
                "subnet": "10.0.4.0/24",
                "pools": [{"pool": "10.0.4.10 - 10.0.4.50"}],
            },
            {
                # subnet_without_pools_or_reservations.
                "id": 5,
                "subnet": "10.0.5.0/24",
            },
            {
                # contradictory_pool_guards: subnet requires cls_red, its
                # only pool requires cls_not_red (the exact negation).
                "id": 6,
                "subnet": "10.0.6.0/24",
                "client-classes": ["cls_red"],
                "pools": [{"pool": "10.0.6.10 - 10.0.6.50", "client-classes": ["cls_not_red"]}],
            },
        ],
    }


@pytest.fixture
def kitchen_sink_hosts():
    return [
        # subnet 3: inside the one pool there.
        {"subnet_id": 3, "identifier_type": "hw-address", "identifier": "aabbccddee03", "ip": "10.0.3.20"},
        # subnet 4: same identifier twice.
        {"subnet_id": 4, "identifier_type": "hw-address", "identifier": "aabbccddee04", "ip": "10.0.4.60"},
        {"subnet_id": 4, "identifier_type": "hw-address", "identifier": "aabbccddee04", "ip": "10.0.4.61"},
        # subnet 4: same address twice (different identifiers).
        {"subnet_id": 4, "identifier_type": "hw-address", "identifier": "aabbccddee05", "ip": "10.0.4.99"},
        {"subnet_id": 4, "identifier_type": "hw-address", "identifier": "aabbccddee06", "ip": "10.0.4.99"},
        # subnet 4: filed under subnet 4 but the address is in subnet 5's range.
        {"subnet_id": 4, "identifier_type": "hw-address", "identifier": "aabbccddee07", "ip": "10.0.5.5"},
    ]


class TestKitchenSink:
    def test_every_subnet_shaped_check_fires(self, kitchen_sink_cfg, kitchen_sink_hosts):
        findings = doctor.diagnose(kitchen_sink_cfg, kitchen_sink_hosts)
        ids = _ids(findings)
        expected = {
            "pools_overlap",
            "pool_outside_subnet",
            "reservation_outside_subnet",
            "reservation_inside_pool",
            "duplicate_reservation_identifier",
            "duplicate_reservation_address",
            "class_unreferenced",
            "class_unknown_member",
            "class_unreachable",
            "contradictory_pool_guards",
            "subnet_without_pools_or_reservations",
        }
        assert expected <= ids, f"missing: {expected - ids}"

    def test_reservation_inside_pool_is_warn_when_out_of_pool_flag_set(self, kitchen_sink_cfg, kitchen_sink_hosts):
        findings = doctor.diagnose(kitchen_sink_cfg, kitchen_sink_hosts)
        row = next(f for f in findings if f["id"] == "reservation_inside_pool")
        assert row["severity"] == "warn"

    def test_class_unreferenced_names_the_right_class(self, kitchen_sink_cfg, kitchen_sink_hosts):
        findings = doctor.diagnose(kitchen_sink_cfg, kitchen_sink_hosts)
        row = next(f for f in findings if f["id"] == "class_unreferenced")
        assert "cls_unused" in row["detail"]

    def test_referenced_classes_are_not_flagged_unreferenced(self, kitchen_sink_cfg, kitchen_sink_hosts):
        findings = doctor.diagnose(kitchen_sink_cfg, kitchen_sink_hosts)
        unreferenced_names = [f["detail"] for f in findings if f["id"] == "class_unreferenced"]
        assert not any("cls_red" in d and "cls_unused" not in d for d in unreferenced_names)

    def test_pool_outside_subnet_is_fail(self, kitchen_sink_cfg, kitchen_sink_hosts):
        findings = doctor.diagnose(kitchen_sink_cfg, kitchen_sink_hosts)
        row = next(f for f in findings if f["id"] == "pool_outside_subnet")
        assert row["severity"] == "fail"

    def test_class_unknown_member_names_the_ghost(self, kitchen_sink_cfg, kitchen_sink_hosts):
        findings = doctor.diagnose(kitchen_sink_cfg, kitchen_sink_hosts)
        row = next(f for f in findings if f["id"] == "class_unknown_member")
        assert "ghost_class" in row["detail"]


# ── the checks that need their own isolated config ───────────────────────────


class TestLeaseTimers:
    def test_out_of_order_timers_warn(self):
        cfg = {
            "valid-lifetime": 3600,
            "renew-timer": 900,
            "rebind-timer": 1800,
            "subnet4": [
                {
                    "id": 10,
                    "subnet": "10.10.10.0/24",
                    "pools": [{"pool": "10.10.10.10 - 10.10.10.50"}],
                    "renew-timer": 2000,  # >= rebind-timer inherited (1800)
                }
            ],
        }
        findings = doctor.diagnose(cfg, hosts=[])
        row = next(f for f in findings if f["id"] == "lease_timers" and "out of order" in f["title"].lower())
        assert row["severity"] == "warn"

    def test_very_short_lease_warns(self):
        cfg = {"valid-lifetime": 30, "renew-timer": 10, "rebind-timer": 20, "subnet4": []}
        findings = doctor.diagnose(cfg, hosts=[])
        row = next(f for f in findings if f["id"] == "lease_timers" and "short" in f["title"].lower())
        assert row["severity"] == "warn"

    def test_very_long_lease_is_info(self):
        cfg = {"valid-lifetime": 40 * 86400, "renew-timer": 900, "rebind-timer": 1800, "subnet4": []}
        findings = doctor.diagnose(cfg, hosts=[])
        row = next(f for f in findings if f["id"] == "lease_timers" and "long" in f["title"].lower())
        assert row["severity"] == "info"


class TestGlobalOptionShadowed:
    def test_option_overridden_by_every_subnet_is_flagged(self):
        cfg = {
            "option-data": [{"code": 6, "name": "domain-name-servers", "data": "8.8.8.8"}],
            "subnet4": [
                {"id": 1, "subnet": "10.0.1.0/24", "option-data": [{"code": 6, "data": "10.0.1.1"}]},
                {"id": 2, "subnet": "10.0.2.0/24", "option-data": [{"code": 6, "data": "10.0.2.1"}]},
            ],
        }
        findings = doctor.diagnose(cfg, hosts=[])
        assert "global_option_shadowed_everywhere" in _ids(findings)

    def test_option_overridden_by_only_some_subnets_is_not_flagged(self):
        cfg = {
            "option-data": [{"code": 6, "name": "domain-name-servers", "data": "8.8.8.8"}],
            "subnet4": [
                {"id": 1, "subnet": "10.0.1.0/24", "option-data": [{"code": 6, "data": "10.0.1.1"}]},
                {"id": 2, "subnet": "10.0.2.0/24"},
            ],
        }
        findings = doctor.diagnose(cfg, hosts=[])
        assert "global_option_shadowed_everywhere" not in _ids(findings)


class TestSharedNetworkAsymmetry:
    def test_different_lease_times_flagged(self):
        cfg = {
            "shared-networks": [
                {
                    "name": "guest-net",
                    "subnet4": [
                        {"id": 20, "subnet": "10.20.0.0/24", "valid-lifetime": 3600},
                        {"id": 21, "subnet": "10.20.1.0/24", "valid-lifetime": 7200},
                    ],
                }
            ]
        }
        findings = doctor.diagnose(cfg, hosts=[])
        assert "shared_network_asymmetry" in _ids(findings)

    def test_matching_members_not_flagged(self):
        cfg = {
            "shared-networks": [
                {
                    "name": "guest-net",
                    "subnet4": [
                        {"id": 20, "subnet": "10.20.0.0/24", "valid-lifetime": 3600},
                        {"id": 21, "subnet": "10.20.1.0/24", "valid-lifetime": 3600},
                    ],
                }
            ]
        }
        findings = doctor.diagnose(cfg, hosts=[])
        assert "shared_network_asymmetry" not in _ids(findings)


class TestHaPeerSemanticDiff:
    def _ha(self, mode="hot-standby", max_ack_delay=10000, peers=None):
        return {
            "this_server_name": "server1",
            "mode": mode,
            "heartbeat_delay": 10000,
            "max_response_delay": 60000,
            "max_ack_delay": max_ack_delay,
            "max_unacked_clients": 0,
            "peers": peers or [{"name": "server1", "role": "primary"}, {"name": "server2", "role": "standby"}],
            "send_lease_updates": True,
            "sync_leases": True,
        }

    def test_matching_configs_not_flagged(self):
        a, b = self._ha(), self._ha()
        assert doctor.diagnose({}, hosts=[], ha_configs={1: a, 2: b}) == []

    def test_differing_timer_flagged(self):
        a, b = self._ha(), self._ha(max_ack_delay=5000)
        findings = doctor.diagnose({}, hosts=[], ha_configs={1: a, 2: b})
        assert "ha_peer_semantic_diff" in _ids(findings)

    def test_only_one_reachable_config_is_not_enough_to_compare(self):
        findings = doctor.diagnose({}, hosts=[], ha_configs={1: self._ha(), 2: None})
        assert "ha_peer_semantic_diff" not in _ids(findings)

    def test_no_ha_configs_given_is_a_noop(self):
        assert doctor.diagnose({}, hosts=[], ha_configs=None) == []


class TestRemovedKeys:
    def test_reservation_mode_is_flagged(self):
        cfg = {"subnet4": [{"id": 1, "subnet": "10.0.0.0/24", "reservation-mode": "out-of-pool"}]}
        findings = doctor.diagnose(cfg, hosts=[])
        assert "removed_keys" in _ids(findings)


# ── cross-cutting invariants over everything above ───────────────────────────


class TestFindingShape:
    def _all_findings(self, kitchen_sink_cfg, kitchen_sink_hosts):
        """Every isolated fixture's own diagnose() call, concatenated —
        deliberately NOT one merged config: the checks that need "every
        subnet agrees" (global_option_shadowed_everywhere) or "every
        subnet in this shared network" (shared_network_asymmetry) would
        silently stop firing the moment an unrelated subnet from another
        fixture got mixed in, which is exactly what happened the first
        time this was one combined dict."""
        out = list(doctor.diagnose(kitchen_sink_cfg, kitchen_sink_hosts))
        out += doctor.diagnose({"valid-lifetime": 30, "renew-timer": 2000, "rebind-timer": 10, "subnet4": []}, hosts=[])
        out += doctor.diagnose({"valid-lifetime": 40 * 86400, "subnet4": []}, hosts=[])
        out += doctor.diagnose(
            {
                "option-data": [{"code": 6, "name": "domain-name-servers", "data": "8.8.8.8"}],
                "subnet4": [
                    {"id": 1, "subnet": "10.0.1.0/24", "option-data": [{"code": 6, "data": "10.0.1.1"}]},
                    {"id": 2, "subnet": "10.0.2.0/24", "option-data": [{"code": 6, "data": "10.0.2.1"}]},
                ],
            },
            hosts=[],
        )
        out += doctor.diagnose(
            {
                "shared-networks": [
                    {
                        "name": "guest-net",
                        "subnet4": [
                            {"id": 20, "subnet": "10.20.0.0/24", "valid-lifetime": 3600},
                            {"id": 21, "subnet": "10.20.1.0/24", "valid-lifetime": 7200},
                        ],
                    }
                ]
            },
            hosts=[],
        )
        out += doctor.diagnose(
            {"subnet4": [{"id": 1, "subnet": "10.0.0.0/24", "reservation-mode": "out-of-pool"}]}, hosts=[]
        )
        out += doctor.diagnose(
            {},
            hosts=[],
            ha_configs={1: TestHaPeerSemanticDiff()._ha(), 2: TestHaPeerSemanticDiff()._ha(max_ack_delay=1)},
        )
        return out

    def test_every_finding_has_a_non_empty_why(self, kitchen_sink_cfg, kitchen_sink_hosts):
        findings = self._all_findings(kitchen_sink_cfg, kitchen_sink_hosts)
        assert findings, "fixtures produced no findings at all — test is vacuous"
        for f in findings:
            assert f["why"], f"finding {f['id']} has no why: {f}"

    def test_every_finding_id_is_one_of_the_registered_checks(self, kitchen_sink_cfg, kitchen_sink_hosts):
        findings = self._all_findings(kitchen_sink_cfg, kitchen_sink_hosts)
        ids = _ids(findings)
        assert ids <= ALL_CHECK_IDS, f"unregistered id(s): {ids - ALL_CHECK_IDS}"

    def test_every_check_id_actually_fires_somewhere_in_this_suite(self, kitchen_sink_cfg, kitchen_sink_hosts):
        findings = self._all_findings(kitchen_sink_cfg, kitchen_sink_hosts)
        ids = _ids(findings)
        assert ids >= ALL_CHECK_IDS, f"never exercised: {ALL_CHECK_IDS - ids}"

    def test_severities_are_valid(self, kitchen_sink_cfg, kitchen_sink_hosts):
        findings = self._all_findings(kitchen_sink_cfg, kitchen_sink_hosts)
        for f in findings:
            assert f["severity"] in ("fail", "warn", "info")

    def test_findings_sorted_most_severe_first(self, kitchen_sink_cfg, kitchen_sink_hosts):
        findings = doctor.diagnose(kitchen_sink_cfg, kitchen_sink_hosts)
        order = {"fail": 0, "warn": 1, "info": 2}
        severities = [order[f["severity"]] for f in findings]
        assert severities == sorted(severities)
