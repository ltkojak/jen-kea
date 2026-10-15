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
    "logger-no-file",
    "logger-pattern-no-timestamp",
    "ddns-two-writers",
    "ddns-hook-present",
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
        out += doctor.diagnose(TestTwoWritersOfDnsNames()._cfg(True, [TestTwoWritersOfDnsNames.HOOK]), hosts=[])
        out += doctor.diagnose(TestTwoWritersOfDnsNames()._cfg(False, [TestTwoWritersOfDnsNames.HOOK]), hosts=[])
        out += doctor.diagnose(TestTheDhcp4Logger.STDOUT, hosts=[])
        out += doctor.diagnose(TestTheDhcp4Logger.FILE_NO_TIME, hosts=[])
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


class TestTheDhcp4Logger:
    """v5.69.0-beta.6 (Q175): the Problems inbox, Trace, Explain and the host-side restore read a FILE; a logger that writes to stdout leaves them blind (the maintainer's
    host was, for 1447 sweeps), and a pattern with no %D leaves the lines Jen's parser cannot read. Doctor says so, with the JSON to paste."""

    STDOUT = {
        "loggers": [
            {"name": "kea-dhcp4", "output-options": [{"output": "stdout", "pattern": "%-5p %m\n"}], "severity": "INFO"}
        ]
    }
    FILE_NO_TIME = {
        "loggers": [
            {
                "name": "kea-dhcp4",
                "output-options": [{"output": "/var/log/kea/kea-dhcp4.log", "pattern": "%-5p %m\n"}],
                "severity": "INFO",
            }
        ]
    }
    FILE_NO_PATTERN = {
        "loggers": [
            {"name": "kea-dhcp4", "output-options": [{"output": "/var/log/kea/kea-dhcp4.log"}], "severity": "INFO"}
        ]
    }

    def test_the_maintainers_stdout_logger_has_no_file_and_its_pattern_is_not_judged(self):
        ids = _ids(doctor.diagnose(self.STDOUT, hosts=[]))
        assert "logger-no-file" in ids
        assert "logger-pattern-no-timestamp" not in ids

    def test_a_file_output_with_a_pattern_without_a_timestamp_is_the_second_note_only(self):
        ids = _ids(doctor.diagnose(self.FILE_NO_TIME, hosts=[]))
        assert "logger-pattern-no-timestamp" in ids
        assert "logger-no-file" not in ids

    @pytest.mark.parametrize(
        "output", ["/tmp/kea.log", "/var/log/kea/dhcp4.txt", "/opt/kea/log/x.log", "/var/log/../etc/x.log"]
    )
    def test_a_file_Jen_cannot_read_is_no_file(self, output):
        """The second pass (Q175, finding 2): a file output outside /var/log, or not a *.log, is one the host's helper refuses - the sweep would fall back and go blind."""
        cfg = {"loggers": [{"name": "kea-dhcp4", "output-options": [{"output": output}]}]}
        assert "logger-no-file" in _ids(doctor.diagnose(cfg, hosts=[]))

    def test_a_readable_file_after_an_unreadable_one_is_a_file(self):
        cfg = {
            "loggers": [
                {
                    "name": "kea-dhcp4",
                    "output-options": [{"output": "/tmp/kea.log"}, {"output": "/var/log/kea/kea-dhcp4.log"}],
                }
            ]
        }
        assert "logger-no-file" not in _ids(doctor.diagnose(cfg, hosts=[]))

    @pytest.mark.parametrize("pattern", ["%d{%Y-%m-%d %H:%M:%S} %-5p %m", "%D %m", "%D{%H:%M:%S.%q} %m"])
    def test_a_pattern_with_either_date_conversion_is_fine(self, pattern):
        cfg = {
            "loggers": [{"name": "kea-dhcp4", "output-options": [{"output": "/var/log/kea/k.log", "pattern": pattern}]}]
        }
        assert "logger-pattern-no-timestamp" not in _ids(doctor.diagnose(cfg, hosts=[]))

    def test_a_file_output_with_no_pattern_is_neither(self):
        ids = _ids(doctor.diagnose(self.FILE_NO_PATTERN, hosts=[]))
        assert not ({"logger-no-file", "logger-pattern-no-timestamp"} & ids)

    def test_a_file_output_with_kea_s_default_pattern_is_neither(self):
        cfg = {
            "loggers": [
                {
                    "name": "kea-dhcp4",
                    "output-options": [{"output": "/var/log/kea/kea-dhcp4.log", "pattern": doctor.LOGGER_PATTERN}],
                }
            ]
        }
        assert not ({"logger-no-file", "logger-pattern-no-timestamp"} & _ids(doctor.diagnose(cfg, hosts=[])))

    def test_the_note_carries_the_json_to_paste(self):
        note = next(f for f in doctor.diagnose(self.STDOUT, hosts=[]) if f["id"] == "logger-no-file")
        assert '"maxver": 4' in note["detail"]
        assert '"maxsize": 10485760' in note["detail"]
        assert '"output": "/var/log/kea/kea-dhcp4.log"' in note["detail"]
        assert '"flush": true' in note["detail"]
        assert note["severity"] == "warn"

    def test_the_pasted_block_is_valid_json_and_a_file_the_definition_accepts(self):
        import json

        from jen.services import kea_log_trace as klt

        block = json.loads("{" + doctor.LOGGER_OUTPUT_JSON + "}")
        cfg = {"Dhcp4": {"loggers": [{"name": "kea-dhcp4", **block}]}}
        assert klt.logger_file_outputs(cfg) == ["/var/log/kea/kea-dhcp4.log"]
        assert klt.host_log_path("/var/log/kea/kea-dhcp4.log")
        assert not (
            {"logger-no-file", "logger-pattern-no-timestamp"}
            & _ids(doctor.diagnose({"loggers": [{"name": "kea-dhcp4", **block}]}, hosts=[]))
        )

    def test_a_pattern_in_the_pasted_default_has_a_timestamp(self):
        assert "%D" in doctor.LOGGER_PATTERN and doctor.LOGGER_PATTERN.endswith(
            "%m\\n"
        )  # the JSON text to paste: backslash and n, not a newline

    def test_a_config_with_no_dhcp4_logger_is_not_second_guessed(self):
        assert not (
            {"logger-no-file", "logger-pattern-no-timestamp"}
            & _ids(doctor.diagnose({"valid-lifetime": 3600}, hosts=[]))
        )
        other = {"loggers": [{"name": "kea-dhcp4.dhcpsrv", "output-options": [{"output": "stdout"}]}]}
        assert not ({"logger-no-file"} & _ids(doctor.diagnose(other, hosts=[])))

    def test_a_logger_with_no_output_options_has_no_file(self):
        assert "logger-no-file" in _ids(doctor.diagnose({"loggers": [{"name": "kea-dhcp4"}]}, hosts=[]))

    def test_malformed_logger_shapes_do_not_raise(self):
        for cfg in (
            {"loggers": "x"},
            {"loggers": [None, 3, {"name": "kea-dhcp4", "output-options": [None, "x", {"output": 5}]}]},
        ):
            doctor.diagnose(cfg, hosts=[])


class TestTwoWritersOfDnsNames:
    """v5.69.0-beta.7 (Q176): Jen never writes DNS. D2 does when dhcp4 sends updates; a `run_script` hook of the operator's own may. Jen cannot know what a hook does, but it can see one
    is loaded - both on is a warning (never a block), the hook alone is information."""

    HOOK = {"library": "/usr/lib/x86_64-linux-gnu/kea/hooks/libdhcp_run_script.so", "parameters": {"name": "/opt/x.sh"}}

    def _cfg(self, updates=None, hooks=None):
        cfg = {}
        if updates is not None:
            cfg["dhcp-ddns"] = {"enable-updates": updates}
        if hooks is not None:
            cfg["hooks-libraries"] = hooks
        return cfg

    def test_updates_on_and_the_hook_loaded_is_the_two_writers_warning(self):
        findings = doctor.diagnose(self._cfg(True, [self.HOOK]), hosts=[])
        two = [f for f in findings if f["id"] == "ddns-two-writers"]
        assert len(two) == 1 and two[0]["severity"] == "warn"
        assert "two writers" in two[0]["detail"] and "turn one off" in two[0]["detail"]
        assert "ddns-hook-present" not in _ids(findings)

    def test_the_hook_alone_is_information_not_a_warning(self):
        findings = doctor.diagnose(self._cfg(False, [self.HOOK]), hosts=[])
        ids = _ids(findings)
        assert "ddns-hook-present" in ids and "ddns-two-writers" not in ids
        note = next(f for f in findings if f["id"] == "ddns-hook-present")
        assert note["severity"] == "info" and "log_path" in note["detail"]

    def test_the_hook_with_no_ddns_block_at_all_is_the_hook_alone(self):
        assert "ddns-hook-present" in _ids(doctor.diagnose(self._cfg(None, [self.HOOK]), hosts=[]))

    def test_d2_alone_is_neither(self):
        ids = _ids(
            doctor.diagnose(self._cfg(True, [{"library": "/usr/lib/kea/hooks/libdhcp_lease_cmds.so"}]), hosts=[])
        )
        assert not ({"ddns-two-writers", "ddns-hook-present"} & ids)

    def test_neither_is_neither(self):
        assert not ({"ddns-two-writers", "ddns-hook-present"} & _ids(doctor.diagnose(self._cfg(False, []), hosts=[])))

    @pytest.mark.parametrize(
        "library", ["libdhcp_run_script.so", "/x/libdhcp_run_script.so", "  /x/libdhcp_run_script.so  "]
    )
    def test_any_path_to_the_library_counts(self, library):
        assert "ddns-two-writers" in _ids(doctor.diagnose(self._cfg(True, [{"library": library}]), hosts=[]))

    @pytest.mark.parametrize(
        "library",
        ["/x/libdhcp_run_script.so.bak", "/x/notlibdhcp_run_script.sox", "/x/notlibdhcp_run_script.so", "", None, 5],
    )
    def test_a_look_alike_does_not(self, library):
        assert not (
            {"ddns-two-writers", "ddns-hook-present"}
            & _ids(doctor.diagnose(self._cfg(True, [{"library": library}]), hosts=[]))
        )

    def test_malformed_hook_lists_never_raise(self):
        for hooks in ("x", [None, 3, "y", {"library": ["a"]}], {"library": "a"}):
            doctor.diagnose({"dhcp-ddns": {"enable-updates": True}, "hooks-libraries": hooks}, hosts=[])
        doctor.diagnose({"dhcp-ddns": "x", "hooks-libraries": [{"library": "/x/libdhcp_run_script.so"}]}, hosts=[])

    def test_a_warning_never_blocks_anything_it_is_only_a_finding(self):
        two = next(f for f in doctor.diagnose(self._cfg(True, [self.HOOK]), hosts=[]) if f["id"] == "ddns-two-writers")
        assert two["why"] and two["fix_url"]


class TestACredentialInheritedAcrossHosts:
    """CRED-003 (v5.69.0-beta.10, Q179): a saved password used on a different host from the secret's own endpoint is named, with both hosts (info, never a failure)."""

    @staticmethod
    def _cfg(**sections):
        import configparser

        p = configparser.ConfigParser(interpolation=None)
        for name, values in sections.items():
            p[name.replace("__", "_")] = values
        return p

    def _notes(self, cfg):
        return [f for f in doctor.diagnose(None, jen_config=cfg) if f["id"] == "credential-inherited-across-hosts"]

    def test_d2_on_another_host_with_no_password_of_its_own_names_both_hosts(self):
        cfg = self._cfg(kea={"api_url": "https://kea-b:8000", "api_pass": "S"}, d2={"api_url": "https://kea-a:53001"})
        (note,) = self._notes(cfg)
        assert note["severity"] == "info" and "kea-a" in note["detail"] and "kea-b" in note["detail"]
        assert note["where"] == "[d2]" and note["fix_url"] == "/settings/kea"

    def test_the_same_host_on_its_own_port_is_the_design_and_gives_no_note(self):
        cfg = self._cfg(kea={"api_url": "https://kea-a:8000", "api_pass": "S"}, d2={"api_url": "https://kea-a:53001"})
        assert self._notes(cfg) == []

    def test_a_daemon_with_its_own_password_gives_no_note(self):
        cfg = self._cfg(
            kea={"api_url": "https://kea-b:8000", "api_pass": "S"},
            d2={"api_url": "https://kea-a:53001", "api_pass": "own"},
        )
        assert self._notes(cfg) == []

    def test_no_primary_password_means_nothing_is_inherited(self):
        cfg = self._cfg(kea={"api_url": "https://kea-b:8000"}, d2={"api_url": "https://kea-a:53001"})
        assert self._notes(cfg) == []

    def test_kea6_and_an_additional_server_and_the_kea6_database_are_named_too(self):
        cfg = self._cfg(
            kea={"api_url": "https://kea-b:8000", "api_pass": "S"},
            kea6={"api_url": "https://kea-a:8006"},
            kea_db={"host": "db-b", "password": "P"},
            kea6_db={"host": "db-a"},
            kea_server_2={"api_url": "https://peer:8000"},
        )
        assert sorted(f["where"] for f in self._notes(cfg)) == ["[kea6]", "[kea6_db]", "[kea_server_2]"]

    def test_an_additional_servers_ipv6_endpoint_on_another_host_uses_its_api_password(self):
        cfg = self._cfg(
            kea={"api_url": "https://kea-b:8000", "api_pass": "S"},
            kea_server_2={"api_url": "https://peer:8000", "api_pass": "own", "api6_url": "https://peer6:8006"},
        )
        (note,) = self._notes(cfg)
        assert note["where"] == "[kea_server_2] (IPv6)" and "peer6" in note["detail"] and "peer" in note["detail"]

    def test_none_and_an_empty_file_give_nothing_and_the_check_needs_no_kea_config(self):
        assert doctor.diagnose(None, jen_config=None) == []
        assert self._notes(self._cfg()) == []
        cfg = self._cfg(kea={"api_url": "https://kea-b:8000", "api_pass": "S"}, d2={"api_url": "https://kea-a:53001"})
        assert [f["id"] for f in doctor.diagnose(None, jen_config=cfg)] == ["credential-inherited-across-hosts"]

    def test_health_and_the_page_carry_the_same_sentence(self):
        import inspect

        from jen.services import health

        src = inspect.getsource(health._config_doctor)
        assert "jen_config=extensions.cfg" in src and "inherited" in src


class TestTheCredentialNoteNamesTheRightSecretAndHost:
    """Q179's second pass: an additional server's IPv6 / D2 endpoint uses its own password, else its API password, else the primary's - the note names THAT one and that host."""

    _cfg = staticmethod(TestACredentialInheritedAcrossHosts._cfg)

    def _notes(self, cfg):
        return [f for f in doctor.diagnose(None, jen_config=cfg) if f["id"] == "credential-inherited-across-hosts"]

    def test_an_ipv6_endpoint_on_the_primarys_own_host_is_not_a_cross_host_use(self):
        cfg = self._cfg(
            kea={"api_url": "https://kea-a:8000", "api_pass": "S"},
            kea_server_2={"api_url": "https://peer:8000", "api_pass": "own", "api6_url": "https://peer:8006"},
            kea_server_3={"api_url": "https://kea-a:8000", "api6_url": "https://kea-a:8006"},
        )
        assert self._notes(cfg) == []

    def test_an_ipv6_endpoint_that_uses_the_primarys_password_names_the_primarys_host(self):
        cfg = self._cfg(
            kea={"api_url": "https://kea-a:8000", "api_pass": "S"},
            kea_server_3={"api_url": "https://kea-a:8000", "api6_url": "https://peer6:8006"},
        )
        (note,) = self._notes(cfg)
        assert note["where"] == "[kea_server_3] (IPv6)" and "the Kea API's password (kea-a)" in note["detail"]

    def test_an_empty_password_key_is_a_password_of_its_own_and_inherits_nothing(self):
        cfg = self._cfg(
            kea={"api_url": "https://kea-a:8000", "api_pass": "S"},
            d2={"api_url": "https://d2-host:53001", "api_pass": ""},
            kea_server_2={"api_url": "https://peer:8000", "api_pass": ""},
        )
        assert self._notes(cfg) == []

    def test_a_server_d2_endpoint_on_a_different_host_is_named(self):
        cfg = self._cfg(
            kea={"api_url": "https://kea-a:8000", "api_pass": "S"},
            kea_server_2={"api_url": "https://kea-a:8000", "api_d2_url": "https://d2-host:53001"},
        )
        (note,) = self._notes(cfg)
        assert note["where"] == "[kea_server_2] (D2)" and "d2-host" in note["detail"]
