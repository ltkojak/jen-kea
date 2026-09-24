"""
tests/kea_compat/test_real_kea.py
──────────────────────────────────
Q50 — what Jen's service layer sends and parses, checked against a real
kea-dhcp4. The fake Kea in tests/e2e and the mocked replies in the unit
suite prove Jen agrees with itself; this proves it agrees with Kea.
"""

import json
import os

import pytest

from jen.services import kea as __kea
from jen.services import kea_config_view as __view

pytestmark = pytest.mark.kea_compat

MAC = "02:50:00:00:00:01"
IP = "10.99.0.150"
BY_MAC = {"subnet-id": 1, "identifier-type": "hw-address", "identifier": MAC}


def _ok(reply):
    assert reply.get("result") == 0, reply
    return reply


def test_version_get():
    reply = _ok(__kea.kea_command("version-get"))
    text = reply["text"]
    assert __kea.parse_kea_version(text) is not None, text
    expected = os.environ.get("KEA_COMPAT_VERSION", "")
    if expected:
        assert text.startswith(expected.rsplit(".", 1)[0]), (text, expected)


def test_config_get_and_subnet_walk():
    args = _ok(__kea.kea_command("config-get"))["arguments"]
    assert "Dhcp4" in args
    subnets = [(s.get("id"), s.get("subnet"), sn) for s, sn in __view.iter_subnet4(args["Dhcp4"])]
    assert (1, "10.99.0.0/24", None) in subnets, subnets


def test_reservation_add_get_del_roundtrip():
    res = {"subnet-id": 1, "hw-address": MAC, "ip-address": IP, "hostname": "kea-compat"}
    __kea.kea_command("reservation-del", arguments=BY_MAC)
    _ok(__kea.kea_command("reservation-add", arguments={"reservation": res}))
    try:
        got = _ok(__kea.kea_command("reservation-get", arguments=BY_MAC))
        assert got["arguments"]["ip-address"] == IP
        assert got["arguments"]["hostname"] == "kea-compat"
    finally:
        _ok(__kea.kea_command("reservation-del", arguments=BY_MAC))
    gone = __kea.kea_command("reservation-get", arguments=BY_MAC)
    assert gone.get("result") == 3, gone  # 3 = empty: Kea's "no such host"


def test_statistic_get_all_pkt4_names():
    args = _ok(__kea.kea_command("statistic-get-all"))["arguments"]
    names = sorted(k for k in args if k.startswith("pkt4-"))
    assert "pkt4-received" in names, names
    out = os.environ.get("KEA_COMPAT_PKT4_OUT")
    if out:
        with open(out, "w") as fh:
            json.dump(names, fh, indent=2)


def test_config_test_accepts_the_running_config():
    """config-test only — a dry run; the job never config-sets."""
    cfg = _ok(__kea.kea_command("config-get"))["arguments"]["Dhcp4"]
    _ok(__kea.kea_command("config-test", arguments={"Dhcp4": cfg}))


def test_ha_heartbeat_on_a_non_ha_server_is_an_error():
    reply = __kea.kea_command("ha-heartbeat")
    assert reply.get("result") not in (0, None), reply
    assert reply.get("text"), reply


def test_derived_capabilities_match_the_real_daemon():
    """v5.64.0 (Q83) — jen.services.capabilities derives what a server can do
    from what it reports; here the derivation is checked against the
    daemon itself rather than against Jen's own assumptions."""
    from jen.services import capabilities as caps
    from jen.services.packet_health import DROP_REASON_LABELS

    cfg = _ok(__kea.kea_command("config-get"))["arguments"]["Dhcp4"]
    facts = caps.gather_kea_facts(None, dhcp4_cfg=cfg)
    got = caps.derive(direct=True, ssh=False, **facts)

    # the version it reports, and the two thresholds that follow from it
    assert got.reachable and got.kea_version is not None
    assert got.direct_control and got.direct_socket and not got.control_agent
    assert got.kea_version >= (3, 0, 0)  # every image this job runs

    # the drop-reason counters exist on the real daemon exactly when Jen
    # says they do — the Q52 finding (3.0.3 reports none, 3.2+ all eight)
    names = set(_ok(__kea.kea_command("statistic-get-all"))["arguments"])
    reported = set(DROP_REASON_LABELS) <= names
    assert got.packet_drop_reasons is reported, (got.kea_version, sorted(set(DROP_REASON_LABELS) - names))

    # the hooks the job's config loads, and the commands they provide
    assert got.hooks_known and got.host_cmds and got.lease_cmds
    assert not got.ha_commands  # no HA hook in this config
    commands = set(_ok(__kea.kea_command("list-commands"))["arguments"])
    assert ("reservation-add" in commands) is got.host_cmds
    assert ("lease4-get-all" in commands) is got.lease_cmds

    # config-test is a command the daemon actually answers
    assert got.config_test
    _ok(__kea.kea_command("config-test", arguments={"Dhcp4": cfg}))

    # the same facts, in Control Agent mode, say the CA is gone from 3.2 on
    ca = caps.derive(direct=False, ssh=False, **facts)
    assert ca.ca_removed is (got.kea_version >= (3, 2, 0))
    assert ca.control_agent is (got.kea_version < (3, 2, 0))
