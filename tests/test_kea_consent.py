"""
tests/test_kea_consent.py
─────────────────────────
Q216 (BF8 a, c, d, e) - ONE definition of "the operator's consents cover the facts" (`kea_api_config.consent_allowed`), and the three places that ask it: the switch, `probe(consent=True)` and the gate.
The ten-state table is the test that says they agree; the refresh keeps the facts fresh without asking again and closes the gate on a fact the consent does not cover; the badge and the sentence are
derived from the gate. Pure: runs under `--noconftest`.
"""

import copy

import pytest

from jen import extensions
from jen.services import capabilities as caps
from jen.services import kea_api_config as api
from jen.services import kea_changeset as cs
from jen.services import kea_host
from jen.services import kea_transport_switch as sw
from tests import _kea_api_world as world
from tests.e2e._fake_kea_server import TWO_SUBNET_DHCP4, StatefulKeaServer
from tests.test_kea_api_probe import _iso, lifetime


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setattr("jen.services.investigation_logging.file_write_refusal", lambda server, cfg: "")
    monkeypatch.setattr("jen.services.investigation_logging.restore_window", lambda server, now=None: "")
    monkeypatch.setattr(cs, "record_outcome", lambda *a, **k: None)
    monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
    monkeypatch.setattr(api, "COMMAND_TIMEOUT", 0.4)


@pytest.fixture
def store(monkeypatch):
    return world.install_store(monkeypatch)


@pytest.fixture
def probes(monkeypatch):
    return world.install_probes(monkeypatch, valid=False)


@pytest.fixture
def daemon():
    f = StatefulKeaServer(copy.deepcopy(TWO_SUBNET_DHCP4))
    f.start()
    yield f
    f.stop()


GOOD = {
    "config_api": True,
    "test_ok": True,
    "include": [],
    "agree": True,
    "write": {"may_write": True, "account": "_kea", "mode": "0660"},
    "auth": "password",
}

# (id, facts that differ from GOOD, has_ssh, the consents given, allowed?, the consent that would answer it)
STATES = [
    ("good with ssh", {}, True, ("consent_rendering",), True, ""),
    ("not readable over the api", {"config_api": False, "read_error": "no answer"}, True, api.CONSENTS, False, ""),
    ("config-test refused", {"test_ok": False, "test_detail": "bad"}, True, api.CONSENTS, False, ""),
    ("an include", {"include": ["/etc/kea/x.json"]}, True, api.CONSENTS, False, ""),
    ("the host's facts unknown", {"include": None, "agree": None}, True, api.CONSENTS, False, ""),
    (
        "no ssh and no confirmation",
        {"include": None, "agree": None, "write": "unknown"},
        False,
        ("consent_rendering",),
        False,
        "confirm_no_include",
    ),
    ("the file differs, not discarded", {"agree": False}, True, ("consent_rendering",), False, "discard_file_edit"),
    ("the file differs, discarded", {"agree": False}, True, ("consent_rendering", "discard_file_edit"), True, ""),
    (
        "the account may not write",
        {"write": {"may_write": False, "account": "_kea", "mode": "0640"}},
        True,
        api.CONSENTS,
        False,
        "allow_config_write",
    ),
    ("rendering not consented", {}, True, (), False, "consent_rendering"),
    (
        "no authentication, not consented",
        {"auth": "none"},
        True,
        ("consent_rendering",),
        False,
        "consent_unauthenticated",
    ),
    (
        "no authentication, consented",
        {"auth": "none"},
        True,
        ("consent_rendering", "consent_unauthenticated"),
        True,
        "",
    ),
]
IDS = [s[0] for s in STATES]


def _server(daemon, ssh):
    return {
        "id": 4,
        "name": "kea-d",
        "api_url": daemon.url,
        "config_transport": "api",
        **({"ssh_host": "10.0.0.4"} if ssh else {}),
    }


@pytest.mark.parametrize(("name", "delta", "ssh", "consents", "allowed", "needs"), STATES, ids=IDS)
class TestTheTenStateTable:
    """For each stored state the three askers say the same thing: `consent_allowed`, the `probe(consent=True)` that records the consent, the gate that reads it, and the switch."""

    def _facts(self, delta):
        facts = copy.deepcopy(GOOD)
        facts.update(delta)
        return facts

    def test_consent_allowed_and_what_would_answer_it(self, daemon, name, delta, ssh, consents, allowed, needs):
        facts = self._facts(delta)
        gap, would = api.consent_gap("kea-d", facts, consents, has_ssh=ssh)
        assert (gap == "") is allowed, gap
        assert would == needs
        assert api.consent_allowed("kea-d", facts, consents, has_ssh=ssh) == gap

    def test_probe_records_consent_only_when_it_is_allowed(
        self, daemon, store, probes, monkeypatch, name, delta, ssh, consents, allowed, needs
    ):
        facts = self._facts(delta)
        server = _server(daemon, ssh)
        monkeypatch.setattr(
            api,
            "_get",
            lambda srv, svc, timeout=None: (
                ({"Dhcp4": {}}, "d" * 64, "") if facts["config_api"] else (None, None, "no answer")
            ),
        )
        monkeypatch.setattr(
            api,
            "test",
            lambda srv, svc, cfg: {"ok": facts.get("test_ok", True), "detail": facts.get("test_detail", "")},
        )
        monkeypatch.setattr(api, "_endpoint_facts", lambda srv, svc: {"auth": facts["auth"], "tls": False})
        monkeypatch.setattr(
            kea_host,
            "config_write_check",
            lambda s, svc: {
                "ok": facts["include"] is not None,
                "may_write": (facts["write"] or {}).get("may_write", True)
                if isinstance(facts["write"], dict)
                else True,
                "includes": facts["include"] or [],
                "mode": "0660",
                "account": {"name": "_kea"},
            },
        )
        monkeypatch.setattr(
            kea_host,
            "read_config_versioned",
            lambda *a, **k: ({"Dhcp4": {}}, "r" * 64) if facts["agree"] is not None else (None, None),
        )
        monkeypatch.setattr(api, "file_in_daemon", lambda file_cfg, live_cfg, svc: bool(facts["agree"]))
        out = api.probe(server, "dhcp4", consent=True, consents=consents)
        assert ("consented_at" in out) is allowed, out
        if allowed:
            assert out["consents"] == sorted(set(consents) & set(api.CONSENTS))

    def test_the_gate_reads_what_the_consent_covered(self, daemon, probes, name, delta, ssh, consents, allowed, needs):
        facts = {"at": _iso(), "consented_at": _iso(), "consents": sorted(consents), **self._facts(delta)}
        probes[4] = facts
        server = _server(daemon, ssh)
        gate = api.probe_gate(server)
        assert (gate == "") is allowed, gate

    def test_the_switch_asks_the_same_question(
        self, daemon, store, probes, monkeypatch, name, delta, ssh, consents, allowed, needs
    ):
        facts = self._facts(delta)
        server = _server(daemon, ssh)
        monkeypatch.setattr(sw._api, "probe", lambda srv, svc: dict(facts))
        result = sw._to_api(server, "off", set(consents), "tester")
        assert result["ok"] is allowed, result["line"]
        if not allowed:
            assert result.get("needs", "") == needs

    def test_the_badge_and_the_sentence_are_the_gates(self, daemon, probes, name, delta, ssh, consents, allowed, needs):
        probes[4] = {"at": _iso(), "consented_at": _iso(), "consents": sorted(consents), **self._facts(delta)}
        server = _server(daemon, ssh)
        gate = api.probe_gate(server)
        c = caps.derive(
            ssh=ssh, config_transport="api", config_declared="api", config_probe=probes[4], config_gate=gate
        )
        assert c.transport_blocked is bool(gate)
        assert (gate in c.transport_why()) if gate else ("no SSH, no restart" in c.transport_why())


class TestAConsentWithoutTheFactsOnThePageIsNotGiven:
    def test_a_stored_result_from_before_the_consents_were_recorded_counts_as_given_all_of_them(self, daemon, probes):
        probes[4] = {
            "at": _iso(),
            "config_api": True,
            "consented_at": _iso(),
            **{k: v for k, v in GOOD.items() if k != "config_api"},
        }
        assert api.probe_gate(_server(daemon, True)) == ""

    def test_a_probe_that_finds_an_unconsented_fact_after_a_legacy_consent_keeps_the_legacy_all(self, daemon, probes):
        probes[4] = {
            "at": _iso(),
            "config_api": True,
            "consented_at": _iso(),
            **{k: v for k, v in GOOD.items() if k != "config_api"},
            "auth": "none",
        }
        assert (
            api.probe_gate(_server(daemon, True)) == ""
        )  # beta.1 recorded no list; the unauthenticated confirmation was a switch rule and the card's one checkbox


class TestTheFactsAreKeptFreshWithoutAskingAgain:
    """Q216 AA12. The gate's seven days apply to the FACTS: the refresh (the scheduler, hourly, and the change set's Plan when the facts are older than a day) re-reads them and never touches
    the consent; a fact the consent does not cover closes the gate with its own sentence; a daemon that does not answer keeps the previous facts and the age."""

    def _healthy_host(self, monkeypatch, daemon, **override):
        check = {"ok": True, "may_write": True, "includes": [], "mode": "0660", "account": {"name": "_kea"}}
        check.update(override)
        monkeypatch.setattr(kea_host, "config_write_check", lambda s, svc: dict(check))
        monkeypatch.setattr(
            kea_host, "read_config_versioned", lambda *a, **k: ({"Dhcp4": copy.deepcopy(daemon.running)}, "r" * 64)
        )

    def _consented(self, daemon, probes, monkeypatch):
        server = {**_server(daemon, True), "api_user": "jen", "api_pass": "pw"}
        self._healthy_host(monkeypatch, daemon)
        out = api.probe(server, "dhcp4", consent=True, consents=("consent_rendering",))
        assert out["consented_at"] and probes[4]["consents"] == ["consent_rendering"]
        return server

    def test_an_eight_day_old_probe_is_refreshed_at_plan_and_the_set_proceeds(self, daemon, store, probes, monkeypatch):
        server = self._consented(daemon, probes, monkeypatch)
        consented = probes[4]["consented_at"]
        probes[4]["at"] = _iso(8)
        assert "older than 7 days" in api.probe_gate(server)
        result = cs.apply_change("dhcp4", lifetime(9), "x", servers=[server])
        assert result.status == "ok", result.lines
        assert probes[4]["consented_at"] == consented, "a refresh never writes the consent"

    @pytest.mark.parametrize(
        ("what", "needle"),
        [
            ("an include appeared", "carries an include"),
            ("the endpoint lost its authentication", "no authentication"),
            ("config-test fails", "did not accept its own configuration"),
            ("the account lost the write", "may not write its file"),
        ],
    )
    def test_each_fact_the_consent_does_not_cover_closes_the_gate_with_its_own_sentence(
        self, daemon, store, probes, monkeypatch, what, needle
    ):
        server = self._consented(daemon, probes, monkeypatch)
        consented = probes[4]["consented_at"]
        if what == "an include appeared":
            self._healthy_host(monkeypatch, daemon, includes=["/etc/kea/extra.json"])
        elif what == "the endpoint lost its authentication":
            server.pop("api_user"), server.pop("api_pass")
        elif what == "config-test fails":
            daemon.test_fails = "unknown parameter"
        else:
            self._healthy_host(monkeypatch, daemon, may_write=False, mode="0640")
        assert api.refresh_probe(server, "dhcp4") is True
        assert needle in api.probe_gate(server), api.probe_gate(server)
        assert probes[4]["consented_at"] == consented

    def test_a_daemon_that_does_not_answer_keeps_the_previous_facts_and_their_age(
        self, daemon, store, probes, monkeypatch
    ):
        server = self._consented(daemon, probes, monkeypatch)
        probes[4]["at"] = at = _iso(2)
        daemon.stopped = True
        assert api.refresh_probe(server, "dhcp4") is False
        assert probes[4]["at"] == at and probes[4]["config_api"] is True

    def test_a_host_that_does_not_answer_keeps_what_was_known(self, daemon, store, probes, monkeypatch):
        server = self._consented(daemon, probes, monkeypatch)
        self._healthy_host(monkeypatch, daemon, ok=False)  # the helper did not answer this time
        before = copy.deepcopy(probes[4])
        assert api.refresh_probe(server, "dhcp4") is False
        assert probes[4] == before

    def test_a_server_that_was_never_consented_is_not_refreshed(self, daemon, probes):
        assert api.refresh_probe(_server(daemon, False), "dhcp4") is False


class TestTheWayOutIsOpen:
    """Q216 AA14: a remembered refusal blocks a new change and never the restore the failure's own line tells the operator to run."""

    def test_a_restore_passes_the_gate_a_new_change_does_not(self, daemon, probes):
        probes[4] = {"at": _iso(), "config_api": True, "consented_at": _iso(), "refused": "denied"}
        server = _server(daemon, False)
        assert (
            api.probe_gate(server, "jen")
            and api.probe_gate(server, "rollback") == ""
            and api.probe_gate(server, "restore") == ""
        )


class TestTheSchedulerKeepsTheFactsFresh:
    def test_the_hourly_refresh_is_registered_and_refreshes_only_api_servers(self):
        import pathlib

        source = (pathlib.Path(__file__).resolve().parent.parent / "jen" / "services" / "scheduler.py").read_text(
            encoding="utf-8"
        )
        assert 'id="jen_probe_refresh"' in source and "IntervalTrigger(hours=1)" in source
        assert "refresh_probe" in source and 'declared_transport(server) != "api"' in source
