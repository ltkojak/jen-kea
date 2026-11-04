"""
tests/test_kea_api_probe.py
───────────────────────────
Q212 (BB3 c/d, BB9 a) - the probe, its stored result and the gate that makes the facts the gate: no API write until an operator has read them once and consented, a probe that is stale,
failed or unconsented refuses, and a refused `config-write` is remembered so a fleet does not undo the same change on every edit. Pure: runs under `--noconftest`.
"""

import copy
from datetime import datetime, timedelta, timezone

import pytest

from jen import extensions
from jen.services import capabilities as caps
from jen.services import kea_api_config as api
from jen.services import kea_changeset as cs
from jen.services import kea_host
from tests import _kea_api_world as world
from tests.e2e._fake_kea_server import TWO_SUBNET_DHCP4, StatefulKeaServer


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


@pytest.fixture
def server(daemon):
    return {"id": 4, "name": "kea-d", "api_url": daemon.url, "config_transport": "api"}


def _iso(days_ago=0.0):
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat(timespec="seconds")


def lifetime(value):
    def mutate(cfg):
        out = copy.deepcopy(cfg)
        out["Dhcp4"]["valid-lifetime"] = value
        return out, "ok"

    return mutate


class TestTheGate:
    def test_a_server_never_checked_cannot_be_written(self, server, probes):
        assert "readiness check" in api.probe_gate(server)

    @pytest.mark.parametrize(
        ("stored", "needle"),
        [
            ({"at": _iso(8), "config_api": True, "consented_at": _iso(8)}, "older than 7 days"),
            ({"at": _iso(), "config_api": False, "consented_at": _iso()}, "could not be read over its API"),
            ({"at": _iso(), "config_api": True}, "have not been allowed yet"),
            (
                {"at": _iso(), "config_api": True, "consented_at": _iso(), "refused": "Permission denied"},
                "may not write its file",
            ),
        ],
        ids=["stale", "no digest", "no consent", "refused"],
    )
    def test_each_way_to_be_refused(self, server, probes, stored, needle):
        probes[4] = stored
        assert needle in api.probe_gate(server)

    def test_a_fresh_consented_probe_passes(self, server, probes):
        probes[4] = {"at": _iso(6), "config_api": True, "consented_at": _iso(6)}
        assert api.probe_gate(server) == ""

    def test_a_rollback_is_not_stopped_by_a_remembered_refusal(self, server, probes):
        probes[4] = {"at": _iso(), "config_api": True, "consented_at": _iso(), "refused": "denied"}
        assert api.probe_gate(server, "jen")
        assert api.probe_gate(server, "rollback") == ""

    def test_apply_asks_the_gate_before_it_sends_anything(self, daemon, server, probes):
        cfg, digest, _ = api._get(server, "dhcp4")
        daemon.commands.clear()
        result = api.apply(server, "dhcp4", cfg, digest, "x", before_cfg=cfg)
        assert result["code"] == "guard" and "readiness check" in result["detail"] and daemon.commands == []

    def test_a_server_added_with_api_cannot_be_changed_until_its_operator_has_read_the_facts(
        self, daemon, server, store, probes
    ):
        result = cs.apply_change("dhcp4", lifetime(9), "x", servers=[server])
        assert result.status == "aborted" and result.last_code == "needs-probe"
        assert daemon.commands == []  # not even the plan read
        probes.clear()
        api.probe(server, "dhcp4", consent=True, consents=api.CONSENTS)
        assert cs.apply_change("dhcp4", lifetime(9), "x", servers=[server]).status == "ok"


class TestARefusedWriteIsRemembered:
    def _ready(self, probes):
        probes[4] = {"at": _iso(), "config_api": True, "consented_at": _iso()}

    def test_the_second_set_is_needs_hands_before_any_read(self, daemon, server, store, probes):
        self._ready(probes)
        daemon.write_fails = "Error during config-write: Unable to open file /etc/kea/kea-dhcp4.conf for writing"
        first = cs.apply_change("dhcp4", lifetime(9), "x", servers=[server])
        assert first.status == "aborted" and "Unable to open file" in " ".join(t for _k, t in first.lines)
        assert "Unable to open file" in probes[4]["refused"]
        daemon.commands.clear()
        second = cs.apply_change("dhcp4", lifetime(10), "x", servers=[server])
        assert second.status == "aborted" and second.last_code == "needs-hands" and second.needs_hands == ["kea-d"]
        assert daemon.commands == []  # before the first read
        assert "run the readiness check" in " ".join(t for _k, t in second.lines)

    def test_a_probe_that_proves_nothing_does_not_clear_it(self, daemon, server, store, probes):
        self._ready(probes)
        api.remember_refusal(server, "denied")
        api.probe(server, "dhcp4")  # no SSH: the write permission is unknown
        assert probes[4]["refused"] == "denied"

    def test_the_host_saying_the_account_may_write_clears_it(self, daemon, server, store, probes, monkeypatch):
        self._ready(probes)
        api.remember_refusal(server, "denied")
        server["ssh_host"] = "10.0.0.4"
        monkeypatch.setattr(
            kea_host,
            "config_write_check",
            lambda s, svc: {"ok": True, "may_write": True, "includes": [], "mode": "0660", "account": {"name": "_kea"}},
        )
        monkeypatch.setattr(
            kea_host, "read_config_versioned", lambda *a, **k: ({"Dhcp4": copy.deepcopy(daemon.running)}, "r" * 64)
        )
        out = api.probe(server, "dhcp4")
        assert "refused" not in out and "refused" not in probes[4]

    def test_i_have_fixed_it_clears_it(self, server, probes):
        api.remember_refusal(server, "denied")
        assert api.clear_refusal(4) and "refused" not in probes[4]


class TestTheProbeNamesItsCause:
    """Q217 BG3 a: SSH exists and the helper did not answer is not "no SSH"."""

    def test_an_old_helper_is_named_not_ssh(self, daemon, server, store, probes, monkeypatch):
        server["ssh_host"] = "10.0.0.4"
        detail = "the Kea host helper on this host is older than build 19 - press Update helper"
        monkeypatch.setattr(
            kea_host, "config_write_check", lambda s, svc: {"ok": False, "code": "helper-too-old", "detail": detail}
        )
        monkeypatch.setattr(kea_host, "read_config_versioned", lambda *a, **k: (None, None))
        out = api.probe(server, "dhcp4")
        assert out["include"] is None and out["include_unavailable"] == detail
        assert out["write"] == {"unavailable": detail}

    def test_no_ssh_is_named_no_ssh(self, daemon, server, store, probes):
        out = api.probe(server, "dhcp4")
        assert out["include"] is None and "include_unavailable" not in out

    def test_where_the_file_differs_is_stored(self, daemon, server, store, probes, monkeypatch):
        server["ssh_host"] = "10.0.0.4"
        monkeypatch.setattr(
            kea_host,
            "config_write_check",
            lambda s, svc: {"ok": True, "may_write": True, "includes": [], "mode": "0660", "account": {"name": "_kea"}},
        )
        monkeypatch.setattr(
            kea_host, "read_config_versioned", lambda *a, **k: ({"Dhcp4": {"valid-lifetime": 1}}, "r" * 64)
        )
        out = api.probe(server, "dhcp4")
        assert out["agree"] is False and out["agree_at"].startswith(
            "at Dhcp4.valid-lifetime: the file says 1, the daemon "
        )


class TestProbe:
    def test_the_facts_for_a_daemon_with_no_ssh(self, daemon, server, store, probes):
        out = api.probe(server, "dhcp4")
        assert out["config_api"] is True and out["test_ok"] is True
        assert out["auth"] == "none" and out["tls"] is False  # a plain-http endpoint with no credential
        assert out["write"].startswith("unknown until the first change")
        assert out["include"] is None and out["agree"] is None and out["authored"] is False
        assert probes[4]["config_api"] is True and "consented_at" not in probes[4]

    def test_a_password_endpoint_is_named_and_never_stored(self, daemon, server, store, probes):
        server.update(api_user="jen", api_pass="s3cr3t")
        out = api.probe(server, "dhcp4")
        assert out["auth"] == "password" and "s3cr3t" not in str(probes[4])

    def test_a_daemon_that_does_not_answer_is_a_failed_check_with_its_reason(self, daemon, server, store, probes):
        daemon.stopped = True
        out = api.probe(server, "dhcp4")
        assert out["config_api"] is False and out["read_error"]

    def test_with_ssh_it_asks_the_host_and_compares_the_file(self, daemon, server, store, probes, monkeypatch):
        server["ssh_host"] = "10.0.0.4"
        monkeypatch.setattr(
            kea_host,
            "config_write_check",
            lambda s, svc: {
                "ok": True,
                "may_write": False,
                "includes": [],
                "mode": "0640",
                "owner_uid": 0,
                "owner_gid": 101,
                "account": {"name": "_kea", "uid": 100, "gid": 101},
            },
        )
        monkeypatch.setattr(
            kea_host, "read_config_versioned", lambda *a, **k: ({"Dhcp4": {"valid-lifetime": 1}}, "r" * 64)
        )
        out = api.probe(server, "dhcp4")
        assert (
            out["write"]["may_write"] is False
            and out["write"]["account"] == "_kea"
            and out["agree"] is False
            and out["include"] == []
        )

    def test_an_include_refuses_consent_and_names_the_file(self, daemon, server, store, probes, monkeypatch):
        server["ssh_host"] = "10.0.0.4"
        monkeypatch.setattr(
            kea_host,
            "config_write_check",
            lambda s, svc: {"ok": True, "may_write": True, "includes": ["/etc/kea/extra.json"], "account": None},
        )
        monkeypatch.setattr(kea_host, "read_config_versioned", lambda *a, **k: (None, None))
        out = api.probe(server, "dhcp4", consent=True, consents=api.CONSENTS)
        assert out["include"] == ["/etc/kea/extra.json"] and "consented_at" not in out and out["consent_refused"]

    def test_consent_is_recorded_only_when_the_facts_allow_it_and_survives_a_later_probe(
        self, daemon, server, store, probes
    ):
        assert "consented_at" in api.probe(server, "dhcp4", consent=True, consents=api.CONSENTS)
        assert "consented_at" in api.probe(server, "dhcp4")  # a click that only reads does not take the consent back

    def test_a_history_with_a_jen_authored_revision_says_so(self, daemon, server, store, probes):
        store.record(4, "dhcp4", {"Dhcp4": {}}, "h", "x", hash_kind="kea", source="jen")
        monkey = pytest.MonkeyPatch()
        monkey.setattr("jen.services.config_revisions.list_revisions", lambda sid, svc, limit=100: list(store.rows))
        try:
            assert api.probe(server, "dhcp4")["authored"] is True
        finally:
            monkey.undo()


class TestTheProbeIsBoundToItsEndpoint:
    """Fix row 6: ids are reused and `api_url` can be re-pointed; consent given to one Kea never carries to another that inherits its number."""

    def test_a_server_that_now_points_elsewhere_is_gated(self, daemon, server, store, probes):
        api.probe(server, "dhcp4", consent=True, consents=api.CONSENTS)
        assert api.probe_gate(server) == ""
        moved = {**server, "api_url": "http://127.0.0.1:1/"}
        assert "different Kea" in api.probe_gate(moved)

    def test_a_probe_of_the_new_endpoint_starts_without_the_old_consent_or_refusal(self, daemon, server, store, probes):
        api.probe(server, "dhcp4", consent=True, consents=api.CONSENTS)
        api.remember_refusal(server, "denied")
        moved = {**server, "api_url": daemon.url.replace("127.0.0.1", "localhost")}
        out = api.probe(moved, "dhcp4")
        assert "consented_at" not in out and "refused" not in out


class TestTheCapabilityAndTheBadge:
    def _derive(self, **kw):
        return caps.derive(kea_version=(3, 0, 5), reachable=True, direct=True, **kw)

    def test_config_api_is_a_bool_capability_with_both_sentences(self):
        off = self._derive()
        on = self._derive(config_probe={"config_api": True, "at": _iso()})
        assert "config_api" in caps.CAPABILITY_NAMES and off.config_api is False and on.config_api is True
        assert "has not been read over its API yet" in off.why("config_api")
        assert "is available on this server" in on.why("config_api")
        assert (
            self._derive(config_probe={"config_api": False, "refused": "x"})
            .why("config_api")
            .startswith("The last check could not read")
        )

    def test_the_transport_is_a_plain_field_outside_the_capability_names(self):
        assert "config_transport" not in caps.CAPABILITY_NAMES
        assert [row for row in self._derive(config_transport="api").as_rows() if row[0] == "config_transport"] == []
        for word in ("api", "file", "off"):
            assert self._derive(config_transport=word).config_transport == word
        assert self._derive(config_transport="bogus").config_transport == "off"

    @pytest.mark.parametrize(
        ("kw", "needle"),
        [
            (
                {"config_transport": "api", "config_declared": "api", "config_probe": {"config_api": True}},
                "no restart, no SSH needed",
            ),
            (
                {"config_transport": "api", "config_declared": "api", "config_probe": {"config_api": False}},
                "did not answer the last readiness check; a change will stop until it does",
            ),
            (
                {"config_transport": "api", "config_declared": "api"},
                "Live at once",
            ),  # never probed: reachability is runtime, the badge stays api
            ({"config_transport": "file", "config_declared": "file", "ssh": True}, "rewrites kea-dhcp4.conf over SSH"),
            ({"config_transport": "off", "config_declared": "off"}, "never changes its configuration"),
            ({"config_transport": "off", "config_declared": "file", "ssh": False}, "needs an SSH host"),
        ],
    )
    def test_one_sentence_per_state(self, kw, needle):
        assert needle in self._derive(**kw).transport_why()

    def test_derive_is_pure_the_stored_probe_is_its_input(self, monkeypatch):
        def boom(*a, **k):
            raise AssertionError("derive must not call out")

        monkeypatch.setattr("jen.services.kea.kea_command", boom)
        monkeypatch.setattr(api, "stored_probe", boom)
        assert self._derive(config_probe={"config_api": True}).config_api is True

    def test_invalidate_drops_the_request_memo(self, monkeypatch):
        memo = {("1", True, True): "stale"}
        monkeypatch.setattr(caps, "_request_memo", lambda: memo)
        caps.invalidate()
        assert memo == {}

    def test_config_inputs_read_the_dict_and_the_stored_probe(self, monkeypatch):
        monkeypatch.setattr(api, "stored_probe", lambda sid: {"config_api": True})
        got = caps.config_inputs({"id": 3, "config_transport": "api"})
        assert got == {
            "config_transport": "api",
            "config_declared": "api",
            "config_probe": {"config_api": True},
            "config_gate": api.probe_gate(
                {"id": 3, "config_transport": "api"}
            ),  # (Q216 AA13) the gate's own answer rides along
        }
        assert got["config_gate"], "a stored result with no timestamp is a closed gate"
        assert caps.config_inputs(None) == {}
