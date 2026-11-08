"""
tests/test_transport_switch.py
──────────────────────────────
Q212 (BB8) - the six transitions of `jen/services/kea_transport_switch.py`, each precondition failing once, against the stateful fake Kea. After every success the fake's file canonically equals what
it runs, a baseline revision of the right kind exists and the setting was written. Pure: runs under `--noconftest`.
"""

import copy
import threading

import pytest

from jen import config as jen_config
from jen import extensions
from jen.services import kea_api_config as api
from jen.services import kea_changeset as cs
from jen.services import kea_host
from jen.services import kea_transport_switch as sw
from jen.services import write_mode as words
from tests import _kea_api_world as world
from tests.e2e._fake_kea_server import TWO_SUBNET_DHCP4, StatefulKeaServer

ALL = {"consent_rendering", "consent_unauthenticated", "confirm_no_include"}


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setattr("jen.services.investigation_logging.file_write_refusal", lambda server, cfg: "")
    monkeypatch.setattr("jen.services.investigation_logging.restore_window", lambda server, now=None: "")
    monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
    monkeypatch.setattr(api, "COMMAND_TIMEOUT", 0.4)


@pytest.fixture(autouse=True)
def file_proof_follows_the_read(monkeypatch):
    """Q219: the proof reads the file through `kea_host.read_config_proof`; the tests that stub the plain read get a proof derived from it (written before the daemon's last load). The tests about the
    clock use `world.host_reads_the_fakes_file`, which installs the `HostClock` world instead."""
    world.proof_follows_the_read(monkeypatch)


@pytest.fixture
def store(monkeypatch):
    return world.install_store(monkeypatch)


@pytest.fixture
def probes(monkeypatch):
    return world.install_probes(monkeypatch, valid=False)


@pytest.fixture
def written(monkeypatch):
    calls = []
    monkeypatch.setattr(
        jen_config.app_config, "write_value", lambda section, key, value, **kw: calls.append((section, key, value))
    )
    return calls


@pytest.fixture
def daemon():
    f = StatefulKeaServer(copy.deepcopy(TWO_SUBNET_DHCP4))
    f.start()
    yield f
    f.stop()


def srv(daemon, transport=None, ssh=False, **extra):
    out = {"id": 5, "name": "kea-e", "api_url": daemon.url, **extra}
    if transport is not None:
        out["config_transport"] = transport
    if ssh:
        out["ssh_host"] = "10.0.0.5"
    return out


def host(monkeypatch, daemon, *, file_cfg="same", may_write=True, includes=(), raw="r" * 64, account="_kea"):
    """The helper's two answers: the file's content and the write-check facts."""
    cfg = {"Dhcp4": copy.deepcopy(daemon.running)} if file_cfg == "same" else file_cfg
    monkeypatch.setattr(kea_host, "read_config_versioned", lambda *a, **k: (cfg, raw if cfg is not None else None))
    monkeypatch.setattr(
        kea_host,
        "config_write_check",
        lambda s, svc: {
            "ok": True,
            "may_write": may_write,
            "includes": list(includes),
            "mode": "0640",
            "account": {"name": account, "uid": 100, "gid": 101},
        },
    )


def assert_file_is_running(daemon):
    assert daemon.file == daemon.running


class TestToApi:
    def test_off_to_api_without_ssh_needs_the_include_confirmation(self, daemon, store, probes, written):
        r = sw.switch(srv(daemon), "api", consents={"consent_rendering", "consent_unauthenticated"})
        assert not r["ok"] and r["needs"] == "confirm_no_include" and written == []

    def test_the_rendering_consent_is_required(self, daemon, store, probes, written):
        r = sw.switch(srv(daemon), "api", consents={"confirm_no_include", "consent_unauthenticated"})
        assert not r["ok"] and r["needs"] == "consent_rendering" and "comments and key order" in r["line"]

    def test_an_unauthenticated_endpoint_needs_its_own_confirmation(self, daemon, store, probes, written):
        r = sw.switch(srv(daemon), "api", consents={"confirm_no_include", "consent_rendering"})
        assert not r["ok"] and r["needs"] == "consent_unauthenticated" and "no authentication" in r["line"]

    def test_off_to_api_succeeds_with_the_named_consents(self, daemon, store, probes, written):
        r = sw.switch(srv(daemon), "api", consents=ALL, actor="root")
        assert r["ok"] and "switched to Live API" in r["line"] and f"revision #{r['revision']}" in r["line"]
        assert_file_is_running(daemon)
        assert written == [("kea_server_5", "config_transport", "api")]
        assert [(x["hash_kind"], x["source"]) for x in store.rows if x["source"] == "switch"] == [("kea", "switch")]
        assert probes[5]["consented_at"]  # the gate in `apply` reads it
        assert api.probe_gate(srv(daemon, "api")) == ""

    def test_the_primary_writes_its_own_section(self, daemon, store, probes, written):
        server = srv(daemon)
        server["id"] = 1
        sw.switch(server, "api", consents=ALL)
        assert written == [("kea", "config_transport", "api")]

    def test_a_daemon_that_does_not_answer_refuses(self, daemon, store, probes, written):
        daemon.stopped = True
        r = sw.switch(srv(daemon), "api", consents=ALL)
        assert not r["ok"] and "could not be read over its API" in r["line"] and written == []

    def test_a_config_test_of_the_running_configuration_that_fails_refuses(self, daemon, store, probes, written):
        daemon.test_fails = "the configuration has an unknown parameter"
        r = sw.switch(srv(daemon), "api", consents=ALL)
        assert not r["ok"] and "config-test" in r["line"] and written == []

    def test_an_include_refuses_and_names_the_file(self, daemon, store, probes, written, monkeypatch):
        host(monkeypatch, daemon, includes=["/etc/kea/extra.json"])
        r = sw.switch(srv(daemon, ssh=True, transport="file"), "api", consents=ALL)
        assert not r["ok"] and "/etc/kea/extra.json" in r["line"] and written == []

    def test_a_file_that_differs_from_the_daemon_refuses_until_the_edit_is_discarded(
        self, daemon, store, probes, written, monkeypatch
    ):
        host(monkeypatch, daemon, file_cfg={"Dhcp4": {"valid-lifetime": 1}})
        server = srv(daemon, ssh=True, transport="file")
        r = sw.switch(server, "api", consents=ALL)
        assert not r["ok"] and r["needs"] == "discard_file_edit" and "restart Kea first" in r["line"] and written == []
        assert "config-write" not in daemon.commands  # nothing was destroyed
        r = sw.switch(server, "api", consents=ALL | {"discard_file_edit"})
        assert r["ok"]
        assert_file_is_running(daemon)  # the daemon's configuration is now the file's

    def test_a_daemon_that_may_not_write_its_file_refuses_and_says_what_to_press(
        self, daemon, store, probes, written, monkeypatch
    ):
        host(monkeypatch, daemon, may_write=False)
        r = sw.switch(srv(daemon, ssh=True, transport="file"), "api", consents=ALL)
        assert (
            not r["ok"]
            and r["needs"] == "allow_config_write"
            and "Allow the daemon to write its file" in r["line"]
            and written == []
        )

    def test_a_refused_config_write_stops_the_switch_and_is_remembered(self, daemon, store, probes, written):
        daemon.write_fails = "Unable to open file /etc/kea/kea-dhcp4.conf for writing"
        r = sw.switch(srv(daemon), "api", consents=ALL)
        assert not r["ok"] and "refused to write its file" in r["line"] and written == []
        assert "Unable to open file" in probes[5]["refused"]

    def test_with_ssh_the_ssh_questions_are_answered_not_asked(self, daemon, store, probes, written, monkeypatch):
        host(monkeypatch, daemon)
        r = sw.switch(
            srv(daemon, ssh=True, transport="file"), "api", consents={"consent_rendering", "consent_unauthenticated"}
        )
        assert r["ok"], r  # no `confirm_no_include`: the host answered it

    def test_a_consent_the_facts_never_called_for_is_not_recorded(self, daemon, store, probes, written):
        """Q218 BH3 a (AC4): the service records what the FRESH facts call for (`consents_called_for`, the one table), never every name the form happened to send; a stray is dropped and named. Here the
        endpoint has a password (no `consent_unauthenticated`) and the server no SSH (no `discard_file_edit`)."""
        server = srv(daemon, api_user="jen", api_pass="pw")
        stray = ALL | {"discard_file_edit"}
        r = sw.switch(server, "api", consents=stray, actor="root")
        assert r["ok"], r
        assert r["consents"] == ["confirm_no_include", "consent_rendering"], r["consents"]
        assert r["ignored"] == ["consent_unauthenticated", "discard_file_edit"], r["ignored"]
        assert probes[5]["consents"] == r["consents"], "what is on record is what the result says"
        assert api.probe_gate(srv(daemon, "api", api_user="jen", api_pass="pw")) == ""

    def test_a_stray_discard_box_never_covers_a_file_edit_that_appears_later(
        self, daemon, store, probes, written, monkeypatch
    ):
        """Q218 BH3 a: with SSH and a file that agrees, a ticked `discard_file_edit` is not recorded - so a hand edit that appears afterward BLOCKS the gate instead of being covered."""
        host(monkeypatch, daemon)
        server = srv(daemon, "file", ssh=True, api_user="jen", api_pass="pw")
        r = sw.switch(server, "api", consents={"consent_rendering", "discard_file_edit"}, actor="root")
        assert r["ok"] and r["consents"] == ["consent_rendering"] and r["ignored"] == ["discard_file_edit"], r
        stored = probes[5]
        assert api.probe_gate(dict(server, config_transport="api")) == ""
        stored["agree"] = False  # the facts a later refresh would read: a hand edit
        probes[5] = stored
        host(monkeypatch, daemon, raw="e" * 64)  # (Q219 E1) the hand edit: other bytes than Jen's rendering ...
        world.proof_follows_the_read(monkeypatch, loaded=False)  # ... written after the daemon's last load
        assert "carries a configuration the daemon is not running" in api.probe_gate(
            dict(server, config_transport="api")
        )

    def test_a_switch_to_file_or_off_says_what_it_used_not_what_was_submitted(
        self, daemon, store, probes, written, monkeypatch
    ):
        host(monkeypatch, daemon)
        r = sw.switch(srv(daemon, "api", ssh=True), "off", consents={"consent_rendering"})
        assert r["ok"] and r["consents"] == [] and r["ignored"] == ["consent_rendering"]
        r = sw.switch(srv(daemon, "api", ssh=True), "file", consents={"discard_file_edit"})
        assert (
            r["ok"] and r["consents"] == [] and r["ignored"] == ["discard_file_edit"]
        )  # the file agreed: nothing was discarded

    def test_api_to_api_records_and_does_not_render(self, daemon, store, probes, written, monkeypatch):
        """Q218 BH1 d (AC14): the button says Record consent and does that - `config-write` goes out only when the file carries an edit AND the operator said to discard it."""
        world.host_reads_the_fakes_file(monkeypatch, daemon, store, server_id=5)
        monkeypatch.setattr(
            kea_host,
            "config_write_check",
            lambda s, svc: {"ok": True, "may_write": True, "includes": [], "mode": "0640", "account": {"name": "_kea"}},
        )
        r = sw.switch(srv(daemon, "api", ssh=True), "api", consents=ALL - {"confirm_no_include"}, actor="root")
        assert r["ok"] and "consent recorded for Live API" in r["line"] and "discarded" not in r["line"], r
        assert "config-write" not in daemon.commands and probes[5]["consented_at"]

    def test_a_discarded_edit_is_in_config_history_before_the_write(self, daemon, store, probes, written, monkeypatch):
        """Q218 BH1 a, d: the edit a consent discards is an `external` row BEFORE the `config-write` that replaces it - to Live API (from the file path and in place) and to File over SSH."""
        monkeypatch.setattr(
            kea_host,
            "config_write_check",
            lambda s, svc: {"ok": True, "may_write": True, "includes": [], "mode": "0640", "account": {"name": "_kea"}},
        )
        edit = {"user-context": {"jen-note": "an edit the daemon never loaded"}}
        for current, target in (("file", "api"), ("api", "api"), ("api", "file")):
            store.rows.clear()
            daemon.commands.clear()
            daemon.set_running(copy.deepcopy(TWO_SUBNET_DHCP4))
            daemon.file = copy.deepcopy(daemon.running)
            world.host_reads_the_fakes_file(monkeypatch, daemon, store, server_id=5)
            kea_host.read_config_versioned(srv(daemon, current, ssh=True), "dhcp4")  # the baseline of the clean file
            daemon.file.update(copy.deepcopy(edit))
            seen = {}
            daemon.hooks["config-write"] = lambda f, seen=seen: seen.setdefault(
                "rows", [(x["source"], x["hash_kind"]) for x in store.rows]
            )
            consents = (ALL - {"confirm_no_include"}) | {"discard_file_edit"}
            r = sw.switch(srv(daemon, current, ssh=True), target, consents=consents, actor="root")
            assert r["ok"], (current, target, r)
            assert ("external", "raw") in seen["rows"], (
                current,
                target,
                "the edit was in Config history before the write",
            )
            assert "user-context" not in daemon.file
            if current == target == "api":
                assert "the file's edit was discarded" in r["line"], r

    def test_without_discard_an_edit_that_appears_after_the_check_is_refused_and_nothing_is_sent(
        self, daemon, store, probes, written, monkeypatch
    ):
        """Q218 BH1 a, CFG-005: the facts the consents were given for said the file agreed; an edit that appeared since is refused by the sender (and no refusal is remembered as Kea's)."""
        world.host_reads_the_fakes_file(monkeypatch, daemon, store, server_id=5)
        monkeypatch.setattr(
            kea_host,
            "config_write_check",
            lambda s, svc: {"ok": True, "may_write": True, "includes": [], "mode": "0640", "account": {"name": "_kea"}},
        )
        real_probe = api.probe

        def probe_then_edit(server, service="dhcp4", **kw):
            facts = real_probe(server, service, **kw)
            daemon.file["user-context"] = {"jen-note": "appeared after the check"}
            return facts

        monkeypatch.setattr(api, "probe", probe_then_edit)
        r = sw.switch(srv(daemon, "file", ssh=True), "api", consents=ALL - {"confirm_no_include"})
        assert not r["ok"] and "has not loaded that edit" in r["line"], r
        assert "config-write" not in daemon.commands and "refused" not in (probes.get(5) or {})
        assert written == []

    def test_the_stored_facts_after_the_switch_are_the_facts_after_its_write(
        self, daemon, store, probes, written, monkeypatch
    ):
        """Q219 BI3 a (AD2): the switch's own `config-write` makes the file the daemon's rendering, so the facts the consent is written over are the facts AFTER it - `agree` True by Jen's own rendering - and
        the consent the act used up (`discard_file_edit`) is not left on record to open the gate on a later edit."""
        w = world.ProofWorld(daemon, srv(daemon, "file", ssh=True), store, monkeypatch)
        server = srv(daemon, "file", ssh=True)
        monkeypatch.setattr(
            kea_host,
            "config_write_check",
            lambda s, svc: {"ok": True, "may_write": True, "includes": [], "mode": "0640", "account": {"name": "_kea"}},
        )
        w.hand_edit({**daemon.file, "user-context": {"jen-note": "an edit the daemon never loaded"}})
        consents = (ALL - {"confirm_no_include"}) | {"discard_file_edit"}
        r = sw.switch(server, "api", consents=consents, actor="root")
        assert r["ok"], r
        stored = probes[5]
        assert stored["agree"] is True and stored["proof"] == "rendering", stored
        assert {"discard_file_edit", "consent_rendering"} <= set(r["consents"]), "the audit row says what was USED"
        assert "discard_file_edit" not in stored["consents"], "and the used-up consent is not on record"
        assert api.probe_gate(dict(server, config_transport="api")) == ""

    def test_a_switch_over_an_unsettled_change_is_refused_with_the_pending_sentence(
        self, daemon, store, probes, written, monkeypatch
    ):
        """Q219 Decided 7: `switch()` asks `record_unreadable` then `pending_block` for an `api` or a `file` target; `off` asks neither."""
        host(monkeypatch, daemon)
        cfg = {"Dhcp4": copy.deepcopy(daemon.running)}
        stranger = copy.deepcopy(daemon.running)
        stranger["valid-lifetime"] = 11
        store.record(5, "dhcp4", cfg, "a" * 64, "left by a crash", hash_kind="kea", source="pending")
        daemon.set_running(stranger)  # neither state: the row stays and blocks
        for target in ("api", "file"):
            r = sw.switch(srv(daemon, "api" if target == "file" else "off", ssh=True), target, consents=ALL)
            assert not r["ok"] and ("unresolved" in r["line"] or "neither" in r["line"]), (target, r)
        assert written == []
        assert sw.switch(srv(daemon, "api", ssh=True), "off")["ok"], "off asks neither"

    def test_a_switch_off_live_api_clears_the_refusal(self, daemon, store, probes, written, monkeypatch):
        """Q219 BI3 b (AD3): a remembered `config-write` refusal belongs to Live API; it is cleared when the server leaves it (after the setting is written), on every transition whose current is `api`."""
        host(monkeypatch, daemon)
        for target in ("off", "file"):
            probes[5] = {
                "at": "2099-01-01T00:00:00+00:00",
                "config_api": True,
                "refused": "Permission denied",
                "bound": "t",
            }
            r = sw.switch(srv(daemon, "api", ssh=True), target)
            assert r["ok"] and r.get("refusal_cleared") is True, (target, r)
            assert "refused" not in probes[5]
        probes[5] = {
            "at": "2099-01-01T00:00:00+00:00",
            "config_api": True,
            "refused": "Permission denied",
            "bound": "t",
        }
        assert sw.switch(srv(daemon, "off", ssh=True), "file")["ok"]
        assert probes[5].get("refused") == "Permission denied", "a server that was not in Live API keeps what it had"
        probes[5] = {"at": "2099-01-01T00:00:00+00:00", "config_api": True, "bound": "t"}
        assert sw.switch(srv(daemon, "api", ssh=True), "off").get("refusal_cleared") is False, (
            "nothing was on record, nothing is claimed"
        )


class TestToFile:
    def test_api_to_file_needs_ssh(self, daemon, store, probes, written):
        r = sw.switch(srv(daemon, "api"), "file")
        assert not r["ok"] and "needs an SSH host" in r["line"] and written == []

    def test_api_to_file_with_a_file_that_agrees_records_a_raw_baseline(
        self, daemon, store, probes, written, monkeypatch
    ):
        host(monkeypatch, daemon)
        r = sw.switch(srv(daemon, "api", ssh=True), "file", actor="root")
        assert r["ok"] and written == [("kea_server_5", "config_transport", "file")]
        assert "config-write" not in daemon.commands  # (fix row 5) they agree already: nothing is written to make them
        assert [(x["hash_kind"], x["source"]) for x in store.rows if x["source"] == "switch"] == [("raw", "switch")]

    def test_a_file_and_daemon_that_differ_refuse_with_both_digests(self, daemon, store, probes, written, monkeypatch):
        host(monkeypatch, daemon, file_cfg={"Dhcp4": {"valid-lifetime": 1}}, raw="f" * 64)
        r = sw.switch(srv(daemon, "api", ssh=True), "file")
        assert not r["ok"] and daemon.digest()[:12] in r["line"] and ("f" * 12) in r["line"] and written == []
        assert (
            r["needs"] == "discard_file_edit" and "config-write" not in daemon.commands
        )  # (fix row 5) a hand edit is never overwritten to make the compare pass

    def test_with_the_named_consent_the_file_is_overwritten_and_the_compare_decides_again(
        self, daemon, store, probes, written, monkeypatch
    ):
        host(monkeypatch, daemon, file_cfg={"Dhcp4": {"valid-lifetime": 1}}, raw="f" * 64)
        daemon.write_fails = "denied"  # still refused: they stay apart and the switch says so
        r = sw.switch(srv(daemon, "api", ssh=True), "file", consents={"discard_file_edit"})
        assert not r["ok"] and "still differs" in r["line"] and written == []
        assert "config-write" in daemon.commands

    def test_a_daemon_never_granted_the_write_can_still_leave_api_when_they_agree(
        self, daemon, store, probes, written, monkeypatch
    ):
        host(monkeypatch, daemon)
        daemon.write_fails = "denied"  # the best-effort write is refused; the compare decides, and they agree
        assert sw.switch(srv(daemon, "api", ssh=True), "file")["ok"]

    def test_an_unreadable_file_refuses(self, daemon, store, probes, written, monkeypatch):
        host(monkeypatch, daemon, file_cfg=None)
        r = sw.switch(srv(daemon, "api", ssh=True), "file")
        assert not r["ok"] and "could not be read" in r["line"]

    def test_api_to_file_with_a_daemon_that_does_not_answer_refuses(self, daemon, store, probes, written, monkeypatch):
        host(monkeypatch, daemon)
        daemon.stopped = True
        assert not sw.switch(srv(daemon, "api", ssh=True), "file")["ok"]

    def test_off_to_file_with_a_daemon_that_does_not_answer_is_allowed(
        self, daemon, store, probes, written, monkeypatch
    ):
        """An `off` server with SSH may have no usable API at all: File over SSH is what it had before (the daemon is not compared when it cannot be asked)."""
        host(monkeypatch, daemon)
        daemon.stopped = True
        assert sw.switch(srv(daemon, "off", ssh=True), "file")["ok"]


class TestTheRefusalNamesAControlTheCardOffers:
    """Q222 (AG7): the card renders the discard box only once a readiness result is stored; a server never readiness-checked was told to tick a box its card did not show."""

    def test_with_no_stored_result_the_sentence_names_the_readiness_check(
        self, daemon, store, probes, written, monkeypatch
    ):
        host(monkeypatch, daemon, file_cfg={"Dhcp4": {"valid-lifetime": 1}}, raw="f" * 64)
        r = sw.switch(srv(daemon, "api", ssh=True), "file")
        assert not r["ok"] and r["needs"] == "discard_file_edit" and written == []
        assert (
            f"press {words.CHECK_BUTTON} under {words.CHECK_ROW} on the server's card, select File over SSH and tick '{words.CONSENT_TEXTS['discard_file_edit']}'"
            in r["line"]
        )  # (Q223, AH4/AH5) the box by its label; a Live API server's card already shows the check; (Q224, AJ8) the check by the card's own words
        assert "restart Kea there, restore from Config history" in r["line"]

    def test_with_a_stored_result_the_sentence_names_the_box(self, daemon, store, probes, written, monkeypatch):
        probes[5] = {"config_api": True}
        host(monkeypatch, daemon, file_cfg={"Dhcp4": {"valid-lifetime": 1}}, raw="f" * 64)
        r = sw.switch(srv(daemon, "api", ssh=True), "file")
        assert not r["ok"] and r["needs"] == "discard_file_edit" and written == []
        assert (
            f"or tick '{words.CONSENT_TEXTS['discard_file_edit']}' on the server's card to overwrite it" in r["line"]
            and words.CHECK_BUTTON not in r["line"]
        )


class TestAnUnknownFactWithSshIsARefusal:
    """Fix row 4: SSH is configured but the helper (or SSH) did not answer: the file could not be compared, so nothing is overwritten."""

    @pytest.mark.parametrize("what", ["file", "helper"])
    def test_file_to_api_is_refused_and_nothing_is_written(self, daemon, store, probes, written, monkeypatch, what):
        if what == "file":
            host(monkeypatch, daemon, file_cfg=None)
        else:
            host(monkeypatch, daemon)
            monkeypatch.setattr(
                kea_host, "config_write_check", lambda s, svc: {"ok": False, "code": "old", "detail": "build 18"}
            )
        r = sw.switch(srv(daemon, ssh=True, transport="file"), "api", consents=ALL)
        assert not r["ok"] and "could not be read" in r["line"] and written == []
        assert "config-write" not in daemon.commands


class TestToOff:
    @pytest.mark.parametrize("current", ["api", "file"])
    def test_the_setting_and_nothing_else(self, daemon, store, probes, written, current):
        r = sw.switch(srv(daemon, current, ssh=True), "off")
        assert r["ok"] and written == [("kea_server_5", "config_transport", "off")]
        assert daemon.commands == [] and store.rows == []  # the daemon keeps serving; Jen stops writing

    def test_the_same_transport_changes_nothing(self, daemon, store, probes, written):
        r = sw.switch(srv(daemon, "api"), "api")
        assert r["ok"] and r["unchanged"] and written == [] and daemon.commands == []

    def test_a_server_already_in_live_api_records_a_consent_in_place(self, daemon, store, probes, written):
        """Q217, second pass row 2: a server whose gate is closed on a fact (an endpoint with no authentication) records the consent where it stands - it used to say `unchanged` and record nothing."""
        r = sw.switch(srv(daemon, "api"), "api", consents=ALL, actor="root")
        assert r["ok"] and not r.get("unchanged") and "consent recorded for Live API" in r["line"], r
        assert probes[5]["consented_at"] and api.probe_gate(srv(daemon, "api")) == ""

    def test_a_word_that_is_not_a_transport_is_refused(self, daemon, store, probes, written):
        assert not sw.switch(srv(daemon, "api"), "ssh")["ok"]


class TestTheLock:
    def test_a_switch_waits_behind_a_change_and_gives_up_with_the_sentence(
        self, daemon, store, probes, written, monkeypatch
    ):
        monkeypatch.setattr(cs, "CHANGE_WAIT_SECONDS", 0.2)
        release, holding = threading.Event(), threading.Event()

        def hold():
            with cs.change_lock(5):
                holding.set()
                release.wait(5)

        t = threading.Thread(target=hold)
        t.start()
        holding.wait(2)
        r = sw.switch(srv(daemon), "api", consents=ALL)
        release.set()
        t.join(3)
        assert not r["ok"] and "another change is running on this box" in r["line"] and written == []

    def test_the_setting_is_written_under_the_lock(self, daemon, store, probes, monkeypatch):
        seen = []

        def spy(section, key, value, **kw):
            seen.append(cs._CHANGE_LOCK.locked())

        monkeypatch.setattr(jen_config.app_config, "write_value", spy)
        sw.switch(srv(daemon), "api", consents=ALL)
        assert seen == [True]


class TestQ216TheSwitchAsksTheWritersQuestionsAndSaysWhenTheSettingFails:
    """Q216 AA10 / AA16: the switch's two `config-write` calls ask `guard_kea_write` and `restore_window` first, and a setting that cannot be saved is a line, never a 500 over a half-done switch."""

    def test_to_api_asks_the_marker_question_before_it_writes(self, daemon, store, probes, written, monkeypatch):
        monkeypatch.setattr(
            "jen.services.investigation_logging.file_write_refusal",
            lambda server, cfg: "Investigation logging is on for kea-e",
        )
        daemon.commands.clear()
        r = sw.switch(srv(daemon, "off"), "api", consents=ALL)
        assert not r["ok"] and "Investigation logging is on" in r["line"] and "config-write" not in daemon.commands
        assert written == []

    def test_to_api_asks_the_restore_window_before_it_writes(self, daemon, store, probes, written, monkeypatch):
        monkeypatch.setattr(
            "jen.services.investigation_logging.restore_window",
            lambda server, now=None: "the host is restoring logging at T; try again after it",
        )
        daemon.commands.clear()
        r = sw.switch(srv(daemon, "off"), "api", consents=ALL)
        assert not r["ok"] and "try again after it" in r["line"] and "config-write" not in daemon.commands

    def test_to_file_asks_both_before_the_best_effort_write(self, daemon, store, probes, written, monkeypatch):
        host(monkeypatch, daemon, file_cfg={"Dhcp4": {"valid-lifetime": 1}}, raw="f" * 64)
        monkeypatch.setattr(
            "jen.services.investigation_logging.restore_window",
            lambda server, now=None: "the host is restoring logging at T; try again after it",
        )
        daemon.commands.clear()
        r = sw.switch(srv(daemon, "api", ssh=True), "file", consents={"discard_file_edit"})
        assert not r["ok"] and "try again after it" in r["line"] and "config-write" not in daemon.commands

    def test_a_setting_that_cannot_be_saved_is_a_line(self, daemon, store, probes, monkeypatch):
        def boom(*a, **k):
            raise OSError("disk full")

        monkeypatch.setattr(jen_config.app_config, "write_value", boom)
        r = sw.switch(srv(daemon, "off"), "api", consents=ALL)
        assert not r["ok"] and "could not be saved" in r["line"] and "the transport did not change" in r["line"]

    def test_an_unreadable_record_refuses_both_directions(self, daemon, store, probes, written, monkeypatch):
        store.unreadable = True
        host(monkeypatch, daemon)
        assert "cannot be read" in sw.switch(srv(daemon, "off"), "api", consents=ALL)["line"]
        assert "cannot be read" in sw.switch(srv(daemon, "api", ssh=True), "file", consents=ALL)["line"]
        assert written == []
