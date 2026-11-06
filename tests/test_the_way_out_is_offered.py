"""v7.0.0-beta.7 (Q221, AE11) - the way out a refusal names is one a control offers.

The world: a change over the API whose process died between `config-set` and `config-write` (the daemon runs the change, its file does not carry it, a `pending` row is on record), and then a hand
edit of the file. At 7.0.0-beta.6 *Settle it now* refused and named "discard it from the server's Write mode card"; the card's discard is the switch, and the switch refuses while a change is
unsettled - so every control the product offered refused, in a circle. Nothing was lost (0 `config-write`, the edit kept), and nothing could be done short of restarting Kea, which drops the change.

The two real ways out are now both offered: restart Kea (the file wins, the change is dropped), or tick the box beside *Settle it now* (the change wins; the capturing read puts the file's edit in
Config history first). Executed against the real `apply`, `settle_pending`, `pending_block` and `file_proof`, over the shipped stateful fake daemon and the shipped host clock."""

import copy

import pytest

from jen import extensions
from jen.services import kea_api_config as api
from jen.services import write_mode as words
from tests import _kea_api_world as world
from tests import _write_mode_render as wm
from tests.e2e._fake_kea_server import TWO_SUBNET_DHCP4, StatefulKeaServer
from tests.test_kea_consent import GOOD

SID = 7
SENTENCE = "tick the discard box beside Settle it now on the server's Write mode card to keep the change"


@pytest.fixture
def store(monkeypatch):
    return world.install_store(monkeypatch)


@pytest.fixture(autouse=True)
def probes(monkeypatch):
    return world.install_probes(monkeypatch)


@pytest.fixture(autouse=True)
def _no_investigation(monkeypatch):
    monkeypatch.setattr("jen.services.investigation_logging.file_write_refusal", lambda server, cfg: "")
    monkeypatch.setattr("jen.services.investigation_logging.restore_window", lambda server, now=None: "")


@pytest.fixture
def fake(monkeypatch, store):
    f = StatefulKeaServer(copy.deepcopy(TWO_SUBNET_DHCP4))
    f.start()
    monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
    monkeypatch.setattr(api, "COMMAND_TIMEOUT", 0.6)
    yield f
    f.stop()


@pytest.fixture
def w(fake, store, monkeypatch):
    server = {"id": SID, "name": "kea-a", "api_url": fake.url, "ssh_host": "10.0.0.9", "config_transport": "api"}
    return world.ProofWorld(fake, server, store, monkeypatch)


def _crash_then_edit(w, store, fake, monkeypatch):
    """The world of the finding. Returns the file as the operator's hand edit left it."""
    server = w.server
    w.start(copy.deepcopy(TWO_SUBNET_DHCP4))
    cfg, digest = api.read(server, "dhcp4", capture=False)
    plan = api.file_proof(server, "dhcp4")
    assert plan["ok"], plan
    candidate = copy.deepcopy(cfg)
    candidate["Dhcp4"]["valid-lifetime"] = 7200

    real_send = api._send_write
    monkeypatch.setattr(api, "_write_with_retries", lambda s, svc: (_ for _ in ()).throw(SystemExit("died")))
    with pytest.raises(SystemExit):
        api.apply(server, "dhcp4", candidate, digest, "lifetime 7200", planned_sha=plan["sha256"])
    monkeypatch.setattr(api, "_write_with_retries", lambda s, svc: real_send(s, svc, api.WRITE_ATTEMPTS))
    monkeypatch.setattr(api, "_row_age_seconds", lambda row: api.PENDING_SETTLE_SECONDS + 10)

    row = store.pending(SID, "dhcp4")
    assert row is not None and row["file_sha256"] == plan["sha256"]
    assert fake.running.get("valid-lifetime") == 7200 and fake.file.get("valid-lifetime") != 7200

    edited = copy.deepcopy(fake.file)
    edited["subnet4"][0]["option-data"] = [{"name": "routers", "data": "10.97.0.254"}]
    w.hand_edit(edited)
    return copy.deepcopy(edited)


class TestSettleItNowOffersBothWaysOut:
    def test_without_the_box_nothing_is_written_and_the_sentence_names_the_box(self, w, store, fake, monkeypatch):
        edited = _crash_then_edit(w, store, fake, monkeypatch)
        before = w.writes()
        lines, settled = api.settle_pending(w.server, "dhcp4")
        text = " ".join(lines)
        assert settled is False and w.writes() == before
        assert SENTENCE in text and "restart Kea there" in text
        assert "discard it from the server's Write mode card" not in text
        assert fake.file == edited and store.pending(SID, "dhcp4") is not None

    def test_with_the_box_the_change_is_written_once_and_the_edit_is_in_config_history_first(
        self, w, store, fake, monkeypatch
    ):
        edited = _crash_then_edit(w, store, fake, monkeypatch)
        before = w.writes()
        edit_sha = api.file_proof(w.server, "dhcp4", capture=False)[
            "sha256"
        ]  # the edited file, read without recording it
        assert edit_sha not in {row["sha256"] for row in store.list_revisions(SID, "dhcp4")}
        lines, settled = api.settle_pending(w.server, "dhcp4", discard=True)
        assert settled is True, lines
        assert w.writes() == before + 1
        assert fake.file.get("valid-lifetime") == 7200, (
            "the file is now the daemon's configuration: the change was kept"
        )
        assert fake.file != edited and store.pending(SID, "dhcp4") is None
        rows = store.list_revisions(SID, "dhcp4")
        captured = [row["id"] for row in rows if row["source"] == "external" and row["sha256"] == edit_sha]
        rendered = [row["id"] for row in rows if row["source"] == "rendering"]
        assert len(captured) == 1 and rendered, "the file's edit is a row in Config history"
        assert captured[0] < min(rendered), "and it was recorded BEFORE the file was replaced"

    def test_the_plan_of_a_change_never_discards(self, w, store, fake, monkeypatch):
        """Only the operator's settlement carries the box: `pending_block` (the Plan, `apply`, the switch) refuses and writes nothing, and names the box."""
        edited = _crash_then_edit(w, store, fake, monkeypatch)
        before = w.writes()
        blocked = api.pending_block(w.server, "dhcp4")
        assert SENTENCE in blocked and w.writes() == before and fake.file == edited

    def test_a_file_that_cannot_be_read_is_never_overwritten_not_even_with_the_box(self, w, store, fake, monkeypatch):
        edited = _crash_then_edit(w, store, fake, monkeypatch)
        before = w.writes()
        monkeypatch.setattr(api._host, "read_config_proof", lambda server, service, capture=True: (None, None, None))
        lines, settled = api.settle_pending(w.server, "dhcp4", discard=True)
        assert settled is False and w.writes() == before and fake.file == edited, lines

    def test_the_other_way_out_restart_kea_drops_the_change_and_keeps_the_edit(self, w, store, fake, monkeypatch):
        edited = _crash_then_edit(w, store, fake, monkeypatch)
        before = w.writes()
        w.reload()  # the operator restarts Kea (or `config-reload`): the daemon takes the edited file
        assert fake.running.get("valid-lifetime") != 7200
        api.settle_pending(w.server, "dhcp4")
        assert w.writes() == before and fake.file == edited


def _facts():
    return {**GOOD, "at": wm.NOW, "consented_at": wm.NOW, "consents": [], "bound": "x", "tls": False}


class TestTheCardCarriesTheBox:
    def _form(self, html):
        start = html.index('action="/settings/infrastructure/settle-pending-change/2"')
        return html[start : html.index("</form>", start)]

    def test_the_settle_form_carries_the_box_with_the_one_consent_value_and_text(self, monkeypatch):
        _cards, html = wm.render(
            monkeypatch, [wm.S_API], {2: _facts()}, pending=True, pending_note="its file write waits"
        )
        form = self._form(html)
        assert f'<input type="checkbox" name="discard_file_edit" value="{words.CONSENT_VALUE}">' in form
        assert words.CONSENT_TEXTS["discard_file_edit"] in form and "it is kept in Config history" in form
        assert 'data-settle-discard="2"' in form and "unless the box beside the button is ticked" in form

    def test_no_pending_change_no_box(self, monkeypatch):
        _cards, html = wm.render(monkeypatch, [wm.S_API], {2: _facts()})
        assert "data-settle-discard" not in html

    def test_an_admin_never_sees_the_form(self, monkeypatch):
        _cards, html = wm.render(monkeypatch, [wm.S_API], {2: _facts()}, superadmin=False, pending=True)
        assert "data-settle-discard" not in html and "settle-pending-change" not in html
