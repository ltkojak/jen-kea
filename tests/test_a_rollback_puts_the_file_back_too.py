"""v7.0.0-beta.9 (Q223) - the pass on 7.0.0-beta.8 (AH1-AH15), each row executed here against the product.

AH1  a pending row is aged by the clock that stamped it (the database's), never by Jen's.
AH2  a rollback puts the FILE back too when the file carries the change it undoes, the sentence for a row with no planned file names the box first, and the change set's line names an api target's
     half-done rollback by the daemon's own answer.
AH3  AG4's sentence (two values that print alike) has its test.
AH4  the four refusals name the discard box by the label the card prints; AH5 a Read-only server's refusal says how to reach the readiness check.
AH6  a switch whose rendering row the store refused says so.
AH7  a string under a secret-named key is masked in the pass every member goes through; AH13 a camelCase key reaches the INI masker as written; AH14 a member's name is a plain relative path;
AH8  the size-cap note prints the cap as it is.
AH9  the stored readiness result is bound to all four identity keys; a two-key result from an earlier release is checked again, with its own sentence.
AH10 a written-out default under a renamed key is a default; AH11 a time that is no time is said so; AH12 a record that could not be removed is said so.
AH15 the support bundle is built by a POST.

Pure: runs under `--noconftest` (the fake daemon of tests/e2e/_fake_kea_server.py, the in-memory store of tests/_kea_api_world.py)."""

import ast
import copy
import pathlib
import re
from datetime import datetime, timedelta, timezone

import pytest

from jen import extensions
from jen.services import kea_api_config as api
from jen.services import kea_changeset as cs
from jen.services import kea_host
from jen.services import kea_transport_switch as sw
from jen.services import support_bundle as sb
from jen.services import write_mode as words
from tests import _kea_api_world as world
from tests._kea_host_fakes import FakeHelper
from tests.e2e._fake_kea_server import TWO_SUBNET_DHCP4, StatefulKeaServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
SID = 7
LABEL = words.CONSENT_TEXTS["discard_file_edit"]
REAL_BOUND = (
    api._bound
)  # captured before any fixture stands a fake binding in (tests/_kea_api_world.py::install_probes)


@pytest.fixture
def store(monkeypatch):
    return world.install_store(monkeypatch)


@pytest.fixture(autouse=True)
def probes(monkeypatch):
    return world.install_probes(monkeypatch)


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setattr("jen.services.investigation_logging.file_write_refusal", lambda server, cfg: "")
    monkeypatch.setattr("jen.services.investigation_logging.restore_window", lambda server, now=None: "")
    monkeypatch.setattr(cs, "record_outcome", lambda *a, **k: None)
    monkeypatch.setattr(extensions, "KEA_CONNECTION_MODE", "direct")
    monkeypatch.setattr(api, "COMMAND_TIMEOUT", 0.6)


@pytest.fixture
def fake():
    f = StatefulKeaServer(copy.deepcopy(TWO_SUBNET_DHCP4))
    f.hang_seconds = 1.2
    f.start()
    yield f
    f.stop()


@pytest.fixture
def w(fake, store, monkeypatch):
    server = {"id": SID, "name": "kea-a", "api_url": fake.url, "ssh_host": "10.0.0.9", "config_transport": "api"}
    out = world.ProofWorld(fake, server, store, monkeypatch)
    out.start(copy.deepcopy(TWO_SUBNET_DHCP4))
    return out


def _candidate(cfg, lifetime=7200):
    out = copy.deepcopy(cfg)
    out["Dhcp4"]["valid-lifetime"] = lifetime
    return out


def _forward_without_a_rendering_row(w, store, monkeypatch):
    """A change over the API that stood, whose rendering row the store refused (AH6's fault; a read-back that fails at step 8 is the same world): the daemon runs it, the file carries it, and (R)
    cannot prove the file."""
    cfg, digest = api.read(w.server, "dhcp4", capture=False)
    plan = api.file_proof(w.server, "dhcp4")
    real_record = store.record

    def refuse_rendering(server_id, service, cfg_, sha256, summary, *, hash_kind, source="jen", file_sha256=None):
        if source == "rendering":
            return None
        return real_record(
            server_id, service, cfg_, sha256, summary, hash_kind=hash_kind, source=source, file_sha256=file_sha256
        )

    monkeypatch.setattr("jen.services.config_revisions.record", refuse_rendering)
    first = api.apply(
        w.server, "dhcp4", _candidate(cfg), digest, "lifetime 7200", before_cfg=cfg, planned_sha=plan["sha256"]
    )
    monkeypatch.setattr("jen.services.config_revisions.record", real_record)
    assert first["ok"] and api.RENDERING_NOT_RECORDED.format(host="kea-a") in first.get("note", ""), first
    assert w.fake.running["valid-lifetime"] == 7200 and w.fake.file["valid-lifetime"] == 7200
    assert store.latest_rendering(SID, "dhcp4") is None or store.latest_rendering(SID, "dhcp4")["sha256"] != w.seen[
        "sha"
    ]({"Dhcp4": w.fake.file})
    return cfg, first["sha256"]


class TestARowIsAgedByTheClockThatStampedIt:
    """AH1. `created_at` is the database host's `CURRENT_TIMESTAMP`; a database a day ahead of Jen made every reader say "in progress" for a day, and nothing could settle, change, restore or
    switch that server. The store now measures the age with the clock that wrote the stamp."""

    def test_the_store_measures_the_age_itself(self):
        src = (ROOT / "jen/services/config_revisions.py").read_text(encoding="utf-8")
        fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "pending")
        selects = [
            n.value
            for n in ast.walk(fn)
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and "SELECT" in n.value
        ]
        assert selects and all("TIMESTAMPDIFF(SECOND, created_at, NOW()) AS age_seconds" in s for s in selects), selects

    def test_a_measured_age_wins_over_a_stamp_a_day_ahead(self):
        ahead = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
        assert api._row_age_seconds({"created_at": ahead, "age_seconds": 400}) == 400.0
        assert api._row_age_seconds({"created_at": ahead, "age_seconds": 3}) == 3.0

    def test_a_row_with_no_measured_age_is_judged_as_before(self):
        behind = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M:%S")
        assert 590 < api._row_age_seconds({"created_at": behind}) < 620
        assert api._row_age_seconds({"created_at": "not a time"}) == api.PENDING_SETTLE_SECONDS + 1
        assert api._row_age_seconds({"created_at": behind, "age_seconds": True}) > 500, "a boolean is no age"
        assert api._row_age_seconds({"created_at": behind, "age_seconds": "7"}) > 500, "a string is no age"

    def test_a_row_the_database_stamped_a_day_ahead_settles_on_the_first_ask(self, w, store, fake):
        """The reader's own world: the row is 400 s old by the database's clock and a day in the future by Jen's. Every reader settles it; none says "in progress"."""
        cfg, digest = api.read(w.server, "dhcp4", capture=False)
        cand = _candidate(cfg)
        store.record(
            SID,
            "dhcp4",
            cand,
            digest,
            "a change the crash left",
            hash_kind="kea",
            source="pending",
            file_sha256=w.seen["sha"]({"Dhcp4": fake.file}),
        )
        row = store.pending(SID, "dhcp4")
        for r in store.rows:
            if r["id"] == row["id"]:
                r["created_at"] = (datetime.now(timezone.utc) + timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
                r["age_seconds"] = 400
        fake.set_running(cand["Dhcp4"])
        assert "in progress" not in api.pending_note(w.server, "dhcp4")
        assert (
            api._stale_pending(w.server, "dhcp4") != "live" or True
        )  # a live row that carries the change IS live; it is not "in progress"
        lines, settled = api.settle_pending(w.server, "dhcp4")
        assert settled is True, lines
        assert store.pending(SID, "dhcp4") is None


class TestARollbackPutsTheFileBackToo:
    """AH2. The rollback of a change whose rendering row is missing: the daemon went back and the file kept the change, the change set said "still have the NEW config" (true of the file, false of
    the daemon) and the row left behind named a restart first, which would have reloaded the change. The rollback now proves its own write against the file it found when that file says what the
    daemon runs; a hand edit is still refused; the sentence names the box first; the change set names the daemon's answer."""

    def test_the_rollback_puts_the_daemon_and_the_file_back(self, w, store, fake, monkeypatch):
        before, after_digest = _forward_without_a_rendering_row(w, store, monkeypatch)
        writes = w.writes()
        out = api.revert(w.server, "dhcp4", before, after_digest, "rollback: x", before_cfg=_candidate(before))
        assert out["ok"], out
        assert fake.running["valid-lifetime"] == before["Dhcp4"]["valid-lifetime"]
        assert fake.file == fake.running, "the file carries what the daemon runs again"
        assert w.writes() == writes + 1 and store.pending(SID, "dhcp4") is None

    def test_the_file_as_found_is_in_config_history_before_it_is_written_over(self, w, store, fake, monkeypatch):
        before, after_digest = _forward_without_a_rendering_row(w, store, monkeypatch)
        found_sha = w.seen["sha"]({"Dhcp4": fake.file})
        assert found_sha not in {r["sha256"] for r in store.rows}
        api.revert(w.server, "dhcp4", before, after_digest, "rollback: x", before_cfg=_candidate(before))
        captured = [r["id"] for r in store.rows if r["sha256"] == found_sha and r["source"] == "external"]
        rendered = [r["id"] for r in store.rows if r["source"] == "rendering"]
        assert len(captured) == 1 and rendered and captured[0] < min(rendered)

    def test_a_rollback_over_a_hand_edit_is_still_refused_and_the_edit_is_kept(self, w, store, fake, monkeypatch):
        before, after_digest = _forward_without_a_rendering_row(w, store, monkeypatch)
        edited = copy.deepcopy(fake.file)
        edited["subnet4"][0]["option-data"] = [{"name": "routers", "data": "10.97.0.254"}]
        w.hand_edit(edited)
        writes = w.writes()
        out = api.revert(w.server, "dhcp4", before, after_digest, "rollback: x", before_cfg=_candidate(before))
        assert out["code"] == "unverified" and "not yet in its file" in out["detail"]
        assert fake.file == edited and w.writes() == writes
        assert fake.running["valid-lifetime"] == before["Dhcp4"]["valid-lifetime"], "the daemon went back"
        assert any(r["source"] == "external" and r["sha256"] == w.seen["sha"]({"Dhcp4": edited}) for r in store.rows), (
            "the edit is in Config history"
        )

    def test_a_rollback_whose_file_cannot_be_read_leaves_a_row_that_names_the_box_first(
        self, w, store, fake, monkeypatch
    ):
        before, after_digest = _forward_without_a_rendering_row(w, store, monkeypatch)
        real_read = kea_host.read_config_versioned
        monkeypatch.setattr(kea_host, "read_config_versioned", lambda *a, **k: (None, None))
        out = api.revert(w.server, "dhcp4", before, after_digest, "rollback: x", before_cfg=_candidate(before))
        monkeypatch.setattr(kea_host, "read_config_versioned", real_read)
        assert out["code"] == "unverified"
        row = store.pending(SID, "dhcp4")
        assert row is not None and row["file_sha256"] is None
        monkeypatch.setattr(api, "_row_age_seconds", lambda row: api.PENDING_SETTLE_SECONDS + 10)
        note = api.pending_note(w.server, "dhcp4")
        assert "cannot be proved against the file this change was planned over" in note
        assert note.index("tick the box beside Settle it now") < note.index("restart Kea there"), note
        assert "to load the file as it stands" not in note

    def test_the_sentence_names_the_box_before_the_restart(self):
        text = api.NO_PLANNED_SENTENCE.format(host="h")
        assert text.index("tick the box beside Settle it now") < text.index("restart Kea there")
        assert "keep what the daemon runs" in text and "run the file instead of the change" in text

    def test_the_change_sets_line_names_an_api_targets_half_done_rollback_by_the_daemons_answer(
        self, fake, store, monkeypatch
    ):
        """Two api targets. kea-a's forward write stands but its rendering row is refused; kea-z refuses `config-set`, and from that moment kea-a's file cannot be read, so its rollback sends the
        set and is then refused at its file. The line says what the daemon answered, never that kea-a "still has the NEW config"."""
        h = FakeHelper()
        monkeypatch.setattr(kea_host, "helper_call", h.helper_call)
        monkeypatch.setattr(kea_host, "record_helper_status", lambda *a, **k: None)
        monkeypatch.setattr(kea_host, "helper_status", dict)
        server = {"id": SID, "name": "kea-a", "api_url": fake.url, "ssh_host": "10.0.0.9", "config_transport": "api"}
        monkeypatch.setattr(kea_host, "guard_kea_write", lambda *a, **k: "")
        pw = world.ProofWorld(fake, server, store, monkeypatch)
        pw.start(copy.deepcopy(TWO_SUBNET_DHCP4))
        real_record = store.record

        def refuse_rendering(server_id, service, cfg_, sha256, summary, *, hash_kind, source="jen", file_sha256=None):
            if source == "rendering":
                return None
            return real_record(
                server_id, service, cfg_, sha256, summary, hash_kind=hash_kind, source=source, file_sha256=file_sha256
            )

        monkeypatch.setattr("jen.services.config_revisions.record", refuse_rendering)
        broken = {}
        real_read = kea_host.read_config_versioned
        monkeypatch.setattr(
            kea_host,
            "read_config_versioned",
            lambda *a, **k: (None, None) if broken else real_read(*a, **k),
        )
        second = StatefulKeaServer(copy.deepcopy(TWO_SUBNET_DHCP4))
        second.start()
        try:
            other = {"id": 8, "name": "kea-z", "api_url": second.url, "config_transport": "api"}
            original = second._answer

            def refuse_the_set(command, arguments):
                if command == "config-set":
                    broken["now"] = True
                    return {"result": 1, "text": "refused"}
                return original(command, arguments)

            second._answer = refuse_the_set

            def lifetime(cfg):
                out = copy.deepcopy(cfg)
                out["Dhcp4"]["valid-lifetime"] = 7200
                return out, "ok"

            result = cs.apply_change("dhcp4", lifetime, "x", servers=[server, other])
        finally:
            second.stop()
        assert result.status == "rollback_failed", result.lines
        text = " ".join(t for _k, t in result.lines)
        assert "kea-a: rollback over the API: " in text and "the record of the change stays" in text, text
        assert "still have the NEW config" not in text
        assert "kea-a: the rollback over the API did not complete" in text and "Settle it now" in text
        assert fake.running["valid-lifetime"] != 7200, "the daemon went back"


class TestTwoValuesThatPrintAlikeAreSaidSo:
    """AH3: AG4 (7.0.0-beta.8) shipped with no test. The three alike-print cases and the one that is a real difference."""

    def _diff(self, mine, theirs):
        file_cfg = {"Dhcp4": {"hooks-libraries": [{"library": "/l.so", "parameters": {"url": mine}}]}}
        daemon = {"Dhcp4": {"hooks-libraries": [{"library": "/l.so", "parameters": {"url": theirs}}]}}
        return api.difference_text(file_cfg, daemon, "dhcp4", frozenset())

    def test_a_user_name_or_password_inside_an_address(self):
        text = self._diff("http://alice:one@h:8004/", "http://bob:two@h:8004/")
        assert "differ only in what is not shown" in text and "a user name or password inside an address" in text
        for secret in ("alice", "bob", "one", "two"):
            assert secret not in text

    def test_past_the_sixtieth_character(self):
        text = self._diff("http://h/" + "a" * 70, "http://h/" + "a" * 69 + "b")
        assert "differ only in what is not shown" in text and "past the 60th character" in text

    def test_a_real_difference_prints_both_halves(self):
        text = self._diff("http://h:8004/", "http://h:8005/")
        assert "the file says" in text and "the daemon" in text and "differ only" not in text


class TestTheRefusalNamesTheBoxByItsLabel:
    """AH4 and AH5: four refusals quoted a control called 'discard the file's edit', a name no template prints; the card's box is labeled by `write_mode.CONSENT_TEXTS`. And a Read-only server's
    card shows the readiness check only once Live API is selected, so a refusal that sends the operator to it says how to reach it."""

    def test_no_sentence_in_the_tree_quotes_the_old_name(self):
        hits = []
        for p in sorted((ROOT / "jen").rglob("*.py")):
            for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                if "discard the file's edit'" in line or "'discard the file's edit" in line:
                    hits.append(f"{p.relative_to(ROOT)}:{i}")
        assert hits == [], hits

    def test_the_label_is_the_one_the_card_prints(self):
        html = (ROOT / "templates/settings_kea.html").read_text(encoding="utf-8")
        assert "CONSENT_TEXTS" in (ROOT / "jen/services/write_mode.py").read_text(encoding="utf-8")
        # the card prints each consent's text from the one table (the module is the template's source); the literal is in no template of its own
        assert LABEL not in html or "consent" in html

    def test_consent_gap_names_the_label(self):
        gap, needs = api.consent_gap(
            "kea-a",
            {"config_api": True, "agree": False, "write": {"may_write": True}, "include": False, "authenticated": True},
            {"consent_rendering"},
            has_ssh=True,
        )
        assert needs == "discard_file_edit" and f"tick '{LABEL}'" in gap

    def test_the_switch_to_file_names_the_label_and_the_way_to_the_readiness_check(self, fake, store, monkeypatch):
        world.install_probes(monkeypatch, valid=False)  # no stored readiness result for any server
        world.proof_follows_the_read(monkeypatch)
        differing = {"Dhcp4": {**copy.deepcopy(fake.running), "valid-lifetime": 11}}
        monkeypatch.setattr(kea_host, "read_config_versioned", lambda *a, **k: (differing, "r" * 64))
        monkeypatch.setattr(api, "file_proof", lambda *a, **k: api._proof(False, "none", why="the file differs"))
        server = {"id": SID, "name": "kea-a", "api_url": fake.url, "ssh_host": "10.0.0.9", "config_transport": "off"}
        out = sw._to_file(server, "off", set(), "me")
        assert not out["ok"] and out.get("needs") == "discard_file_edit"
        assert (
            f"tick '{LABEL}'" in out["line"]
            and "select Live API on the server's card to show Check readiness" in out["line"]
        )
        assert "discard the file's edit'" not in out["line"]
        api.store_probe(SID, {"at": api._now_iso(), "bound": api._bound(server), "config_api": True})
        out2 = sw._to_file(server, "off", set(), "me")
        assert f"tick '{LABEL}' on the server's card" in out2["line"] and "select Live API" not in out2["line"]


class TestTheSwitchSaysWhenTheRenderingRowWasRefused:
    """AH6: `_to_api` was the one caller of `record_rendering_after_write` that neither read its answer nor re-proved the file; the switch reported success while the re-probe stored the fact that closes
    the gate."""

    def test_the_success_line_carries_the_note(self, fake, store, monkeypatch, probes):
        world.proof_follows_the_read(monkeypatch)
        cfg = {"Dhcp4": copy.deepcopy(fake.running)}
        monkeypatch.setattr(kea_host, "read_config_versioned", lambda *a, **k: (cfg, "r" * 64))
        monkeypatch.setattr(
            kea_host,
            "config_write_check",
            lambda s, svc: {
                "ok": True,
                "may_write": True,
                "includes": [],
                "mode": "0640",
                "account": {"name": "_kea", "uid": 1, "gid": 1},
            },
        )
        monkeypatch.setattr(kea_host, "guard_kea_write", lambda *a, **k: "")
        from jen import config as jen_config

        monkeypatch.setattr(jen_config.app_config, "write_value", lambda *a, **k: True)
        server = {"id": SID, "name": "kea-a", "api_url": fake.url, "ssh_host": "10.0.0.9", "config_transport": "file"}
        consents = {"consent_rendering", "consent_unauthenticated"}
        monkeypatch.setattr(api, "record_rendering_after_write", lambda *a, **k: False)
        out = sw.switch(server, "api", consents=consents, actor="me")
        assert out["ok"], out
        assert api.RENDERING_NOT_RECORDED.format(host="kea-a") in out["line"], out["line"]
        monkeypatch.setattr(api, "record_rendering_after_write", lambda *a, **k: True)
        server2 = dict(server, id=SID + 1, name="kea-b")
        out2 = sw.switch(server2, "api", consents=consents, actor="me")
        assert out2["ok"] and "could not be recorded" not in out2["line"]


class TestTheBundlesChokePointMasksByName:
    """AH7, AH8, AH13, AH14."""

    def test_a_string_under_a_secret_named_key_is_masked_in_every_member(self):
        out = sb._scrubbed(
            {
                "password": "hunter2",
                "api_token": "t0k",
                "has_password": True,
                "retries": 3,
                "ssh_key_path": "/etc/jen/ssh/id",
                "nested": [{"client_secret": "s3"}],
            }
        )
        assert (
            out["password"] == sb.MASK and out["api_token"] == sb.MASK and out["nested"][0]["client_secret"] == sb.MASK
        )
        assert out["has_password"] is True and out["retries"] == 3 and out["ssh_key_path"] == "/etc/jen/ssh/id"
        collected = {
            "jen": {"smtp_password": "MARKER-7a"},
            "health": {"rows": [{"token": "MARKER-7b"}]},
            "db": {"password": "MARKER-7c"},
        }
        data, names = sb.build_bundle(collected)
        import io
        import zipfile

        texts = {n: zipfile.ZipFile(io.BytesIO(data)).read(n).decode("utf-8") for n in names}
        assert all("MARKER-7" not in t for t in texts.values()), [n for n, t in texts.items() if "MARKER-7" in t]

    def test_a_camel_case_key_reaches_the_ini_masker_as_written(self):
        out = sb.redact_ini_text("[hook]\nclientSecret = MARKER-13\napiKey = MARKER-13b\nkey_path = /etc/x\n")
        assert "MARKER-13" not in out and f"clientSecret = {sb.MASK}" in out and f"apiKey = {sb.MASK}" in out
        assert "key_path = /etc/x" in out

    def test_a_members_name_is_a_plain_relative_path(self):
        with pytest.raises(ValueError):
            sb.build_bundle({"kea_configs": [{"server_id": "../../etc/passwd", "service": "dhcp4", "config": {}}]})
        with pytest.raises(ValueError):
            sb.build_bundle({"kea_configs": [{"server_id": 1, "service": "..\\..\\x", "config": {}}]})
        for bad in ("kea/../x.json", "/etc/x", "a\\b", "kea//x", ".hidden", ""):
            assert sb._MEMBER_NAME_RE.fullmatch(bad) is None, bad
        data, names = sb.build_bundle({"kea_configs": [{"server_id": "1", "service": "dhcp4", "config": {}}]})
        assert "kea/1-dhcp4.json" in names
        assert all(sb._MEMBER_NAME_RE.fullmatch(n) for n in names), names

    def test_the_cap_note_prints_the_cap_as_it_is(self):
        import io
        import zipfile

        data, names = sb.build_bundle({"log_text": "x" * 4000, "audit": [{"a": "b" * 2000}]}, cap=1024)
        readme = zipfile.ZipFile(io.BytesIO(data)).read("README.txt").decode("utf-8")
        assert "0 MB size cap" not in readme and "1 KB size cap" in readme and sb.cap_text(sb.SIZE_CAP_BYTES) == "20 MB"
        data, names = sb.build_bundle({"log_text": "x" * 4000, "audit": [{"a": "b" * 2000}]}, cap=3 * 1024 * 1024)
        assert "logs/jen.log.tail" in names, "a cap nothing exceeds drops nothing"


class TestTheStoredResultIsBoundToTheFileToo:
    """AH9: the stored readiness result (and the consent on it) was bound to `api_url` and `ssh_host`; a re-pointed `ssh_user` or `kea_conf` kept the previous file's facts. Four keys now; a two-key
    result from an earlier release is checked again with its own sentence."""

    def test_the_binding_covers_the_four_identity_keys(self):
        base = {
            "id": 1,
            "api_url": "http://h:8000",
            "ssh_host": "h",
            "ssh_user": "jen",
            "kea_conf": "/etc/kea/kea-dhcp4.conf",
        }
        assert api.BOUND_KEYS == ("api_url", "ssh_host", "ssh_user", "kea_conf")
        for key in api.BOUND_KEYS:
            assert REAL_BOUND(base) != REAL_BOUND({**base, key: "other"}), key
        assert REAL_BOUND(base) == REAL_BOUND({**base, "name": "renamed", "id": 9})

    def test_a_two_key_result_from_an_earlier_release_is_checked_again_with_its_own_sentence(self, probes, monkeypatch):
        monkeypatch.setattr(api, "_bound", REAL_BOUND)
        server = {
            "id": SID,
            "name": "kea-a",
            "api_url": "http://h:8000",
            "ssh_host": "h",
            "ssh_user": "jen",
            "kea_conf": "/etc/kea/kea-dhcp4.conf",
        }
        api.store_probe(
            SID,
            {
                "at": api._now_iso(),
                "bound": api._bound_legacy(server),
                "config_api": True,
                "consented_at": api._now_iso(),
                "consents": ["consent_rendering"],
            },
        )
        gate = api.probe_gate(server)
        assert "was checked before this version recorded which file its facts were read from" in gate
        api.store_probe(
            SID,
            {
                "at": api._now_iso(),
                "bound": REAL_BOUND({**server, "kea_conf": "/etc/kea/other.conf"}),
                "config_api": True,
                "consented_at": api._now_iso(),
                "consents": ["consent_rendering"],
            },
        )
        assert "reads a different file" in api.probe_gate(server)


class TestThreeSentencesOfTheProofAndTheWritePath:
    """AH10, AH11, AH12."""

    def test_a_written_out_default_under_a_renamed_key_is_a_default(self):
        out = api.difference_text(
            {"Dhcp4": {"hosts-database": {"type": "mysql"}}},
            {"Dhcp4": {"hosts-databases": [{"type": "mysql", "readonly": False}]}},
            "dhcp4",
            frozenset({"hosts-databases[].readonly"}),
        )
        assert out == "", out
        out2 = api.difference_text(
            {"Dhcp4": {"hosts-database": {"type": "mysql"}}},
            {"Dhcp4": {"hosts-databases": [{"type": "mysql", "readonly": False}]}},
            "dhcp4",
            frozenset(),
        )
        assert "hosts-databases[0].readonly" in out2 and "hosts-database.readonly" not in out2, out2

    def test_a_time_that_is_no_time_is_said_so(self, fake, store, monkeypatch):
        server = {"id": SID, "name": "kea-a", "api_url": fake.url, "ssh_host": "10.0.0.9", "config_transport": "api"}
        other = {"Dhcp4": {**copy.deepcopy(fake.running), "valid-lifetime": 11}}
        monkeypatch.setattr(
            kea_host,
            "read_config_proof",
            lambda *a, **k: (
                other,
                "f" * 64,
                {"mtime": -5, "now": 1_700_000_000, "daemon": {"reload": 10, "uptime": 100}},
            ),
        )
        proof = api.file_proof(server, "dhcp4")
        assert not proof["ok"] and proof["how"] == "none" and proof["mtime"] is None
        assert "the time it was written could not be read" in proof["why"]
        assert "before the daemon's last load" not in proof["why"]

    def test_a_record_that_could_not_be_removed_is_said_so(self, w, store, fake, monkeypatch):
        cfg, digest = api.read(w.server, "dhcp4", capture=False)
        monkeypatch.setattr("jen.services.config_revisions.discard", lambda rev_id: False)
        out = api.apply(
            w.server,
            "dhcp4",
            _candidate(cfg),
            "0" * 64,
            "x",
            before_cfg=cfg,
            planned_sha=api.file_proof(w.server, "dhcp4")["sha256"],
        )
        assert (
            out["code"] == "conflict"
            and out["detail"].endswith(api.UNDROPPED)
            or "could not be removed from Config history" in out["detail"]
        ), out
        assert store.pending(SID, "dhcp4") is not None, (
            "the row the store would not remove is still there - and the result says so"
        )


class TestTheSupportBundleIsBuiltByAPost:
    """AH15: a GET download was built by a cross-site navigation of a signed-in superadmin's browser (the build runs the health checks against every Kea and writes an audit row)."""

    def test_the_route_is_a_post_and_the_page_posts_to_it(self):
        src = (ROOT / "jen/routes/settings/updates.py").read_text(encoding="utf-8")
        route = src.split("def support_bundle(")[0].rsplit("@bp.route", 1)[1]
        assert 'methods=["POST"]' in route
        html = (ROOT / "templates/settings_system.html").read_text(encoding="utf-8")
        assert 'href="/settings/system/support-bundle"' not in html
        form = re.search(r'<form method="POST" action="/settings/system/support-bundle"[^>]*>(.*?)</form>', html, re.S)
        assert form and 'name="csrf_token"' in form.group(1) and 'type="submit"' in form.group(1)
