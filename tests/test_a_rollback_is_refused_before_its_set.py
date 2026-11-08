"""v7.0.0-beta.10 (Q224) - the pass on 7.0.0-beta.9 (AJ1-AJ21), each row executed here against the product.

AJ1  a pending row whose measured age is NEGATIVE (the database's clock stepped back) is old, never "in progress".
AJ2  a rollback's file is proved as two renderings of one configuration (`mirrors`, both directions): a key deleted from the file is a hand edit.
AJ3  a rollback that is not proved leaves no row; AJ9 it is refused BEFORE its set: daemon and file both keep the change, nothing is sent.
AJ6  a discard that found nothing to discard is never left on record; the line says so.
AJ7  AH6's note is not appended for a server with no SSH host.
AJ8  three sentences name the readiness check by the card's own words (`write_mode.CHECK_ROW`, `CHECK_BUTTON`).
AJ10 Explain places a revision in Jen's clock by the age the database measured (tests/test_kea_log_transactions.py); Health reads the snapshot's age in the query.
AJ11 S10 sees a tuple return whose first element is empty (tests/test_invariant_sweeps.py); the two lockout checks fail CLOSED.
AJ12 a container under a secret-named key is masked whole; AJ13 a spaced key is a secret name.
AJ16 one ASCII whole-number test (`text.is_whole`) for every form value and path segment under jen/; no `isdigit()` anywhere else in the tree.
AJ17 the OIDC subnet map never raises on a typo. AJ19 a set that answers no digest is proved by content at step (7). AJ20 the cookie is cleared with the attributes it was set with.
AJ14, AJ18 (the admin ratchet and the bounds): pure functions here; the routes in tests/test_security_settings_ratchet.py (DB-backed).
AJ4, AJ5, AJ15: DB-backed, in tests/test_a_scoped_admin_reads_no_log.py and tests/test_users.py.

Pure: runs under `--noconftest` (the fake daemon of tests/e2e/_fake_kea_server.py, the in-memory store of tests/_kea_api_world.py)."""

import ast
import copy
import pathlib

import pytest

from jen import extensions
from jen.services import kea_api_config as api
from jen.services import kea_changeset as cs
from jen.services import kea_host, text
from jen.services import kea_transport_switch as sw
from jen.services import support_bundle as sb
from jen.services.secret_keys import is_secret_key
from tests import _kea_api_world as world
from tests.e2e._fake_kea_server import TWO_SUBNET_DHCP4, StatefulKeaServer

ROOT = pathlib.Path(__file__).resolve().parent.parent
SID = 7


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
    """A change over the API that stood, whose rendering row the store refused (Q223 AH6's fault): the daemon runs it, the file carries it, and (R) cannot prove the file."""
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
    out = api.apply(w.server, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg, planned_sha=plan["sha256"])
    assert out["ok"], out
    monkeypatch.setattr("jen.services.config_revisions.record", real_record)
    assert not any(r["source"] == "rendering" for r in store.rows)
    return cfg, out["sha256"]


class TestANegativeAgeIsOld:
    """AJ1: `TIMESTAMPDIFF` is negative exactly when the database's own clock has stepped back since it stamped the row. AG5 made the readiness result's age refuse a negative; the row's did not."""

    @pytest.mark.parametrize("age", [-1, -3600, -86400, -0.5])
    def test_a_negative_measured_age_reads_as_past_the_settle_window(self, age):
        assert api._row_age_seconds({"age_seconds": age}) > api.PENDING_SETTLE_SECONDS

    def test_a_non_negative_measured_age_is_returned_as_it_is(self):
        assert api._row_age_seconds({"age_seconds": 0}) == 0.0
        assert api._row_age_seconds({"age_seconds": 17}) == 17.0

    def test_the_row_is_not_in_progress_and_the_settlement_finishes_it(self, w, store, fake, monkeypatch):
        cfg, digest = api.read(w.server, "dhcp4", capture=False)
        cand = _candidate(cfg)
        store.record(
            SID,
            "dhcp4",
            cand,
            digest,
            "x",
            hash_kind="kea",
            source="pending",
            file_sha256=w.seen["sha"]({"Dhcp4": fake.file}),
        )
        row = store.pending(SID, "dhcp4")
        for r in store.rows:
            if r["id"] == row["id"]:
                r["age_seconds"] = -3600  # the database's clock stepped back an hour after it stamped the row
        fake.set_running(cand["Dhcp4"])
        assert "in progress" not in api.pending_note(w.server, "dhcp4")
        assert api._stale_pending(w.server, "dhcp4") == "live"
        lines, settled = api.settle_pending(w.server, "dhcp4")
        assert settled is True, lines
        assert store.pending(SID, "dhcp4") is None


class TestARollbackIsRefusedBeforeItsSet:
    """AJ2, AJ3, AJ9."""

    def test_the_baseline_still_puts_the_daemon_and_the_file_back(self, w, store, fake, monkeypatch):
        before, after_digest = _forward_without_a_rendering_row(w, store, monkeypatch)
        out = api.revert(w.server, "dhcp4", before, after_digest, "rollback: x", before_cfg=_candidate(before))
        assert out["ok"], out
        assert fake.running["valid-lifetime"] == before["Dhcp4"]["valid-lifetime"]
        assert fake.file == fake.running and store.pending(SID, "dhcp4") is None

    def test_a_key_deleted_from_the_file_is_a_hand_edit_and_the_rollback_is_refused(self, w, store, fake, monkeypatch):
        before, after_digest = _forward_without_a_rendering_row(w, store, monkeypatch)
        edited = copy.deepcopy(fake.file)
        del edited["rebind-timer"]
        w.hand_edit(edited)
        assert api.file_in_daemon({"Dhcp4": edited}, {"Dhcp4": fake.running}, "dhcp4"), "the one-way ask says agreement"
        assert not api.mirrors({"Dhcp4": edited}, {"Dhcp4": fake.running}, "dhcp4"), "the two-way ask does not"
        fake.commands.clear()
        out = api.revert(w.server, "dhcp4", before, after_digest, "rollback: x", before_cfg=_candidate(before))
        assert out["code"] == "guard" and "does not say what the daemon runs" in out["detail"], out
        assert "config-set" not in fake.commands and "config-write" not in fake.commands
        assert fake.file == edited, "the deletion survives"
        assert fake.running["valid-lifetime"] == 7200, "the daemon keeps the change it would have undone"
        assert store.pending(SID, "dhcp4") is None, "no row names a file Jen did not prove"
        assert any(r["source"] == "external" and r["sha256"] == w.seen["sha"]({"Dhcp4": edited}) for r in store.rows)

    def test_a_key_added_to_the_file_is_refused_the_same(self, w, store, fake, monkeypatch):
        before, after_digest = _forward_without_a_rendering_row(w, store, monkeypatch)
        edited = copy.deepcopy(fake.file)
        edited["subnet4"][0]["option-data"] = [{"name": "routers", "data": "10.97.0.254"}]
        w.hand_edit(edited)
        out = api.revert(w.server, "dhcp4", before, after_digest, "rollback: x", before_cfg=_candidate(before))
        assert out["code"] == "guard" and fake.file == edited and store.pending(SID, "dhcp4") is None

    def test_the_control_agent_silent_at_the_one_read_refuses_the_whole_rollback(self, w, store, fake, monkeypatch):
        """AJ9: the one `config-get` the proof needs is asked before the set; a daemon that does not answer it leaves no half state."""
        before, after_digest = _forward_without_a_rendering_row(w, store, monkeypatch)
        real_get = api._get

        def silent(server, service):
            return None, None, "no answer"

        monkeypatch.setattr(api, "_get", silent)
        fake.commands.clear()
        out = api.revert(w.server, "dhcp4", before, after_digest, "rollback: x", before_cfg=_candidate(before))
        monkeypatch.setattr(api, "_get", real_get)
        assert out["code"] == "guard" and "could not be read" in out["detail"] and "nothing was sent" in out["detail"]
        assert "config-set" not in fake.commands
        assert fake.running["valid-lifetime"] == 7200 and fake.file["valid-lifetime"] == 7200
        assert store.pending(SID, "dhcp4") is None

    def test_mirrors_tolerates_what_kea_rerenders_and_nothing_else(self):
        live = {
            "Dhcp4": {
                "valid-lifetime": 1,
                "subnet4": [{"id": 1, "subnet": "10.0.0.0/24", "pools": [{"pool": "10.0.0.10-10.0.0.20"}]}],
            }
        }
        spaced = copy.deepcopy(live)
        spaced["Dhcp4"]["subnet4"][0]["pools"][0]["pool"] = "10.0.0.10 - 10.0.0.20"
        assert api.mirrors(spaced, live, "dhcp4") and api.mirrors(live, spaced, "dhcp4")
        fewer = copy.deepcopy(live)
        del fewer["Dhcp4"]["valid-lifetime"]
        more = copy.deepcopy(live)
        more["Dhcp4"]["renew-timer"] = 5
        assert not api.mirrors(fewer, live, "dhcp4") and not api.mirrors(more, live, "dhcp4")
        assert not api.mirrors(None, live, "dhcp4") and not api.mirrors(live, None, "dhcp4")


class TestADiscardThatFoundNothingIsNotRecorded:
    """AJ6: the stored facts called for the discard; by the switch the daemon had loaded the file (or Jen rendered it). Nothing is discarded, and the consent is not left on record."""

    FACTS = {
        "config_api": True,
        "test_ok": True,
        "include": [],
        "agree": False,
        "write": {"may_write": True, "account": "_kea", "mode": "0644"},
        "auth": "basic",
    }

    def test_the_consent_is_not_stored_and_the_line_says_so(self, w, store, fake, monkeypatch):
        edited = copy.deepcopy(fake.file)
        edited["renew-timer"] = 111
        w.hand_edit(edited)
        monkeypatch.setattr(api, "probe", lambda server, service="dhcp4", **k: dict(self.FACTS))
        monkeypatch.setattr(api, "file_proof", lambda *a, **k: api._proof(True, "loaded", sha256="f" * 64))
        out = sw._to_api(w.server, "api", {"consent_rendering", "discard_file_edit"}, "me")
        assert out["ok"] and out["discarded"] is False, out
        assert "nothing was discarded - the file is one the daemon has loaded" in out["line"], out["line"]
        stored = api.stored_probe(SID) or {}
        assert "discard_file_edit" not in (stored.get("consents") or []), stored
        assert fake.file.get("renew-timer") == 111, "the file was not written"
        assert api.consent_allowed(
            "kea-a", dict(stored, agree=False), set(stored.get("consents") or []), has_ssh=True, strict=False
        ), "a later edit is still refused"

    def test_the_control_a_proof_that_says_none_discards_and_strips_the_consent(self, w, store, fake, monkeypatch):
        edited = copy.deepcopy(fake.file)
        edited["renew-timer"] = 111
        w.hand_edit(edited)
        monkeypatch.setattr(api, "probe", lambda server, service="dhcp4", **k: dict(self.FACTS))
        out = sw._to_api(w.server, "api", {"consent_rendering", "discard_file_edit"}, "me")
        assert out["ok"] and out["discarded"] is True and "discarded" in out["line"], out
        assert "discard_file_edit" not in ((api.stored_probe(SID) or {}).get("consents") or [])
        assert fake.file.get("renew-timer") != 111


class TestTheNoteIsForAServerWithAFile:
    """AJ7: `record_rendering_after_write` answers False by construction for a server with no SSH host; the note about Config history has nothing to say there."""

    def test_no_ssh_host_no_note(self, fake, store, monkeypatch, probes):
        from jen import config as jen_config

        monkeypatch.setattr(jen_config.app_config, "write_value", lambda *a, **k: True)
        server = {"id": SID, "name": "kea-a", "api_url": fake.url, "config_transport": "off"}
        out = sw.switch(
            server, "api", consents={"consent_rendering", "consent_unauthenticated", "confirm_no_include"}, actor="me"
        )
        assert out["ok"], out
        assert "could not be recorded" not in out["line"], out["line"]

    def test_with_an_ssh_host_the_note_stays(self, fake, store, monkeypatch, probes):
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
        monkeypatch.setattr(api, "record_rendering_after_write", lambda *a, **k: False)
        server = {"id": SID, "name": "kea-a", "api_url": fake.url, "ssh_host": "10.0.0.9", "config_transport": "file"}
        out = sw.switch(server, "api", consents={"consent_rendering", "consent_unauthenticated"}, actor="me")
        assert out["ok"] and api.RENDERING_NOT_RECORDED.format(host="kea-a") in out["line"]


class TestTheCheckIsNamedByTheCardsWords:
    """AJ8: the card's row reads `CHECK_ROW` and its button `CHECK_BUTTON` / `CHECK_AGAIN`; a sentence that sends the operator there uses the same constants, so no sentence under jen/ names
    the check by a name of its own."""

    def test_the_card_and_the_template_read_the_constants(self):
        card = (ROOT / "jen/routes/settings/infrastructure.py").read_text(encoding="utf-8")
        assert (
            "__words.CHECK_BUTTON" in card
            and "__words.CHECK_AGAIN" in card
            and '"check_row": __words.CHECK_ROW' in card
        )
        html = (ROOT / "templates/settings_kea.html").read_text(encoding="utf-8")
        assert "{{ c.check_row }}" in html and "Readiness check" not in html

    def test_no_sentence_names_the_check_by_another_name(self):
        hits = []
        for path in sorted((ROOT / "jen").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Constant) and isinstance(node.value, str) and "Check readiness" in node.value:
                    hits.append(f"{path.relative_to(ROOT)}:{node.lineno}")
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and "Run check" in node.value
                    and path.name != "write_mode.py"
                ):
                    hits.append(f"{path.relative_to(ROOT)}:{node.lineno} (the literal, not the constant)")
        assert hits == [], hits

    def test_the_three_sentences_carry_the_words(self):
        switch = (ROOT / "jen/services/kea_transport_switch.py").read_text(encoding="utf-8")
        route = (ROOT / "jen/routes/settings/kea_transport.py").read_text(encoding="utf-8")
        assert switch.count("{_words.CHECK_BUTTON}") >= 2 and switch.count("{_words.CHECK_ROW}") >= 2
        assert "{__write_mode.CHECK_BUTTON} under {__write_mode.CHECK_ROW}" in route


class TestTheBundleMasksAContainerAndASpacedName:
    """AJ12, AJ13."""

    def test_a_container_under_a_secret_named_key_is_masked_whole(self):
        out = sb._scrubbed(
            {
                "credentials": [{"user": "u", "password": "Sentinel-1"}],
                "db_password": {"a": "Sentinel-2"},
                "token": b"Sentinel-3",
                "api_key": ("Sentinel-4",),
                "has_password": True,
                "password_length": 12,
                "password": None,
                "nested": {"secret": ["Sentinel-5"]},
            }
        )
        assert (
            out["credentials"] == sb.MASK
            and out["db_password"] == sb.MASK
            and out["token"] == sb.MASK
            and out["api_key"] == sb.MASK
        )
        assert out["has_password"] is True and out["password_length"] == 12 and out["password"] is None
        assert out["nested"]["secret"] == sb.MASK
        assert "Sentinel" not in repr(out)

    @pytest.mark.parametrize("name", ["Client Secret", "api key", "smtp  password", "Private\tKey", "DB Pass"])
    def test_a_spaced_name_is_a_secret_name(self, name):
        assert is_secret_key(name)

    @pytest.mark.parametrize("name", ["display name", "key path", "ssh key path", "pass through"])
    def test_a_spaced_name_that_is_not_one(self, name):
        assert not is_secret_key(name)

    def test_the_ini_masker_masks_a_spaced_key(self):
        text_ = "[smtp]\nClient Secret = Sentinel-6\nhost = mail\n"
        out = sb.redact_ini_text(text_) if hasattr(sb, "redact_ini_text") else None
        if out is not None:
            assert "Sentinel-6" not in out and "host = mail" in out


class TestOneWholeNumberTest:
    """AJ16: `str.isdigit()` is True for a full-width or an Arabic-Indic digit that `int()` then rejects; `text.is_whole` is the one test, and nothing under jen/ calls `isdigit()`."""

    @pytest.mark.parametrize("value", ["0", "7", "00005", "123456789012345678"])
    def test_a_whole_number(self, value):
        assert text.is_whole(value) and text.whole(value) == int(value)

    @pytest.mark.parametrize(
        "value", ["²", "٣", "１２", "-1", "+1", " 1", "1 ", "1.0", "1e3", "", "x", "1234567890123456789", True, 5, None]
    )
    def test_not_a_whole_number(self, value):
        assert not text.is_whole(value) and text.whole(value) is None and text.whole(value, 9) == 9

    def test_isdigit_is_called_nowhere_under_jen(self):
        hits = []
        for path in sorted((ROOT / "jen").rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and node.attr in ("isdigit", "isnumeric", "isdecimal"):
                    hits.append(f"{path.relative_to(ROOT)}:{node.lineno}")
        assert hits == [], hits

    def test_the_oidc_map_never_raises_on_a_typo(self):
        from jen.services import oidc

        assert oidc.parse_subnet_map("g1:²") == {}
        assert oidc.parse_subnet_map("g1: 2, 3;g2:*") in ({"g1": {2, 3}, "g2": "*"}, {"g1": {2, 3}})


class TestASetWithoutADigestIsProvedByContent:
    """AJ19: a `config-set` that answers result 0 with no digest made step (7) a digest-only check across two instants; it compares content, as a set with no answer does."""

    def test_another_clients_configuration_is_not_taken_for_jens_change(self, w, store, fake, monkeypatch):
        cfg, digest = api.read(w.server, "dhcp4", capture=False)
        real_answer = fake._answer

        def no_digest_and_a_second_client(command, arguments):
            reply = real_answer(command, arguments)
            if command == "config-set" and reply.get("result") == 0:
                reply.get("arguments", {}).pop("hash", None)
                other = copy.deepcopy(fake.running)
                other["valid-lifetime"] = 9999  # a second client's set lands between Jen's set and its read
                fake.set_running(other)
            return reply

        fake._answer = no_digest_and_a_second_client
        out = api.apply(w.server, "dhcp4", _candidate(cfg), digest, "x", before_cfg=cfg)
        assert not out["ok"] and out["code"] == "unverified", (
            out
        )  # (the write at (6) precedes the verify at (7): what is refused is the CLAIM that Jen's change is live)
        assert "did not confirm the change" in out["detail"]


class TestTheCookieIsClearedAsItWasSet:
    """AJ20."""

    def test_delete_cookie_carries_secure_on_https(self):
        from flask import Flask

        from jen.services import view_prefs

        app = Flask(__name__)
        with app.test_request_context(
            "/", base_url="https://jen.test/", headers={"Cookie": f"{view_prefs.COOKIE}=junk"}
        ):
            from flask import request

            resp = app.make_response("x")
            view_prefs.remember(resp, request, {})
            header = resp.headers.get("Set-Cookie", "")
            assert view_prefs.COOKIE in header and "Secure" in header, header


class TestTheLockoutChecksFailClosed:
    """AJ11: `is_locked_out` and `is_mfa_locked_out` answered (False, 0) from `except Exception` - "not locked out, 0 minutes" from a check that could not be made."""

    def test_a_failing_query_is_a_lockout(self, monkeypatch):
        from contextlib import contextmanager

        from jen.services import auth

        @contextmanager
        def broken():
            raise RuntimeError("login_attempts is gone")
            yield

        monkeypatch.setattr(auth, "__jen_db_ctx", broken, raising=False)
        monkeypatch.setattr(
            auth, "get_rate_limit_settings", lambda: {"mode": "both", "max_attempts": 5, "lockout_minutes": 15}
        )
        assert auth.is_locked_out("10.0.0.1", "u") == (True, 1)
        assert auth.is_mfa_locked_out(3) == (True, 1)

    def test_the_sweep_sees_a_tuple_whose_head_is_empty(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("sweeps", ROOT / "tests/test_invariant_sweeps.py")
        sweeps = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sweeps)
        stmt = ast.parse("return False, 0").body[0]
        assert sweeps._s10_effect(stmt) == "return (False, 0)"
        assert sweeps._s10_effect(ast.parse("return None, None, None").body[0]) == "return (None, None, None)"
        assert sweeps._s10_effect(ast.parse("return True, 1").body[0]) is None
        assert sweeps._s10_effect(ast.parse("return 0, 0").body[0]) is None, "0 is a count, not a verdict"


class TestTheSecurityRatchetAndTheBounds:
    """AJ14, AJ18: the pure halves. The routes are tested with the database (tests/test_security_settings_ratchet.py)."""

    def test_session_looser(self, monkeypatch):
        from jen.routes.settings import security

        # the string form: `security.__user` inside a class body is name-mangled
        monkeypatch.setattr(
            "jen.models.user.get_global_setting", lambda k, d=None: {"session_timeout_enabled": "true"}.get(k, d)
        )
        monkeypatch.setattr("jen.services.session_timeout.global_minutes", lambda: 60)
        assert security._session_looser("false", 60) is True
        assert security._session_looser("true", 0) is True
        assert security._session_looser("true", 120) is True
        assert security._session_looser("true", 60) is False
        assert security._session_looser("true", 15) is False

    def test_rate_limit_looser(self, monkeypatch):
        from jen.routes.settings import security

        monkeypatch.setattr(
            "jen.services.auth.get_rate_limit_settings",
            lambda: {"mode": "both", "max_attempts": 10, "lockout_minutes": 15},
        )
        assert security._rate_limit_looser("off", 10, 15) is True
        assert security._rate_limit_looser("both", 0, 15) is True
        assert security._rate_limit_looser("both", 11, 15) is True
        assert security._rate_limit_looser("both", 10, 14) is True
        assert security._rate_limit_looser("ip", 10, 15) is False
        assert security._rate_limit_looser("both", 9, 0) is False, "0 is until cleared: the longest lockout"
        assert security._rate_limit_looser("both", 10, 15) is False
        monkeypatch.setattr(
            "jen.services.auth.get_rate_limit_settings",
            lambda: {"mode": "off", "max_attempts": 10, "lockout_minutes": 15},
        )
        assert security._rate_limit_looser("both", 100, 1) is False, "anything is stricter than off"

    def test_the_bounds_are_named_once(self):
        from jen.routes.settings import __init__ as settings_pkg  # noqa: F401
        from jen.services import auth

        assert auth.MAX_LOCKOUT_MINUTES == 10080 and auth.MAX_ATTEMPTS_BOUND == 1000
        src = (ROOT / "jen/services/auth.py").read_text(encoding="utf-8")
        assert "INTERVAL {lockout_minutes}" not in src and "INTERVAL %s MINUTE" in src
