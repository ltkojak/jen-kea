"""
tests/test_the_mode_is_part_of_the_strictness.py
────────────────────────────────────────────────
7.0.0-beta.11 (Q225): the pure half of the pass on 7.0.0-beta.10 (Opus, AK1-AK24). Each class names its row. The database-backed half - the
alert channel's scope, the Users page's stored list - is `tests/test_a_restricted_admins_channel_covers_its_subnets.py`.

Pure: no database (`--noconftest` runs it on the Windows box), the real `StatefulKeaServer` for the write-path rows.
"""

import ast
import copy
import pathlib
import re
from contextlib import contextmanager

import pytest

from jen import extensions
from jen.services import kea_api_config as api
from jen.services import kea_changeset as cs
from jen.services import kea_transport_switch as sw
from jen.services import support_bundle as sb
from jen.services.secret_keys import is_secret_key
from tests import _kea_api_world as world
from tests.e2e._fake_kea_server import TWO_SUBNET_DHCP4, StatefulKeaServer

ROOT = pathlib.Path(__file__).resolve().parents[1]
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


def _settings(monkeypatch, **rows):
    """The `settings` table as `get_global_setting` reads it, for every module that imports the function by its private alias."""
    monkeypatch.setattr("jen.models.user.get_global_setting", lambda k, d=None: rows.get(k, d))


class TestTheModeIsPartOfTheStrictness:
    """AK2: `both` counts two buckets and locks on the larger, so it is at least as strict as `ip` or `username` alone. An admin may move TO it and may not leave it or trade one bucket for
    the other. AK24: the three measures are judged together - an admin cannot trade attempts for lockout length in either direction; that is the conservative side and a superadmin's move."""

    @pytest.fixture(autouse=True)
    def _now_both(self, monkeypatch):
        monkeypatch.setattr(
            "jen.services.auth.get_rate_limit_settings",
            lambda: {"mode": "both", "max_attempts": 10, "lockout_minutes": 15},
        )

    @pytest.mark.parametrize("mode", ["ip", "username"])
    def test_leaving_both_is_looser_whatever_the_numbers_do(self, mode):
        from jen.routes.settings import security

        assert security._rate_limit_looser(mode, 10, 15) is True
        assert security._rate_limit_looser(mode, 5, 30) is True, (
            "fewer attempts and a longer lockout do not buy back the dropped bucket"
        )

    def test_staying_at_both_and_tightening_is_not_looser(self):
        from jen.routes.settings import security

        assert security._rate_limit_looser("both", 10, 15) is False
        assert security._rate_limit_looser("both", 5, 30) is False

    @pytest.mark.parametrize("now", ["ip", "username"])
    def test_moving_to_both_from_a_single_bucket_is_not_looser(self, monkeypatch, now):
        from jen.routes.settings import security

        monkeypatch.setattr(
            "jen.services.auth.get_rate_limit_settings",
            lambda: {"mode": now, "max_attempts": 10, "lockout_minutes": 15},
        )
        assert security._rate_limit_looser("both", 10, 15) is False
        other = "username" if now == "ip" else "ip"
        assert security._rate_limit_looser(other, 10, 15) is True, "one bucket for the other is not a tightening"
        assert security._rate_limit_looser(now, 10, 15) is False

    def test_ak24_a_trade_is_refused_in_both_directions(self):
        from jen.routes.settings import security

        assert security._rate_limit_looser("both", 5, 10) is True, (
            "fewer attempts, shorter lockout: the lockout is looser"
        )
        assert security._rate_limit_looser("both", 20, 60) is True, (
            "more attempts, longer lockout: the attempts are looser"
        )

    def test_the_four_words_are_named_once(self):
        from jen.services import auth

        assert auth.RATE_LIMIT_MODES == ("ip", "username", "both", "off")
        src = (ROOT / "jen/routes/settings/security.py").read_text(encoding="utf-8")
        assert '("ip", "username", "both", "off")' not in src and "RATE_LIMIT_MODES" in src


class TestARateLimitThatCannotBeReadIsTheStrictest:
    """AK3, AK19, AK13's rate-limit half: the reader puts a row the form never wrote where the policy is strictest - a mode outside the four words is `both` (it used to count nothing: no
    rate limiting, silently), a number that is not whole is its default (it used to raise out of `/login`), a number past the bound is the bound."""

    def test_an_unknown_mode_reads_as_both(self, monkeypatch):
        from jen.services import auth

        _settings(monkeypatch, rl_mode="everyone", rl_max_attempts="10", rl_lockout_minutes="15")
        assert auth.get_rate_limit_settings() == {"max_attempts": 10, "lockout_minutes": 15, "mode": "both"}

    @pytest.mark.parametrize("mode", ["ip", "username", "both", "off"])
    def test_the_four_words_read_as_themselves(self, monkeypatch, mode):
        from jen.services import auth

        _settings(monkeypatch, rl_mode=mode)
        assert auth.get_rate_limit_settings()["mode"] == mode

    @pytest.mark.parametrize("raw", ["", "ten", "-5", "1.5", "²", " 7", None])
    def test_a_number_that_is_not_whole_is_its_default(self, monkeypatch, raw):
        from jen.services import auth

        _settings(monkeypatch, rl_max_attempts=raw, rl_lockout_minutes=raw)
        out = auth.get_rate_limit_settings()
        assert (out["max_attempts"], out["lockout_minutes"]) == (10, 15)

    def test_a_number_past_the_bound_is_the_bound(self, monkeypatch):
        from jen.services import auth

        _settings(monkeypatch, rl_max_attempts="5000", rl_lockout_minutes="999999")
        out = auth.get_rate_limit_settings()
        assert (out["max_attempts"], out["lockout_minutes"]) == (auth.MAX_ATTEMPTS_BOUND, auth.MAX_LOCKOUT_MINUTES)

    def test_zero_keeps_its_meanings(self, monkeypatch):
        from jen.services import auth

        _settings(monkeypatch, rl_max_attempts="0", rl_lockout_minutes="0")
        out = auth.get_rate_limit_settings()
        assert (out["max_attempts"], out["lockout_minutes"]) == (0, 0)

    def test_an_unknown_mode_counts_the_buckets_at_login(self, monkeypatch):
        """The consequence: with `rl_mode = everyone` stored, the login is rate limited (as `both`), where it used to let every attempt through."""
        from jen.services import auth

        _settings(monkeypatch, rl_mode="everyone", rl_max_attempts="3", rl_lockout_minutes="15")
        cur = _Cursor(ip=0, username=5)
        monkeypatch.setattr(auth, "__jen_db_ctx", _ctx(cur), raising=False)
        locked, minutes = auth.is_locked_out("10.0.0.1", "admin")
        assert locked is True and minutes >= 1
        assert [q for q in cur.queries if "username=%s" in q], "the account's bucket was asked"


class _Cursor:
    """A `login_attempts` table with one count per bucket and one remaining time per bucket; the statements are recorded with the parameters they came with."""

    def __init__(self, ip: int, username: int, remaining_ip: int = 60, remaining_username: int = 780):
        self.counts = {"ip_address": ip, "username": username}
        self.remaining = {"ip_address": remaining_ip, "username": remaining_username}
        self.queries: list[str] = []
        self.params: list[tuple] = []
        self._last = None

    def execute(self, sql, params=()):
        self.queries.append(sql)
        self.params.append(tuple(params))
        field = "username" if "username=%s" in sql else "ip_address"
        if "COUNT(*)" in sql:
            self._last = {"cnt": self.counts[field]}
        else:
            self._last = {"remaining": self.remaining[field]}

    def fetchone(self):
        return self._last


def _ctx(cur):
    @contextmanager
    def ctx():
        class _Db:
            def cursor(self):
                @contextmanager
                def c():
                    yield cur

                return c()

        yield _Db()

    return ctx


class TestTheRemainingTimeIsMeasuredInTheBucketThatLocked:
    """AK12: under `both` the remaining time was read from the address's bucket always; a lockout the ACCOUNT's attempts triggered from many addresses measured MIN() over an empty bucket and
    said "1 minute" of a fifteen-minute lockout."""

    @pytest.fixture(autouse=True)
    def _policy(self, monkeypatch):
        _settings(monkeypatch, rl_mode="both", rl_max_attempts="3", rl_lockout_minutes="15")

    def test_the_account_bucket_decides_when_it_is_the_one_over_the_line(self, monkeypatch):
        from jen.services import auth

        cur = _Cursor(ip=0, username=5, remaining_username=780)
        monkeypatch.setattr(auth, "__jen_db_ctx", _ctx(cur), raising=False)
        assert auth.is_locked_out("10.0.0.1", "admin") == (True, 13)
        remaining = [p for q, p in zip(cur.queries, cur.params, strict=True) if "CEIL" in q]
        assert remaining == [(15, "admin", 15)], remaining

    def test_the_address_bucket_decides_when_it_is(self, monkeypatch):
        from jen.services import auth

        cur = _Cursor(ip=4, username=1, remaining_ip=60)
        monkeypatch.setattr(auth, "__jen_db_ctx", _ctx(cur), raising=False)
        assert auth.is_locked_out("10.0.0.1", "admin") == (True, 1)
        remaining = [p for q, p in zip(cur.queries, cur.params, strict=True) if "CEIL" in q]
        assert remaining == [(15, "10.0.0.1", 15)], remaining

    def test_a_tie_reads_the_address(self, monkeypatch):
        from jen.services import auth

        cur = _Cursor(ip=3, username=3, remaining_ip=120, remaining_username=780)
        monkeypatch.setattr(auth, "__jen_db_ctx", _ctx(cur), raising=False)
        assert auth.is_locked_out("10.0.0.1", "admin") == (True, 2)

    def test_under_the_line_nothing_is_measured(self, monkeypatch):
        from jen.services import auth

        cur = _Cursor(ip=1, username=2)
        monkeypatch.setattr(auth, "__jen_db_ctx", _ctx(cur), raising=False)
        assert auth.is_locked_out("10.0.0.1", "admin") == (False, 0)
        assert not [q for q in cur.queries if "CEIL" in q]


class TestARetentionPastTheBoundIsTheBound:
    """AK13: the bound Q224 put on the form is applied by the reader too - a value stored past it by an earlier release reached `INTERVAL %s DAY`, the DELETE failed on every pass and the
    table was never pruned, silently."""

    def _purge(self, monkeypatch, **rows):
        from jen.services import alerts

        _settings(monkeypatch, **rows)
        seen: list[tuple] = []

        class _Cur:
            def execute(self, sql, params=()):
                seen.append((sql, tuple(params)))

            rowcount = 0

        class _Db:
            def cursor(self):
                @contextmanager
                def c():
                    yield _Cur()

                return c()

            def commit(self):
                pass

        @contextmanager
        def ctx():
            yield _Db()

        monkeypatch.setattr(alerts, "__jen_db_ctx", ctx, raising=False)
        monkeypatch.setattr(alerts, "_purge_old_alert_log", lambda: 0, raising=False)
        alerts.purge_history()
        return {sql.split("FROM ")[1].split(" ")[0]: params[0] for sql, params in seen}

    def test_the_one_bound_is_the_pages(self):
        from jen.routes.settings import MAX_AUDIT_RETENTION_DAYS
        from jen.services import alerts

        assert alerts.MAX_RETENTION_DAYS == 3650 and MAX_AUDIT_RETENTION_DAYS is alerts.MAX_RETENTION_DAYS

    def test_a_stored_value_past_the_bound_prunes_at_the_bound(self, monkeypatch):
        kept = self._purge(monkeypatch, audit_retention_days="99999999", history_retention_days="4000")
        assert kept["audit_log"] == 3650 and kept["lease_history"] == 3650

    def test_a_value_inside_the_bound_and_a_bad_one_read_as_before(self, monkeypatch):
        kept = self._purge(
            monkeypatch, audit_retention_days="30", history_retention_days="ninety", events_retention_days="-1"
        )
        assert kept["audit_log"] == 30 and kept["lease_history"] == 90 and kept["events"] == 90

    def test_zero_still_keeps_the_audit_log_forever(self, monkeypatch):
        kept = self._purge(monkeypatch, audit_retention_days="0")
        assert "audit_log" not in kept


class TestAGroupWithATypoIsScopedToNothing:
    """AK11: `parse_subnet_map` dropped a group whose list held no valid id; under `subnet_map_default = all` the login then matched nothing and came in unrestricted."""

    def test_the_group_is_kept_and_empty(self):
        from jen.services import oidc

        assert oidc.parse_subnet_map("ops:²") == {"ops": set()}
        assert oidc.parse_subnet_map("ops:1,garbage,2") == {"ops": {1, 2}}, "a partial typo keeps the ids that parse"
        assert oidc.parse_subnet_map("garbage;:1,2") == {}, "a segment with no group is still skipped"

    @pytest.mark.parametrize("default", ["all", "none"])
    def test_the_login_is_scoped_to_nothing_not_everything(self, monkeypatch, default):
        from jen.services import oidc

        monkeypatch.setattr(extensions, "OIDC_SUBNET_MAP", "ops:²;net:3", raising=False)
        monkeypatch.setattr(extensions, "OIDC_SUBNET_MAP_DEFAULT", default, raising=False)
        monkeypatch.setattr(extensions, "OIDC_ROLE_CLAIM", "groups", raising=False)
        assert oidc.map_subnet_access({"groups": ["ops"]}) == "[]", "the typo scopes the account to nothing"
        assert oidc.map_subnet_access({"groups": ["net"]}) == "[3]", (
            "the control: a group that parses is scoped to its ids"
        )
        unmatched = oidc.map_subnet_access({"groups": ["nobody"]})
        assert unmatched == (None if default == "all" else "[]"), (
            "a group that is not in the map at all keeps the default's meaning"
        )


class TestASecretNameInAnUpperCaseRun:
    """AK16: `_CAMEL` split only after a lower-case letter, so `DBPassword` was one word; `pass_phrase` and the singular `credential` were outside the table; a dot was not a boundary."""

    @pytest.mark.parametrize(
        "name",
        [
            "DBPassword",
            "APIPassword",
            "SMTPPass",
            "DbPassword",
            "smtp.password",
            "pass_phrase",
            "pass phrase",
            "credential",
            "Credential",
        ],
    )
    def test_a_secret(self, name):
        assert is_secret_key(name), name

    @pytest.mark.parametrize(
        "name", ["DBHost", "HTTPServer", "API_URL", "ssl_key", "password-file", "passphrase_file", "credential_path"]
    )
    def test_not_a_secret(self, name):
        assert not is_secret_key(name), name


class TestTheBundleKeepsADefaultSection:
    """AK20: `configparser` folded `[DEFAULT]` into every section and dropped its header; the redacted file was not the shape of the operator's."""

    def test_the_section_is_re_emitted_as_itself(self):
        out = sb.redact_ini_text("[DEFAULT]\nregion = us\npassword = hunter2\n[server]\nport = 8443\n")
        assert "[DEFAULT]" in out and "region = us" in out and "hunter2" not in out
        server = out.split("[server]")[1]
        assert "region" not in server and "port = 8443" in server

    def test_a_file_without_one_is_unchanged_in_shape(self):
        out = sb.redact_ini_text("[server]\nport = 8443\n")
        assert out.strip().splitlines() == ["[server]", "port = 8443"]


class TestAnUnreadableScopeIsNoSubnets:
    """AK21: a `users.subnet_access` value that is not JSON made the account unrestricted (and JSON that is not a list, which a JSON column lets through, raised or read as nothing by luck); the three forms write only a JSON list or NULL, so the row was not theirs."""

    def test_garbage_is_no_subnets(self):
        from jen.models.user import User

        for stored in ("not json", '"abc"', "5", "{}", '{"a": 1}', "null"):
            u = User(1, "x", "admin", subnet_access=stored)
            assert u.all_subnets is False and u.can_access_subnet(1) is False, stored
        assert User(1, "x", "admin", subnet_access=[1]).can_access_subnet(1) is True, "a list already parsed is kept"
        assert User(1, "x", "admin", subnet_access={"a": 1}).all_subnets is False, (
            "a parsed value that is not a list is no subnets"
        )
        assert User(1, "x", "admin", subnet_access=None).all_subnets is True
        assert User(1, "x", "admin", subnet_access="[1, 2]").can_access_subnet(2) is True


class TestTheStaleThresholdIsStoredCanonically:
    """AK23."""

    def test_the_route_stores_the_int_text(self):
        src = (ROOT / "jen/routes/devices.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "save_device_settings")
        assigns = [
            n
            for n in ast.walk(fn)
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "stale_days" for t in n.targets)
        ]
        assert any(isinstance(a.value, ast.Call) and getattr(a.value.func, "id", "") == "str" for a in assigns), (
            "str(int(stale_days)) before the store"
        )


class TestTheCheckIsNamedByTheCardsWordsEverywhere:
    """AK7: Q224's walk refused the old name under `jen/` only; the upgrading page still told the operator to press a button no page prints."""

    def test_no_document_or_template_names_the_old_button(self):
        hits = []
        for path in list((ROOT / "docs").rglob("*.md")) + list((ROOT / "templates").rglob("*.html")):
            if "release-history" in path.parts:
                continue  # an archived page describes the release it was written for
            text = path.read_text(encoding="utf-8")
            for i, line in enumerate(text.splitlines(), 1):
                if "Check readiness" in line:
                    hits.append(f"{path.relative_to(ROOT)}:{i}")
        assert not hits, hits

    def test_the_comment_names_the_test_that_exists(self):
        src = (ROOT / "jen/services/text.py").read_text(encoding="utf-8")
        m = re.search(r"`tests/(test_\w+\.py)::(\w+)`", src)
        assert m, "the comment names its guard"
        guard = (ROOT / "tests" / m.group(1)).read_text(encoding="utf-8")
        assert f"class {m.group(2)}" in guard


class TestAFileWithNoSectionIsNotTheDaemons:
    """AK17: `file_in_daemon` carried an empty section vacuously - a combined file holding only `Dhcp6` under a dhcp4 `kea_conf` was "loaded" and `config-write` would have written over it;
    `mirrors` said True of two empty renderings."""

    def test_file_in_daemon_refuses_an_empty_section(self):
        live = {"Dhcp4": copy.deepcopy(TWO_SUBNET_DHCP4)}
        assert api.file_in_daemon({"Dhcp6": {"subnet6": []}}, live, "dhcp4") is False
        assert api.file_in_daemon({}, live, "dhcp4") is False
        assert api.file_in_daemon(None, live, "dhcp4") is False
        assert api.file_in_daemon(copy.deepcopy(live), live, "dhcp4") is True, "the control: the file is the daemon's"

    def test_mirrors_refuses_an_empty_rendering_on_either_side(self):
        live = {"Dhcp4": copy.deepcopy(TWO_SUBNET_DHCP4)}
        assert api.mirrors(None, None, "dhcp4") is False
        assert api.mirrors({"Dhcp4": {}}, {"Dhcp4": {}}, "dhcp4") is False
        assert api.mirrors({"Dhcp4": {}}, live, "dhcp4") is False
        assert api.mirrors(live, {"Dhcp4": {}}, "dhcp4") is False
        assert api.mirrors(copy.deepcopy(live), live, "dhcp4") is True


class TestTheUnverifiedSentenceNamesTheCheckThatFired:
    """AK4: when step (7)'s content check fired, the sentence printed "its digest is X, not the X the set returned" - the same digest twice."""

    def test_a_set_without_a_digest_whose_content_is_not_carried(self, w, fake, store, monkeypatch):
        cfg, digest = api.read(w.server, "dhcp4", capture=False)
        plan = api.file_proof(w.server, "dhcp4")
        candidate = copy.deepcopy(cfg)
        candidate["Dhcp4"]["valid-lifetime"] = 7200
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
        out = api.apply(w.server, "dhcp4", candidate, digest, "x", before_cfg=cfg, planned_sha=plan["sha256"])
        assert not out["ok"] and out["code"] == "unverified", out
        assert "does not carry what was sent (valid-lifetime)" in out["detail"], out["detail"]
        assert "not the" not in out["detail"], "the digest sentence is not printed with one digest twice"


class TestEveryOneStateRollbackResultIsBucketedAsStillNew:
    """AK5: `api_refused` counted a `guard` only; `noanswer`, `conflict` and `unreadable` also send nothing, and such a target read "did not complete ... Settle it now" with no row to settle."""

    def test_a_rollback_the_daemon_did_not_answer_the_digest_question_of_is_still_new(self, fake, store, monkeypatch):
        """Two api targets. kea-a's forward write stands; kea-z refuses `config-set`, and from that moment kea-a answers everything but `config-hash-get`. kea-a's rollback proves its file
        (`mirrors`), records its row, asks the digest, gets no answer and is refused `noanswer` with nothing sent and the row dropped. The group line says kea-a still has the NEW config and
        names no settlement; under beta.10 it said "did not complete ... Settle it now" and the button had nothing to settle."""
        from jen.services import kea_host
        from tests._kea_host_fakes import FakeHelper

        h = FakeHelper()
        monkeypatch.setattr(kea_host, "helper_call", h.helper_call)
        monkeypatch.setattr(kea_host, "record_helper_status", lambda *a, **k: None)
        monkeypatch.setattr(kea_host, "helper_status", dict)
        monkeypatch.setattr(kea_host, "guard_kea_write", lambda *a, **k: "")
        server = {"id": SID, "name": "kea-a", "api_url": fake.url, "ssh_host": "10.0.0.9", "config_transport": "api"}
        pw = world.ProofWorld(fake, server, store, monkeypatch)
        pw.start(copy.deepcopy(TWO_SUBNET_DHCP4))
        second = StatefulKeaServer(copy.deepcopy(TWO_SUBNET_DHCP4))
        second.start()
        try:
            other = {"id": 8, "name": "kea-z", "api_url": second.url, "config_transport": "api"}
            original = second._answer

            def refuse_the_set(command, arguments):
                if command == "config-set":
                    fake.hang = {"config-hash-get": "before"}
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
        assert "did not answer the digest question; nothing was sent" in text, text
        assert (
            "kea-a still have the NEW config" in text and "did not complete" not in text and "Settle it now" not in text
        ), text
        assert fake.running["valid-lifetime"] == 7200 and fake.file["valid-lifetime"] == 7200, "daemon and file alike"
        assert store.pending(SID, "dhcp4") is None, "the row the refusal dropped"

    def test_every_refusal_before_the_set_has_no_needs_hands(self):
        """The property the bucket rests on, read from `apply`: every `_result(False, ...)` textually before the `config-set` is a plain result (no `needs_hands`), and every refusal after it that
        leaves two states is `_unproved`."""
        src = (ROOT / "jen/services/kea_api_config.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "apply")
        send = next(
            n
            for n in ast.walk(fn)
            if isinstance(n, ast.Call) and any(isinstance(a, ast.Constant) and a.value == "config-set" for a in n.args)
        )
        before = [
            n
            for n in ast.walk(fn)
            if isinstance(n, ast.Call)
            and getattr(n.func, "id", "") in ("_result", "_unproved")
            and n.lineno < send.lineno
        ]
        codes = {a.value for c in before for a in c.args[1:2] if isinstance(a, ast.Constant)}
        plain = {
            a.value
            for c in before
            if getattr(c.func, "id", "") == "_result"
            for a in c.args[1:2]
            if isinstance(a, ast.Constant)
        }
        assert {"guard", "noanswer", "conflict", "unreadable"} <= plain, plain
        assert "unverified" not in plain and codes - plain <= {"unverified"}, codes


class TestADiscardOverAnUnreadableFileIsRefused:
    """AK6: a `how` of `unreadable` fell to the fallback and the switch answered "nothing was discarded - the file is proved (unreadable)"; the audit row's `consents` named a discard nothing made."""

    FACTS = {
        "config_api": True,
        "test_ok": True,
        "include": [],
        "agree": False,
        "write": {"may_write": True, "account": "_kea", "mode": "0644"},
        "auth": "basic",
    }

    def test_unreadable_is_a_refusal(self, w, store, fake, monkeypatch):
        monkeypatch.setattr(api, "probe", lambda server, service="dhcp4", **k: dict(self.FACTS))
        monkeypatch.setattr(
            api,
            "file_proof",
            lambda *a, **k: api._proof(False, "unreadable", why="the file on kea-a could not be read"),
        )
        out = sw._to_api(w.server, "api", {"consent_rendering", "discard_file_edit"}, "me")
        assert not out["ok"] and "could not be read; nothing was changed" in out["line"], out
        assert "proved (unreadable)" not in out["line"]

    def test_the_table_is_total_over_the_proofs_that_are_ok(self):
        assert set(sw.NOTHING_TO_DISCARD) == {h for h in api.PROOF_HOWS if h not in ("none", "unreadable")}
        src = (ROOT / "jen/services/kea_transport_switch.py").read_text(encoding="utf-8")
        assert "NOTHING_TO_DISCARD.get(" not in src, "a total table is indexed, never defaulted"

    def test_the_consents_name_no_discard_when_none_was_made(self, w, store, fake, monkeypatch):
        monkeypatch.setattr(api, "probe", lambda server, service="dhcp4", **k: dict(self.FACTS))
        monkeypatch.setattr(api, "file_proof", lambda *a, **k: api._proof(True, "loaded", sha256="f" * 64))
        out = sw._to_api(w.server, "api", {"consent_rendering", "discard_file_edit"}, "me")
        assert out["ok"] and out["discarded"] is False and "discard_file_edit" not in out["consents"], out


class TestTheRegistryCarriesThisReleasesRules:
    """AK10: three rules shipped in beta.10 with no entry. The registry's own test walks entry -> test; this one asks the other direction for the rules Q224 and Q225 established."""

    def test_the_entries_exist_and_name_their_tests(self):
        text = (ROOT / "docs/SAFETY_INVARIANTS.md").read_text(encoding="utf-8")
        for rid, test in (
            ("RBAC-003", "TestTheModeIsPartOfTheStrictness"),
            ("BOUND-001", "TestARateLimitThatCannotBeReadIsTheStrictest"),
            ("BOUND-001", "TestARetentionPastTheBoundIsTheBound"),
            ("DEF-003", "TestOneWholeNumberTest"),
        ):
            section = text.split(f"### {rid} ")[1].split("\n### ")[0]
            assert test in section, (rid, test)
