"""
tests/test_a_page_carries_only_what_it_names.py
───────────────────────────────────────────────
Q227 - the rows of Opus's pass on 7.0.0-beta.12 (AM1..AM28) that a pure test can hold. Every P2 of that pass was inside a mechanism Q226 added, so this Q adds the smallest
mechanisms it can: an allowlist where there was a blocklist, one reader where there were two, and a result that is asked instead of a line that guesses. Pure: runs under
`--noconftest`. The cells that need the database are in `tests/test_the_alerts_page_keeps_its_secrets.py` and `tests/test_mfa_stepup.py`.

AM24, AM25  one reading of a channel's stored scope (`alerts.channel_scope`); delivery, the route and the page ask it.
AM2         the daily summary names every subnet: only a channel for every subnet handles it.
AM4         the OIDC callback names no account: `auth.NO_ACCOUNT` has no username bucket.
AM3         only a superadmin makes a lockout permanent, and the clear button says what it ended.
AM5         a blank OIDC client secret keeps the stored one only for the same issuer.
AM22        the Settings landing page counts the channels the Alerts page lists for this account.
AM11        the switch's sentence asks the write whether an edit was discarded.
AM13, AM28  a configuration that is not an object has no section, and the rollback gate names each cause.
AM14        a rollback over the API that raised is "not known", never "still new" and never "did not complete".
AM21        the IPv6 switch says enabled or disabled only when its row was stored.
AM27        `_int_setting`'s callers carry the table's own defaults.
AM23        a channel's URL never carries a password (CRED-005), asked before a secret is kept.
AM8         `CREATE TABLE` is DDL to the migration sweep.
"""

import ast
import copy
import pathlib
import types

import pytest

from jen import extensions
from jen.services import alerts, auth, setting_bounds
from jen.services import kea_api_config as api
from jen.services import kea_changeset as cs
from jen.services import kea_transport_switch as sw
from tests import _kea_api_world as world
from tests.e2e._fake_kea_server import TWO_SUBNET_DHCP4, StatefulKeaServer
from tests.test_the_mode_is_part_of_the_strictness import _ctx, _Cursor

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
    monkeypatch.setattr("jen.models.user.get_global_setting", lambda k, d=None: rows.get(k, d))


class _Principal:
    def __init__(self, all_subnets: bool, ids=()):
        self.all_subnets = all_subnets
        self._ids = list(ids)

    def accessible_subnet_ids(self, subnet_map):
        return list(self._ids)


def _function(rel: str, name: str) -> str:
    """The source of one function of a file under the repository, as written."""
    src = (ROOT / rel).read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.get_source_segment(src, fn)


def _python_files():
    for base in ("jen", "plugins"):
        yield from sorted((ROOT / base).rglob("*.py"))


# ── the scope of an alert channel ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


class TestOneReadingOfAChannelsScope:
    """AM24, AM25: the route read the stored scope with its own parser (`_scope_list`) and delivery read it with another. They agreed on every value a form writes and disagreed
    on the damaged ones, so the page could call a channel "All Subnets" that delivery had closed. There is one reading: None is every subnet, a tuple of ids is those subnets,
    an EMPTY tuple is a scope that is present and damaged."""

    @pytest.mark.parametrize(
        "stored, want", [(None, None), ("[1, 2]", (1, 2)), ("[7]", (7,)), ([3], (3,)), ((4, 5), (4, 5))]
    )
    def test_a_scope_a_form_writes(self, stored, want):
        assert alerts.channel_scope({"subnet_scope": stored}) == want

    @pytest.mark.parametrize(
        "stored",
        ["[]", "{}", "5", "not json", "", "[true]", '["1"]', "[1, null]", "null", "[1.5]", [], {}, 5, [True], ["1"]],
    )
    def test_a_damaged_scope_is_the_empty_tuple_and_delivers_nothing_about_a_subnet(self, stored):
        ch = {"subnet_scope": stored}
        assert alerts.channel_scope(ch) == ()
        assert alerts.channel_allows_subnet(ch, 1) is False
        assert alerts.channel_allows_subnet(ch, None, scoped=True) is False
        assert alerts.channel_allows_subnet(ch, None) is True, "a server-level alert (Kea down) still goes to it"

    def test_the_route_asks_the_service(self, monkeypatch):
        from jen.routes.settings import alerts as route

        assert not hasattr(route, "_scope_list"), "the route's own parser is gone"
        monkeypatch.setattr(route, "current_user", _Principal(False, [1, 2]))
        assert route._may_act_on({"subnet_scope": "[1, 2]"}) and not route._may_act_on({"subnet_scope": "[1, 3]"})
        for damaged in ("[]", "{}", "5", "not json", "[true]", '["1"]', "null"):
            assert not route._may_act_on({"subnet_scope": damaged}), damaged
        monkeypatch.setattr(route, "current_user", _Principal(True))
        assert route._may_act_on({"subnet_scope": "[]"}), (
            "an unrestricted account acts on every channel, a damaged one too"
        )

    def test_the_stored_scope_is_read_in_one_place_in_the_whole_tree(self):
        """Every `X.get("subnet_scope")` and every `X["subnet_scope"]` that is READ, over `jen/` and `plugins/`. The page's `ch["subnet_scope"] = ...` is a write and is not counted."""
        reads = []
        for path in _python_files():
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "get"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and node.args[0].value == "subnet_scope"
                ) or (
                    isinstance(node, ast.Subscript)
                    and isinstance(node.ctx, ast.Load)
                    and isinstance(node.slice, ast.Constant)
                    and node.slice.value == "subnet_scope"
                ):
                    reads.append(path.relative_to(ROOT).as_posix())
        assert reads == ["jen/services/alerts.py"], reads

    def test_the_page_says_a_damaged_scope_is_damaged(self):
        html = (ROOT / "templates/settings_alerts.html").read_text(encoding="utf-8")
        assert "{% if ch.scope_damaged %}" in html
        assert "This channel's subnet scope cannot be read, so no subnet-specific alert is delivered to it." in html


class TestTheDailySummaryGoesOnlyToAChannelForEverySubnet:
    """AM2: the daily summary lists every subnet with its utilization and counts every known device, and it is sent with no subnet id, so a channel's scope was never asked. A
    subnet-restricted admin's channel (always scoped) received the whole network's summary. A scoped channel does not handle it; the form refuses the pair."""

    TYPES = '["kea_down", "daily_summary"]'

    def test_the_list_of_whole_network_alert_types(self):
        assert set(alerts.WHOLE_NETWORK_ALERT_TYPES) == {"daily_summary"}

    @pytest.mark.parametrize(
        "scope, handled", [(None, True), ("[1]", False), ("[1, 2]", False), ("[]", False), ("not json", False)]
    )
    def test_only_a_channel_for_every_subnet_handles_it(self, scope, handled):
        ch = {"alert_types": self.TYPES, "subnet_scope": scope}
        assert alerts.channel_handles_alert(ch, "daily_summary") is handled
        assert alerts.channel_handles_alert(ch, "kea_down") is True, "a server-level alert is untouched"

    def test_a_channel_that_did_not_ask_for_it_does_not_get_it(self):
        assert (
            alerts.channel_handles_alert({"alert_types": '["kea_down"]', "subnet_scope": None}, "daily_summary")
            is False
        )

    def test_every_alert_sent_with_no_subnet_is_on_the_reviewed_list(self):
        """Where else is this true: every `send_alert(` call under `jen/` and `plugins/` that names its type with a literal and passes no `subnet_id`. The daily summary is about
        the whole network; `ha_failover` is about one Kea server and names no subnet or client. A new one is reviewed here before it ships."""
        bare = set()
        for path in _python_files():
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if not isinstance(node, ast.Call):
                    continue
                f = node.func
                name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""
                if name != "send_alert" or not node.args or not isinstance(node.args[0], ast.Constant):
                    continue
                keywords = [k.arg for k in node.keywords]
                if "subnet_id" not in keywords and None not in keywords:
                    bare.add(node.args[0].value)
        assert bare == {"daily_summary", "ha_failover"}, sorted(bare)

    def test_the_form_offers_it_only_to_an_account_that_can_make_such_a_channel(self):
        html = (ROOT / "templates/settings_alerts.html").read_text(encoding="utf-8")
        assert "{% if can_grant_all_subnets or atype not in whole_network_alert_types %}" in html
        assert "{% if ch.unsent_types %}" in html
        route = _function("jen/routes/settings/alerts.py", "save_alert_channel")
        assert "only a channel for All Subnets can receive it" in route
        assert "Choose the alert types from the list." in route


class TestTheLandingPageCountsWhatTheAlertsPageLists:
    """AM22: Settings counted every enabled channel; the Alerts page lists a restricted admin only the channels inside their scope. One function answers both."""

    ROWS = [{"subnet_scope": None}, {"subnet_scope": "[1]"}, {"subnet_scope": "[3]"}, {"subnet_scope": "[]"}]

    class _Cur:
        def __init__(self, rows):
            self.rows = rows
            self.queries = []

        def execute(self, sql, params=()):
            self.queries.append(sql)

        def fetchall(self):
            return list(self.rows)

    def _count(self, monkeypatch, principal):
        import jen.routes.settings as settings
        from jen.routes.settings import alerts as route

        cur = self._Cur(self.ROWS)
        monkeypatch.setattr("jen.routes.settings.__db", types.SimpleNamespace(jen_db=_ctx(cur)))
        monkeypatch.setattr(route, "current_user", principal)
        monkeypatch.setattr(
            settings, "current_user", principal
        )  # (Q228, AN3) the count asks `alerts.enabled_channels_for` with its own module's principal
        return settings._enabled_channels(), cur

    def test_a_restricted_admin_counts_the_channels_inside_their_scope(self, monkeypatch):
        n, cur = self._count(monkeypatch, _Principal(False, [1, 2]))
        assert n == 1 and cur.queries == ["SELECT subnet_scope FROM alert_channels WHERE enabled=1"]

    def test_an_unrestricted_account_counts_them_all(self, monkeypatch):
        assert self._count(monkeypatch, _Principal(True))[0] == 4

    def test_a_database_that_does_not_answer_is_no_number(self, monkeypatch):
        import jen.routes.settings as settings

        def down():
            raise RuntimeError("no database")

        monkeypatch.setattr("jen.routes.settings.__db", types.SimpleNamespace(jen_db=down))
        assert settings._enabled_channels() is None


class TestAChannelUrlNeverCarriesAPassword:
    """AM23 (CRED-005): the channel form was the one save path that stored a URL with user-info in it. The refusal comes before a blank secret is kept, so a refused URL keeps
    nothing. AM1: a generic webhook's URL carries its token in the path or the query, so its input is a password field the page never fills."""

    def test_the_refusal_comes_before_a_secret_is_kept(self):
        src = _function("jen/routes/settings/alerts.py", "save_alert_channel")
        refusal, kept = src.index("_address_refusal(channel_type, config)"), src.index("_kept_secrets(")
        assert 0 < refusal < kept
        judge = _function(
            "jen/routes/settings/alerts.py", "_address_refusal"
        )  # (Q228, AN6) the refusals of a typed address are one function
        assert "__auth.USERINFO_SENTENCE" in judge and '{"webhook_url": "webhook_url", "url": "ntfy_url"}' in judge

    def test_a_blank_url_is_not_refused_for_user_info(self):
        assert not auth.userinfo_sentence(""), "an edit posts a write-only URL blank; the stored one is taken next"
        assert auth.userinfo_sentence("https://jen:" + "x" + "@hooks.example.test/x") == auth.USERINFO_SENTENCE

    def test_the_webhook_url_input_is_a_secret_field(self):
        html = (ROOT / "templates/settings_alerts.html").read_text(encoding="utf-8")
        assert '<input id="f-webhook_url" type="password" name="webhook_url" data-secret="1" autocomplete="off"' in html


# ── login rate limiting ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


class TestTheCallbackNamesNoAccount:
    """AM4: the OIDC callback recorded its failures under the username "oidc", one bucket for every user of the provider. Under a permanent lockout three failed callbacks from
    anywhere locked the name "oidc" until an admin cleared it, and every OIDC login after that was refused. The callback names no account, and no account has no username bucket."""

    def test_no_account_is_the_empty_name(self):
        assert auth.NO_ACCOUNT == ""

    def test_under_both_only_the_address_is_read_and_counted(self, monkeypatch):
        _settings(monkeypatch, rl_mode="both", rl_max_attempts="3", rl_lockout_minutes="15")
        cur = _Cursor(username=[30, 20, 10], locked=[("username", "")])
        monkeypatch.setattr(auth, "__jen_db_ctx", _ctx(cur), raising=False)
        assert auth.is_locked_out("10.0.0.1", auth.NO_ACCOUNT) == (False, 0)
        assert cur.queries, "the address was asked"
        assert all("username=%s" not in q for q in cur.queries) and ("username", "") not in cur.params

    def test_the_address_still_locks_the_callback(self, monkeypatch):
        _settings(monkeypatch, rl_mode="both", rl_max_attempts="3", rl_lockout_minutes="15")
        cur = _Cursor(ip=[30, 20, 10])
        monkeypatch.setattr(auth, "__jen_db_ctx", _ctx(cur), raising=False)
        locked, minutes = auth.is_locked_out("10.0.0.1", auth.NO_ACCOUNT)
        assert locked and minutes >= 1

    def test_under_username_mode_nothing_is_asked(self, monkeypatch):
        """Decided: under mode `username` there is no bucket for a login that names no account, so the callback is not rate limited by Jen (the provider limits its own form)."""
        _settings(monkeypatch, rl_mode="username", rl_max_attempts="3", rl_lockout_minutes="0")
        cur = _Cursor(username=[30, 20, 10], locked=[("username", "")])
        monkeypatch.setattr(auth, "__jen_db_ctx", _ctx(cur), raising=False)
        assert auth.is_locked_out("10.0.0.1", auth.NO_ACCOUNT) == (False, 0)
        assert cur.queries == []

    def test_a_named_account_is_untouched(self, monkeypatch):
        _settings(monkeypatch, rl_mode="username", rl_max_attempts="3", rl_lockout_minutes="15")
        cur = _Cursor(username=[30, 20, 10])
        monkeypatch.setattr(auth, "__jen_db_ctx", _ctx(cur), raising=False)
        assert auth.is_locked_out("10.0.0.1", "admin")[0] is True

    def test_no_rate_limit_call_is_given_the_word_oidc(self):
        """Whole tree: no `is_locked_out`, `record_login_attempt` or `clear_login_attempts` call under `jen/` or `plugins/` passes the literal "oidc"."""
        hits = []
        for path in _python_files():
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                if (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("is_locked_out", "record_login_attempt", "clear_login_attempts")
                    and any(isinstance(a, ast.Constant) and a.value == "oidc" for a in node.args)
                ):
                    hits.append(f"{path.relative_to(ROOT).as_posix()}:{node.lineno}")
        assert not hits, hits
        assert _function("jen/routes/auth.py", "login_oidc_callback").count("__auth.NO_ACCOUNT") == 6


class TestOnlyASuperadminMakesALockoutPermanent:
    """AM3: 0 minutes is the strictest lockout, so the ratchet (RBAC-003) let an admin move TO it. An admin could then fail a superadmin's name at /login and leave that account
    locked until someone cleared it. Setting 0 is a superadmin's act; an admin may keep a 0 a superadmin set. The clear button says what it ended."""

    def test_the_route_refuses_an_admin_who_would_make_it_permanent(self):
        src = _function("jen/routes/settings/security.py", "save_rate_limit")
        assert 'current_user.role != "superadmin"' in src and "int(lockout_minutes) == 0" in src
        assert '__auth.get_rate_limit_settings()["lockout_minutes"] != 0' in src, (
            "an admin may keep a 0 that is already stored"
        )
        refusal, save = src.index("PERMANENT_IS_A_SUPERADMINS"), src.index("set_global_settings(")
        assert 0 < refusal < save, "refused before anything is stored"

    def test_the_sentences(self):
        from jen.routes.settings import security

        assert security.PERMANENT_IS_A_SUPERADMINS == (
            "Only a superadmin can set a lockout that lasts until it is cleared (0 minutes)."
        )
        assert security.CLEARED_SENTENCE.format(attempts=4, lockouts=2) == (
            "Cleared 4 failed login attempt(s) and ended 2 permanent lockout(s)."
        )

    def test_the_clear_counts_what_it_deleted(self):
        src = _function("jen/routes/settings/security.py", "clear_lockouts")
        assert src.index("DELETE FROM login_attempts") < src.index("DELETE FROM login_lockouts")
        assert (
            src.count("max(cur.rowcount, 0)") == 2
            and "CLEARED_SENTENCE.format(attempts=attempts, lockouts=lockouts)" in src
        )
        assert 'flash("All login attempt records cleared."' not in src

    def test_the_security_page_shows_the_lockouts_in_force_and_who_sets_zero(self):
        html = (ROOT / "templates/settings_security.html").read_text(encoding="utf-8")
        assert (
            'id="rl-permanent-lockouts"' in html
            and "{{ rl_lockouts_username }}" in html
            and "{{ rl_lockouts_ip }}" in html
        )
        assert "Only a superadmin can set 0." in html
        assert "end every permanent lockout?" in html
        page = (ROOT / "jen/routes/settings/__init__.py").read_text(encoding="utf-8")
        assert page.count("SELECT COUNT(*) AS cnt FROM login_lockouts WHERE kind=%s") == 2


class TestTheOidcSecretStaysWithItsIssuer:
    """AM5 (CRED-002): a blank client secret kept the stored one when the issuer changed, so the secret typed for one identity provider was sent to the next one's token
    endpoint. The same rule the alert channels have: a blank secret is kept only for the same place."""

    def test_the_route_compares_the_issuer_before_it_keeps_the_secret(self):
        src = _function("jen/routes/settings/security.py", "save_oidc")
        assert (
            "not __auth.same_destination(issuer, extensions.OIDC_ISSUER)" in src
        )  # (Q228, AN2) with its path: `same_endpoint` stops at the port
        assert 'flash_field("client_secret", OIDC_ISSUER_CHANGED)' in src
        assert "not client_secret" in src and "extensions.OIDC_CLIENT_SECRET" in src

    def test_the_sentence(self):
        from jen.routes.settings import security

        assert security.OIDC_ISSUER_CHANGED == "The issuer changed - enter the client secret again."

    @pytest.mark.parametrize(
        "new, old, same",
        [
            ("https://idp.example.test/realms/a", "https://idp.example.test/realms/a", True),
            ("https://idp.example.test/realms/a/", "https://idp.example.test/realms/a", True),
            ("https://idp2.example.test/realms/a", "https://idp.example.test/realms/a", False),
            ("http://idp.example.test/realms/a", "https://idp.example.test/realms/a", False),
            ("https://idp.example.test/realms/a", "", False),
            (
                "https://idp.example.test/realms/a",
                "https://idp.example.test/realms/b",
                False,
            ),  # (Q228, AN2) another realm
        ],
    )
    def test_what_the_same_issuer_is(self, new, old, same):
        assert auth.same_destination(new, old) is same


# ── the write path's sentences ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


class TestTheSentenceAsksTheWrite:
    """AM11: a consent recorded in place read the FIRST proof to say "the file's edit was discarded" and the write's own answer to fill the audit row (AL28). When the daemon
    loaded the file between the two reads, the flash said discarded and the audit row said nothing was. The sentence asks the write."""

    FACTS = {
        "config_api": True,
        "test_ok": True,
        "include": [],
        "agree": False,
        "write": {"may_write": True, "account": "_kea", "mode": "0644"},
        "auth": "basic",
    }

    def _switch(self, w, monkeypatch, discarded):
        monkeypatch.setattr(api, "probe", lambda server, service="dhcp4", **k: dict(self.FACTS))
        monkeypatch.setattr(api, "file_proof", lambda *a, **k: api._proof(False, "none", why="edited"))
        monkeypatch.setattr(api, "write_file", lambda *a, **k: api._result(True, "ok", discarded=discarded))
        monkeypatch.setattr(api, "record_rendering_after_write", lambda *a, **k: True)
        return sw._to_api(w.server, "api", {"consent_rendering", "discard_file_edit"}, "me")

    def test_a_write_that_found_no_edit_left_says_nothing_was_discarded(self, w, store, fake, monkeypatch):
        out = self._switch(w, monkeypatch, discarded=False)
        assert out["ok"], out
        assert sw.NOTHING_LEFT_TO_DISCARD in out["line"] and "the file's edit was discarded" not in out["line"], out[
            "line"
        ]
        assert out["discarded"] is False and "discard_file_edit" not in out["consents"], out

    def test_the_control_a_write_that_discarded_an_edit_says_so(self, w, store, fake, monkeypatch):
        out = self._switch(w, monkeypatch, discarded=True)
        assert out["ok"], out
        assert "the file's edit was discarded" in out["line"] and "nothing was discarded" not in out["line"], out[
            "line"
        ]
        assert out["discarded"] is True and "discard_file_edit" in out["consents"], out


class TestAConfigurationThatIsNotAnObjectHasNoSection:
    """AM13: `_section` called `.get` on whatever it was handed, so a file whose top level is a JSON array raised AttributeError out of the rollback gate. AM28: the gate said
    "came back empty" for a section that was there and was not an object."""

    @pytest.mark.parametrize("cfg", [[], ["Dhcp4"], "text", 3, None, True])
    def test_no_section(self, cfg):
        assert api._section(cfg, "dhcp4") == {}

    def test_a_file_that_is_an_array_mirrors_nothing_and_raises_nothing(self):
        live = {"Dhcp4": copy.deepcopy(TWO_SUBNET_DHCP4)}
        array = [{"Dhcp4": {}}]  # (Q228, AN23) `[]` passed on the tag before the fix too
        assert api.mirrors(array, live, "dhcp4") is False and api.mirrors(live, array, "dhcp4") is False
        assert api.file_in_daemon(array, live, "dhcp4") is False

    def test_the_gate_has_one_sentence_per_cause(self):
        src = _function("jen/services/kea_api_config.py", "apply")
        not_object = src.index("section is not an object); the file was not judged")
        empty = src.index("came back empty; the file was not judged")
        edited = src.index("it was edited since Kea wrote it")
        assert 0 < not_object < empty < edited


class TestARollbackThatRaisedIsNotKnown:
    """AM14: an api target whose rollback RAISED reported neither what was sent nor what stood. It was counted with the half-finished rollbacks ("did not complete ... what the
    daemon and the file hold is in the line above") and the line above held an exception's name. It has its own sentence, which claims neither state."""

    def test_the_group_line_claims_neither_state(self, fake, store, monkeypatch):
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
                    return {"result": 1, "text": "refused"}
                return original(command, arguments)

            second._answer = refuse_the_set

            def raising_revert(*a, **k):
                raise RuntimeError("the connection was reset")

            monkeypatch.setattr(api, "revert", raising_revert)

            def lifetime(cfg):
                out = copy.deepcopy(cfg)
                out["Dhcp4"]["valid-lifetime"] = 7200
                return out, "ok"

            result = cs.apply_change("dhcp4", lifetime, "x", servers=[server, other])
        finally:
            second.stop()
        assert result.status == "rollback_failed", result.lines
        text = " ".join(t for _k, t in result.lines)
        assert f"kea-a: {cs.ROLLBACK_NOT_KNOWN}" in text, text
        assert "still have the NEW config" not in text and "did not complete" not in text, text

    def test_the_sentence_names_the_card(self):
        assert "is not known" in cs.ROLLBACK_NOT_KNOWN and "Settle it now" in cs.ROLLBACK_NOT_KNOWN


# ── the smaller rows ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


class TestTheIpv6SwitchSaysSavedOnlyWhenItIs:
    """AM21 (STORE-001): `toggle_ipv6` called `set_global_setting` and flashed "enabled" whatever it answered."""

    def test_both_directions_read_the_writers_answer(self):
        src = _function("jen/routes/settings/infrastructure.py", "toggle_ipv6")
        assert 'elif __user.set_global_setting("ipv6_enabled", "true"):' in src
        assert (
            'stored = "yes" if __user.set_global_setting("ipv6_enabled", "false") else "no"' in src
        )  # (Q228, AN11) and the audit row carries it
        assert src.count("IPV6_NOT_SAVED.format(") == 2

    def test_the_sentence_says_what_jen_still_shows(self):
        from jen.routes.settings import infrastructure

        assert infrastructure.IPV6_NOT_SAVED.format(state="off") == (
            "The IPv6 switch could not be saved, so IPv6 stays off in Jen. The reason is in the Jen log."
        )


class TestTheCallersNumbersAreTheTables:
    """AM27: `_int_setting(key, default)` reads the table and ignores `default`. Each caller's number is held equal to the table's, so the one a reader sees is the one applied."""

    def test_every_caller_carries_the_tables_default(self):
        src = (ROOT / "jen/services/alerts.py").read_text(encoding="utf-8")
        seen = {}
        for node in ast.walk(ast.parse(src)):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "_int_setting":
                key, default = node.args
                seen[key.value] = default.value
        assert seen == {"alert_threshold_pct": 80, "pool_exhaustion_free": 5, "snapshot_interval_minutes": 30}, seen
        for key, default in seen.items():
            assert setting_bounds.SETTING_BOUNDS[key][0] == default, key

    def test_the_two_pages_print_through_the_table(self):  # AM10
        for rel in ("jen/routes/settings/alerts.py", "jen/routes/reports.py"):
            src = (ROOT / rel).read_text(encoding="utf-8")
            assert "bounded_setting(" in src, rel
        assert 'name="pool_exhaustion_free"' in (ROOT / "templates/settings_alerts.html").read_text(encoding="utf-8")


class TestCreateTableIsDdl:
    """AM8: sweep S3 (every DDL statement of a migration has its own guard) never matched `CREATE TABLE`, so migration 39's guarded statement was held by nobody."""

    def test_the_sweeps_pattern_matches_it(self):
        from tests import test_invariant_sweeps as sweeps

        assert sweeps._DDL.search("CREATE TABLE login_lockouts (")
        assert sweeps._DDL.search("ALTER TABLE users ADD COLUMN x INT") and sweeps._DDL.search(
            "CREATE UNIQUE INDEX i ON t (c)"
        )
        assert not sweeps._DDL.search("SELECT 1 FROM login_lockouts")


class TestTheRegistryCarriesThisReleasesRules:
    """Each rule this release changed has its test named in its entry of `docs/SAFETY_INVARIANTS.md`."""

    @pytest.mark.parametrize(
        "rid,test",
        [
            ("RBAC-001", "TestOneReadingOfAChannelsScope"),
            ("RBAC-001", "TestTheDailySummaryGoesOnlyToAChannelForEverySubnet"),
            ("RBAC-001", "TestAScopedChannelIsNotSentTheDailySummary"),
            ("RBAC-001", "TestTheLandingPageCountsWhatTheAlertsPageLists"),
            ("RBAC-003", "TestOnlyASuperadminMakesALockoutPermanent"),
            ("RBAC-003", "TestTheCallbackNamesNoAccount"),
            ("CRED-002", "TestTheOidcSecretStaysWithItsIssuer"),
            ("CRED-002", "TestAChannelsSecretIsWriteOnly"),
            ("CRED-005", "TestAChannelUrlNeverCarriesAPassword"),
            ("LEAK-001", "TestAChannelsSecretIsWriteOnly"),
            ("STORE-001", "TestTheIpv6SwitchSaysSavedOnlyWhenItIs"),
            ("BOUND-001", "TestTheCallersNumbersAreTheTables"),
            ("CFG-002", "TestARollbackThatRaisedIsNotKnown"),
            ("CFG-004", "TestAConfigurationThatIsNotAnObjectHasNoSection"),
            ("CFG-005", "TestTheSentenceAsksTheWrite"),
            ("MIG-001", "TestCreateTableIsDdl"),
            ("DEF-003", "TestTheTreesSmallerRows"),
        ],
    )
    def test_the_entry_names_the_test(self, rid, test):
        text = (ROOT / "docs/SAFETY_INVARIANTS.md").read_text(encoding="utf-8")
        section = text.split(f"### {rid} ")[1].split("\n### ")[0].split("\n## ")[0]
        assert test in section, f"{rid} does not name {test}"
