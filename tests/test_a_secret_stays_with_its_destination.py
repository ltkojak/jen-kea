"""Q228: the ONE Q of Opus's pass on v7.0.0-beta.13 (AN1-AN25) and of the independent review of the same tag (five findings).

The pass named one habit with six instances: a fix written against the instance that was reported, with "where else is this true?" asked of the code that was touched and not
of the rule. Every class here holds a rule at the place the last release did not carry it to.

review #1, AN2   an OIDC issuer is compared WITH its path, and a client secret belongs to one client registration.
review #2        a webhook's header value and an ntfy token are kept only for the same destination, path and query included.
review #3        a blank optional secret with nothing stored to keep is "none", never a secret to carry.
review #4        the MFA countdown is the Nth most recent attempt's, as the password countdown has been since Q226.
review #5, AN1   a page shows an address only when it is a plain one; a stored address with a password or a token in it is withheld.
AN6              a typed address is an http(s) URL with a host: `u:p@host/path` has no authority to read user-info from.
AN3              every count of channels a page prints asks the service.
AN4              a count that could not be read says so.
AN11             the IPv6 switch's audit row says whether the row was stored.
AN13             an alert type is stored once.
AN20             a running configuration that is not an object has its own sentence at the top level too.
AN21             a File over SSH target whose restore raised is not known.
"""

import ast
import copy
import pathlib
import re
from contextlib import contextmanager

import pytest

from jen.services import alerts, auth, kea_host
from jen.services import kea_api_config as api
from jen.services import kea_changeset as cs
from tests._kea_host_fakes import FakeHelper

ROOT = pathlib.Path(__file__).resolve().parents[1]


def _function(rel: str, name: str) -> str:
    src = (ROOT / rel).read_text(encoding="utf-8")
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == name)
    return ast.get_source_segment(src, fn)


def _route():
    from jen.routes.settings import alerts as route

    return route


class _Principal:
    def __init__(self, all_subnets: bool, ids=()):
        self.all_subnets = all_subnets
        self._ids = list(ids)

    def accessible_subnet_ids(self, subnet_map):
        return list(self._ids)


# ── the destination of a secret ─────────────────────────────────────────────────────────


class TestTheDestinationIsThePlaceAndThePath:
    """`same_endpoint` stops at the port, by design: a Kea endpoint is dialed at its root. An OIDC issuer, a webhook and an ntfy server are spent on a path."""

    @pytest.mark.parametrize(
        "a, b, same",
        [
            ("https://login.example.test/tenant-a/v2.0", "https://login.example.test/tenant-a/v2.0", True),
            ("https://login.example.test/tenant-a/v2.0", "https://login.example.test/tenant-a/v2.0/", True),
            ("https://LOGIN.example.test:443/tenant-a/v2.0", "https://login.example.test/tenant-a/v2.0", True),
            ("https://login.example.test/tenant-a/v2.0", "https://login.example.test/tenant-b/v2.0", False),
            ("https://idp.example.test/realms/jen", "https://idp.example.test/realms/second", False),
            ("https://idp.example.test/realms/jen", "https://idp2.example.test/realms/jen", False),
            ("https://idp.example.test/realms/jen", "http://idp.example.test/realms/jen", False),
            ("https://idp.example.test/realms/jen", "https://idp.example.test:8443/realms/jen", False),
            ("https://hooks.example.test/in?team=a", "https://hooks.example.test/in?team=b", False),
            ("https://hooks.example.test/in?team=a", "https://hooks.example.test/in?team=a", True),
            ("https://hooks.example.test", "https://hooks.example.test/", True),
            ("https://hooks.example.test/team-a", "", False),
            ("", "", False),
            ("https://someone:pw@ntfy.example.test/x", "https://ntfy.example.test/x", True),
        ],
    )
    def test_what_one_destination_is(self, a, b, same):
        assert auth.same_destination(a, b) is same
        assert auth.same_destination(b, a) is same

    def test_the_kea_comparison_is_left_as_it_was(self):
        # the control: the path is NOT part of a Kea endpoint, and this Q does not make it one
        assert auth.same_endpoint("https://idp.example.test/realms/jen", "https://idp.example.test/realms/second")
        assert "never the path or the query" in (auth.same_endpoint.__doc__ or "")

    def test_the_discovery_url_is_built_from_the_path_the_comparison_reads(self):
        src = _function("jen/services/oidc.py", "init_oidc")
        assert 'extensions.OIDC_ISSUER.rstrip("/") + "/.well-known/openid-configuration"' in src
        assert '.path.rstrip("/")' in _function("jen/services/auth.py", "same_destination")


class TestTheOidcSecretStaysWithItsIssuerAndItsClient:
    """Review #1 and AN2 (CRED-002). Q227 asked `same_endpoint` of the issuer: two realms of one Keycloak, or two tenants of one login host, were one place to the guard and two
    to the client. And a secret belongs to one client registration."""

    def test_the_route_compares_the_destination_and_the_client(self):
        src = _function("jen/routes/settings/security.py", "save_oidc")
        assert "not __auth.same_destination(issuer, extensions.OIDC_ISSUER)" in src
        assert "client_id != extensions.OIDC_CLIENT_ID" in src
        assert "same_endpoint(" not in src
        assert src.index('flash_field("client_secret", OIDC_ISSUER_CHANGED)') < src.index(
            "__config.app_config.write_values(items)"
        )
        assert src.index('flash_field("client_secret", OIDC_CLIENT_CHANGED)') < src.index(
            "__config.app_config.write_values(items)"
        )

    def test_the_sentences(self):
        from jen.routes.settings import security

        assert security.OIDC_CLIENT_CHANGED == "The client ID changed - enter the client secret again."
        assert security.OIDC_SAVED == (
            "Single sign-on settings saved. A change to the issuer, the client ID or the client secret takes effect when Jen restarts."
        )

    def test_the_save_says_when_it_takes_effect(self):
        # AN2, second order: the client is registered once, in create_app, and the page said only "saved"
        assert 'flash(OIDC_SAVED, "success")' in _function("jen/routes/settings/security.py", "save_oidc")
        callers = [
            p.relative_to(ROOT).as_posix()
            for base in ("jen", "plugins")
            for p in sorted((ROOT / base).rglob("*.py"))
            if re.search(r"\binit_oidc\(", p.read_text(encoding="utf-8")) and p.name != "oidc.py"
        ]
        assert callers == ["jen/__init__.py"], (
            "a second caller of init_oidc changes when a save takes effect: OIDC_SAVED must say so"
        )


# ── an alert channel's kept secret ──────────────────────────────────────────────────────


def _kept(monkeypatch, channel_type, new, old, old_type=None, readable=True):
    monkeypatch.setattr("jen.services.alerts.get_channel_config", lambda row: dict(old) if readable else {})
    stored = {"id": 4, "channel_type": old_type or channel_type, "config": "x"}
    return _route()._kept_secrets(4, channel_type, dict(new), stored), stored


HOOK = {
    "webhook_url": "https://hooks.example.test/team-a",
    "payload_type": "json",
    "header_name": "Authorization",
    "header_value": "TEAM_A_SECRET",
}
NTFY = {"url": "https://ntfy.example.test/base", "topic": "jen", "token": "tk_SECRET", "priority": "default"}


class TestAKeptSecretIsJudgedByTheWholeAddress:
    """Review #2 (CRED-002): the header value typed for /team-a was carried to /team-b, because the comparison stopped at the port."""

    def test_the_same_url_keeps_the_header_value(self, monkeypatch):
        out, _ = _kept(monkeypatch, "webhook", {**HOOK, "header_value": ""}, HOOK)
        assert out["header_value"] == "TEAM_A_SECRET"

    def test_a_blank_url_is_the_stored_one(self, monkeypatch):
        out, _ = _kept(monkeypatch, "webhook", {**HOOK, "webhook_url": "", "header_value": ""}, HOOK)
        assert out["webhook_url"] == HOOK["webhook_url"] and out["header_value"] == "TEAM_A_SECRET"

    @pytest.mark.parametrize(
        "url",
        [
            "https://hooks.example.test/team-b",
            "https://hooks.example.test/team-a?tenant=b",
            "https://hooks2.example.test/team-a",
            "http://hooks.example.test/team-a",
            "https://hooks.example.test:8443/team-a",
        ],
    )
    def test_a_changed_address_refuses_the_blank_header_value(self, monkeypatch, url):
        out, _ = _kept(monkeypatch, "webhook", {**HOOK, "webhook_url": url, "header_value": ""}, HOOK)
        assert out == ("header_value", _route().DESTINATION_CHANGED)

    def test_a_changed_address_with_the_secret_typed_again_is_saved(self, monkeypatch):
        new = {**HOOK, "webhook_url": "https://hooks.example.test/team-b", "header_value": "TEAM_B_SECRET"}
        out, _ = _kept(monkeypatch, "webhook", new, HOOK)
        assert out["header_value"] == "TEAM_B_SECRET" and out["webhook_url"].endswith("/team-b")

    def test_a_changed_header_name_keeps_the_value(self, monkeypatch):
        # decided: the same receiver is sent the value under another name. The destination did not change
        out, _ = _kept(monkeypatch, "webhook", {**HOOK, "header_name": "X-Token", "header_value": ""}, HOOK)
        assert out["header_value"] == "TEAM_A_SECRET" and out["header_name"] == "X-Token"

    def test_a_webhook_with_no_header_changes_its_address(self, monkeypatch):
        old = {**HOOK, "header_name": "", "header_value": ""}
        new = {**old, "webhook_url": "https://hooks.example.test/team-b"}
        out, _ = _kept(monkeypatch, "webhook", new, old)
        assert out["webhook_url"].endswith("/team-b") and out["header_value"] == ""

    def test_an_ntfy_token_stays_with_its_server_and_path(self, monkeypatch):
        out, _ = _kept(monkeypatch, "ntfy", {**NTFY, "token": ""}, NTFY)
        assert out["token"] == "tk_SECRET"
        out, _ = _kept(monkeypatch, "ntfy", {**NTFY, "topic": "second", "token": ""}, NTFY)
        assert out["token"] == "tk_SECRET", "the topic is not the server: the token is the server's"
        for url in (
            "https://ntfy.example.test/elsewhere",
            "https://ntfy2.example.test/base",
            "http://ntfy.example.test/base",
        ):
            out, _ = _kept(monkeypatch, "ntfy", {**NTFY, "url": url, "token": ""}, NTFY)
            assert out == ("ntfy_token", _route().DESTINATION_CHANGED), url

    def test_a_blank_ntfy_address_is_the_stored_one(self, monkeypatch):
        # AN1: a withheld address comes back blank from the form, and a blank keeps what is stored - never the default server
        old = {**NTFY, "url": "https://alice:OLDPASSWORD@ntfy.example.test"}
        out, _ = _kept(monkeypatch, "ntfy", {**NTFY, "url": "", "token": ""}, old)
        assert out["url"] == old["url"] and out["token"] == "tk_SECRET"

    def test_the_same_server_retyped_without_its_password_keeps_the_token(self, monkeypatch):
        old = {**NTFY, "url": "https://alice:OLDPASSWORD@ntfy.example.test/base"}
        out, _ = _kept(monkeypatch, "ntfy", {**NTFY, "token": ""}, old)
        assert out["url"] == NTFY["url"] and out["token"] == "tk_SECRET"

    def test_the_route_asks_the_destination(self):
        src = _function("jen/routes/settings/alerts.py", "_kept_secrets")
        assert "__auth.same_destination(_endpoint(channel_type, config), _endpoint(channel_type, old))" in src
        assert "same_endpoint(" not in src


class TestABlankOptionalSecretIsNone:
    """Review #3: the blanks were judged before anyone asked whether a secret was stored for them. A Telegram channel could not become a webhook with no authorization header, and a
    channel whose stored settings were unreadable could not be re-entered without inventing one."""

    def test_the_optional_secrets_are_write_only_keys(self):
        route = _route()
        for channel_type, keys in route.OPTIONAL_SECRETS.items():
            assert set(keys) <= set(route.WRITE_ONLY_KEYS[channel_type]), channel_type
        assert route.OPTIONAL_SECRETS == {"webhook": ("header_value",), "ntfy": ("token",), "email": ("smtp_pass",)}
        assert set(route.SECRET_LABELS) == {k for keys in route.OPTIONAL_SECRETS.values() for k in keys}

    def test_telegram_becomes_a_webhook_with_no_header(self, monkeypatch):
        new = {
            "webhook_url": "https://hooks.example.test/in",
            "payload_type": "json",
            "header_name": "",
            "header_value": "",
        }
        out, _ = _kept(monkeypatch, "webhook", new, {"token": "123:abc", "chat_id": "9"}, old_type="telegram")
        assert out == new

    def test_email_becomes_ntfy_with_no_token(self, monkeypatch):
        old = {"smtp_host": "mail.example.test", "smtp_port": "587", "smtp_pass": "s3cret"}
        out, _ = _kept(monkeypatch, "ntfy", {**NTFY, "token": ""}, old, old_type="email")
        assert out["token"] == "" and out["url"] == NTFY["url"]

    def test_a_type_change_never_carries_a_secret_across(self, monkeypatch):
        # both types name `token`: Telegram's bot token is not an ntfy access token
        out, _ = _kept(
            monkeypatch, "ntfy", {**NTFY, "token": ""}, {"token": "123:abc", "chat_id": "9"}, old_type="telegram"
        )
        assert out["token"] == ""

    @pytest.mark.parametrize(
        "channel_type, new, field",
        [
            ("slack", {"webhook_url": ""}, "slack_webhook"),
            ("telegram", {"token": "", "chat_id": "9"}, "token"),
            ("webhook", {"webhook_url": "", "header_name": "", "header_value": ""}, "webhook_url"),
            ("pushover", {"user_key": "u", "api_token": ""}, "pushover_api_token"),
        ],
    )
    def test_a_type_change_with_a_needed_secret_blank_is_refused(self, monkeypatch, channel_type, new, field):
        out, _ = _kept(monkeypatch, channel_type, new, {"smtp_host": "m", "smtp_pass": "p"}, old_type="email")
        assert out == (field, _route().DESTINATION_CHANGED)

    def test_an_unreadable_row_takes_a_whole_new_config(self, monkeypatch):
        new = {
            "webhook_url": "https://hooks.example.test/in",
            "payload_type": "json",
            "header_name": "",
            "header_value": "",
        }
        out, stored = _kept(monkeypatch, "webhook", new, {}, readable=False)
        assert out == new
        assert _route()._emptied("webhook", out, stored) == ["the authorization header value"]

    def test_an_unreadable_row_with_its_needed_secret_blank_is_refused(self, monkeypatch):
        route = _route()
        out, _ = _kept(monkeypatch, "webhook", {**HOOK, "webhook_url": "", "header_value": ""}, {}, readable=False)
        assert out == ("webhook_url", route.STORED_UNREADABLE)
        out, _ = _kept(monkeypatch, "telegram", {"token": "", "chat_id": "9"}, {}, readable=False)
        assert out == ("token", route.STORED_UNREADABLE)

    def test_a_readable_row_empties_nothing(self, monkeypatch):
        out, stored = _kept(
            monkeypatch, "webhook", {**HOOK, "header_name": "", "header_value": ""}, {**HOOK, "header_value": ""}
        )
        assert _route()._emptied("webhook", out, stored) == []
        assert _route()._emptied("webhook", out, None) == []

    def test_the_save_names_what_is_empty_now(self):
        route = _route()
        src = _function("jen/routes/settings/alerts.py", "save_alert_channel")
        assert "emptied = _emptied(channel_type, config, stored)" in src
        assert 'flash(NOTHING_KEPT.format(fields=", ".join(emptied)), "warning")' in src
        assert route.NOTHING_KEPT.format(fields="the access token") == (
            "This channel's stored settings could not be read, so nothing was kept from them. Empty now: the access token."
        )

    def test_a_changed_destination_with_a_stored_secret_is_still_refused(self, monkeypatch):
        old = {"smtp_host": "mail.example.test", "smtp_port": "587", "smtp_pass": "s3cret", "use_tls": "true"}
        out, _ = _kept(monkeypatch, "email", {**old, "smtp_host": "elsewhere.example.test", "smtp_pass": ""}, old)
        assert out == ("smtp_pass", _route().DESTINATION_CHANGED)


# ── an address on a page, and an address typed ──────────────────────────────────────────


class TestThePageWithholdsAnAddressThatIsNotPlain:
    """Review #5 and AN1 (CRED-005 at the display): Q227 refused a password in a TYPED address and still printed the one an earlier release stored."""

    @pytest.mark.parametrize(
        "url, plain",
        [
            ("https://ntfy.sh", True),
            ("https://ntfy.example.test:8443/base", True),
            ("http://10.0.0.5", True),
            ("https://alice:OLDPASSWORD@ntfy.example.test", False),
            ("https://alice@ntfy.example.test", False),
            ("https://ntfy.example.test/?auth=QmVhcmVyIHRrXw", False),
            ("https://ntfy.example.test/#frag", False),
            ("alice:OLDPASSWORD@ntfy.example.test/x", False),
            ("ntfy.example.test", False),
            ("ftp://ntfy.example.test", False),
            ("", False),
            (None, False),
        ],
    )
    def test_what_a_plain_address_is(self, url, plain):
        assert auth.plain_address(url) is plain

    @pytest.mark.parametrize(
        "url",
        [
            "https://alice:OLDPASSWORD@ntfy.example.test",
            "https://ntfy.example.test/?auth=OLDPASSWORD",
            "alice:OLDPASSWORD@ntfy.example.test/x",
        ],
    )
    def test_a_stored_address_that_is_not_plain_is_withheld(self, url):
        shown = _route()._shown("ntfy", {"url": url, "topic": "jen", "token": "tk_SECRET", "priority": "high"})
        assert shown == {"topic": "jen", "priority": "high", "url_withheld": True}
        assert "OLDPASSWORD" not in repr(shown) and "tk_SECRET" not in repr(shown)

    def test_a_plain_address_is_shown_and_a_blank_one_is_not_called_withheld(self):
        route = _route()
        assert route._shown("ntfy", {"url": "https://ntfy.sh", "topic": "jen"}) == {
            "url": "https://ntfy.sh",
            "topic": "jen",
        }
        assert route._shown("ntfy", {"url": "", "topic": "jen"}) == {"url": "", "topic": "jen"}

    def test_every_address_a_page_may_show_goes_through_the_question(self):
        # the address keys, and which of them SHOWN_KEYS names: a new shown address is withheld by the same line
        route = _route()
        assert route.ADDRESS_KEY == {"webhook": "webhook_url", "ntfy": "url"}
        shown_addresses = {t: k for t, k in route.ADDRESS_KEY.items() if k in route.SHOWN_KEYS[t]}
        assert shown_addresses == {"ntfy": "url"}
        assert "not __auth.plain_address(out[address])" in _function("jen/routes/settings/alerts.py", "_shown")

    def test_the_card_and_the_form_say_it_is_kept(self):
        html = (ROOT / "templates/settings_alerts.html").read_text(encoding="utf-8")
        assert "{% if ch.config.get('url_withheld') %}" in html
        assert "so it is not shown. It is still used as saved." in html
        assert "u.value = cfg.url_withheld ? '' : (cfg.url || 'https://ntfy.sh');" in html
        assert "u.placeholder = cfg.url_withheld ? 'Saved - leave blank to keep' : 'https://ntfy.sh';" in html
        assert "cfg.url || 'https://ntfy.sh'; " not in html


class TestATypedAddressIsAnHttpUrl:
    """AN6: `userinfo_sentence` reads the authority, and `u:p@host/path` has none, so nine refusals were right and that value was stored with its password."""

    @pytest.mark.parametrize(
        "channel_type, key, value, want",
        [
            ("webhook", "webhook_url", "https://u:p@hooks.example.test/in", "userinfo"),
            ("ntfy", "url", "https://u:p@ntfy.example.test", "userinfo"),
            ("webhook", "webhook_url", "u:p@hooks.example.test/in", "scheme"),
            ("ntfy", "url", "u:p@ntfy.example.test/x", "scheme"),
            ("webhook", "webhook_url", "hooks.example.test/in", "scheme"),
            ("ntfy", "url", "ftp://ntfy.example.test", "scheme"),
            ("ntfy", "url", "https://ntfy.example.test/?auth=abc", "ntfy"),
            ("ntfy", "url", "https://ntfy.example.test/#x", "ntfy"),
            ("webhook", "webhook_url", "https://hooks.example.test/in?token=abc", None),
            ("webhook", "webhook_url", "https://hooks.example.test/in", None),
            ("ntfy", "url", "https://ntfy.sh", None),
            ("ntfy", "url", "http://10.0.0.5:8080/ntfy", None),
            ("webhook", "webhook_url", "", None),
            ("ntfy", "url", "", None),
            ("slack", "webhook_url", "u:p@anything", None),
        ],
    )
    def test_what_is_refused(self, channel_type, key, value, want):
        route = _route()
        sentence = {
            "userinfo": auth.USERINFO_SENTENCE,
            "scheme": route.ADDRESS_NEEDS_SCHEME,
            "ntfy": route.NTFY_ADDRESS_SHAPE,
        }.get(want)
        got = route._address_refusal(channel_type, {key: value})
        assert (got[1] if got else None) == sentence
        if got:
            assert got[0] == {"webhook_url": "webhook_url", "url": "ntfy_url"}[key]
            assert value not in got[1], "a refusal never echoes the address"

    def test_the_save_asks_it_before_anything_is_kept_or_written(self):
        src = _function("jen/routes/settings/alerts.py", "save_alert_channel")
        assert src.index("refused = _address_refusal(channel_type, config)") < src.index("kept = _kept_secrets(")
        assert src.index("kept = _kept_secrets(") < src.index("encode_channel_config(config)")


# ── the MFA countdown ───────────────────────────────────────────────────────────────────


class _MfaCursor:
    """`mfa_attempts` for one user as a list of attempt ages in seconds."""

    def __init__(self, ages):
        self.ages = sorted(ages)
        self.queries, self.params, self._last = [], [], None

    def execute(self, sql, params=()):
        self.queries.append(sql)
        self.params.append(tuple(params))
        window = auth.MFA_LOCKOUT_MINUTES * 60
        inside = [a for a in self.ages if a <= window]
        if "COUNT(*)" in sql:
            self._last = {"cnt": len(inside)}
        elif "OFFSET" in sql:
            offset = params[-1]
            self._last = {"age": inside[offset]} if offset < len(inside) else None
        else:
            raise AssertionError(f"a statement this table does not know: {sql}")

    def fetchone(self):
        return self._last


def _mfa(monkeypatch, ages):
    cur = _MfaCursor(ages)

    @contextmanager
    def ctx():
        class _Db:
            def cursor(self):
                @contextmanager
                def c():
                    yield cur

                return c()

        yield _Db()

    monkeypatch.setattr(auth, "__jen_db_ctx", ctx, raising=False)
    return auth.is_mfa_locked_out(3), cur


M = 60


class TestTheMfaCountdownIsTheNthNewest:
    """Review #4: Q226 moved `is_locked_out` from the OLDEST attempt to the Nth most recent and left this twin on MIN(). The lock was right; the number was not."""

    def test_the_reviews_own_case(self, monkeypatch):
        # eleven failures aged 1 to 10 and 14 minutes, a threshold of 10 and 15 minutes: MIN() promised one minute; the tenth newest is ten minutes old, so five remain
        (locked, minutes), cur = _mfa(monkeypatch, [m * M for m in (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 14)])
        assert (locked, minutes) == (True, 5)
        assert cur.params[-1] == (3, auth.MFA_LOCKOUT_MINUTES, auth.MFA_MAX_ATTEMPTS - 1)

    @pytest.mark.parametrize(
        "ages, want",
        [
            ([M] * 9, (False, 0)),
            ([M] * 10, (True, 14)),
            ([10] * 20, (True, 15)),
            ([14 * M] * 10, (True, 1)),
            ([15 * M] * 10, (True, 1)),
            ([15 * M + 1] * 10, (False, 0)),
            ([M] * 5 + [16 * M] * 30, (False, 0)),
            ([2 * M] * 9 + [13 * M], (True, 2)),
            ([], (False, 0)),
        ],
    )
    def test_the_count_and_the_minutes(self, monkeypatch, ages, want):
        assert _mfa(monkeypatch, ages)[0] == want

    def test_the_oldest_attempt_is_not_asked(self):
        src = _function("jen/services/auth.py", "is_mfa_locked_out")
        assert "MIN(attempted_at)" not in src
        assert "ORDER BY attempted_at DESC LIMIT 1 OFFSET %s" in src
        assert "(user_id, MFA_LOCKOUT_MINUTES, MFA_MAX_ATTEMPTS - 1)" in src

    def test_no_countdown_under_jen_reads_the_oldest_attempt(self):
        # the definition's every use: a countdown computed from MIN(attempted_at) anywhere is this defect again
        hits = [
            p.relative_to(ROOT).as_posix()
            for base in ("jen", "plugins")
            for p in sorted((ROOT / base).rglob("*.py"))
            if "MIN(attempted_at)" in p.read_text(encoding="utf-8")
        ]
        assert hits == []

    def test_a_table_that_cannot_be_read_is_a_lockout(self, monkeypatch):
        @contextmanager
        def broken():
            raise RuntimeError("mfa_attempts is gone")
            yield

        monkeypatch.setattr(auth, "__jen_db_ctx", broken, raising=False)
        assert auth.is_mfa_locked_out(3) == (True, 1)


# ── counts ──────────────────────────────────────────────────────────────────────────────


ROWS = [
    {"subnet_scope": None},
    {"subnet_scope": "[1]"},
    {"subnet_scope": "[3]"},
    {"subnet_scope": "[]"},
    {"subnet_scope": "[1, 2]"},
]


class TestEveryChannelCountAsksTheService:
    """AN3: Q227 counted the channels an account may act on at `/settings` and left `/getting-started` on a bare COUNT(*), read by the same subnet-restricted admin."""

    @pytest.mark.parametrize(
        "principal, want",
        [
            (_Principal(True), 5),
            (_Principal(False, [1, 2]), 2),
            (_Principal(False, [1]), 1),
            (_Principal(False, []), 0),
        ],
    )
    def test_the_number(self, principal, want):
        assert alerts.enabled_channels_for(principal, ROWS) == want

    def test_a_channel_for_every_subnet_and_a_damaged_scope_are_inside_nobodys_restriction(self):
        restricted = _Principal(False, [1, 2, 3])
        assert alerts.channel_inside({"subnet_scope": None}, restricted) is False
        assert alerts.channel_inside({"subnet_scope": "[]"}, restricted) is False
        assert alerts.channel_inside({"subnet_scope": "garbage"}, restricted) is False
        assert alerts.channel_inside({"subnet_scope": "[2, 3]"}, restricted) is True
        assert alerts.channel_inside({"subnet_scope": "[2, 4]"}, restricted) is False

    def test_the_alerts_page_asks_the_same_function(self):
        assert "return __alerts.channel_inside(channel, current_user)" in _function(
            "jen/routes/settings/alerts.py", "_may_act_on"
        )

    def test_both_pages_ask_it(self):
        assert "__alerts.enabled_channels_for(current_user, cur.fetchall())" in _function(
            "jen/routes/settings/__init__.py", "_enabled_channels"
        )
        assert "__alerts.enabled_channels_for(user, cur.fetchall())" in _function(
            "jen/services/onboarding.py", "build_ctx"
        )

    def test_no_statement_under_jen_counts_alert_channels_in_sql(self):
        # the whole tree: a COUNT(*) over alert_channels cannot ask whose channels they are
        hits = []
        for base in ("jen", "plugins"):
            for p in sorted((ROOT / base).rglob("*.py")):
                if p.name == "migrations.py":
                    continue  # a migration counts rows to decide whether to seed; it prints no page
                for m in re.finditer(
                    r"COUNT\([^)]*\)[^\"']*FROM\s+alert_channels", p.read_text(encoding="utf-8"), re.I
                ):
                    hits.append(f"{p.relative_to(ROOT).as_posix()}: {m.group(0)}")
        assert hits == []


class TestACountThatCannotBeReadSaysSo:
    """AN4: `_count` answers None for a table it could not read, and the Security page printed "0 account name(s), 0 address(es)" while `is_locked_out` failed closed."""

    def test_the_security_page_is_handed_none(self):
        src = _function("jen/routes/settings/__init__.py", "settings_security")
        assert "rl_lockouts_username=rl_lockouts_username," in src and "rl_lockouts_ip=rl_lockouts_ip," in src
        assert "rl_active_ips=rl_active_ips," in src and "rl_attempts_1h=rl_attempts_1h," in src
        assert " or 0," not in src, "a count of this card that could not be read is not 0"

    def test_the_card_says_it_could_not_be_read(self):
        html = (ROOT / "templates/settings_security.html").read_text(encoding="utf-8")
        assert (
            "{% if rl_lockouts_username is none or rl_lockouts_ip is none %}could not be read - logins are refused while"
            in html
        )

    def test_the_card_renders_both_ways(self):
        import jinja2

        html = (ROOT / "templates/settings_security.html").read_text(encoding="utf-8")
        cell = re.search(r'<strong class="u-52df2b" id="rl-permanent-lockouts">(.*?)</strong>', html, re.S).group(1)
        render = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=True).from_string(cell).render
        assert render(rl_lockouts_username=2, rl_lockouts_ip=0) == "2 account name(s), 0 address(es)"
        assert render(rl_lockouts_username=0, rl_lockouts_ip=0) == "0 account name(s), 0 address(es)"
        for a, b in ((None, 0), (0, None), (None, None)):
            assert render(rl_lockouts_username=a, rl_lockouts_ip=b).startswith("could not be read")

    @pytest.mark.parametrize("ident, name", [("rl-attempts-1h", "rl_attempts_1h"), ("rl-active-ips", "rl_active_ips")])
    def test_the_two_counts_beside_it_say_so_too(self, ident, name):
        import jinja2

        html = (ROOT / "templates/settings_security.html").read_text(encoding="utf-8")
        cell = re.search(rf'<strong class="u-52df2b" id="{ident}">(.*?)</strong>', html, re.S).group(1)
        render = jinja2.Environment(undefined=jinja2.StrictUndefined, autoescape=True).from_string(cell).render
        assert render(**{name: None}) == "could not be read"
        assert render(**{name: 0}) == "0" and render(**{name: 7}) == "7"

    def test_every_count_the_settings_pages_read_is_judged_for_none(self):
        # the whole file: `_count` answers None for a table it could not read, and each of its eight callers either prints that or skips its line
        src = (ROOT / "jen/routes/settings/__init__.py").read_text(encoding="utf-8")
        assert src.count("= _count(") == 8, "a new caller of _count: say what it prints when the table cannot be read"
        assert " or 0" not in src.split("def settings_security")[1].split("\ndef ")[0]

    def test_the_landing_page_prints_no_none(self):
        src = (ROOT / "jen/routes/settings/__init__.py").read_text(encoding="utf-8")
        assert '[("channels could not be counted", "warn")]' in src and "if channels is None" in src


# ── the smaller rows ────────────────────────────────────────────────────────────────────


class TestTheSmallerRows:
    def test_an_alert_type_is_stored_once(self):  # AN13
        assert 'alert_types = list(dict.fromkeys(request.form.getlist("alert_types[]")))' in _function(
            "jen/routes/settings/alerts.py", "save_alert_channel"
        )
        assert list(dict.fromkeys(["new_lease", "kea_down", "new_lease"])) == ["new_lease", "kea_down"]

    def test_the_ipv6_audit_row_says_whether_the_row_was_stored(self):  # AN11
        src = _function("jen/routes/settings/infrastructure.py", "toggle_ipv6")
        assert "servers={len(results)} stored={stored}" in src
        assert 'stored = "not attempted"' in src
        assert 'stored = "yes" if __user.set_global_setting("ipv6_enabled", "false") else "no"' in src
        # the server warning is no longer behind the failed write's `elif`
        disable = src[src.index('stored = "yes" if __user.set_global_setting("ipv6_enabled", "false")') :]
        assert disable.index("if not all_ok:") < disable.index('elif stored == "yes":')
        assert "elif not all_ok:" not in disable

    def test_a_configuration_that_is_not_an_object_has_its_own_sentence(self):  # AN20
        src = _function("jen/services/kea_api_config.py", "apply")
        top = src.index("is not one Jen can read (it is not an object); the file was not judged")
        section = src.index("section is not an object); the file was not judged")
        empty = src.index("came back empty; the file was not judged")
        assert 0 < top < section < empty
        assert "elif not isinstance(live_now, dict):" in src

    @pytest.mark.parametrize("cfg", [[{"Dhcp4": {}}], "text", 3])
    def test_the_shape_the_sentence_names_has_no_section(self, cfg):
        # AN23: Q227's cell used `[]`, which the tag before it already handled, so it passed on both trees. These do not
        assert api._section(cfg, "dhcp4") == {}
        assert not isinstance(cfg, dict)


SERVER_A = {"id": 1, "name": "kea-a", "ssh_host": "10.0.0.1"}
SERVER_B = {"id": 2, "name": "kea-b", "ssh_host": "10.0.0.2"}


@pytest.fixture
def helper(monkeypatch):
    f = FakeHelper()
    for sid, sha in ((1, "sha-a"), (2, "sha-b")):
        f.configs[(sid, "dhcp4")] = {"Dhcp4": {"subnet4": [{"id": 1}]}}
        f.shas[(sid, "dhcp4")] = sha
    monkeypatch.setattr(kea_host, "helper_call", f.helper_call)
    monkeypatch.setattr(kea_host, "record_helper_status", lambda *a, **k: None)
    monkeypatch.setattr(kea_host, "helper_status", dict)
    monkeypatch.setattr("jen.services.investigation_logging.file_write_refusal", lambda server, cfg: "")
    monkeypatch.setattr("jen.services.config_revisions.latest", lambda *a, **k: None)
    monkeypatch.setattr("jen.services.config_revisions.record", lambda *a, **k: None)
    monkeypatch.setattr(cs, "record_outcome", lambda *a, **k: None)
    return f


def _add_pool(cfg):
    out = copy.deepcopy(cfg)
    out["Dhcp4"]["subnet4"][0].setdefault("pools", []).append({"pool": "10.0.0.10 - 10.0.0.20"})
    return out, "ok"


class TestAFileRestoreThatRaisedIsNotKnown:
    """AN21: Q227 read `_safe`'s `raised` for an api target only. `_restore_target` wraps the file restore in `_safe` too, and a file target whose restore RAISED read "still have
    the NEW config" - which may be false, because the helper's replace may have put the old file back before the raise."""

    def _run(self, helper, revert):
        helper.responses["test-config"] = {"ok": True}
        seen = {"a": 0}

        def apply_resp(server, op, payload):
            if server["id"] == 1:
                seen["a"] += 1
                if seen["a"] == 1:
                    return {"ok": True, "sha256": "new-a", "helper_version": 2}
                return revert()
            return {"ok": False, "error": "conflict", "helper_version": 2}

        helper.responses["apply-config"] = apply_resp
        result = cs.apply_change("dhcp4", _add_pool, "test change", servers=[SERVER_A, SERVER_B])
        assert result.status == "rollback_failed", result.lines
        (line,) = [text for _k, text in result.lines if "ROLLBACK FAILED" in text]
        return line, result

    def test_a_restore_that_raised_claims_neither_config(self, helper):
        def raised():
            raise RuntimeError("the connection was reset")

        line, result = self._run(helper, raised)
        assert f"kea-a: {cs.RESTORE_NOT_KNOWN}" in line, line
        assert "still have the NEW config" not in line, line
        assert "kea-b was never changed" in line and result.needs_hands == ["kea-a"]

    def test_the_control_a_restore_that_was_refused_still_has_the_new_config(self, helper):
        line, _ = self._run(helper, lambda: {"ok": False, "error": "conflict", "helper_version": 2})
        assert "kea-a still have the NEW config" in line and "is not known" not in line, line

    def test_the_sentence_says_where_to_look(self):
        assert "is not known" in cs.RESTORE_NOT_KNOWN and "Config history" in cs.RESTORE_NOT_KNOWN
        assert "over the API" not in cs.RESTORE_NOT_KNOWN


# ── the registry ────────────────────────────────────────────────────────────────────────


class TestTheRegistryCarriesThisReleasesRules:
    @pytest.mark.parametrize(
        "entry, tests",
        [
            (
                "CRED-002",
                [
                    "TestTheDestinationIsThePlaceAndThePath",
                    "TestTheOidcSecretStaysWithItsIssuerAndItsClient",
                    "TestAKeptSecretIsJudgedByTheWholeAddress",
                    "TestABlankOptionalSecretIsNone",
                ],
            ),
            ("CRED-005", ["TestThePageWithholdsAnAddressThatIsNotPlain", "TestATypedAddressIsAnHttpUrl"]),
            ("RBAC-001", ["TestEveryChannelCountAsksTheService"]),
            ("RBAC-003", ["TestTheMfaCountdownIsTheNthNewest"]),
            ("FAIL-001", ["TestACountThatCannotBeReadSaysSo"]),
            ("CFG-002", ["TestAFileRestoreThatRaisedIsNotKnown"]),
        ],
    )
    def test_each_entry_names_its_new_tests(self, entry, tests):
        text = (ROOT / "docs/SAFETY_INVARIANTS.md").read_text(encoding="utf-8")
        start = text.index(f"### {entry} - ")
        end = text.find("\n### ", start + 1)
        body = text[start : end if end != -1 else len(text)]
        for name in tests:
            assert f"`tests/test_a_secret_stays_with_its_destination.py::{name}`" in body, (entry, name)
