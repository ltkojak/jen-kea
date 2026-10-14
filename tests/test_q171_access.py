"""
tests/test_q171_access.py
────────────────────────
v5.69.0-beta.2 (Q171) - access control and secrets on Jen's side: the register's P1s and security P2s in the routes, Settings, DDNS, the updater, users and the
plugins. One class per item of the Q, so a regression names the item. The surfaces that carry a role or a subnet boundary are also rows of the authz matrix
(tests/test_authz_matrix.py); the tests here are the ones that assert a WRITE did not happen.
"""

import json
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

from jen import extensions
from tests.conftest import restricted_client

A = {"name": "Alpha-A", "cidr": "10.98.1.0/24"}
B = {"name": "ZZ-SECRET-B", "cidr": "10.77.0.0/24"}


@pytest.fixture
def two_subnets(monkeypatch):
    monkeypatch.setattr(extensions, "SUBNET_MAP", {1: dict(A), 2: dict(B)})


def _stale(client):
    """Make this client's last password confirmation old enough that a step-up route sends it to /auth/reauth."""
    with client.session_transaction() as sess:
        sess["auth_at"] = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()


# ── 1. /subnets/add is for an admin who may see every subnet ────────────────────────────────────────────────────────────────────────────────────


class TestAddSubnetNeedsEverySubnet:
    FORM = {"subnet_id": "9", "name": "New", "cidr": "10.77.0.0/24", "pool": "10.77.0.10-10.77.0.20"}

    def test_a_scoped_admin_gets_the_sentence_and_learns_nothing_on_get(self, client, db, two_subnets):
        c, _ = restricted_client(client, db, [1], role="admin", username="q171_scoped_get")
        r = c.get("/subnets/add", follow_redirects=True)
        body = r.get_data(as_text=True)
        assert "Adding a subnet needs access to all subnets." in body
        assert "ZZ-SECRET-B" not in body and "10.77.0.0/24" not in body

    def test_a_scoped_admin_posting_an_overlapping_cidr_sees_neither_name_nor_cidr_and_creates_nothing(
        self, client, db, two_subnets, monkeypatch
    ):
        from jen.services import kea_changeset

        called = []
        monkeypatch.setattr(kea_changeset, "apply_change", lambda *a, **k: called.append(a))
        c, _ = restricted_client(client, db, [1], role="admin", username="q171_scoped_post")
        r = c.post("/subnets/add", data=self.FORM, follow_redirects=True)
        body = r.get_data(as_text=True)
        assert "Adding a subnet needs access to all subnets." in body
        assert "ZZ-SECRET-B" not in body and "10.77.0.0/24" not in body
        assert called == [], "a scoped admin reached the change set"

    def test_the_overlap_sentence_names_only_what_the_caller_may_see(self, two_subnets):
        import ipaddress

        from jen.routes import subnets

        class Who:
            def __init__(self, ids):
                self.ids = ids

            def can_access_subnet(self, sid):
                return sid in self.ids

        net = ipaddress.IPv4Network("10.77.0.0/24")
        hidden = subnets._overlap_message(net, "10.77.0.0/24", user=Who({1}))
        assert hidden == "CIDR 10.77.0.0/24 overlaps a subnet you do not have access to."
        assert "ZZ-SECRET-B" not in hidden
        seen = subnets._overlap_message(net, "10.77.0.0/24", user=Who({1, 2}))
        assert "ZZ-SECRET-B" in seen and "10.77.0.0/24" in seen
        assert subnets._overlap_message(ipaddress.IPv4Network("10.200.0.0/24"), "10.200.0.0/24", user=Who({1})) is None

    def test_an_unrestricted_admin_still_reaches_the_form_and_the_overlap_check(
        self, client, db, two_subnets, mock_kea
    ):
        c, _ = restricted_client(client, db, None, role="admin", username="q171_all_post")
        r = c.post("/subnets/add", data=self.FORM, follow_redirects=True)
        body = r.get_data(as_text=True)
        assert "overlaps with existing subnet" in body and "ZZ-SECRET-B" in body and "10.77.0.0/24" in body


# ── 2. Jen's own database, Kea's database and the restart: superadmin and step-up ───────────────────────────────────────────────────────────


class TestDatabaseCardsAndRestartAreSuperadminWithStepUp:
    DB = {"host": "evil.example", "user": "u", "password": "p", "database": "d"}
    ROUTES = [
        "/settings/infrastructure/save-jen-db",
        "/settings/infrastructure/save-kea-db",
        "/settings/infrastructure/save-kea6",
        "/settings/infrastructure/restart",
    ]

    @pytest.fixture
    def spies(self, monkeypatch):
        import jen.config as config
        from jen.services import runtime

        calls = {"write": [], "restart": []}
        monkeypatch.setattr(config.app_config, "write_values", lambda items: calls["write"].append(items))
        monkeypatch.setattr(type(config.app_config), "mutate", lambda self, fn, reload=True: calls["write"].append(fn))
        monkeypatch.setattr(runtime, "restart_service", lambda *a, **k: calls["restart"].append(1) or "systemd")
        return calls

    @pytest.mark.parametrize("path", ROUTES)
    @pytest.mark.parametrize("role", ["admin", "viewer"])
    def test_below_superadmin_nothing_is_written_and_nothing_restarts(self, client, db, spies, path, role):
        c, _ = restricted_client(client, db, None, role=role, username=f"q171_db_{role}")
        c.post(path, data=self.DB)
        assert spies["write"] == [] and spies["restart"] == []

    @pytest.mark.parametrize("path", ROUTES)
    def test_a_superadmin_with_a_stale_confirmation_is_sent_to_reauth_and_nothing_happens(
        self, logged_in_client, spies, path
    ):
        _stale(logged_in_client)
        r = logged_in_client.post(path, data=self.DB)
        assert r.status_code == 302 and "/auth/reauth" in r.headers["Location"]
        assert spies["write"] == [] and spies["restart"] == []

    def test_a_fresh_superadmin_saves_both_and_restarts(self, logged_in_client, spies):
        logged_in_client.post("/settings/infrastructure/save-jen-db", data=self.DB)
        logged_in_client.post("/settings/infrastructure/save-kea-db", data=self.DB)
        logged_in_client.post("/settings/infrastructure/restart")
        assert len(spies["write"]) == 2 and spies["restart"] == [1]

    def test_the_connections_tab_hides_the_forms_from_an_admin_and_says_why(self, client, db):
        c, _ = restricted_client(client, db, None, role="admin", username="q171_db_page")
        body = c.get("/settings/databases?tab=connections", follow_redirects=True).get_data(as_text=True)
        assert "Jen MySQL Database" in body
        assert 'action="/settings/infrastructure/save-jen-db"' not in body
        assert 'action="/settings/infrastructure/save-kea-db"' not in body
        assert "Only a superadmin changes where Jen keeps its own data." in body

    def test_the_connections_tab_keeps_the_forms_for_a_superadmin(self, logged_in_client):
        body = logged_in_client.get("/settings/databases?tab=connections", follow_redirects=True).get_data(as_text=True)
        assert 'action="/settings/infrastructure/save-jen-db"' in body
        assert 'action="/settings/infrastructure/save-kea-db"' in body

    def test_the_restart_banner_has_no_button_for_an_admin(self, client, db):
        from jen.models.user import set_global_setting

        set_global_setting("restart_pending", "true")
        try:
            c, _ = restricted_client(client, db, None, role="admin", username="q171_banner")
            body = c.get("/settings/kea", follow_redirects=True).get_data(as_text=True)
            assert 'action="/settings/infrastructure/restart"' not in body
            assert "A superadmin restarts Jen." in body
        finally:
            set_global_setting("restart_pending", "false")


# ── 3. DDNS: one sentence for a failed lookup, the log and the lookup for a caller who may see every subnet, a log path inside /var/log ───────────


class TestDdnsStatusIsScoped:
    @pytest.fixture
    def log(self, monkeypatch):
        from jen.services import kea_host

        calls = []

        def tail(srv, path, lines=200, **kw):
            calls.append(path)
            return {"ok": True, "code": "ok", "lines": ["DDNS-LINE-FOR-B ZZ-SECRET-B 10.77.0.9"], "via": "helper"}

        monkeypatch.setattr(kea_host, "tail_log", tail)
        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "10.0.0.5")
        monkeypatch.setattr(
            extensions, "KEA_SERVERS", [{"id": 1, "name": "kea-a", "ssh_host": "10.0.0.5", "ssh_user": "kea"}]
        )
        return calls

    def test_a_scoped_viewer_gets_the_d2_table_alone_and_the_log_is_never_read(
        self, client, db, mock_kea, log, monkeypatch
    ):
        from jen.routes import ddns

        asked = []
        monkeypatch.setattr(ddns, "_provider_lookup", lambda host: asked.append(host) or "x")
        c, _ = restricted_client(client, db, [1], role="viewer", username="q171_ddns_viewer")
        body = c.get("/ddns?host=anything.example").get_data(as_text=True)
        assert "dhcp4 → D2" in body
        assert "DDNS-LINE-FOR-B" not in body and "ZZ-SECRET-B" not in body
        assert "Recent Log Activity" not in body and "Hostname Lookup" not in body and "Mode &amp; Log Info" not in body
        assert log == [] and asked == [], "a scoped caller reached the log or the provider"

    def test_a_scoped_admin_gets_the_same_status_tab(self, client, db, mock_kea, log):
        c, _ = restricted_client(client, db, [1], role="admin", username="q171_ddns_admin")
        body = c.get("/ddns").get_data(as_text=True)
        assert "Recent Log Activity" not in body and "DDNS-LINE-FOR-B" not in body and log == []

    def test_a_scoped_admin_cannot_open_the_verify_tab_and_no_resolver_is_asked(
        self, client, db, mock_kea, log, monkeypatch
    ):
        """G3 (the release audit): Verify resolves any name and reverse-resolves any address through the Jen host's resolver."""
        import socket

        def boom(*a, **k):
            pytest.fail("the Jen host's resolver was asked on behalf of a scoped caller")

        monkeypatch.setattr(socket, "gethostbyaddr", boom)
        monkeypatch.setattr(socket, "getaddrinfo", boom)
        c, _ = restricted_client(client, db, [1], role="admin", username="q171_ddns_verify")
        body = c.get("/ddns?tab=verify&ip=10.0.0.5&hostname=hidden.example").get_data(as_text=True)
        assert "dhcp4 → D2" in body, "the answer is the Status tab"
        assert "tab=verify" not in body and "Verify</a>" not in body

    def test_an_unrestricted_admin_still_has_the_verify_tab(self, client, db, mock_kea, log):
        a, _ = restricted_client(client, db, None, role="admin", username="q171_ddns_verify_all")
        assert "tab=verify" in a.get("/ddns").get_data(as_text=True)

    def test_a_viewer_sees_no_tab_strip_and_an_admin_sees_all_five(self, client, db, mock_kea, log):
        v, _ = restricted_client(client, db, [1], role="viewer", username="q171_ddns_strip_v")
        body = v.get("/ddns").get_data(as_text=True)
        for label in ("Naming (dhcp4)", "D2 Configuration", "Reconcile"):
            assert label not in body
        a, _ = restricted_client(client, db, None, role="admin", username="q171_ddns_strip_a")
        body = a.get("/ddns").get_data(as_text=True)
        for label in ("Naming (dhcp4)", "D2 Configuration", "Verify", "Reconcile"):
            assert label in body

    def test_an_unrestricted_caller_still_has_the_log_and_the_lookup(self, logged_in_client, mock_kea, log):
        body = logged_in_client.get("/ddns").get_data(as_text=True)
        assert "Recent Log Activity" in body and "DDNS-LINE-FOR-B" in body and "Hostname Lookup" in body
        assert log


class TestDdnsLookupErrorNeverCarriesTheProviderUrl:
    def test_a_connection_error_with_a_token_in_its_url_is_one_sentence(self, monkeypatch, caplog):
        import configparser

        import requests

        from jen.routes import ddns

        cfg = configparser.ConfigParser()
        cfg.read_dict(
            {"ddns": {"dns_provider": "technitium", "api_url": "http://dns.example:5380", "api_token": "SECRET-TOKEN"}}
        )
        monkeypatch.setattr(extensions, "cfg", cfg)

        def boom(*a, **k):
            raise requests.ConnectionError("HTTPConnectionPool: url?token=SECRET-TOKEN&domain=x")

        monkeypatch.setattr(requests, "get", boom)
        with caplog.at_level("WARNING"):
            out = ddns._provider_lookup("host.example")
        assert out == "Lookup failed (the provider did not answer)."
        assert "SECRET-TOKEN" not in out and "SECRET-TOKEN" not in caplog.text
        assert "ConnectionError" in caplog.text

    def test_the_page_never_prints_the_token(self, logged_in_client, mock_kea, monkeypatch):
        import configparser

        import requests

        cfg = configparser.ConfigParser()
        cfg.read_dict({"ddns": {"dns_provider": "pihole", "api_url": "http://pi.example", "api_token": "SECRET-AUTH"}})
        monkeypatch.setattr(extensions, "cfg", cfg)
        monkeypatch.setattr(extensions, "KEA_SSH_HOST", "")

        def boom(*a, **k):
            raise requests.ConnectionError("GET /admin/api.php?auth=SECRET-AUTH failed")

        monkeypatch.setattr(requests, "get", boom)
        monkeypatch.setattr(requests, "post", boom)
        body = logged_in_client.get("/ddns?host=h.example").get_data(as_text=True)
        assert "SECRET-AUTH" not in body and "auth=" not in body
        assert "Lookup failed (the provider did not answer)." in body


class TestDdnsLogPathStaysInsideVarLog:
    @pytest.mark.parametrize(
        "path,ok",
        [
            ("/var/log/kea/kea-ddns.log", True),
            ("/var/log/kea-ddns.log", True),
            ("/etc/shadow", False),
            ("/var/log/../../etc/shadow", False),
            ("/var/log/kea/../shadow.log", False),
            ("/var/log/kea/x.txt", False),
            ("/var/logs/x.log", False),
            ("var/log/x.log", False),
            ("/var/log/kea//x.log", False),
            ("/var/log/kea/x.log; id", False),
        ],
    )
    def test_the_rule(self, path, ok):
        from jen.services import auth

        assert auth.valid_log_path(path) is ok

    def test_save_refuses_a_path_outside_and_writes_nothing(self, logged_in_client, monkeypatch):
        import jen.config as config

        wrote = []
        monkeypatch.setattr(type(config.app_config), "mutate", lambda self, fn, reload=True: wrote.append(fn))
        r = logged_in_client.post(
            "/settings/infrastructure/save-ddns",
            data={"log_path": "/etc/shadow", "dns_provider": "none"},
            follow_redirects=True,
        )
        assert "under /var/log" in r.get_data(as_text=True)
        assert wrote == []

    def test_the_legacy_tail_refuses_a_path_outside_before_any_command(self, monkeypatch):
        from jen.services import kea_host

        def no_helper(*a, **k):
            raise kea_host.HelperMissing("no helper")

        ran = []
        monkeypatch.setattr(kea_host, "helper_call", no_helper)
        monkeypatch.setattr(kea_host, "_flag_legacy", lambda server: None)
        monkeypatch.setattr(kea_host, "_legacy_ssh", lambda *a, **k: ran.append(a) or ("x\n", "", 0))
        with pytest.raises(kea_host.HelperError, match="legacy tail refused: /etc/shadow is outside /var/log"):
            kea_host._tail_log({"id": 1}, "/etc/shadow", 5, None, False)
        res = kea_host.tail_log({"id": 1}, "/etc/shadow", 5)
        assert res["ok"] is False and "outside /var/log" in res["detail"]
        assert ran == []
        ok = kea_host.tail_log({"id": 1}, "/var/log/kea/kea-ddns.log", 5)
        assert ok["ok"] is True and len(ran) == 1


class TestSaveDdnsClearsWhatIsBlank:
    @pytest.fixture
    def cfg(self, monkeypatch):
        import configparser

        import jen.config as config

        parser = configparser.ConfigParser()
        parser.read_dict(
            {
                "ddns": {
                    "dns_provider": "technitium",
                    "log_path": "/var/log/kea/kea-ddns.log",
                    "api_url": "http://dns.example:5380",
                    "api_user": "u",
                    "api_token": "TOKEN",
                    "forward_zone": "example.com",
                }
            }
        )
        monkeypatch.setattr(type(config.app_config), "mutate", lambda self, fn, reload=True: fn(parser))
        return parser

    def test_blank_clears_each_key_and_the_token_is_kept_for_the_same_provider(self, logged_in_client, cfg):
        """Q177 adjustment: this posted technitium -> none and expected the token kept. A token is kept only for the provider it was typed for (DNS-CRED-001), so the
        same-provider case is what 'blank keeps the token' now means; the switch to none removes it (TestACredentialBelongsToItsProvider)."""
        # (Q178 adjustment: the address is posted as it was saved - clearing it is a change of endpoint, which removes the token: CRED-002)
        logged_in_client.post(
            "/settings/infrastructure/save-ddns",
            data={"dns_provider": "technitium", "api_url_technitium": "http://dns.example:5380"},
        )
        assert cfg.get("ddns", "dns_provider") == "technitium"
        for key in ("log_path", "api_user", "forward_zone"):
            assert not cfg.has_option("ddns", key), key
        assert cfg.get("ddns", "api_url") == "http://dns.example:5380"
        assert cfg.get("ddns", "api_token") == "TOKEN"

    def test_clearing_the_address_is_a_change_of_endpoint_and_removes_the_token(self, logged_in_client, cfg):
        logged_in_client.post("/settings/infrastructure/save-ddns", data={"dns_provider": "technitium"})
        assert not cfg.has_option("ddns", "api_url") and not cfg.has_option("ddns", "api_token")

    def test_the_token_goes_only_when_its_box_is_ticked_and_is_replaced_when_typed(self, logged_in_client, cfg):
        # (Q177 adjustment: this posted a token for provider none; a provider with no credential stores none - DNS-CRED-001 - so the replacement is typed for a provider that has one)
        logged_in_client.post(
            "/settings/infrastructure/save-ddns", data={"dns_provider": "technitium", "api_token": "NEW"}
        )
        assert cfg.get("ddns", "api_token") == "NEW"
        logged_in_client.post(
            "/settings/infrastructure/save-ddns", data={"dns_provider": "none", "api_token": "CRAFTED"}
        )
        assert not cfg.has_option("ddns", "api_token")
        logged_in_client.post(
            "/settings/infrastructure/save-ddns", data={"dns_provider": "technitium", "api_token": "NEW"}
        )
        logged_in_client.post(
            "/settings/infrastructure/save-ddns", data={"dns_provider": "technitium", "clear_api_token": "1"}
        )
        assert not cfg.has_option("ddns", "api_token")

    def test_each_provider_block_is_read_by_its_own_name(self, logged_in_client, cfg):
        """G4 (the release audit): every provider's block is submitted; the visible one is the selected provider's."""
        logged_in_client.post(
            "/settings/infrastructure/save-ddns",
            data={
                "dns_provider": "pihole",
                "api_url_technitium": "http://old",
                "api_token_technitium": "OLD",
                "api_url_pihole": "http://new",
                "api_token_pihole": "NEWTOKEN",
            },
        )
        assert cfg.get("ddns", "api_url") == "http://new"
        assert cfg.get("ddns", "api_token") == "NEWTOKEN"

    def test_a_blank_in_the_selected_providers_block_clears_the_key_whatever_another_block_holds(
        self, logged_in_client, cfg
    ):
        logged_in_client.post(
            "/settings/infrastructure/save-ddns",
            data={"dns_provider": "pihole", "api_url_technitium": "http://old", "api_url_pihole": ""},
        )
        assert not cfg.has_option("ddns", "api_url")

    def test_adguards_user_is_its_own_field(self, logged_in_client, cfg):
        logged_in_client.post(
            "/settings/infrastructure/save-ddns",
            data={"dns_provider": "adguard", "api_url_adguard": "http://ag:3000", "api_user_adguard": "root"},
        )
        assert cfg.get("ddns", "api_user") == "root" and cfg.get("ddns", "api_url") == "http://ag:3000"

    def test_a_form_that_sends_the_plain_names_alone_still_works(self, logged_in_client, cfg):
        logged_in_client.post(
            "/settings/infrastructure/save-ddns", data={"dns_provider": "technitium", "api_url": "http://plain"}
        )
        assert cfg.get("ddns", "api_url") == "http://plain"

    def test_the_page_has_no_plain_named_provider_input_and_each_suffixed_name_once(self):
        import re

        text = pathlib.Path("templates/settings_kea.html").read_text(encoding="utf-8")  # the card moved here in Q176
        # (the page also holds the Kea API and D2 forms, whose plain `api_url` is theirs: the rule is about the provider card, from its id to the end of its form)
        start = text.index('id="kea-dns-provider"')
        card = text[start : text.index("</form>", start)]
        assert re.findall(r'name="(api_url|api_user|api_token)"', card) == []
        for name in (
            "api_url_technitium",
            "api_token_technitium",
            "api_url_pihole",
            "api_token_pihole",
            "api_url_adguard",
            "api_user_adguard",
            "api_token_adguard",
        ):
            assert text.count(f'name="{name}"') == 1, name

    def test_an_unknown_provider_and_a_bad_url_are_refused(self, logged_in_client, cfg):
        logged_in_client.post("/settings/infrastructure/save-ddns", data={"dns_provider": "evil"})
        logged_in_client.post(
            "/settings/infrastructure/save-ddns", data={"dns_provider": "pihole", "api_url": "file:///etc/passwd"}
        )
        assert cfg.get("ddns", "dns_provider") == "technitium"
        assert cfg.get("ddns", "api_url") == "http://dns.example:5380"


# ── 5/6. Users: fail-closed subnet ids, a password change ends the other sessions, the profile redirect, one MFA reset route; the lockout clear ────────


def _make_user(db, username, role="viewer", password="oldpassword1", subnet_access=None):
    from jen.models.user import hash_password

    with db.cursor() as cur:
        cur.execute("DELETE FROM users WHERE username=%s", (username,))
        cur.execute(
            "INSERT INTO users (username, password, role, subnet_access, must_change_password) VALUES (%s, %s, %s, %s, 0)",
            (username, hash_password(password), role, subnet_access),
        )
        uid = cur.lastrowid
    db.commit()
    return uid


class TestAddUserFailsClosed:
    def _count(self, db, username):
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) c FROM users WHERE username=%s", (username,))
            return cur.fetchone()["c"]

    def test_a_subnet_id_that_is_not_a_number_is_refused_whole_and_nothing_is_created(self, logged_in_client, db):
        r = logged_in_client.post(
            "/users/add",
            data={"username": "q171_bad_ids", "password": "longenough1", "role": "viewer", "subnet_ids": ["1", "x1"]},
        )
        assert r.status_code == 400
        assert "Subnet ids must be numbers." in r.get_data(as_text=True)
        assert self._count(db, "q171_bad_ids") == 0

    def test_a_list_of_numbers_is_stored_as_that_list(self, logged_in_client, db):
        r = logged_in_client.post(
            "/users/add",
            data={"username": "q171_ids_ok", "password": "longenough1", "role": "viewer", "subnet_ids": ["1", "2"]},
        )
        assert r.status_code in (200, 302)
        with db.cursor() as cur:
            cur.execute("SELECT subnet_access FROM users WHERE username='q171_ids_ok'")
            assert json.loads(cur.fetchone()["subnet_access"]) == [1, 2]

    def test_all_still_means_unrestricted(self, logged_in_client, db):
        logged_in_client.post(
            "/users/add",
            data={"username": "q171_ids_all", "password": "longenough1", "role": "viewer", "subnet_ids": ["all"]},
        )
        with db.cursor() as cur:
            cur.execute("SELECT subnet_access FROM users WHERE username='q171_ids_all'")
            assert cur.fetchone()["subnet_access"] is None


class TestAPasswordChangeEndsTheOtherSessions:
    def _login(self, app, username, password):
        c = app.test_client()
        r = c.post("/login", data={"username": username, "password": password})
        assert r.status_code in (200, 302)
        assert c.get("/profile").status_code == 200, "the login did not take"
        return c

    def test_the_session_that_changed_it_stays_and_a_second_session_is_logged_out(self, app, db):
        _make_user(db, "q171_pw_user")
        first = self._login(app, "q171_pw_user", "oldpassword1")
        second = self._login(app, "q171_pw_user", "oldpassword1")
        r = first.post(
            "/users/change-password",
            data={
                "current_password": "oldpassword1",
                "new_password": "newpassword2",
                "confirm_password": "newpassword2",
            },
        )
        assert r.status_code == 302 and "/profile" in r.headers["Location"]
        assert first.get("/profile").status_code == 200, "the session that changed the password was ended"
        r2 = second.get("/profile")
        assert r2.status_code == 302 and "/login" in r2.headers["Location"], (
            "an older session survived a password change"
        )

    def test_token_version_moves_with_the_password_in_both_routes(self, app, db):
        uid = _make_user(db, "q171_pw_tv")
        c = self._login(app, "q171_pw_tv", "oldpassword1")
        db.commit()
        with db.cursor() as cur:
            cur.execute("SELECT token_version FROM users WHERE id=%s", (uid,))
            before = cur.fetchone()["token_version"]
        c.post(
            "/users/change-password",
            data={
                "current_password": "oldpassword1",
                "new_password": "newpassword2",
                "confirm_password": "newpassword2",
            },
        )
        db.commit()
        with db.cursor() as cur:
            cur.execute("SELECT token_version FROM users WHERE id=%s", (uid,))
            mid = cur.fetchone()["token_version"]
            cur.execute("UPDATE users SET must_change_password=1 WHERE id=%s", (uid,))
        db.commit()
        assert mid == before + 1
        from jen.models.user import _invalidate_settings_cache

        _invalidate_settings_cache()
        c2 = self._login_forced(app, "q171_pw_tv", "newpassword2")
        c2.post("/force-password-change", data={"new_password": "thirdpassword3", "confirm_password": "thirdpassword3"})
        db.commit()
        with db.cursor() as cur:
            cur.execute("SELECT token_version FROM users WHERE id=%s", (uid,))
            assert cur.fetchone()["token_version"] == mid + 1

    def _login_forced(self, app, username, password):
        c = app.test_client()
        c.post("/login", data={"username": username, "password": password})
        return c

    def test_a_session_opened_before_the_fingerprint_existed_is_adopted_not_ended(self, app, db):
        uid = _make_user(db, "q171_pw_legacy")
        c = app.test_client()
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc).isoformat()
        with c.session_transaction() as sess:
            sess["_user_cache"] = {"id": uid, "username": "q171_pw_legacy", "role": "viewer", "session_timeout": None}
            sess["_user_id"] = str(uid)
            sess["_fresh"] = True
            sess["last_active"] = now
            sess["auth_at"] = now
        assert c.get("/profile").status_code == 200
        with c.session_transaction() as sess:
            assert sess["_user_cache"].get("pw_fp"), "the first request did not adopt the row's fingerprint"

    def test_a_login_that_rehashed_a_legacy_hash_stays_signed_in(self, client, db):
        """G1 (the release audit): the rehash writes a new hash, and the session fingerprints the one now stored."""
        from werkzeug.security import generate_password_hash

        legacy = generate_password_hash("legacy-pass-1", method="pbkdf2:sha256")
        with db.cursor() as cur:
            cur.execute("DELETE FROM users WHERE username='q171_legacy'")
            cur.execute("INSERT INTO users (username, password, role) VALUES ('q171_legacy', %s, 'viewer')", (legacy,))
        db.commit()
        assert client.post("/login", data={"username": "q171_legacy", "password": "legacy-pass-1"}).status_code == 302
        # the profile is a page every signed-in role has: a bounce to /login would be a 302 here
        assert client.get("/profile").status_code == 200
        assert client.get("/profile").status_code == 200
        db.commit()
        with db.cursor() as cur:
            cur.execute("SELECT password FROM users WHERE username='q171_legacy'")
            assert cur.fetchone()["password"].startswith("scrypt:")

    def test_the_fingerprint_is_one_way_and_empty_for_no_password(self):
        from jen.models.user import password_fingerprint

        assert password_fingerprint("") == "" and password_fingerprint(None) == ""
        fp = password_fingerprint("scrypt:32768:8:1$salt$hash")
        assert len(fp) == 16 and "scrypt" not in fp and "hash" not in fp


class TestAFailedSelfServicePasswordChangeReturnsToTheProfile:
    @pytest.mark.parametrize(
        "form",
        [
            {"current_password": "oldpassword1", "new_password": "newpassword2", "confirm_password": "different22"},
            {"current_password": "oldpassword1", "new_password": "short", "confirm_password": "short"},
            {"current_password": "WRONGpassword", "new_password": "newpassword2", "confirm_password": "newpassword2"},
        ],
    )
    def test_a_viewer_lands_on_the_profile_with_the_reason(self, client, db, form):
        c, _ = restricted_client(client, db, None, role="viewer", username="q171_pw_viewer")
        with db.cursor() as cur:
            from jen.models.user import hash_password

            cur.execute(
                "UPDATE users SET password=%s WHERE username='q171_pw_viewer'", (hash_password("oldpassword1"),)
            )
        db.commit()
        r = c.post("/users/change-password", data=form, follow_redirects=True)
        body = r.get_data(as_text=True)
        assert "SuperAdmin access required" not in body
        assert any(
            s in body
            for s in (
                "New passwords do not match.",
                "New password must be at least 8 characters.",
                "Current password is incorrect.",
            )
        )


class TestOneMfaResetRoute:
    def _seed(self, db, uid):
        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_methods WHERE user_id=%s", (uid,))
            cur.execute(
                "INSERT INTO mfa_methods (user_id, method_type, secret, name, enabled) VALUES (%s, 'totp', '\"x\"', 'App', 1)",
                (uid,),
            )
        db.commit()

    def _methods(self, db, uid):
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) c FROM mfa_methods WHERE user_id=%s", (uid,))
            return cur.fetchone()["c"]

    def test_the_old_route_is_gone(self, logged_in_client):
        assert logged_in_client.post("/users/reset-mfa/1").status_code in (404, 405)

    def test_the_users_page_posts_to_the_step_up_route(self):
        text = pathlib.Path("templates/users.html").read_text(encoding="utf-8")
        assert "/mfa/admin-reset/" in text and "/users/reset-mfa/" not in text

    def test_a_stale_confirmation_goes_to_reauth_and_resets_nothing(self, logged_in_client, db):
        uid = _make_user(db, "q171_mfa_target")
        self._seed(db, uid)
        _stale(logged_in_client)
        r = logged_in_client.post(f"/mfa/admin-reset/{uid}")
        assert r.status_code == 302 and "/auth/reauth" in r.headers["Location"]
        assert self._methods(db, uid) == 1

    def test_a_fresh_superadmin_deletes_the_methods_and_the_message_names_the_user(self, logged_in_client, db):
        uid = _make_user(db, "q171_mfa_target2")
        self._seed(db, uid)
        r = logged_in_client.post(f"/mfa/admin-reset/{uid}", follow_redirects=True)
        body = r.get_data(as_text=True)
        assert "MFA reset for user" in body and "q171_mfa_target2" in body and "They will need to re-enroll." in body
        assert self._methods(db, uid) == 0

    def test_an_id_that_is_not_an_account_says_so(self, logged_in_client):
        r = logged_in_client.post("/mfa/admin-reset/987654", follow_redirects=True)
        assert "User not found." in r.get_data(as_text=True)


class TestLockoutClearIsThePairOnly:
    def test_one_success_does_not_clear_another_accounts_failures_from_the_same_address(self, db):
        from jen.services import auth

        with db.cursor() as cur:
            cur.execute("DELETE FROM login_attempts WHERE ip_address='203.0.113.7'")
        db.commit()
        for _ in range(3):
            auth.record_login_attempt("203.0.113.7", "q171_victim")
        auth.record_login_attempt("203.0.113.7", "q171_viewer")
        auth.record_login_attempt("203.0.113.8", "q171_viewer")
        auth.clear_login_attempts("203.0.113.7", "q171_viewer")
        with db.cursor() as cur:
            cur.execute(
                "SELECT username, ip_address FROM login_attempts WHERE ip_address IN ('203.0.113.7','203.0.113.8')"
            )
            rows = sorted((r["username"], r["ip_address"]) for r in cur.fetchall())
        assert rows == [("q171_victim", "203.0.113.7")] * 3 + [("q171_viewer", "203.0.113.8")]
        with db.cursor() as cur:
            cur.execute("DELETE FROM login_attempts WHERE ip_address IN ('203.0.113.7','203.0.113.8')")
        db.commit()


# ── 7/8. /api/stats pool_sizes for the caller's subnets only; the two 500s ─────────────────────────────────────────────────────────────────────────


class TestApiStatsPoolSizesAreTheCallersOwn:
    @pytest.fixture
    def kea_config(self, monkeypatch, mock_kea, two_subnets):
        from jen.services import kea as kea_svc

        config = {
            "Dhcp4": {
                "subnet4": [
                    {"id": 1, "subnet": A["cidr"], "pools": [{"pool": "10.98.1.10 - 10.98.1.20"}]},
                    {"id": 2, "subnet": B["cidr"], "pools": [{"pool": "10.77.0.10 - 10.77.0.90"}]},
                ]
            }
        }

        def command(cmd, *a, **kw):
            if cmd == "config-get":
                return {"result": 0, "arguments": config}
            return {"result": 0, "text": "ok", "arguments": {}}

        monkeypatch.setattr(kea_svc, "kea_command", command)

    def test_a_scoped_viewer_gets_pool_sizes_for_the_subnets_it_may_see_only(self, client, db, kea_config):
        c, _ = restricted_client(client, db, [1], role="viewer", username="q171_stats_viewer")
        data = c.get("/api/stats").get_json()
        assert set(data["pool_sizes"]) <= set(data["subnets"]) == {"1"}
        assert data["pool_sizes"] == {"1": 11}
        assert "2" not in json.dumps(data["pool_sizes"])

    def test_an_unrestricted_caller_still_gets_every_subnet(self, logged_in_client, kea_config):
        data = logged_in_client.get("/api/stats").get_json()
        assert set(data["pool_sizes"]) == {"1", "2"}


class TestTheTwoFiveHundreds:
    def test_a_secret_that_is_not_base32_is_a_flash_not_a_500(self, logged_in_client):
        r = logged_in_client.post(
            "/mfa/enroll", data={"action": "enroll", "secret": "abc", "code": "123456"}, follow_redirects=True
        )
        assert r.status_code == 200
        assert "The secret is not valid base32." in r.get_data(as_text=True)

    @pytest.mark.parametrize("days", ["abc", "-1", "0", "1000", "7.5", ""])
    def test_days_never_raises(self, logged_in_client, days):
        assert logged_in_client.get(f"/api/lease-history?days={days}").status_code == 200

    def test_days_is_clamped_into_one_to_ninety(self, app):
        from jen.routes import dashboard

        with app.test_request_context("/api/lease-history?days=-5"):
            assert dashboard._int_arg("days", 7, 1, 90) == 1
        with app.test_request_context("/api/lease-history?days=900"):
            assert dashboard._int_arg("days", 7, 1, 90) == 90
        with app.test_request_context("/api/lease-history?days=abc"):
            assert dashboard._int_arg("days", 7, 1, 90) == 7
        with app.test_request_context("/api/lease-history"):
            assert dashboard._int_arg("days", 7, 1, 90) == 7


# ── 9. IPv6 is behind the flag, not behind `[subnets6]` ────────────────────────────────────────────────────────────────────────────────────────


class TestIpv6RoutesFollowTheFlag:
    @pytest.fixture
    def v6_configured(self, monkeypatch, mock_kea):
        monkeypatch.setattr(
            extensions, "SUBNET6_MAP", {1: {"name": "Six-A", "cidr": "2001:db8:1::/64", "paired_subnet4_id": 1}}
        )
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: dict(A)})

    @pytest.fixture
    def flag(self):
        from jen.models.user import _invalidate_settings_cache, get_global_setting, set_global_setting

        before = get_global_setting("ipv6_enabled", "false")

        def put(value):
            set_global_setting("ipv6_enabled", value)
            _invalidate_settings_cache()

        put("false")
        yield put
        put(before)

    @pytest.mark.parametrize(
        "route,fn",
        [
            ("/leases?view=v6", "_leases_v6"),
            ("/devices?view=v6", "_devices_v6"),
            ("/reservations?view=v6", "_reservations_v6"),
        ],
    )
    def test_with_the_flag_off_the_v6_list_is_the_v4_page(
        self, logged_in_client, v6_configured, flag, monkeypatch, route, fn
    ):
        import importlib

        module = importlib.import_module("jen.routes." + route.split("/")[1].split("?")[0])
        called = []
        monkeypatch.setattr(module, fn, lambda *a, **k: called.append(1) or "v6 page")
        r = logged_in_client.get(route)
        assert r.status_code == 200 and called == [], "the v6 branch ran with IPv6 switched off"
        flag("true")
        r = logged_in_client.get(route)
        assert called == [1] and b"v6 page" in r.data

    @pytest.mark.parametrize(
        "method,path",
        [
            ("GET", "/reservations/add6"),
            ("POST", "/reservations/add6"),
            ("POST", "/reservations/delete6"),
            ("GET", "/subnets/edit6/1"),
            ("POST", "/subnets/edit6/1"),
            ("POST", "/subnets/edit6/1/preview"),
        ],
    )
    def test_with_the_flag_off_every_v6_write_surface_is_a_404(
        self, logged_in_client, v6_configured, flag, method, path
    ):
        r = logged_in_client.open(path, method=method, data={"duid": "00:01", "subnet_id": "1"})
        assert r.status_code == 404, (method, path, r.status_code)

    def test_with_the_flag_on_the_add_form_is_served(self, logged_in_client, v6_configured, flag):
        flag("true")
        assert logged_in_client.get("/reservations/add6").status_code == 200


# ── 10. One answer for "not yours" and "not there" on the v4 per-object admin routes ─────────────────────────────────────────────────────────────


class TestHiddenAndNonexistentAreOneAnswer:
    HIDDEN_IP = "10.77.0.77"
    GHOST_IP = "10.77.0.199"
    MAC_HEX = "DEADBEEF0171"

    @pytest.fixture
    def hidden(self, db, two_subnets, mock_kea):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)=%s", (self.MAC_HEX,))
            cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)=%s", (self.MAC_HEX,))
            cur.execute("DELETE FROM devices WHERE mac='de:ad:be:ef:01:71'")
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, valid_lifetime, expire, subnet_id, state, hostname) VALUES "
                "(INET_ATON(%s), UNHEX(%s), 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 2, 0, 'hidden-host')",
                (self.HIDDEN_IP, self.MAC_HEX),
            )
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX(%s), 0, 2, INET_ATON('10.77.0.88'), 'hidden-host')",
                (self.MAC_HEX,),
            )
            host_id = None
            cur.execute("SELECT host_id FROM hosts WHERE HEX(dhcp_identifier)=%s", (self.MAC_HEX,))
            host_id = cur.fetchone()["host_id"]
            cur.execute(
                "INSERT INTO devices (mac, last_ip, last_hostname, last_subnet_id, device_name, first_seen, last_seen) "
                "VALUES ('de:ad:be:ef:01:71', %s, 'hidden-host', 2, 'Hidden', NOW(), NOW())",
                (self.HIDDEN_IP,),
            )
            device_id = cur.lastrowid
        db.commit()
        yield {"host_id": host_id, "device_id": device_id}
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr)=%s", (self.MAC_HEX,))
            cur.execute("DELETE FROM hosts WHERE HEX(dhcp_identifier)=%s", (self.MAC_HEX,))
            cur.execute("DELETE FROM devices WHERE mac='de:ad:be:ef:01:71'")
        db.commit()

    @staticmethod
    def _answer(client, response):
        """What a caller can tell from the answer: status, where it went, the flashed sentences or the JSON body."""
        flashes = []
        with client.session_transaction() as sess:
            flashes = [m for _c, m in sess.pop("_flashes", [])]
        body = None
        if response.is_json:
            body = response.get_json()
        return response.status_code, response.headers.get("Location", ""), flashes, body

    def _pair(self, client, method, hidden_path, ghost_path, data=None, ghost_data=None, normalise=()):
        a = self._answer(client, client.open(hidden_path, method=method, data=data or {}))
        b = self._answer(
            client, client.open(ghost_path, method=method, data=ghost_data if ghost_data is not None else (data or {}))
        )

        # the one thing that may differ is a value the caller itself typed (an IP in the sentence, the id in a URL)
        def n(answer):
            text = repr(answer)
            for value in normalise:
                text = text.replace(value, "<typed>")
            return text

        assert n(a) == n(b), f"hidden and nonexistent differ:\n  hidden:      {a}\n  nonexistent: {b}"
        return a

    def test_a_lease_release(self, client, db, hidden):
        c, _ = restricted_client(client, db, [1], role="admin", username="q171_one_answer_lease")
        answer = self._pair(
            c,
            "POST",
            "/leases/release",
            "/leases/release",
            data={"ip": self.HIDDEN_IP},
            ghost_data={"ip": self.GHOST_IP},
            normalise=(self.HIDDEN_IP, self.GHOST_IP),
        )
        assert answer[2] == [f"No active lease found for {self.HIDDEN_IP}."]
        with db.cursor() as cur:
            cur.execute("SELECT state FROM lease4 WHERE HEX(hwaddr)=%s", (self.MAC_HEX,))
            assert cur.fetchone()["state"] == 0, "a hidden lease was released"

    def test_the_reservation_routes(self, client, db, hidden):
        c, _ = restricted_client(client, db, [1], role="admin", username="q171_one_answer_res")
        hid, ghost = hidden["host_id"], 987654
        data = {"hostname": "x", "dns_override": ""}
        for method, tmpl in (("GET", "/reservations/edit/{}"), ("POST", "/reservations/edit/{}")):
            answer = self._pair(c, method, tmpl.format(hid), tmpl.format(ghost), data=data)
            assert answer[2] == ["Reservation not found."], (method, answer)
        h = self._answer(c, c.post(f"/reservations/delete/{hid}"))
        g = self._answer(c, c.post(f"/reservations/delete/{ghost}"))
        assert h == g and h[2] == ["Reservation not found."]
        hx = {"HX-Request": "true"}
        h = c.post(f"/reservations/delete/{hid}", headers=hx)
        g = c.post(f"/reservations/delete/{ghost}", headers=hx)
        assert (h.status_code, h.get_data()) == (g.status_code, g.get_data()) and h.status_code == 404
        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) c FROM hosts WHERE host_id=%s", (hid,))
            assert cur.fetchone()["c"] == 1, "a hidden reservation was deleted"

    def test_the_device_routes_and_a_nonexistent_id_is_no_longer_a_success(self, client, db, hidden):
        c, _ = restricted_client(client, db, [1], role="admin", username="q171_one_answer_dev")
        hid, ghost = hidden["device_id"], 987654
        edit = self._pair(c, "POST", f"/devices/edit/{hid}", f"/devices/edit/{ghost}", data={"device_name": "renamed"})
        assert edit[0] == 404 and edit[3] == {"ok": False, "error": "Device not found."}
        delete = self._pair(c, "POST", f"/devices/delete/{hid}", f"/devices/delete/{ghost}")
        assert delete[2] == ["Device not found."]
        with db.cursor() as cur:
            cur.execute("SELECT device_name FROM devices WHERE id=%s", (hid,))
            assert cur.fetchone()["device_name"] == "Hidden"

    def test_the_subnet_routes(self, client, db, hidden, monkeypatch):
        c, _ = restricted_client(client, db, [1], role="admin", username="q171_one_answer_sub")
        for method, tmpl, data in (
            ("POST", "/subnets/delete/{}", {}),
            ("GET", "/subnets/edit/{}", {}),
            ("POST", "/subnets/edit/{}", {"name": "x"}),
            ("POST", "/subnets/move/{}", {"shared_network": ""}),
        ):
            answer = self._pair(c, method, tmpl.format(2), tmpl.format(999), data=data)
            assert answer[2] == ["Subnet not found."], (method, tmpl, answer)
        preview = self._pair(c, "POST", "/subnets/edit/2/preview", "/subnets/edit/999/preview", data={"name": "x"})
        assert preview[0] == 404 and preview[3] == {"ok": False, "error": "Subnet not found."}
