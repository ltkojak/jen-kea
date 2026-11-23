"""
tests/test_q248_b1.py
─────────────────────
Q248, the rows where a page said the wrong thing, or two things (the look over v7.2.0-beta.5, rows V19 to V43). What a rendered page, a
message or the source can hold is here; what only a browser can measure (a wrapped phone row, the Filters count, the search cards on a
phone) is tests/e2e/test_q248_b1.py.

* V19 "reserved" is said of leases; a count of reservations is labeled "reservations" and sits apart from the split of the active leases.
* V20 Explain's step 1 says "the subnet of the current lease" only when the subnet evaluated IS the lease's.
* V21 an audit search that matches nothing says so; "1 audit entry".
* V22 the Windows import names the unnamed first server once.
* V23 the single sign-on help says "Jen role".
* V24 the packet counters are ACK and NAK.
* V25 a viewer's API documentation page has no Settings strip and no link to the key page.
* V26 Getting Started shows a warning as a warning.
* V27 a pre-release on the stable channel is said in words.
* V28 a health check carries a link; no message prints an address.
* V29 the reconcile link says where it goes.
* V31 Multi-Factor Authentication, sign in and sign out, Superadmin.
* V32 Investigate shows a subnet as the badge and drops the code nobody could look up.
* V34 the separator stylesheet is linked by the pages with a row list.
* V35 the stale-days setting is not inside the filter bar.
* V36 a count and the noun that agrees with it.
* V39 every Save on a settings page names what it saves; checkbox labels are sentences.
* V40 the daily summary time is a 24-hour text field.
* V43 search groups with no match are one closing line; the result tables are row lists.
"""

import pathlib
import re

import pytest

from jen.routes.settings import nav as navmod
from jen.services import dhcp_explain, health, onboarding, reltime

ROOT = pathlib.Path(__file__).resolve().parent.parent
TEMPLATES = ROOT / "templates"


def _src(name):
    return (TEMPLATES / name).read_text(encoding="utf-8").replace("\r\n", "\n")


def _viewer(client, db, username):
    from tests.conftest import restricted_client

    restricted_client(client, db, None, role="viewer", username=username)
    return client


# ── V19 ──────────────────────────────────────────────────────────────────────


class TestReservedIsSaidOfLeases:
    def test_the_subnet_card_splits_the_leases_and_counts_reservations_apart(self, logged_in_client, mock_kea):
        html = logged_in_client.get("/").get_data(as_text=True)
        meta = re.search(r'id="stat-meta-1">(.*?)</div>', html, re.S).group(1)
        assert "dynamic" in meta and meta.rstrip().endswith("reserved"), meta
        assert "reservation" not in meta
        line = re.search(r'<div class="[^"]*stat-pool-line[^"]*">(.*?)</div>', html, re.S).group(1)
        assert 'id="util-pct-1"' in line and 'id="stat-res-1"' in line and "reservations" in line

    def test_the_totals_have_a_reservations_figure_of_their_own(self, logged_in_client, mock_kea):
        html = logged_in_client.get("/").get_data(as_text=True)
        labels = re.findall(r'<div class="u-1d385c">\s*([A-Za-z ]+?)\s*(?:<|$)', html)
        assert labels[:5] == ["Total Active", "Dynamic", "Reserved", "Pool Used", "Reservations"], labels
        assert 'id="total-reserved"' in html and 'id="total-reservations"' in html

    def test_the_page_script_never_puts_the_reservation_count_under_reserved(self):
        src = _src("dashboard.html")
        assert "totalReserved += s.reservations" not in src
        assert "var reservedLeases = Math.max(0, (s.active || 0) - (s.dynamic || 0));" in src
        assert "totalReserved += reservedLeases;" in src and "totalReservations += reservations;" in src
        assert "(s.reservations || 0).toLocaleString('en-US') + ' reserved'" not in src
        assert "' reserved';" in src and "' reservations')" in src
        # the IPv6 figures are reservations too
        assert "s6.reserved|plural('reservation')" in src and "{{ s6.reserved|number }} reserved" not in src

    def test_the_reports_series_are_named_for_what_they_count(self):
        src = _src("reports.html")
        assert "'Reserved addresses'" not in src and "'Reserved prefixes'" not in src
        assert "'Address reservations', 'reserved_na'" in src and "'Prefix reservations', 'reserved_pd'" in src
        assert "label: 'Reservations configured'" in src

    def test_the_daily_summary_counts_reservations(self, app):
        from jen.services import alerts

        with app.app_context():
            text = alerts._build_daily_summary()
        assert re.search(r"\d+ active, \d[\d,]* reservations?\b", text), text
        assert " reserved" not in text


# ── V20 ──────────────────────────────────────────────────────────────────────

_CFG = {
    "subnet4": [
        {"id": 1, "subnet": "10.0.1.0/24", "pools": [{"pool": "10.0.1.100 - 10.0.1.199"}]},
        {"id": 2, "subnet": "10.0.2.0/24", "pools": [{"pool": "10.0.2.100 - 10.0.2.199"}]},
    ]
}
_CLIENT = {"mac": "00:11:22:33:44:55"}


def _step1(**kw):
    result = dhcp_explain.explain(_CFG, dict(_CLIENT), **kw)
    assert result["ok"] is not False, result
    return next(s for s in result["steps"] if s["stage"] == "subnet")["detail"]


class TestExplainStepOneGivesTheTrueReason:
    def test_a_subnet_chosen_by_hand_with_the_lease_elsewhere(self):
        detail = _step1(subnet_id=2, lease={"ip": "10.0.1.150", "subnet_id": 1})
        assert "the subnet you chose" in detail and "the subnet of the current lease" not in detail
        assert "current lease is in" not in detail, "no name was given, so no subnet is named"

    def test_the_leases_subnet_is_named_only_when_the_caller_gave_its_name(self):
        detail = _step1(subnet_id=2, lease={"ip": "10.0.1.150", "subnet_id": 1}, lease_subnet_name="Office")
        assert "the subnet you chose (the client's current lease is in Office)" in detail

    def test_the_subnet_of_the_lease_is_still_said_when_it_is(self):
        detail = _step1(subnet_id=1, lease={"ip": "10.0.1.150", "subnet_id": 1}, lease_subnet_name="Office")
        assert "the subnet of the current lease" in detail and "you chose" not in detail

    def test_no_lease_is_the_subnet_you_chose(self):
        assert "the subnet you chose" in _step1(subnet_id=2)

    def test_the_routes_pass_a_name_from_the_callers_own_map_only(self):
        from jen.routes import client as client_route
        from jen.routes import explain as explain_route

        for fn in (client_route._lease_subnet_name, explain_route._lease_subnet_name):
            assert fn({"subnet_id": 1}, {1: {"name": "Office"}}) == "Office"
            assert fn({"subnet_id": 7}, {1: {"name": "Office"}}) is None, "a subnet the map does not hold has no name"
            assert fn(None, {1: {"name": "Office"}}) is None
            assert fn({"subnet_id": "x"}, {1: {"name": "Office"}}) is None


# ── V21 ──────────────────────────────────────────────────────────────────────


class TestLogsSayWhatDidNotMatch:
    def test_a_search_that_matches_nothing_says_so_and_offers_the_way_out(self, logged_in_client):
        html = logged_in_client.get("/settings/logs?tab=audit&search=zzzz-nothing-matches").get_data(as_text=True)
        assert "No audit events match." in html and "No audit events yet." not in html
        assert re.search(r'<a class="btn btn-sm" href="/settings/logs\?tab=audit">Clear search</a>', html)

    def test_an_empty_log_still_says_yet(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM audit_log")
        db.commit()
        html = logged_in_client.get("/settings/logs?tab=audit").get_data(as_text=True)
        assert "No audit events yet." in html and "No audit events match." not in html

    def test_one_audit_entry_is_singular_on_the_hub(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM audit_log")
            cur.execute(
                "INSERT INTO audit_log (user_id, username, action, entity, details) VALUES (1, 'admin', 'TEST', 'q248', 'one row')"
            )
        db.commit()
        html = logged_in_client.get("/settings").get_data(as_text=True)
        assert "1 audit entry" in html and "1 audit entries" not in html
        # the retention card on the System page counts the same log
        system = logged_in_client.get("/settings/system").get_data(as_text=True)
        assert "Current log: <strong>1</strong> entry —" in system
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO audit_log (user_id, username, action, entity, details) VALUES (1, 'admin', 'TEST', 'q248', 'two rows')"
            )
        db.commit()
        assert "2 audit entries" in logged_in_client.get("/settings").get_data(as_text=True)


# ── V22, V23, V24 ────────────────────────────────────────────────────────────


class TestSmallWords:
    PHRASE = "the first server that takes changes"

    def test_an_unnamed_import_target_is_named_once(self, logged_in_client, monkeypatch):
        monkeypatch.setattr("jen.services.kea_changeset.first_write_target", lambda service: {"id": 1})
        html = logged_in_client.get("/subnets/import-windows").get_data(as_text=True)
        assert html.count(self.PHRASE) == 1, html.count(self.PHRASE)
        assert f"<strong>{self.PHRASE}</strong>" in html

    def test_a_named_import_target_keeps_the_explanation(self, logged_in_client, monkeypatch):
        monkeypatch.setattr("jen.services.kea_changeset.first_write_target", lambda service: {"id": 1, "name": "kea-a"})
        html = logged_in_client.get("/subnets/import-windows").get_data(as_text=True)
        assert f"<strong>kea-a</strong>, {self.PHRASE}" in html

    def test_the_sso_help_names_jens_roles(self, logged_in_client):
        html = logged_in_client.get("/settings/security").get_data(as_text=True)
        assert "Jen role → claim values" in html and "Kea role" not in html

    def test_the_packet_counters_are_ack_and_nak(self):
        from jen.routes import servers

        labels = dict(servers._PACKET_HEALTH_NAMED_KEYS)
        assert labels["pkt4-nak-sent"] == "NAK" and labels["pkt4-ack-sent"] == "ACK"
        assert "Naked" not in labels.values() and "Acked" not in labels.values()


# ── V25 ──────────────────────────────────────────────────────────────────────


class TestAViewerOnTheApiDocs:
    def test_the_strip_is_for_an_account_that_has_a_settings(self):
        viewer = navmod.nav_context("api.api_docs", "viewer")
        assert viewer["strip"] == [] and viewer["in_settings"] is False and viewer["pin"] is None
        admin = navmod.nav_context("api.api_docs", "admin")
        assert admin["in_settings"] is True and [t["id"] for t in admin["strip"]] == [
            g["id"] for g in navmod.SETTINGS_GROUPS
        ]
        assert navmod.nav_context("settings.settings", "viewer")["in_settings"] is False

    def test_a_viewers_page_has_no_strip_no_way_back_and_no_link_to_the_key_page(self, client, db):
        html = _viewer(client, db, "q248_docs_viewer").get("/settings/api-docs").get_data(as_text=True)
        assert "REST API Documentation" in html
        assert "Ask an administrator for an API key." in html and "Create one" not in html
        assert 'href="/settings/api-keys"' not in html
        assert 'class="settings-back"' not in html and 'class="section-tabs-wrap' not in html
        for group in navmod.SETTINGS_GROUPS:
            assert f'href="{group["url"]}"' not in html, group["url"]

    def test_an_admin_keeps_the_link_and_the_strip(self, logged_in_client):
        html = logged_in_client.get("/settings/api-docs").get_data(as_text=True)
        assert 'class="section-tabs-wrap' in html and 'href="/settings/api-keys"' in html
        assert "Ask an administrator for an API key." not in html


# ── V26 ──────────────────────────────────────────────────────────────────────


def _transport_ctx(status, detail, mode="ca"):
    check = health.Check("kea32_control_transport", "Control transport ready for 3.2", "readiness", status, detail)
    check.fix_url = "/settings/kea"
    return {"checks": {"kea32_control_transport": check}, "kea_connection_mode": mode}


class TestGettingStartedShowsAWarningAsAWarning:
    def test_a_warning_is_not_ticked_and_links_to_health(self):
        row = onboarding._control_transport_row(_transport_ctx("warn", "before you upgrade: set up a direct socket"))
        assert row["done"] is False and row["warn"] is True
        assert row["detail"] == "before you upgrade: set up a direct socket" and row["link"] == "/health-center"

    def test_a_pass_is_ticked_and_a_failure_is_not_a_warning(self):
        ok = onboarding._control_transport_row(_transport_ctx("ok", "direct mode", mode="direct"))
        assert ok["done"] is True and not ok.get("warn")
        fail = onboarding._control_transport_row(_transport_ctx("fail", "3.2 removes the Control Agent"))
        assert fail["done"] is False and not fail.get("warn") and fail["link"] == "/settings/kea"

    def test_the_page_draws_the_warning_mark_and_the_link(self, logged_in_client, monkeypatch):
        rows = [
            {"title": "Kea is reachable", "done": True, "detail": "1 server", "link": "/servers"},
            {
                "title": "Control transport ready for 3.2",
                "done": False,
                "warn": True,
                "detail": "before you upgrade",
                "link": "/health-center",
            },
            {"title": "HTTPS is on", "done": False, "detail": "running on plain HTTP", "link": "/settings/security"},
        ]
        monkeypatch.setattr("jen.services.onboarding.build_ctx", lambda user, is_superadmin: {})
        monkeypatch.setattr(
            "jen.services.onboarding.checklist",
            lambda ctx: {"rows": rows, "done": 1, "total": 3, "all_done": False},
        )
        html = logged_in_client.get("/getting-started").get_data(as_text=True)
        warn_row = re.search(r'data-row="1">(.*?)</a>', html, re.S).group(1)
        assert 'role="img" aria-label="Warning"' in warn_row and "#i-triangle-alert" in warn_row
        assert re.search(r'href="/health-center">Open Health$', warn_row)
        todo_row = re.search(r'data-row="2">(.*?)</a>', html, re.S).group(1)
        assert 'aria-label="Warning"' not in todo_row and todo_row.endswith(">Fix")


# ── V27 ──────────────────────────────────────────────────────────────────────


class TestAPreReleaseOnTheStableChannel:
    SENTENCE = (
        "This build is a pre-release, and the stable channel offers stable releases only: the next update offered will be "
        "the first stable release newer than this build."
    )

    def _page(self, client, monkeypatch, version, channel):
        import jen
        from jen import extensions

        monkeypatch.setattr(jen, "JEN_VERSION", version)
        monkeypatch.setattr(extensions, "UPDATE_CHANNEL", channel)
        return client.get("/settings/system").get_data(as_text=True)

    def test_it_is_said(self, logged_in_client, monkeypatch):
        assert self.SENTENCE in self._page(logged_in_client, monkeypatch, "7.2.0-beta.6", "stable")
        assert self.SENTENCE in self._page(logged_in_client, monkeypatch, "7.2.0-rc.1", "stable")

    def test_it_is_not_said_of_a_stable_build_or_on_the_beta_channel(self, logged_in_client, monkeypatch):
        assert self.SENTENCE not in self._page(logged_in_client, monkeypatch, "7.2.0", "stable")
        assert self.SENTENCE not in self._page(logged_in_client, monkeypatch, "7.2.0-beta.6", "beta")

    def test_the_sentence_is_what_the_picker_does(self):
        from jen.version import parse_version, pick_release

        releases = [
            {"tag_name": "v7.2.0-beta.7", "prerelease": True},
            {"tag_name": "v7.1.0", "prerelease": False},
            {"tag_name": "v7.2.0", "prerelease": False},
        ]
        offered = pick_release(releases, "stable")
        assert offered["tag_name"] == "v7.2.0" and parse_version("7.2.0") > parse_version("7.2.0-beta.6")
        # with no stable release newer than the build, nothing is offered: the newest stable is older than what runs
        older = pick_release(releases[:2], "stable")
        assert parse_version(older["tag_name"].lstrip("v")) < parse_version("7.2.0-beta.6")


# ── V28 ──────────────────────────────────────────────────────────────────────


class TestAHealthCheckCarriesALink:
    def test_the_json_has_two_more_fields_and_the_old_ones(self):
        d = health.Check("x", "X", "kea").as_dict()
        assert list(d) == [
            "id",
            "title",
            "group",
            "status",
            "detail",
            "fix_hint",
            "fix_url",
            "elapsed_ms",
            "link",
            "link_label",
        ]
        assert d["link"] == "" and d["link_label"] == ""

    def _doctor(self, monkeypatch, **ctx):
        monkeypatch.setattr(health, "_doctor_hosts", list)
        monkeypatch.setattr(health, "_doctor_ha_configs", lambda: None)
        cfg = {"subnet4": [{"id": 1, "subnet": "10.0.0.0/24", "reservation-mode": "out-of-pool"}]}
        return health._config_doctor({"dhcp4_config": cfg, "unrestricted": True, **ctx})

    def test_doctors_row_links_to_doctor_and_prints_no_address(self, monkeypatch):
        c = self._doctor(monkeypatch)
        assert c.status == "warn" and (c.link, c.link_label) == ("/tools/doctor", "Open Doctor")
        assert "/tools/doctor" not in c.detail and "(s)" not in c.detail and re.search(r"\d+ findings?$", c.detail)

    def test_a_viewers_row_names_no_admin_page(self, monkeypatch):
        c = self._doctor(monkeypatch, admin=False)
        assert c.link == "" and c.link_label == "" and "/tools/doctor" not in c.detail

    def test_the_hooks_row_names_the_guide_in_words(self):
        c = health._kea_hooks({"dhcp4_config": {"hooks-libraries": []}})
        assert c.status == "fail" and "see the admin guide, section Health Center" in c.detail
        assert "/docs/" not in c.detail and ".md" not in c.detail

    def test_no_message_of_the_two_modules_says_see_and_an_address(self):
        for name in ("health.py", "investigation_logging.py"):
            text = (ROOT / "jen" / "services" / name).read_text(encoding="utf-8")
            assert not re.search(r"see \{?/|see /[a-z]|/docs/[a-z-]+\.md", text), name

    def test_the_health_page_draws_the_link_and_does_not_draw_fix_twice(self, app):
        linked = health.Check("config_doctor", "Configuration Doctor", "kea", "warn", "3 findings", "", "/tools/doctor")
        linked.link, linked.link_label = "/tools/doctor", "Open Doctor"
        plain = health.Check("kea_reachable", "Kea servers reachable", "kea", "fail", "down", "", "/servers")
        with app.test_request_context("/health-center"):
            from datetime import datetime, timezone

            from flask import render_template

            html = render_template(
                "_health_checks.html",
                grouped=[("kea", "Kea", [linked, plain])],
                group_banners={},
                summary={"ok": 0, "warn": 1, "fail": 1, "skip": 0},
                checked_at=datetime.now(timezone.utc),
            )
        assert '3 findings <a class="hc-link" href="/tools/doctor">Open Doctor</a>' in html
        assert html.count('href="/tools/doctor"') == 1, "the Fix link to the same page is not drawn beside it"
        assert '<a class="hc-fix" href="/servers">Fix &rarr;</a>' in html

    def test_the_dashboard_widget_draws_it_and_the_api_schema_names_it(self):
        assert (
            "(c.link ? ' <a href=\"' + escapeHtml(c.link) + '\">' + escapeHtml(c.link_label || 'Open') + '</a>' : '')"
            in _src("dashboard.html")
        )
        spec = (ROOT / "jen" / "routes" / "api_spec.py").read_text(encoding="utf-8")
        assert '"link": {"type": "string"}' in spec and '"link_label": {"type": "string"}' in spec

    def test_the_page_tells_the_checks_who_is_asking(self, client, db, mock_kea, monkeypatch):
        seen = []
        monkeypatch.setattr(health, "run_checks", lambda ctx=None: seen.append(dict(ctx)) or [])
        _viewer(client, db, "q248_health_viewer").get("/health-center/data")
        assert seen and seen[-1]["admin"] is False
        client.get("/dashboard/catalog-data?widgets=readiness")
        assert seen[-1]["admin"] is False


# ── V29, V31 ─────────────────────────────────────────────────────────────────


class TestOneNameForOneThing:
    def test_the_reconcile_link_says_where_it_goes(self):
        src = _src("ddns_reconcile.html")
        assert "Fix in Kea" not in src
        assert '<a href="/reservations?search={{ r.ip|urlencode }}" class="u-6cb285">Open Reservation</a>' in src
        assert '<a href="/leases?search={{ r.ip|urlencode }}" class="u-6cb285">Open Lease</a>' in src
        assert "nothing here is ever written to Kea" in src

    def test_the_second_step_is_multi_factor_authentication(self):
        for path in TEMPLATES.glob("*.html"):
            assert "Two-Factor" not in path.read_text(encoding="utf-8"), path.name
        assert "Multi-Factor Authentication</h1>" in _src("mfa_enroll.html")

    def test_the_menus_say_sign_out(self):
        base = _src("base.html")
        assert base.count("Sign Out</button>") == 2 and "Logout</button>" not in base

    def test_no_page_says_log_in_or_log_out(self):
        offenders = []
        for path in sorted(TEMPLATES.glob("*.html")):
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if "{% for log in" in line:
                    continue  # a loop variable
                if re.search(
                    r"\b[Ll]og(?:ged|ging)? (?:in|out)\b|\bLogout\b", re.sub(r'(?:href|action)="[^"]*"', "", line)
                ):
                    if "goToLogin" in line or "logout-link" in line or "auth.logout" in line:
                        continue  # an identifier, not a word on the page
                    offenders.append(f"{path.name}:{n}: {line.strip()[:90]}")
        assert not offenders, offenders

    def test_the_messages_a_person_reads_say_sign_in(self):
        import jen

        text = pathlib.Path(jen.__file__).read_text(encoding="utf-8")
        assert '"Please sign in to access Jen."' in text and '"Session expired. Please sign in again."' in text
        assert "Please log in" not in text
        auth = (ROOT / "jen" / "routes" / "auth.py").read_text(encoding="utf-8")
        assert 'signed in from {ip}"' in auth and 'signed in via SSO from {ip}"' in auth and 'signed out"' in auth
        assert 'logged in from {ip}"' not in auth and 'logged out"' not in auth
        mfa = (ROOT / "jen" / "routes" / "mfa_routes.py").read_text(encoding="utf-8")
        assert 'signed in (after MFA enrollment)"' in mfa

    def test_signing_in_is_audited_in_those_words(self, client, db):
        from jen.models.user import hash_password

        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO users (username, password, role) VALUES ('q248_signer', %s, 'viewer')",
                (hash_password("q248-Passw0rd!x"),),
            )
        db.commit()
        client.post("/login", data={"username": "q248_signer", "password": "q248-Passw0rd!x"})
        with db.cursor() as cur:
            cur.execute("SELECT details FROM audit_log WHERE action='LOGIN' ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
        assert row is not None, "the sign-in was not audited"
        details = row["details"] if isinstance(row, dict) else row[0]
        assert details.startswith("User q248_signer signed in from "), details

    def test_the_role_is_written_superadmin_everywhere(self):
        offenders = []
        for path in list(TEMPLATES.glob("*.html")) + list((ROOT / "jen").rglob("*.py")):
            if "SuperAdmin" in path.read_text(encoding="utf-8"):
                offenders.append(str(path.relative_to(ROOT)))
        assert not offenders, offenders

    def test_a_refusal_names_the_role_that_way(self, client, db):
        r = _viewer(client, db, "q248_role_viewer").get("/settings/users", follow_redirects=True)
        body = r.get_data(as_text=True)
        assert "Superadmin access required for /settings/users." in body and "SuperAdmin" not in body


# ── V32 ──────────────────────────────────────────────────────────────────────


class TestInvestigateShowsASubnetAsTheBadge:
    MAC = "ac:24:80:00:00:b1"

    @pytest.fixture
    def lease(self, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX('AC24800000B1')")
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state, hostname) VALUES "
                "(INET_ATON('10.99.0.177'), UNHEX('AC24800000B1'), 1, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0, 'q248-b1')"
            )
        db.commit()
        yield
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX('AC24800000B1')")
        db.commit()

    def test_the_lease_row_carries_the_badge_and_the_name(self, logged_in_client, mock_kea, lease):
        html = logged_in_client.get(f"/client?q={self.MAC}").get_data(as_text=True)
        row = re.search(r'<td class="mono">10\.99\.0\.177</td><td>(.*?)</td>', html, re.S)
        assert row, "the lease row is not on the page"
        assert re.fullmatch(r'<span class="badge badge-tone-[a-z0-9-]+">Test Network</span>', row.group(1).strip()), (
            row.group(1)
        )

    def test_the_corner_code_is_gone(self, logged_in_client, mock_kea, lease):
        html = logged_in_client.get(f"/client?q={self.MAC}").get_data(as_text=True)
        assert 'title="investigation ' not in html and not re.search(r"\d{8}T\d{6}Z-[0-9a-f]{6}", html)

    def test_a_subnet_outside_the_callers_map_stays_a_number_and_zero_is_global(self):
        src = _src("client.html")
        assert (
            "{% macro subnet4_cell(sid) %}{% if sid in subnet_choices %}{{ subnet_badge(sid, subnet_choices[sid].name) }}"
            "{% elif sid == 0 %}Global{% else %}{{ sid }}{% endif %}{% endmacro %}"
        ) in src
        assert "<td>{{ l.subnet_id }}</td>" not in src and "<td>{{ r.subnet_id }}</td>" not in src
        assert "<td>{{ a.subnet_id }}</td>" not in src and "<td>{{ h.subnet_id }}</td>" not in src
        route = (ROOT / "jen" / "routes" / "client.py").read_text(encoding="utf-8")
        assert "subnet6_choices=accessible_subnet6_map()" in route and "investigation_id" not in route


# ── V34, V35 ─────────────────────────────────────────────────────────────────

ROWLIST_PAGES = (
    "dashboard.html",
    "reservations.html",
    "logs.html",
    "client.html",
    "ddns_reconcile.html",
    "explain.html",
    "leases.html",
    "devices.html",
    "search_results.html",
)


class TestTheSeparatorStylesheet:
    def test_base_links_it_once_for_every_page(self):
        """Thirty-eight templates draw a row list, the seven plugin pages among them: the link is base.html's, not a line each page has to remember."""
        link = '<link rel="stylesheet" href="/static/css/rowlist-dots.css?v={{ jen_version }}">'
        assert _src("base.html").count(link) == 1
        assert not (TEMPLATES / "_rowlist_dots.html").exists()
        for name in ROWLIST_PAGES:
            assert "rowlist-dots" not in _src(name) and "_rowlist_dots" not in _src(name), name

    def test_the_rule_clips_the_row_and_takes_the_dot_out_of_the_flow(self):
        css = (ROOT / "static" / "css" / "rowlist-dots.css").read_text(encoding="utf-8")
        assert css.count("@media") == 1 and "@media screen and (max-width: 768px)" in css
        assert (
            "table.rowlist.rowlist tbody tr { overflow: hidden; padding-left: var(--sp-2); border-left: var(--sp-1) solid transparent; }"
            in css
        )
        assert "position: absolute; right: calc(100% + var(--sp-2));" in css
        assert not re.search(r"#[0-9a-fA-F]{3,6}\b|rgb\(", css), "no literal color"

    def test_the_stylesheet_is_served(self, logged_in_client):
        r = logged_in_client.get("/static/css/rowlist-dots.css")
        assert r.status_code == 200 and b"table.rowlist.rowlist" in r.data
        assert "/static/css/rowlist-dots.css?v=" in logged_in_client.get("/reservations").get_data(as_text=True)


class TestTheStaleDaysSettingIsNotAFilter:
    def test_it_is_beside_the_filter_bar_not_in_it(self, logged_in_client):
        html = logged_in_client.get("/devices").get_data(as_text=True)
        row = html.split('<div class="devices-filter-row">', 1)[1]
        bar, rest = row.split("</form>\n</div>", 1)
        assert '<div class="filter-bar">' in bar and 'name="stale_days"' not in bar
        assert rest.lstrip().startswith("<form") or 'class="flex items-center gap-2 devices-stale"' in rest[:400]
        assert 'name="stale_days"' in rest[:900]


# ── V36 ──────────────────────────────────────────────────────────────────────


class TestACountAgreesWithItsNoun:
    COUNT_WITH_BRACKETS = re.compile(r"\{[^{}]+\} (?:[A-Za-z/-]+ ){0,3}[A-Za-z-]+\((?:s|es)\)")

    def test_no_message_in_the_tree_prints_a_count_and_a_bracketed_s(self):
        """Whole tree (jen/): an f-string that prints `{count} noun(s)`. Left alone are the log lines (a `logger.` call and its continuation lines) and the migrations,
        which nobody reads on a page."""
        offenders = []
        for path in sorted((ROOT / "jen").rglob("*.py")):
            rel = str(path.relative_to(ROOT)).replace("\\", "/")
            if rel == "jen/models/migrations.py":
                continue
            depth = 0
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"\blogger\.\w+\(", line):
                    depth = line.count("(") - line.count(")")
                    continue
                if depth > 0:
                    depth += line.count("(") - line.count(")")
                    continue
                if line.strip().startswith("#"):
                    continue
                if self.COUNT_WITH_BRACKETS.search(line.split("  # ")[0]):
                    offenders.append(f"{rel}:{n}: {line.strip()[:100]}")
        assert not offenders, offenders

    def test_no_template_does(self):
        offenders = []
        for path in sorted(TEMPLATES.glob("*.html")):
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(
                    r"\}\}(?:</strong>)?\s+(?:[A-Za-z-]+\s+){0,2}[A-Za-z-]+\((?:s|es)\)|(?:error|name)\(s\)", line
                ):
                    offenders.append(f"{path.name}:{n}")
        assert not offenders, offenders

    def test_the_sentences(self):
        from jen.routes.settings import security
        from jen.services import kea_host

        assert security.cleared_sentence(1, 1) == "Cleared 1 failed login attempt and ended 1 permanent lockout."
        assert security.cleared_sentence(2, 0) == "Cleared 2 failed login attempts and ended 0 permanent lockouts."
        assert reltime.plural(1, "audit entry", "audit entries") == "1 audit entry"
        assert kea_host.helper_version_phrase([5], 5) == "1/1 host on helper v5"
        assert kea_host.helper_version_phrase([5, 5], 5) == "2/2 hosts on helper v5"

    def test_a_verb_agrees_too(self):
        src = (ROOT / "jen" / "services" / "dhcp_options.py").read_text(encoding="utf-8")
        assert "'an IPv4 address' if len(bad) == 1 else 'IPv4 addresses'" in src
        src = (ROOT / "jen" / "services" / "health.py").read_text(encoding="utf-8")
        assert "{'is' if len(ambiguous) == 1 else 'are'} hex text with no lease" in src
        assert "{'has' if len(undeclared) == 1 else 'have'} no name in Jen" in src

    def test_the_lockout_card_and_the_import_review(self):
        assert (
            "{{ rl_lockouts_username|plural('account name') }}, {{ rl_lockouts_ip|plural('address', 'addresses') }}"
            in _src("settings_security.html")
        )
        review = _src("import_windows_review.html")
        assert "active {% if leases.active == 1 %}lease{% else %}leases{% endif %} in the file" in review
        assert "global_class_count|plural('client class', 'client classes')" in review


# ── V39, V40 ─────────────────────────────────────────────────────────────────

SETTINGS_PAGES = ("/settings/kea", "/settings/security", "/settings/alerts", "/settings/appearance", "/settings/system")
BARE_SAVE = re.compile(r"<button[^>]*>\s*(?:<svg.*?</svg>\s*)?Save\s*</button>", re.S)
CHECKBOX_LABEL = re.compile(r'<label(?P<attrs>[^>]*)>\s*(?:<input type="hidden"[^>]*>)?<input type="checkbox"')


class TestSettingsSaveButtonsAndCheckboxLabels:
    @pytest.mark.parametrize("path", SETTINGS_PAGES)
    def test_every_save_names_what_it_saves(self, logged_in_client, mock_kea, path):
        html = logged_in_client.get(path).get_data(as_text=True)
        assert "Save" in html, "the page has no Save at all: the test's premise moved"
        assert not BARE_SAVE.search(html), BARE_SAVE.search(html).group(0)

    def test_the_names(self):
        assert _src("settings_alerts.html").count(">Save Template</button>") == 2
        security = _src("settings_security.html")
        assert ">Save Session Timeout</button>" in security and ">Save Rate Limiting</button>" in security
        system = _src("settings_system.html")
        assert "Save Audit Retention</button>" in system and "Save Config History</button>" in system
        appearance = _src("settings_appearance.html")
        assert "Save Nav Color</button>" in appearance and "Save Default Theme</button>" in appearance

    def test_the_release_channel_save_is_a_primary_button(self, logged_in_client):
        html = logged_in_client.get("/settings/system").get_data(as_text=True)
        form = html.split('action="/settings/infrastructure/update-channel"', 1)[1].split("</form>", 1)[0]
        assert '<button type="submit" class="btn btn-sm btn-primary">Save Channel</button>' in form
        assert "btn-secondary" not in form

    def test_a_checkbox_label_in_a_form_group_is_a_sentence_label(self):
        """Source, the three settings pages whose checkbox labels were small upper case: a label whose first control is a checkbox carries `check-label`, or is one
        of the kinds that never were upper case (a hint, the write-mode consents, a label that styles itself)."""
        not_a_field_label = ("form-hint", "wm-mode-label", "style=", "data-settle-discard", "data-wm-")
        for name in ("settings_kea.html", "settings_security.html", "settings_alerts.html"):
            src = _src(name)
            for m in CHECKBOX_LABEL.finditer(src):
                attrs = m.group("attrs")
                line = src.count("\n", 0, m.start()) + 1
                tail = src[m.end() : m.end() + 200]
                if any(k in attrs for k in not_a_field_label) or 'form="wm-form-' in tail:
                    continue
                assert "check-label" in attrs, f"{name}:{line}: {m.group(0)[:80]}"

    def test_the_labels_the_readers_named(self, logged_in_client, mock_kea):
        security = logged_in_client.get("/settings/security").get_data(as_text=True)
        assert '<label class="check-label"><input type="checkbox" name="auto_create"' in security
        kea = logged_in_client.get("/settings/kea").get_data(as_text=True)
        assert re.search(r'<label class="check-label u-bf5dd8">\s*<input type="checkbox" name="api_tls_verify"', kea)


class TestTheDailySummaryTimeIsATextField:
    def _field(self, client):
        html = client.get("/settings/alerts").get_data(as_text=True)
        return re.search(r'<input id="f-summary_time"[^>]*>', html).group(0)

    def test_it_is_a_24_hour_text_field(self, logged_in_client):
        field = self._field(logged_in_client)
        for attr in (
            'type="text"',
            'inputmode="numeric"',
            'name="summary_time"',
            'pattern="([01][0-9]|2[0-3]):[0-5][0-9]"',
            'placeholder="07:00"',
            'maxlength="5"',
            'aria-describedby="f-summary_time-hint"',
        ):
            assert attr in field, attr
        assert 'type="time"' not in field

    def test_the_pattern_is_the_routes_own_shape(self):
        pattern = re.search(
            r'pattern="([^"]+)"', _src("settings_alerts.html").split('id="f-summary_time"', 1)[1]
        ).group(1)
        for good in ("00:00", "07:00", "18:30", "23:59"):
            assert re.fullmatch(pattern, good), good
        for bad in ("24:00", "7:00", "07:60", "7am", "0700", "07:00 AM"):
            assert not re.fullmatch(pattern, bad), bad

    def test_a_value_that_is_not_hh_mm_is_refused_beside_the_field_and_nothing_is_saved(self, logged_in_client):
        from jen.models.user import get_global_setting, set_global_setting

        set_global_setting("daily_summary_time", "06:15")
        r = logged_in_client.post(
            "/settings/alerts/save-global",
            data={
                "summary_time": "7am",
                "pool_exhaustion_free": "5",
                "alert_threshold_pct": "80",
                "reserved_lease_mode": "always",
            },
            follow_redirects=True,
        )
        body = r.get_data(as_text=True)
        assert "The daily summary time must be HH:MM in UTC, for example 07:00." in body
        assert get_global_setting("daily_summary_time", "07:00") == "06:15"


# ── V43 ──────────────────────────────────────────────────────────────────────


class TestSearchResults:
    def _providers(self):
        return [
            {"title": "IPAM Lite", "rows": [], "unavailable": False, "reason": ""},
            {
                "title": "Switch Ports",
                "rows": [{"title": "sw1 port 4", "subtitle": "zz", "href": "/network/switchport"}],
                "unavailable": False,
                "reason": "",
            },
            {"title": "Host Watchdog", "rows": [], "unavailable": False, "reason": ""},
            {"title": "Network Discovery", "rows": [], "unavailable": True, "reason": "timed out"},
        ]

    def _page(self, client, monkeypatch, providers):
        monkeypatch.setattr("jen.services.search_providers.run_search_providers", lambda q, ids, all_subnets: providers)
        return client.get("/search?q=zzzz-q248").get_data(as_text=True)

    def test_groups_with_no_match_are_one_closing_line(self, logged_in_client, monkeypatch):
        html = self._page(logged_in_client, monkeypatch, self._providers())
        assert html.count("No matches in: IPAM Lite, Host Watchdog.") == 1
        assert "No IPAM Lite results." not in html and "No Host Watchdog results." not in html
        cards = re.findall(r'<span class="card-title"><svg[^>]*>.*?</svg>\s*([^<(]+?)\s*(?:\(|</span>)', html, re.S)
        assert cards == ["Switch Ports", "Network Discovery"], cards
        assert "Network Discovery search is unavailable right now (timed out)." in html

    def test_no_closing_line_when_every_group_matched(self, logged_in_client, monkeypatch):
        html = self._page(logged_in_client, monkeypatch, self._providers()[1:2])
        assert "No matches in:" not in html and 'id="search-no-match"' not in html

    def test_the_result_tables_are_row_lists_with_the_action_trailing(self):
        src = _src("search_results.html")
        assert src.count('<table class="rowlist">') == 6 and "<table>" not in src
        assert src.count('data-m="trailing"') == 6 and src.count('data-m="primary"') == 6
        assert src.count("{{ row_investigate(") == 5
        assert (
            '{% macro row_investigate(who) %}<span class="desk-only">{{ investigate_link(who, "button") }}</span>'
            '<span class="phone-only">{{ investigate_link(who, "icon") }}</span>{% endmacro %}'
        ) in src

    def test_a_lease_row_renders_with_its_roles(self, logged_in_client, db, monkeypatch):
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX('AC24800000B2')")
            cur.execute(
                "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state, hostname) VALUES "
                "(INET_ATON('10.99.0.178'), UNHEX('AC24800000B2'), 1, 3600, DATE_ADD(NOW(), INTERVAL 1 HOUR), 0, 'q248-search-row')"
            )
        db.commit()
        try:
            monkeypatch.setattr("jen.services.search_providers.run_search_providers", lambda q, ids, all_subnets: [])
            html = logged_in_client.get("/search?q=q248-search-row").get_data(as_text=True)
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease4 WHERE hwaddr=UNHEX('AC24800000B2')")
            db.commit()
        row = re.search(r"<tr>\s*<td class=\"mono\" data-m=\"secondary\">.*?</tr>", html, re.S).group(0)
        assert 'data-m="primary"' in row and 'data-m="trailing"' in row
        # the word on a desktop, the icon alone on a phone: the same link twice, one of them hidden by the width
        assert re.search(
            r'<span class="desk-only"><a href="/client\?q=(?i:ac)[^"]*(?i:b2)" class="btn btn-sm btn-secondary"><svg',
            row,
        ), row
        assert re.search(
            r'<span class="phone-only"><a href="/client\?q=(?i:ac)[^"]*(?i:b2)" class="btn btn-sm btn-secondary" title=',
            row,
        )
