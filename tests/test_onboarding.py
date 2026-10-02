"""
tests/test_onboarding.py
─────────────────────────
v5.39.0 (Q39) — the getting-started checklist.
checklist() is pure (fabricated ctx, no DB/Kea); the route tests below
cover access control and the dismiss flag.
"""

import pytest

from jen.services import onboarding
from jen.services.health import Check

_TITLES = {
    "kea_reachable": "Kea servers reachable",
    "kea_subnets_declared": "Every Kea subnet is named",
    "helper_installed": "Kea host helper installed",
    "kea32_helper_version": "Kea host helper current for 3.2",
    "kea32_control_transport": "Control transport ready for 3.2",
    "lease_snapshot_fresh": "Lease snapshots current",
}


def _check(cid, status="ok", detail=""):
    return Check(cid, _TITLES.get(cid, cid), "kea", status, detail, "", "")


def _ctx(**over):
    base = {
        "checks": {cid: _check(cid) for cid in _TITLES},
        "is_superadmin": True,
        "kea_connection_mode": "direct",
        "ssl_configured": True,
        "mfa_mode": "required_admins",
        "current_user_has_mfa": True,
        "alert_channels_enabled": 1,
        "backup_count": 1,
        "backup_schedule_enabled": False,
        "last_recovery_bundle_at": "2026-10-01T00:00:00",
        "ha_mode": False,
        "server_count": 1,
    }
    base.update(over)
    return base


@pytest.fixture(autouse=True)
def _reset_pill_cache():
    onboarding._pill_cache.clear()
    yield
    onboarding._pill_cache.clear()


# ── checklist() — pure ───────────────────────────────────────────────────────


class TestChecklistRows:
    def test_all_done(self):
        summary = onboarding.checklist(_ctx())
        assert summary["all_done"] is True
        assert summary["done"] == summary["total"] > 0

    def test_kea_unreachable_marks_undone(self):
        ctx = _ctx()
        ctx["checks"]["kea_reachable"] = _check("kea_reachable", "fail", "down")
        summary = onboarding.checklist(ctx)
        row = next(r for r in summary["rows"] if r["title"] == "Kea is reachable")
        assert row["done"] is False
        assert summary["all_done"] is False

    def test_missing_check_fails_closed(self):
        ctx = _ctx()
        del ctx["checks"]["kea_reachable"]
        summary = onboarding.checklist(ctx)
        row = next(r for r in summary["rows"] if r["title"] == "Kea is reachable")
        assert row["done"] is False

    def test_control_transport_ca_mode_below_30_counts_as_done(self):
        ctx = _ctx(kea_connection_mode="ca")
        ctx["checks"]["kea32_control_transport"] = _check("kea32_control_transport", "warn", "before you upgrade")
        summary = onboarding.checklist(ctx)
        row = next(r for r in summary["rows"] if "Control transport" in r["title"])
        assert row["done"] is True
        assert "fine for now" in row["detail"]

    def test_control_transport_direct_mode_warn_is_not_done(self):
        ctx = _ctx()
        ctx["checks"]["kea32_control_transport"] = _check("kea32_control_transport", "warn", "missing socket")
        summary = onboarding.checklist(ctx)
        row = next(r for r in summary["rows"] if "Control transport" in r["title"])
        assert row["done"] is False

    def test_helper_needs_both_installed_and_current(self):
        ctx = _ctx()
        ctx["checks"]["kea32_helper_version"] = _check("kea32_helper_version", "warn", "behind")
        summary = onboarding.checklist(ctx)
        row = next(r for r in summary["rows"] if "helper" in r["title"])
        assert row["done"] is False

    def test_plain_admin_hides_security_rows(self):
        summary = onboarding.checklist(_ctx(is_superadmin=False))
        titles = [r["title"] for r in summary["rows"]]
        assert "HTTPS is on" not in titles
        assert "MFA is enabled for your account" not in titles

    def test_superadmin_sees_security_rows(self):
        summary = onboarding.checklist(_ctx(is_superadmin=True))
        titles = [r["title"] for r in summary["rows"]]
        assert "HTTPS is on" in titles
        assert "MFA is enabled for your account" in titles

    def test_no_backup_no_schedule_is_undone(self):
        ctx = _ctx(backup_count=0, backup_schedule_enabled=False)
        summary = onboarding.checklist(ctx)
        row = next(r for r in summary["rows"] if "backup" in r["title"].lower())
        assert row["done"] is False

    def test_schedule_without_a_backup_yet_counts(self):
        ctx = _ctx(backup_count=0, backup_schedule_enabled=True)
        summary = onboarding.checklist(ctx)
        row = next(r for r in summary["rows"] if "backup" in r["title"].lower())
        assert row["done"] is True

    def test_ha_row_absent_when_ha_not_configured(self):
        summary = onboarding.checklist(_ctx())
        assert not any("HA" in r["title"] for r in summary["rows"])

    def test_ha_row_undone_with_one_server(self):
        summary = onboarding.checklist(_ctx(ha_mode=True, server_count=1))
        row = next(r for r in summary["rows"] if "HA" in r["title"])
        assert row["done"] is False

    def test_ha_row_done_with_two_servers(self):
        summary = onboarding.checklist(_ctx(ha_mode=True, server_count=2))
        row = next(r for r in summary["rows"] if "HA" in r["title"])
        assert row["done"] is True

    def test_recovery_bundle_row_undone_when_never_downloaded(self):
        # v5.67.0-beta.5 (Q117, item i) — distinct from "A backup
        # exists": a recovery bundle (encrypted, config + keys, one-time
        # download) had no row of its own before this Q.
        summary = onboarding.checklist(_ctx(last_recovery_bundle_at=""))
        row = next(r for r in summary["rows"] if r["title"] == "A recovery bundle exists")
        assert row["done"] is False
        assert row["detail"] == "none downloaded yet"

    def test_recovery_bundle_row_done_when_downloaded(self):
        summary = onboarding.checklist(_ctx(last_recovery_bundle_at="2026-10-01T12:00:00"))
        row = next(r for r in summary["rows"] if r["title"] == "A recovery bundle exists")
        assert row["done"] is True
        assert "2026-10-01T12:00:00" in row["detail"]


# ── v5.67.0 (Q115) — links into whichever wizard step is still open ─────────


class TestSetupWizardLinks:
    def test_open_steps_link_into_setup(self):
        summary = onboarding.checklist(_ctx(wizard_state={}))
        by_title = {r["title"]: r for r in summary["rows"]}
        assert by_title["Kea is reachable"]["link"] == "/setup/connect"
        assert by_title["Every subnet is named"]["link"] == "/setup/found"
        assert by_title["SSH and the Kea host helper are current"]["link"] == "/setup/helper"
        assert by_title["A backup exists or is scheduled"]["link"] == "/setup/recovery"
        assert by_title["A recovery bundle exists"]["link"] == "/setup/recovery"

    def test_resolved_steps_fall_back_to_their_usual_link(self):
        resolved = {"connect": "done", "found": "skipped", "helper": "done", "recovery": "done"}
        summary = onboarding.checklist(_ctx(wizard_state=resolved))
        by_title = {r["title"]: r for r in summary["rows"]}
        assert by_title["Kea is reachable"]["link"] == "/servers"
        assert by_title["Every subnet is named"]["link"] == "/settings/kea"
        assert by_title["SSH and the Kea host helper are current"]["link"] == "/settings/kea"
        assert by_title["A backup exists or is scheduled"]["link"] == "/settings/databases?tab=backups"
        assert by_title["A recovery bundle exists"]["link"] == "/settings/databases?tab=recovery"

    def test_missing_wizard_state_does_not_crash(self):
        """A ctx with no "wizard_state" key at all (every other test in
        this file) must not raise — checklist() predates the wizard and
        most callers never set it. ctx.get(..., {}) treats that the same
        as an empty state (every step still open)."""
        summary = onboarding.checklist(_ctx())
        by_title = {r["title"]: r for r in summary["rows"]}
        assert by_title["Kea is reachable"]["link"] == "/setup/connect"


class TestSetupLinksAreRoleAware:
    """v5.67.0-beta.8 (Q120, item h) — /setup/* is superadmin-only; a plain admin was sent to a 403."""

    def test_an_admin_keeps_every_settings_target_while_every_step_is_open(self):
        summary = onboarding.checklist(_ctx(is_superadmin=False, wizard_state={}))
        by_title = {r["title"]: r for r in summary["rows"]}
        assert by_title["Kea is reachable"]["link"] == "/servers"
        assert by_title["Every subnet is named"]["link"] == "/settings/kea"
        assert by_title["SSH and the Kea host helper are current"]["link"] == "/settings/kea"
        assert by_title["A backup exists or is scheduled"]["link"] == "/settings/databases?tab=backups"
        assert by_title["A recovery bundle exists"]["link"] == "/settings/databases?tab=recovery"

    def test_no_row_an_admin_sees_links_into_setup(self):
        summary = onboarding.checklist(_ctx(is_superadmin=False, wizard_state={}))
        assert not [r for r in summary["rows"] if r["link"].startswith("/setup")]

    def test_a_superadmin_still_goes_to_the_open_step(self):
        summary = onboarding.checklist(_ctx(is_superadmin=True, wizard_state={}))
        by_title = {r["title"]: r for r in summary["rows"]}
        assert by_title["Kea is reachable"]["link"] == "/setup/connect"


# ── dismiss flag ──────────────────────────────────────────────────────────────


class TestDismissFlag:
    def test_default_not_dismissed(self):
        assert onboarding.is_dismissed() is False

    def test_dismiss_sets_flag(self):
        onboarding.dismiss()
        assert onboarding.is_dismissed() is True


# ── cached_pill() ─────────────────────────────────────────────────────────────


class TestCachedPill:
    def test_hidden_when_dismissed(self, monkeypatch):
        monkeypatch.setattr(onboarding, "is_dismissed", lambda: True)
        assert onboarding.cached_pill(user=object(), is_superadmin=True) is None

    def test_hidden_when_all_done(self, monkeypatch):
        monkeypatch.setattr(onboarding, "is_dismissed", lambda: False)
        monkeypatch.setattr(onboarding, "build_ctx", lambda user, is_superadmin: _ctx())
        assert onboarding.cached_pill(user=object(), is_superadmin=True) is None

    def test_shown_when_incomplete(self, monkeypatch):
        ctx = _ctx()
        ctx["checks"]["kea_reachable"] = _check("kea_reachable", "fail")
        monkeypatch.setattr(onboarding, "is_dismissed", lambda: False)
        monkeypatch.setattr(onboarding, "build_ctx", lambda user, is_superadmin: ctx)
        result = onboarding.cached_pill(user=object(), is_superadmin=True)
        assert result is not None
        assert result["done"] < result["total"]

    def test_never_calls_build_ctx_twice_within_ttl(self, monkeypatch):
        calls = {"n": 0}

        def _fake_build_ctx(user, is_superadmin):
            calls["n"] += 1
            ctx = _ctx()
            ctx["checks"]["kea_reachable"] = _check("kea_reachable", "fail")
            return ctx

        monkeypatch.setattr(onboarding, "is_dismissed", lambda: False)
        monkeypatch.setattr(onboarding, "build_ctx", _fake_build_ctx)
        onboarding.cached_pill(user=object(), is_superadmin=True)
        onboarding.cached_pill(user=object(), is_superadmin=True)
        assert calls["n"] == 1


class _U:
    """The two attributes cached_pill() reads off a user."""

    def __init__(self, role, scope=None):
        self.role = role
        self.subnet_access_list = scope


class TestPillIsCachedPerRoleAndScope:
    """v5.67.0-beta.8 (Q120, item o) — one process-wide slot meant whichever user rendered first set
    everyone's count for the TTL."""

    def _setup(self, monkeypatch):
        calls = []

        def build(user, is_superadmin):
            calls.append((user.role, user.subnet_access_list, is_superadmin))
            ctx = _ctx(is_superadmin=is_superadmin)
            ctx["checks"]["kea_reachable"] = _check("kea_reachable", "fail")
            if is_superadmin:  # a superadmin's list carries two more rows, both failing here
                ctx.update(ssl_configured=False, current_user_has_mfa=False)
            return ctx

        monkeypatch.setattr(onboarding, "is_dismissed", lambda: False)
        monkeypatch.setattr(onboarding, "build_ctx", build)
        return calls

    def test_an_admin_does_not_see_a_superadmins_count_or_the_reverse(self, monkeypatch):
        self._setup(monkeypatch)
        sup = onboarding.cached_pill(_U("superadmin"), True)
        adm = onboarding.cached_pill(_U("admin"), False)
        assert sup["total"] > adm["total"]
        assert (sup["total"] - sup["done"]) > (adm["total"] - adm["done"])
        # and the order does not matter: the admin first, then the superadmin
        onboarding._pill_cache.clear()
        adm2 = onboarding.cached_pill(_U("admin"), False)
        sup2 = onboarding.cached_pill(_U("superadmin"), True)
        assert (adm2, sup2) == (adm, sup)

    def test_each_scope_is_computed_once_within_the_ttl(self, monkeypatch):
        calls = self._setup(monkeypatch)
        for _ in range(3):
            onboarding.cached_pill(_U("admin"), False)
            onboarding.cached_pill(_U("superadmin"), True)
            onboarding.cached_pill(_U("admin", [3, 1]), False)
        assert len(calls) == 3

    def test_two_users_with_the_same_role_and_scope_share_an_entry(self, monkeypatch):
        calls = self._setup(monkeypatch)
        onboarding.cached_pill(_U("admin", [1, 2]), False)
        onboarding.cached_pill(_U("admin", [2, 1]), False)  # the same set in a different order
        assert len(calls) == 1

    def test_a_different_subnet_scope_is_a_different_entry(self, monkeypatch):
        calls = self._setup(monkeypatch)
        onboarding.cached_pill(_U("admin", [1]), False)
        onboarding.cached_pill(_U("admin", [2]), False)
        onboarding.cached_pill(_U("admin", None), False)
        assert len(calls) == 3

    def test_an_expired_entry_is_recomputed(self, monkeypatch):
        calls = self._setup(monkeypatch)
        onboarding.cached_pill(_U("admin"), False)
        for key, (ts, result) in list(onboarding._pill_cache.items()):
            onboarding._pill_cache[key] = (ts - onboarding._PILL_CACHE_TTL - 1, result)
        onboarding.cached_pill(_U("admin"), False)
        assert len(calls) == 2

    def test_the_cache_is_bounded(self, monkeypatch):
        self._setup(monkeypatch)
        for n in range(onboarding._PILL_CACHE_MAX + 20):
            onboarding.cached_pill(_U("admin", [n]), False)
        assert len(onboarding._pill_cache) <= onboarding._PILL_CACHE_MAX


# ── route ─────────────────────────────────────────────────────────────────────


class TestGettingStartedPage:
    def test_renders_for_superadmin(self, logged_in_client, mock_kea, db):
        r = logged_in_client.get("/getting-started")
        assert r.status_code == 200
        assert b"Getting Started" in r.data

    def test_renders_for_plain_admin_without_security_rows(self, client, db, mock_kea):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=None, role="admin", username="onb_admin")
        r = c.get("/getting-started")
        assert r.status_code == 200
        assert b"HTTPS is on" not in r.data

    def test_viewer_redirected(self, client, db, mock_kea):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=None, role="viewer", username="onb_viewer")
        r = c.get("/getting-started", follow_redirects=False)
        assert r.status_code == 302

    def test_login_required(self, client, db):
        r = client.get("/getting-started", follow_redirects=False)
        assert r.status_code in (302, 401)

    def test_dismiss_requires_superadmin(self, client, db, mock_kea):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=None, role="admin", username="onb_admin2")
        r = c.post("/getting-started/dismiss", follow_redirects=False)
        assert r.status_code == 302
        assert onboarding.is_dismissed() is False

    def test_dismiss_as_superadmin(self, logged_in_client, db, mock_kea):
        r = logged_in_client.post("/getting-started/dismiss", follow_redirects=False)
        assert r.status_code == 302
        assert onboarding.is_dismissed() is True
