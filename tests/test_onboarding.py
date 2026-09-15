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
        "ha_mode": False,
        "server_count": 1,
    }
    base.update(over)
    return base


@pytest.fixture(autouse=True)
def _reset_pill_cache():
    onboarding._pill_cache[:] = [0.0, (0, 0)]
    yield
    onboarding._pill_cache[:] = [0.0, (0, 0)]


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
