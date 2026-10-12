"""
tests/test_q174_routes.py
─────────────────────────
v5.69.0-beta.5 (Q174): the P3 sweep's route-level behaviours - each is the one-line test its register item implies. Database-backed (the app, the test client, the settings table).
"""

import io
import json
import os
import pathlib
from datetime import datetime, timedelta, timezone

import pytest

from jen import extensions
from tests.conftest import restricted_client

A = {"name": "Office", "cidr": "10.99.0.0/24"}
B = {"name": "Guest", "cidr": "10.99.1.0/24"}


def _stale(client):
    with client.session_transaction() as sess:
        sess["auth_at"] = (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat()


# ── users, login ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


class TestUsersAndLogin:
    def test_a_timeout_for_an_account_that_is_not_there_says_so(self, logged_in_client):
        r = logged_in_client.post("/users/set-timeout/987654", data={"timeout": "30"}, follow_redirects=True)
        assert "User not found." in r.get_data(as_text=True)

    def test_a_timeout_for_a_real_account_still_works(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE username='admin'")
            uid = cur.fetchone()["id"]
        db.commit()
        r = logged_in_client.post(f"/users/set-timeout/{uid}", data={"timeout": ""}, follow_redirects=True)
        assert "Session timeout updated." in r.get_data(as_text=True)

    def test_something_that_is_not_an_image_gets_a_sentence(self, logged_in_client):
        r = logged_in_client.post(
            "/users/upload-avatar", data={"avatar_data_url": "javascript:alert(1)"}, follow_redirects=True
        )
        assert "That is not an image." in r.get_data(as_text=True)

    def test_a_plain_login_goes_where_it_was_sent_from(self, client):
        r = client.post("/login?next=/leases", data={"username": "admin", "password": "admin"})
        assert r.status_code in (301, 302) and r.headers["Location"].endswith("/leases")

    @pytest.mark.parametrize(
        "bad", ["//evil.example/x", "https://evil.example/", "/\\evil.example", "leases", "javascript:alert(1)"]
    )
    def test_a_next_that_leaves_this_host_is_ignored(self, client, bad):
        r = client.post("/login?next=" + bad, data={"username": "admin", "password": "admin"})
        assert (
            r.status_code in (301, 302)
            and "evil" not in r.headers["Location"]
            and not r.headers["Location"].endswith("leases")
        )


# ── subnets, the API, the dashboard ──────────────────────────────────────────────────────────────────────────────────────────────────────────────


class TestSubnetNote:
    def test_a_note_id_that_is_not_a_number_is_a_400(self, logged_in_client):
        r = logged_in_client.post("/subnets/save-note", data={"subnet_id": "abc", "notes": "x"})
        assert r.status_code == 400 and r.get_json()["ok"] is False

    def test_a_note_for_an_id_jen_does_not_list_is_a_404_and_stores_nothing(self, logged_in_client, db, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: dict(A)})
        r = logged_in_client.post("/subnets/save-note", data={"subnet_id": "4242", "notes": "x"})
        assert r.status_code == 404
        with db.cursor() as cur:
            cur.execute("SELECT 1 FROM subnet_notes WHERE subnet_id=4242")
            assert cur.fetchone() is None
        db.commit()


class TestRecentLeasesOnTheDashboardAreTheCallersOwn:
    def test_a_scoped_viewer_sees_only_their_subnets_recent_leases(self, client, db, mock_kea, monkeypatch):
        monkeypatch.setattr(extensions, "SUBNET_MAP", {1: dict(A), 2: dict(B)})
        with db.cursor() as cur:
            cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr) IN ('AABBCCDDEE81','AABBCCDDEE82')")
            for mac, ip, sid in (("AABBCCDDEE81", "10.99.0.181", 1), ("AABBCCDDEE82", "10.99.1.182", 2)):
                cur.execute(
                    "INSERT INTO lease4 (address, hwaddr, subnet_id, valid_lifetime, expire, state, hostname) VALUES "
                    "(INET_ATON(%s), UNHEX(%s), %s, 3600, DATE_ADD(NOW(), INTERVAL 30 MINUTE), 0, 'q174')",
                    (ip, mac, sid),
                )
        db.commit()
        try:
            c, _ = restricted_client(client, db, [1], role="viewer", username="q174_dash_viewer")
            body = c.get("/?hours=1", headers={"HX-Request": "true"}).get_data(as_text=True)
            assert "10.99.0.181" in body and "10.99.1.182" not in body
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM lease4 WHERE HEX(hwaddr) IN ('AABBCCDDEE81','AABBCCDDEE82')")
            db.commit()


class TestAPartialCarriesItsOwnSentences:
    def test_explain_in_a_partial_does_not_queue_a_flash(self, logged_in_client):
        r = logged_in_client.get("/tools/explain?mac=not-a-mac", headers={"HX-Request": "true"})
        assert r.status_code == 200 and "That isn&#39;t a MAC address" in r.get_data(as_text=True)
        page = logged_in_client.get("/getting-started").get_data(
            as_text=True
        )  # the NEXT full page: nothing carried over
        assert "That isn&#39;t a MAC address" not in page

    def test_timeline_in_a_partial_returns_the_sentence_not_a_flash(self, logged_in_client):
        r = logged_in_client.get("/timeline?mac=not-a-mac", headers={"HX-Request": "true"})
        assert r.status_code == 200 and "That isn't a MAC address" in r.get_data(as_text=True)
        page = logged_in_client.get("/getting-started").get_data(as_text=True)
        assert "isn&#39;t a MAC address" not in page


# ── settings ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────


class TestAlertChannels:
    @staticmethod
    def _config(**kw):
        from jen.services import alerts

        return alerts.encode_channel_config(kw)

    def test_an_edit_that_changes_the_type_writes_it(self, logged_in_client, db):
        with db.cursor() as cur:
            cur.execute("DELETE FROM alert_channels WHERE channel_name='q174-type'")
            cur.execute(
                "INSERT INTO alert_channels (channel_type, channel_name, enabled, config, alert_types) VALUES ('slack','q174-type',1,%s,'[]')",
                (self._config(webhook_url="https://hooks.example/x"),),
            )
            cid = cur.lastrowid
        db.commit()
        try:
            logged_in_client.post(
                "/settings/alerts/save-channel",
                data={
                    "channel_id": str(cid),
                    "channel_type": "discord",
                    "channel_name": "q174-type",
                    "enabled": "1",
                    "discord_webhook": "https://discord.example/w",
                },
            )
            with db.cursor() as cur:
                cur.execute("SELECT channel_type FROM alert_channels WHERE id=%s", (cid,))
                assert cur.fetchone()["channel_type"] == "discord"
            db.commit()
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM alert_channels WHERE channel_name='q174-type'")
            db.commit()

    def test_a_type_that_is_not_one_of_ours_is_refused(self, logged_in_client, db):
        r = logged_in_client.post(
            "/settings/alerts/save-channel",
            data={"channel_type": "carrier-pigeon", "channel_name": "q174-bad", "enabled": "1"},
            follow_redirects=True,
        )
        assert "Choose a channel type from the list." in r.get_data(as_text=True)
        with db.cursor() as cur:
            cur.execute("SELECT 1 FROM alert_channels WHERE channel_name='q174-bad'")
            assert cur.fetchone() is None
        db.commit()

    def test_the_test_button_knows_pushover(self, logged_in_client, db, monkeypatch):
        from jen.services import alerts

        sent = []
        monkeypatch.setattr(alerts, "_send_pushover_channel", lambda msg, cfg: sent.append(cfg) or True)
        with db.cursor() as cur:
            cur.execute("DELETE FROM alert_channels WHERE channel_name='q174-push'")
            cur.execute(
                "INSERT INTO alert_channels (channel_type, channel_name, enabled, config, alert_types) VALUES ('pushover','q174-push',1,%s,'[]')",
                (self._config(user_key="u" * 30, api_token="t" * 30),),
            )
            cid = cur.lastrowid
        db.commit()
        try:
            r = logged_in_client.post(f"/settings/alerts/test-channel/{cid}", follow_redirects=True)
            assert sent and "Test message sent successfully" in r.get_data(as_text=True)
        finally:
            with db.cursor() as cur:
                cur.execute("DELETE FROM alert_channels WHERE channel_name='q174-push'")
            db.commit()


class TestHaSettings:
    def test_a_mode_that_is_none_of_the_four_is_refused_not_saved(self, logged_in_client, monkeypatch):
        from jen import config as config_mod

        wrote = []
        monkeypatch.setattr(config_mod.app_config, "write_values", lambda items: wrote.append(items))
        r = logged_in_client.post(
            "/settings/infrastructure/save-ha", data={"ha_mode": "round-robin"}, follow_redirects=True
        )
        assert "HA mode must be" in r.get_data(as_text=True) and wrote == []


class TestStepUp:
    def test_self_update_needs_a_recent_confirmation(self, logged_in_client):
        _stale(logged_in_client)
        r = logged_in_client.post("/settings/infrastructure/self-update", data={})
        assert r.status_code in (301, 302) and "reauth" in r.headers["Location"]

    def test_finishing_an_ha_maintenance_needs_one_too(self, logged_in_client):
        _stale(logged_in_client)
        r = logged_in_client.post("/servers/ha/maintenance/finish", data={})
        assert r.status_code in (301, 302) and "reauth" in r.headers["Location"]


class TestBranding:
    def test_a_favicon_over_the_cap_is_refused(self, logged_in_client):
        data = {"favicon": (io.BytesIO(b"\x00" * (201 * 1024)), "big.ico")}
        r = logged_in_client.post(
            "/settings/upload-favicon", data=data, content_type="multipart/form-data", follow_redirects=True
        )
        assert "under 200KB" in r.get_data(as_text=True)

    def test_an_upper_case_svg_extension_is_still_an_svg(self, logged_in_client, tmp_path, monkeypatch):
        monkeypatch.setattr(extensions, "ICONS_CUSTOM_DIR", str(tmp_path))
        svg = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1 1"><rect width="1" height="1"/></svg>'
        data = {"icon": (io.BytesIO(svg), "Logo.SVG"), "icon_name": "q174icon"}
        r = logged_in_client.post(
            "/settings/icons/upload", data=data, content_type="multipart/form-data", follow_redirects=True
        )
        assert "Only SVG files are accepted" not in r.get_data(as_text=True)
        assert os.path.exists(tmp_path / "q174icon.svg")

    def test_a_failed_nav_logo_save_leaves_the_old_logo(self, logged_in_client, tmp_path, monkeypatch):
        from werkzeug.datastructures import FileStorage

        base = str(tmp_path / "nav_logo")
        monkeypatch.setattr(extensions, "NAV_LOGO_PATH", base)
        (tmp_path / "nav_logo.png").write_bytes(b"old-logo")

        def boom(self, dst, *a, **k):
            raise OSError("disk full")

        monkeypatch.setattr(FileStorage, "save", boom)
        data = {"logo": (io.BytesIO(b"\x89PNG new"), "new.webp")}
        logged_in_client.post("/settings/upload-nav-logo", data=data, content_type="multipart/form-data")
        assert (tmp_path / "nav_logo.png").read_bytes() == b"old-logo"
        assert not any(p.name.endswith(".new") for p in tmp_path.iterdir())


class TestMigrationLockIsReleased:
    def test_run_migrations_leaves_the_lock_free(self, db):
        from jen.models import migrations

        migrations.run_migrations()
        with db.cursor() as cur:
            cur.execute("SELECT IS_FREE_LOCK(%s) AS free", (migrations.MIGRATION_LOCK_NAME,))
            assert cur.fetchone()["free"] == 1
        db.commit()


def test_a_note_for_a_listed_subnet_is_saved(logged_in_client, monkeypatch):
    monkeypatch.setattr(extensions, "SUBNET_MAP", {1: dict(A)})
    r = logged_in_client.post("/subnets/save-note", data={"subnet_id": "1", "notes": json.dumps("x")})
    assert r.get_json()["ok"] is True


class TestRegeneratingTheSshKey:
    def test_the_pair_is_made_beside_the_live_one_and_replaces_it(self, logged_in_client, tmp_path, monkeypatch):
        import subprocess

        key = tmp_path / "id_rsa"
        key.write_text("old-private")
        (tmp_path / "id_rsa.pub").write_text("ssh-rsa OLD old@host")
        monkeypatch.setattr(extensions, "SSH_KEY_PATH", str(key))
        seen = {}

        def fake_keygen(cmd, **kw):
            seen["cmd"] = cmd
            path = cmd[cmd.index("-f") + 1]
            pathlib.Path(path).write_text("new-private")
            pathlib.Path(path + ".pub").write_text("ssh-rsa NEW jen@box\n")
            return subprocess.CompletedProcess(cmd, 0, b"", b"")

        monkeypatch.setattr(subprocess, "run", fake_keygen)
        r = logged_in_client.post("/settings/generate-ssh-key", data={}, follow_redirects=True)
        assert seen["cmd"][seen["cmd"].index("-f") + 1].endswith(".new"), (
            "never ssh-keygen on the live path (it prompts for an overwrite)"
        )
        assert key.read_text() == "new-private" and (tmp_path / "id_rsa.pub").read_text().startswith("ssh-rsa NEW")
        assert not (tmp_path / "id_rsa.new").exists()
        assert "authorized_keys" in r.get_data(as_text=True) and "your-kea-server" not in r.get_data(as_text=True)
        assert "chown" not in " ".join(map(str, seen["cmd"]))
