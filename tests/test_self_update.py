"""
tests/test_self_update.py
────────────────────────────
v5.2.6 — SECURITY FIX. Every test previously in this file verified the
old self_update() route's own download/checksum/extract/copy pipeline,
which no longer exists in this route at all. That entire pipeline
moved to a standalone, root-owned script (jen-update-root.py, tested
separately in tests/test_jen_update_root.py) that www-data cannot read
or modify.

The vulnerability this release fixes: the old design had www-data
write a helper script to /tmp/jen_update_install.sh and then sudo-
execute it as root. Since /tmp is world-writable and www-data is the
exact account permitted to write that exact path, every validation the
old route performed was irrelevant to an attacker who'd already gained
any code execution as www-data — they never needed to go through this
route at all; they could write that file themselves and sudo it
directly.

These tests verify the route now does none of the privileged work
itself: it only optionally takes a DB backup (unchanged — that's Jen
backing up its own database with credentials it already has, not a
privilege-boundary concern) and triggers
`sudo systemctl start --no-block jen-update.service` — a command with
no attacker-controllable parameters at all.
"""

from unittest.mock import MagicMock, patch


class TestSelfUpdateRouteIsNowJustATrigger:
    """The core regression guard for this fix: the route must not
    perform any download, extraction, or file-copy work itself, and
    must not write anything to /tmp at all — the exact behavior that
    created the vulnerability in the first place."""

    def test_triggers_jen_update_service_with_no_block(self, logged_in_client):
        captured = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            result = MagicMock()
            result.returncode = 0
            result.stderr = ""
            return result

        with patch("jen.routes.settings.subprocess.run", side_effect=fake_run):
            r = logged_in_client.post(
                "/settings/infrastructure/self-update", data={"db_backup": "0"}, follow_redirects=True
            )

        assert r.status_code == 200
        assert "cmd" in captured, "self_update() never reached the point of triggering the service"
        cmd = captured["cmd"]
        assert cmd == ["/usr/bin/sudo", "/usr/bin/systemctl", "start", "--no-block", "jen-update.service"], (
            f"expected the exact hardened trigger command, got: {cmd}"
        )

    def test_never_writes_to_tmp_jen_update_install(self, logged_in_client, tmp_path, monkeypatch):
        """The actual vulnerability: this exact path must never be
        written by this route again, under any code path."""
        sentinel = "/tmp/jen_update_install.sh"
        if __import__("os").path.exists(sentinel):
            __import__("os").unlink(sentinel)  # clean slate, in case a prior test-run left one

        with patch("jen.routes.settings.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            logged_in_client.post(
                "/settings/infrastructure/self-update", data={"db_backup": "0"}, follow_redirects=True
            )

        assert not __import__("os").path.exists(sentinel), (
            "self_update() wrote to /tmp/jen_update_install.sh — this is exactly "
            "the vulnerable pattern this release exists to remove"
        )

    def test_never_calls_requests_get_or_tarfile_itself(self, logged_in_client):
        """The route must not perform any of the old download/verify/
        extract work at all — that's entirely the root script's job
        now. A regression here would mean someone partially reverted
        this fix."""
        with (
            patch("jen.routes.settings.subprocess.run") as mock_run,
            patch("requests.get") as mock_requests_get,
            patch("tarfile.open") as mock_tarfile_open,
        ):
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            logged_in_client.post(
                "/settings/infrastructure/self-update", data={"db_backup": "0"}, follow_redirects=True
            )
        mock_requests_get.assert_not_called()
        mock_tarfile_open.assert_not_called()

    def test_service_start_failure_is_reported_without_leaking_raw_output(self, logged_in_client):
        with patch("jen.routes.settings.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stderr="some internal systemd detail")
            r = logged_in_client.post(
                "/settings/infrastructure/self-update", data={"db_backup": "0"}, follow_redirects=True
            )
        assert r.status_code == 200
        assert b"Could not start the update" in r.data
        assert b"some internal systemd detail" not in r.data

    def test_requires_superadmin(self, client, db):
        from tests.conftest import restricted_client

        # restricted_client creates a plain 'admin'-role session, not superadmin
        restricted_client(client, db, allowed_subnets=[1], role="admin")
        with patch("jen.routes.settings.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            r = client.post("/settings/infrastructure/self-update", data={"db_backup": "0"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"SuperAdmin access required" in r.data
        mock_run.assert_not_called()


class TestSelfUpdateOptionalDbBackup:
    """DB backup behavior is unchanged from before this fix — this is
    Jen backing up its own database with credentials it already
    legitimately has as www-data, not part of the privilege-escalation
    surface this release addresses. Verified separately here so a
    future change to the trigger logic doesn't have to also worry
    about re-verifying backup behavior."""

    def test_backup_requested_calls_export_before_triggering_update(self, logged_in_client):
        calls = []

        def fake_export_jen():
            calls.append("export_jen")
            return b'{"tables": {}}', "jen-backup.json.gz"

        def fake_write_backup(payload, fname):
            calls.append("write_backup")
            return f"/opt/jen/backups/{fname}"

        with (
            patch("jen.services.dbexport.export_jen", side_effect=fake_export_jen),
            patch("jen.services.dbexport._write_backup", side_effect=fake_write_backup),
            patch("jen.routes.settings.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            r = logged_in_client.post(
                "/settings/infrastructure/self-update", data={"db_backup": "1"}, follow_redirects=True
            )

        assert r.status_code == 200
        assert calls == ["export_jen", "write_backup"]
        assert mock_run.called, "update must still be triggered after a successful backup"

    def test_backup_failure_aborts_before_triggering_update(self, logged_in_client):
        with (
            patch("jen.services.dbexport.export_jen", side_effect=RuntimeError("disk full")),
            patch("jen.routes.settings.subprocess.run") as mock_run,
        ):
            r = logged_in_client.post(
                "/settings/infrastructure/self-update", data={"db_backup": "1"}, follow_redirects=True
            )

        assert r.status_code == 200
        assert b"Database backup failed" in r.data
        assert b"disk full" not in r.data  # raw exception text must not leak to the user
        mock_run.assert_not_called()

    def test_backup_not_requested_skips_export_entirely(self, logged_in_client):
        with (
            patch("jen.services.dbexport.export_jen") as mock_export,
            patch("jen.routes.settings.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stderr="")
            logged_in_client.post(
                "/settings/infrastructure/self-update", data={"db_backup": "0"}, follow_redirects=True
            )
        mock_export.assert_not_called()
