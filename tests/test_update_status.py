"""
tests/test_update_status.py
───────────────────────────
v5.8.4 — /settings/infrastructure/update-status, polled by the update
overlay next to check-update so a jen-update.service that crashed
*before* restarting Jen is reported as "update failed (exit N)" instead
of the old, wrong "Jen restarted but still reports vX".

`systemctl show` is a read-only property query — no sudo, so no sudoers
entry (CLAUDE.md rule 8 doesn't apply). subprocess.run is mocked here;
the parser is tested directly.
"""

from unittest.mock import MagicMock, patch

from jen.routes.settings.updates import _parse_systemctl_show


class TestParseSystemctlShow:
    def test_parses_key_value_lines(self):
        out = "ActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainStatus=1\n"
        assert _parse_systemctl_show(out) == {
            "ActiveState": "failed",
            "SubState": "failed",
            "Result": "exit-code",
            "ExecMainStatus": "1",
        }

    def test_ignores_lines_without_equals_and_keeps_later_equals(self):
        assert _parse_systemctl_show("garbage\nA=b=c\n") == {"A": "b=c"}

    def test_empty(self):
        assert _parse_systemctl_show("") == {}


class TestUpdateStatusRoute:
    def _show(self, text):
        return MagicMock(returncode=0, stdout=text, stderr="")

    def test_failed_unit_reports_failed_with_exit_status(self, logged_in_client):
        with patch("jen.routes.settings.updates.subprocess.run") as run:
            run.return_value = self._show("ActiveState=failed\nSubState=failed\nResult=exit-code\nExecMainStatus=1\n")
            resp = logged_in_client.get("/settings/infrastructure/update-status")
        assert resp.status_code == 200
        d = resp.get_json()
        assert d["failed"] is True
        assert d["exit_status"] == "1"
        assert d["result"] == "exit-code"
        argv = run.call_args.args[0]
        assert argv[:3] == ["/usr/bin/systemctl", "show", "jen-update.service"]
        assert "sudo" not in " ".join(argv)

    def test_running_unit_is_not_failed(self, logged_in_client):
        with patch("jen.routes.settings.updates.subprocess.run") as run:
            run.return_value = self._show("ActiveState=activating\nSubState=start\nResult=success\nExecMainStatus=0\n")
            d = logged_in_client.get("/settings/infrastructure/update-status").get_json()
        assert d["failed"] is False
        assert d["active_state"] == "activating"
        assert d["sub_state"] == "start"

    def test_systemctl_error_degrades_to_unknown_not_500(self, logged_in_client):
        with patch("jen.routes.settings.updates.subprocess.run", side_effect=OSError("no systemctl")):
            resp = logged_in_client.get("/settings/infrastructure/update-status")
        assert resp.status_code == 200
        d = resp.get_json()
        assert d["active_state"] == "unknown"
        assert d["failed"] is False

    def test_requires_login(self, client):
        resp = client.get("/settings/infrastructure/update-status")
        assert resp.status_code in (302, 401)
