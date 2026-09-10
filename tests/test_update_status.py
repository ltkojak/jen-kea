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

import pathlib
import re
from unittest.mock import MagicMock, patch

from jen.routes.settings.updates import _parse_systemctl_show

_REPO = pathlib.Path(__file__).resolve().parent.parent
_SETTINGS_SYSTEM_HTML = (_REPO / "templates" / "settings_system.html").read_text(encoding="utf-8")


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


class TestUpdateOverlayLivesWithThePoller:
    """v5.10.4 — self_update() redirects to settings.settings_system
    with ?updating=1; the overlay markup and the restart-poller that
    reads that flag must both be on exactly that page, or an update
    completes without the browser ever noticing."""

    def test_overlay_and_poll_live_on_the_page_the_route_redirects_to(self, logged_in_client):
        resp = logged_in_client.get("/settings/system?updating=1")
        assert resp.status_code == 200
        assert b'id="update-overlay"' in resp.data
        assert b"params.get('updating')" in resp.data

    def test_poll_give_up_budget_is_at_least_three_minutes(self):
        """The poller ticks every 2s. The server-side health window is
        90s ([server] update_health_timeout) plus restart + byte-compile
        time, so the two "give up and tell the operator" points must
        allow at least ~3 minutes (N >= 90). The separate `attempts > 1`
        guard on the failed-service branch is deliberately low and is
        excluded here (N < 10)."""
        budgets = [int(n) for n in re.findall(r"attempts\s*>\s*(\d+)", _SETTINGS_SYSTEM_HTML)]
        give_up = [n for n in budgets if n >= 10]
        assert len(give_up) == 2, f"expected exactly two give-up budgets, found {budgets}"
        assert all(n >= 90 for n in give_up), give_up
        assert not [n for n in budgets if 10 <= n < 90], f"a give-up budget is under 3 min: {budgets}"
