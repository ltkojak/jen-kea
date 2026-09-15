"""
tests/test_doctor.py
─────────────────────
v5.40.0 (Q41) — GET /tools/doctor: access control, the config-get-
error banner, the empty state, and one real finding rendering end to
end. jen/services/config_doctor.py's own checks are covered in
tests/test_config_doctor.py; this file only exercises the route.
"""


class TestDoctorPage:
    def test_requires_login(self, client, db):
        r = client.get("/tools/doctor", follow_redirects=False)
        assert r.status_code in (302, 401)

    def test_viewer_redirected(self, client, db, mock_kea):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=None, role="viewer", username="doc_viewer")
        r = c.get("/tools/doctor", follow_redirects=False)
        assert r.status_code == 302

    def test_admin_can_view(self, client, db, mock_kea):
        from tests.conftest import restricted_client

        c, _uid = restricted_client(client, db, allowed_subnets=None, role="admin", username="doc_admin")
        r = c.get("/tools/doctor")
        assert r.status_code == 200

    def test_renders_no_findings_for_a_clean_config(self, logged_in_client, mock_kea, db):
        r = logged_in_client.get("/tools/doctor")
        assert r.status_code == 200
        assert b"No findings" in r.data

    def test_config_get_error_shows_a_banner(self, logged_in_client, monkeypatch, db):
        from jen.services import kea as kea_svc

        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: {"result": 1, "text": "connection refused"})
        monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: {"id": 1, "name": "Test Kea"})
        r = logged_in_client.get("/tools/doctor")
        assert r.status_code == 200
        assert b"Could not read the Kea config" in r.data

    def test_renders_a_real_finding(self, logged_in_client, monkeypatch, db):
        from jen.services import kea as kea_svc

        cfg = {
            "subnet4": [
                {
                    "id": 1,
                    "subnet": "10.0.0.0/24",
                    "pools": [{"pool": "10.0.0.10 - 10.0.0.50"}, {"pool": "10.0.0.40 - 10.0.0.60"}],
                }
            ]
        }

        def _fake_kea_command(cmd, *a, **kw):
            if cmd == "config-get":
                return {"result": 0, "arguments": {"Dhcp4": cfg}}
            return {"result": 0, "arguments": {}}

        monkeypatch.setattr(kea_svc, "kea_command", _fake_kea_command)
        monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: {"id": 1, "name": "Test Kea"})
        r = logged_in_client.get("/tools/doctor")
        assert r.status_code == 200
        body = r.data.decode()
        assert "Pools overlap" in body
        assert "fail" in body
        assert 'href="/subnets"' in body
