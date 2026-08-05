"""
tests/test_security_fixes.py
─────────────────────────────
Regression coverage for the v4.4.2 security fixes:
  1. Subnet-restricted admins/users can no longer bypass their subnet
     restrictions on reservation/subnet mutation and export routes.
  2. /mfa/verify now enforces a 10-attempt / 15-minute lockout.
  3. New SSH-target / remote-path / DNS-lookup validators reject the
     inputs that previously reached a remote shell unvalidated.
"""

import json
import time

import pytest


# ── Helpers ────────────────────────────────────────────────────────────────
def _restricted_client(client, db, allowed_subnets, role="admin", username="restricted1"):
    """Create a DB user restricted to `allowed_subnets` and log the test
    client in as that user (bypassing the login form, same pattern as the
    `logged_in_client` fixture)."""
    from jen.models.user import hash_password
    with db.cursor() as cur:
        cur.execute(
            "INSERT INTO users (username, password, role, subnet_access) VALUES (%s, %s, %s, %s)",
            (username, hash_password("testpass123"), role, json.dumps(allowed_subnets))
        )
        user_id = cur.lastrowid
    db.commit()

    with client.session_transaction() as sess:
        sess["_user_cache"] = {
            "id": user_id, "username": username, "role": role,
            "session_timeout": None, "subnet_access": allowed_subnets,
        }
        sess["_user_id"] = str(user_id)
        sess["_fresh"] = True
        sess["last_active"] = __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc).isoformat()
    return client, user_id


class TestSubnetRestrictionOnMutations:
    """Test subnet_map only has subnet 1 (see conftest._patch_extensions).
    A user restricted to subnet_access=[999] (a subnet that doesn't exist
    in SUBNET_MAP) must never be able to touch subnet 1's data via any
    mutating or export route, even by submitting form fields directly."""

    def test_add_reservation_rejected_for_out_of_scope_subnet(self, client, db, mock_kea):
        _restricted_client(client, db, allowed_subnets=[999])
        r = client.post("/reservations/add", data={
            "subnet_id": "1", "mac": "aa:bb:cc:dd:ee:02",
            "ip": "10.99.0.20", "hostname": "sneaky",
        }, follow_redirects=True)
        assert r.status_code == 200
        assert b"do not have access" in r.data.lower()

    def test_edit_reservation_rejected_for_out_of_scope_subnet(self, client, db, mock_kea):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, "
                "dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('aabbccddee03'), 0, 1, INET_ATON('10.99.0.30'), 'restricted-target')"
            )
            host_id = cur.lastrowid
        db.commit()

        _restricted_client(client, db, allowed_subnets=[999])
        r = client.get(f"/reservations/edit/{host_id}", follow_redirects=True)
        assert r.status_code == 200
        assert b"do not have access" in r.data.lower()

        r = client.post(f"/reservations/edit/{host_id}", data={
            "hostname": "hijacked",
        }, follow_redirects=True)
        assert r.status_code == 200
        assert b"do not have access" in r.data.lower()

    def test_delete_reservation_rejected_for_out_of_scope_subnet(self, client, db, mock_kea):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, "
                "dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('aabbccddee04'), 0, 1, INET_ATON('10.99.0.40'), 'restricted-target-2')"
            )
            host_id = cur.lastrowid
        db.commit()

        _restricted_client(client, db, allowed_subnets=[999])
        client.post(f"/reservations/delete/{host_id}", follow_redirects=True)

        with db.cursor() as cur:
            cur.execute("SELECT host_id FROM hosts WHERE host_id=%s", (host_id,))
            still_there = cur.fetchone()
        assert still_there is not None, "reservation must not be deleted by an out-of-scope user"

    def test_export_reservations_filters_by_access(self, client, db, mock_kea):
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO hosts (dhcp_identifier, dhcp_identifier_type, "
                "dhcp4_subnet_id, ipv4_address, hostname) "
                "VALUES (UNHEX('aabbccddee05'), 0, 1, INET_ATON('10.99.0.50'), 'export-target')"
            )
        db.commit()

        _restricted_client(client, db, allowed_subnets=[999])
        r = client.get("/reservations/export")
        assert r.status_code == 200
        assert b"export-target" not in r.data

    def test_delete_subnet_rejected_for_out_of_scope_subnet(self, client, db, mock_kea):
        _restricted_client(client, db, allowed_subnets=[999])
        r = client.post("/subnets/delete/1", follow_redirects=True)
        assert r.status_code == 200
        assert b"do not have access" in r.data.lower()

    def test_add_reservation_allowed_within_scope(self, client, db, mock_kea):
        """Sanity check: the fix doesn't block legitimate in-scope access."""
        _restricted_client(client, db, allowed_subnets=[1])
        r = client.post("/reservations/add", data={
            "subnet_id": "1", "mac": "aa:bb:cc:dd:ee:06",
            "ip": "10.99.0.60", "hostname": "allowed-host",
        }, follow_redirects=True)
        assert r.status_code == 200
        assert b"do not have access" not in r.data.lower()


class TestMfaLockout:
    """/mfa/verify — brute-force throttling added in v4.4.2."""

    def test_locked_out_after_max_attempts(self, client, db):
        from jen.services.auth import MFA_MAX_ATTEMPTS, is_mfa_locked_out
        user_id = 1
        with db.cursor() as cur:
            for _ in range(MFA_MAX_ATTEMPTS):
                cur.execute("INSERT INTO mfa_attempts (user_id) VALUES (%s)", (user_id,))
        db.commit()

        locked, remaining = is_mfa_locked_out(user_id)
        assert locked is True
        assert remaining > 0

        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_attempts WHERE user_id=%s", (user_id,))
        db.commit()

    def test_not_locked_out_below_threshold(self, db):
        from jen.services.auth import MFA_MAX_ATTEMPTS, is_mfa_locked_out
        user_id = 2
        with db.cursor() as cur:
            for _ in range(MFA_MAX_ATTEMPTS - 1):
                cur.execute("INSERT INTO mfa_attempts (user_id) VALUES (%s)", (user_id,))
        db.commit()

        locked, _ = is_mfa_locked_out(user_id)
        assert locked is False

        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_attempts WHERE user_id=%s", (user_id,))
        db.commit()

    def test_lockout_is_never_permanent(self, db):
        """Unlike password rate limiting, MFA lockout must always resolve
        to a fixed number of minutes — never the rl_lockout_minutes=0
        'permanent until admin clears' mode."""
        from jen.services.auth import MFA_LOCKOUT_MINUTES
        assert MFA_LOCKOUT_MINUTES > 0

    def test_mfa_verify_route_blocks_when_locked_out(self, client, db):
        from jen.services.auth import MFA_MAX_ATTEMPTS
        with db.cursor() as cur:
            for _ in range(MFA_MAX_ATTEMPTS):
                cur.execute("INSERT INTO mfa_attempts (user_id) VALUES (%s)", (1,))
        db.commit()

        with client.session_transaction() as sess:
            sess["mfa_pending_user_id"] = 1
            sess["mfa_pending_username"] = "admin"

        r = client.post("/mfa/verify", data={"code": "000000"}, follow_redirects=True)
        assert r.status_code == 200
        assert b"too many failed codes" in r.data.lower()

        with db.cursor() as cur:
            cur.execute("DELETE FROM mfa_attempts WHERE user_id=%s", (1,))
        db.commit()

    def test_clear_mfa_attempts(self, db):
        from jen.services.auth import clear_mfa_attempts, is_mfa_locked_out, MFA_MAX_ATTEMPTS
        user_id = 3
        with db.cursor() as cur:
            for _ in range(MFA_MAX_ATTEMPTS):
                cur.execute("INSERT INTO mfa_attempts (user_id) VALUES (%s)", (user_id,))
        db.commit()
        assert is_mfa_locked_out(user_id)[0] is True

        clear_mfa_attempts(user_id)
        time.sleep(0.3)  # fire-and-forget thread
        assert is_mfa_locked_out(user_id)[0] is False


class TestRemoteCommandValidators:
    """Validators guarding every value that ends up in a remote-shell
    command string over SSH (DDNS log path, lookup host, SSH host/user)."""

    def test_valid_ssh_target_accepts_hostname_and_ip(self):
        from jen.services.auth import valid_ssh_target
        assert valid_ssh_target("theelders.local") is True
        assert valid_ssh_target("10.10.11.250") is True

    def test_valid_ssh_target_rejects_flag_injection(self):
        from jen.services.auth import valid_ssh_target
        assert valid_ssh_target("-oProxyCommand=touch /tmp/pwned") is False
        assert valid_ssh_target("") is False

    def test_valid_unix_username_accepts_normal_names(self):
        from jen.services.auth import valid_unix_username
        assert valid_unix_username("kea") is True
        assert valid_unix_username("service_1") is True

    def test_valid_unix_username_rejects_shell_metacharacters(self):
        from jen.services.auth import valid_unix_username
        assert valid_unix_username("kea; rm -rf /") is False
        assert valid_unix_username("$(whoami)") is False

    def test_valid_remote_path_accepts_normal_absolute_paths(self):
        from jen.services.auth import valid_remote_path
        assert valid_remote_path("/var/log/kea/kea-ddns.log") is True

    def test_valid_remote_path_rejects_command_injection(self):
        from jen.services.auth import valid_remote_path
        assert valid_remote_path("/tmp/x; rm -rf /") is False
        assert valid_remote_path("/tmp/x`whoami`") is False
        assert valid_remote_path("relative/path") is False

    def test_valid_dns_lookup_host_accepts_hostname_and_ip(self):
        from jen.services.auth import valid_dns_lookup_host
        assert valid_dns_lookup_host("tardis.local") is True
        assert valid_dns_lookup_host("10.10.11.5") is True

    def test_valid_dns_lookup_host_rejects_command_injection(self):
        from jen.services.auth import valid_dns_lookup_host
        assert valid_dns_lookup_host("x; rm -rf /") is False
        assert valid_dns_lookup_host("$(id)") is False
        assert valid_dns_lookup_host("host `whoami`") is False

    def test_ddns_lookup_route_rejects_invalid_host(self, logged_in_client):
        r = logged_in_client.get("/ddns", query_string={"host": "x; touch /tmp/pwned"})
        assert r.status_code == 200
        assert b"invalid hostname" in r.data.lower()


class TestDatabaseSuperadminOnly:
    """/database/* — export/import/migrate/backup. v4.4.2: escalated from
    admin to superadmin-only, since a full export includes password
    hashes, MFA secrets, and API key records for every subnet, not just
    ones a restricted admin is scoped to."""

    def _admin_client(self, client, db):
        return _restricted_client(client, db, allowed_subnets=None,
                                   role="admin", username="plainadmin1")

    def test_database_page_forbidden_for_plain_admin(self, client, db):
        self._admin_client(client, db)
        r = client.get("/database", follow_redirects=True)
        assert r.status_code == 200
        assert b"superadmin access required" in r.data.lower()

    def test_export_jen_forbidden_for_plain_admin(self, client, db):
        self._admin_client(client, db)
        r = client.post("/database/export/jen", follow_redirects=True)
        assert r.status_code == 200
        assert b"superadmin access required" in r.data.lower()

    def test_import_confirm_forbidden_for_plain_admin(self, client, db):
        self._admin_client(client, db)
        r = client.post("/database/import/confirm", follow_redirects=True)
        assert r.status_code == 200
        assert b"superadmin access required" in r.data.lower()

    def test_migrate_run_forbidden_for_plain_admin(self, client, db):
        self._admin_client(client, db)
        r = client.post("/database/migrate/run", follow_redirects=True)
        assert r.status_code == 200
        assert b"superadmin access required" in r.data.lower()

    def test_database_page_allowed_for_superadmin(self, logged_in_client):
        r = logged_in_client.get("/database")
        assert r.status_code == 200
        assert b"superadmin access required" not in r.data.lower()


class TestPluginsSuperadminOnly:
    """/settings/plugins/* — install/enable/etc. v4.4.2: escalated from
    admin to superadmin-only, since installing a plugin runs arbitrary
    Python with the full privileges of the Jen process."""

    def _admin_client(self, client, db):
        return _restricted_client(client, db, allowed_subnets=None,
                                   role="admin", username="plainadmin2")

    def test_plugins_page_forbidden_for_plain_admin(self, client, db):
        self._admin_client(client, db)
        r = client.get("/settings/plugins", follow_redirects=True)
        assert r.status_code == 200
        assert b"superadmin access required" in r.data.lower()

    def test_install_plugin_forbidden_for_plain_admin(self, client, db):
        self._admin_client(client, db)
        r = client.post("/settings/plugins/install/network-discovery", follow_redirects=True)
        assert r.status_code == 200
        assert b"superadmin access required" in r.data.lower()

    def test_enable_plugin_forbidden_for_plain_admin(self, client, db):
        self._admin_client(client, db)
        r = client.post("/settings/plugins/enable/network-discovery", follow_redirects=True)
        assert r.status_code == 200
        assert b"superadmin access required" in r.data.lower()

    def test_plugins_page_allowed_for_superadmin(self, logged_in_client):
        r = logged_in_client.get("/settings/plugins")
        assert r.status_code == 200
        assert b"superadmin access required" not in r.data.lower()


class TestPluginZipSlip:
    """jen.services.plugins._safe_extract — Zip Slip protection.
    A malicious plugin archive must not be able to write files outside
    its own plugin directory via ../ path traversal or absolute paths."""

    def _make_zip(self, entries):
        import zipfile, io
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, content in entries.items():
                zf.writestr(name, content)
        buf.seek(0)
        return zipfile.ZipFile(buf)

    def test_rejects_parent_directory_traversal(self, tmp_path):
        from jen.services.plugins import _safe_extract
        zf = self._make_zip({"../../../tmp/evil_pwned.txt": "pwned"})
        dest = tmp_path / "plugin_dest"
        with pytest.raises(ValueError, match="Unsafe path"):
            _safe_extract(zf, str(dest))
        assert not (tmp_path / "tmp" / "evil_pwned.txt").exists()

    def test_rejects_absolute_path(self, tmp_path):
        from jen.services.plugins import _safe_extract
        zf = self._make_zip({"/etc/evil_pwned.txt": "pwned"})
        dest = tmp_path / "plugin_dest"
        with pytest.raises(ValueError, match="Unsafe path"):
            _safe_extract(zf, str(dest))

    def test_allows_normal_plugin_contents(self, tmp_path):
        from jen.services.plugins import _safe_extract
        zf = self._make_zip({
            "manifest.json": '{"id": "test-plugin"}',
            "plugin.py": "def register(app): pass",
            "templates/index.html": "<h1>hi</h1>",
        })
        dest = tmp_path / "plugin_dest"
        _safe_extract(zf, str(dest))
        assert (dest / "manifest.json").is_file()
        assert (dest / "plugin.py").is_file()
        assert (dest / "templates" / "index.html").is_file()

    def test_install_plugin_rejects_https_only_violation(self, monkeypatch):
        from jen.services import plugins as plugins_svc
        ok, msg = plugins_svc.install_plugin("evil-plugin", {
            "download_url": "http://not-secure.example.com/evil"
        })
        assert ok is False
        assert "https" in msg.lower()
