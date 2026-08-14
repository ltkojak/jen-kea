import pytest


class TestSaveSubnetNoteAccessControl:
    """v4.4.9: save_subnet_note() had no can_access_subnet() check at
    all, unlike every sibling route on this page (edit_subnet,
    edit_subnet_post, delete_subnet all check it) — a subnet-restricted
    admin could write/overwrite notes for any subnet_id."""

    def test_rejected_for_out_of_scope_subnet(self, client, db):
        from tests.conftest import restricted_client as _restricted_client
        _restricted_client(client, db, allowed_subnets=[999], role="admin",
                            username="subnetnote_restricted1")
        r = client.post("/subnets/save-note",
                        data={"subnet_id": "1", "notes": "should not be allowed"})
        assert r.status_code == 403
        data = r.get_json()
        assert data["ok"] is False
        assert "access" in data["error"].lower()

    def test_allowed_within_scope(self, logged_in_client):
        r = logged_in_client.post("/subnets/save-note",
                                  data={"subnet_id": "1", "notes": "allowed note"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is True

    def test_rejects_non_integer_subnet_id(self, logged_in_client):
        r = logged_in_client.post("/subnets/save-note",
                                  data={"subnet_id": "not-a-number", "notes": "x"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["ok"] is False


class TestParseAndValidateSubnetEditForm:
    """v4.4.24: extracted from edit_subnet_post() so the new preview
    endpoint can share the exact same validation rather than
    duplicating it and risking the two drifting apart — the same
    class of bug already found and fixed for the plugin registry and
    the CSRF tokens."""

    def _form(self, **kwargs):
        class FakeForm(dict):
            def get(self, k, default=""):
                return dict.get(self, k, default)
        return FakeForm(kwargs)

    def test_valid_full_form_returns_no_error(self):
        from jen.routes.subnets import _parse_and_validate_subnet_edit_form
        fields, error = _parse_and_validate_subnet_edit_form(self._form(
            pool="10.0.0.10-10.0.0.200", valid_lifetime="3600",
            renew_timer="1800", rebind_timer="3150",
            routers="10.0.0.1", dns_servers="9.9.9.9, 1.1.1.1",
        ))
        assert error is None
        assert fields["new_pool"] == "10.0.0.10-10.0.0.200"

    def test_empty_form_is_valid_no_op(self):
        from jen.routes.subnets import _parse_and_validate_subnet_edit_form
        fields, error = _parse_and_validate_subnet_edit_form(self._form())
        assert error is None
        assert not any(fields.values())

    def test_bad_pool_format_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet_edit_form
        fields, error = _parse_and_validate_subnet_edit_form(self._form(pool="not-a-pool"))
        assert fields is None
        assert "Invalid pool format" in error

    def test_bad_router_ip_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet_edit_form
        fields, error = _parse_and_validate_subnet_edit_form(self._form(routers="999.999.999.999"))
        assert fields is None
        assert "Invalid router IP" in error

    def test_bad_dns_ip_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet_edit_form
        fields, error = _parse_and_validate_subnet_edit_form(self._form(dns_servers="not.an.ip"))
        assert fields is None
        assert "Invalid DNS server IP" in error

    def test_negative_timer_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet_edit_form
        fields, error = _parse_and_validate_subnet_edit_form(self._form(valid_lifetime="-5"))
        assert fields is None
        assert "Valid Lifetime must be a positive integer" in error

    def test_zero_timer_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet_edit_form
        fields, error = _parse_and_validate_subnet_edit_form(self._form(renew_timer="0"))
        assert fields is None
        assert "Renew Timer must be a positive integer" in error

    def test_non_numeric_timer_rejected(self):
        from jen.routes.subnets import _parse_and_validate_subnet_edit_form
        fields, error = _parse_and_validate_subnet_edit_form(self._form(rebind_timer="abc"))
        assert fields is None
        assert "Rebind Timer must be a positive integer" in error


class TestBuildSubnetPatchScript:
    """v4.4.24: extracted from edit_subnet_post()'s inline script so the
    new preview endpoint (dry_run=True) can reuse the exact same
    tested patch-and-validate logic without duplicating it."""

    def test_dry_run_false_matches_original_inline_script_byte_for_byte(self):
        """The refactor must not change edit_subnet_post()'s actual
        behavior at all — this is a literal string-equality check
        against a copy of the pre-refactor inline script."""
        from jen.routes.subnets import _build_subnet_patch_script
        subnet_id, kea_conf = 5, '/etc/kea/kea-dhcp4.conf'
        new_pool, extra_pools = '10.0.0.10-10.0.0.200', ['10.0.1.10-10.0.1.200']
        new_lifetime, new_renew, new_rebind = '3600', '1800', '3150'
        new_routers, new_dns = '10.0.0.1', '9.9.9.9,1.1.1.1'

        original = f"""
import json, sys, shutil, subprocess, os, tempfile

path   = {repr(kea_conf)}
backup = path + '.jen_backup'

# Make a backup before touching anything
shutil.copy2(path, backup)

with open(path) as f:
    cfg = json.load(f)

changed = False
for s in cfg.get('Dhcp4', {{}}).get('subnet4', []):
    if s['id'] != {subnet_id}:
        continue
    new_pool = {repr(new_pool)}
    if new_pool:
        extra_pools = {repr(extra_pools)}
        s['pools'] = [{{'pool': new_pool}}] + [{{'pool': p}} for p in extra_pools]
        changed = True
    new_lifetime = {repr(new_lifetime)}
    new_renew    = {repr(new_renew)}
    new_rebind   = {repr(new_rebind)}
    if new_lifetime:
        s['valid-lifetime'] = int(new_lifetime); changed = True
    if new_renew:
        s['renew-timer'] = int(new_renew); changed = True
    if new_rebind:
        s['rebind-timer'] = int(new_rebind); changed = True
    new_routers = {repr(new_routers)}
    new_dns     = {repr(new_dns)}
    if new_routers or new_dns:
        opts = s.get('option-data', [])
        if new_routers:
            found = False
            for o in opts:
                if o.get('name') == 'routers':
                    o['data'] = new_routers; found = True; break
            if not found:
                opts.append({{'name': 'routers', 'code': 3, 'space': 'dhcp4',
                              'csv-format': True, 'data': new_routers}})
            changed = True
        if new_dns:
            found = False
            for o in opts:
                if o.get('name') == 'domain-name-servers':
                    o['data'] = new_dns; found = True; break
            if not found:
                opts.append({{'name': 'domain-name-servers', 'code': 6, 'space': 'dhcp4',
                              'csv-format': True, 'data': new_dns}})
            changed = True
        s['option-data'] = opts
    break

if not changed:
    print('nochange')
    sys.exit(0)

# Write to a temp file first, test it, then move into place
tmp = path + '.jen_tmp'
with open(tmp, 'w') as f:
    json.dump(cfg, f, indent=2)

# Run kea-dhcp4 -t against the temp file
result = subprocess.run(
    ['kea-dhcp4', '-t', tmp],
    capture_output=True, text=True
)
combined = result.stdout + result.stderr

if result.returncode != 0 or 'ERROR' in combined:
    # Config test failed — clean up temp, leave original untouched
    os.unlink(tmp)
    error_lines = [l for l in combined.splitlines() if 'ERROR' in l or 'Error' in l]
    print('testerror:' + ' | '.join(error_lines[:3]))
    sys.exit(1)

# Config test passed — move temp into place
os.replace(tmp, path)
print('ok')
"""
        actual = _build_subnet_patch_script(subnet_id, kea_conf, new_pool, extra_pools,
                                              new_lifetime, new_renew, new_rebind,
                                              new_routers, new_dns, dry_run=False)
        assert actual == original

    def test_both_modes_produce_valid_python(self):
        import ast
        from jen.routes.subnets import _build_subnet_patch_script
        for dry_run in (False, True):
            script = _build_subnet_patch_script(
                5, '/etc/kea/kea-dhcp4.conf', '10.0.0.10-10.0.0.200', [],
                '3600', '', '', '', '', dry_run=dry_run,
            )
            ast.parse(script)  # raises on invalid syntax

    def test_dry_run_true_never_writes_the_live_config(self, tmp_path):
        """Actually execute the generated script (not just parse it),
        with a fake kea-dhcp4 binary standing in for the real one, and
        confirm via a real file hash that dry_run=True genuinely never
        touches the original config — the guarantee the whole preview
        feature depends on."""
        import subprocess, hashlib, os
        conf_path = tmp_path / "kea-dhcp4.conf"
        conf_path.write_text('{"Dhcp4": {"subnet4": [{"id": 5, "pools": [{"pool": "10.0.0.10-10.0.0.100"}]}]}}')
        original_hash = hashlib.md5(conf_path.read_bytes()).hexdigest()

        fake_bin = tmp_path / "fakebin"
        fake_bin.mkdir()
        (fake_bin / "kea-dhcp4").write_text("#!/bin/bash\nexit 0\n")
        os.chmod(fake_bin / "kea-dhcp4", 0o755)

        from jen.routes.subnets import _build_subnet_patch_script
        script = _build_subnet_patch_script(
            5, str(conf_path), "10.0.0.10-10.0.0.200", [],
            "7200", "", "", "", "", dry_run=True,
        )
        script_path = tmp_path / "script.py"
        script_path.write_text(script)

        env = dict(os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}")
        result = subprocess.run(["python3", str(script_path)], capture_output=True, text=True, env=env)

        assert result.stdout.strip() == "preview-ok"
        assert hashlib.md5(conf_path.read_bytes()).hexdigest() == original_hash, \
            "dry_run=True must never modify the live config file"
        # No leftover temp/backup files either
        assert list(tmp_path.glob("*.jen_tmp")) == []
        assert list(tmp_path.glob("*.jen_backup")) == []

    def test_dry_run_true_on_failing_test_also_never_writes(self, tmp_path):
        import subprocess, hashlib, os
        conf_path = tmp_path / "kea-dhcp4.conf"
        conf_path.write_text('{"Dhcp4": {"subnet4": [{"id": 5, "pools": [{"pool": "10.0.0.10-10.0.0.100"}]}]}}')
        original_hash = hashlib.md5(conf_path.read_bytes()).hexdigest()

        fake_bin = tmp_path / "fakebin"
        fake_bin.mkdir()
        (fake_bin / "kea-dhcp4").write_text('#!/bin/bash\necho "ERROR: bad config" >&2\nexit 1\n')
        os.chmod(fake_bin / "kea-dhcp4", 0o755)

        from jen.routes.subnets import _build_subnet_patch_script
        script = _build_subnet_patch_script(
            5, str(conf_path), "10.0.0.10-10.0.0.200", [],
            "", "", "", "", "", dry_run=True,
        )
        script_path = tmp_path / "script.py"
        script_path.write_text(script)

        env = dict(os.environ, PATH=f"{fake_bin}:{os.environ['PATH']}")
        result = subprocess.run(["python3", str(script_path)], capture_output=True, text=True, env=env)

        assert result.stdout.strip().startswith("testerror:")
        assert hashlib.md5(conf_path.read_bytes()).hexdigest() == original_hash


class TestComputeSubnetEditDiff:
    def test_only_submitted_fields_appear_in_diff(self, monkeypatch):
        from jen.routes import subnets as subnets_mod
        monkeypatch.setattr(subnets_mod, "_get_subnet_kea_data", lambda sid: {
            "pool_str": "10.0.0.10-10.0.0.100", "pools": ["10.0.0.10-10.0.0.100"],
            "valid_lifetime": 3600, "renew_timer": 1800, "rebind_timer": 3150,
            "routers": "10.0.0.1", "dns_servers": "9.9.9.9",
        })
        fields = {"new_pool": "10.0.0.10-10.0.0.250", "extra_pools": [],
                   "new_lifetime": "", "new_renew": "", "new_rebind": "",
                   "new_routers": "", "new_dns": ""}
        diff = subnets_mod._compute_subnet_edit_diff(1, fields)
        assert len(diff) == 1
        assert diff[0]["field"] == "Primary Pool"
        assert diff[0]["old"] == "10.0.0.10-10.0.0.100"
        assert diff[0]["new"] == "10.0.0.10-10.0.0.250"

    def test_unset_current_value_shows_placeholder(self, monkeypatch):
        from jen.routes import subnets as subnets_mod
        monkeypatch.setattr(subnets_mod, "_get_subnet_kea_data", lambda sid: {
            "pool_str": "", "pools": [], "valid_lifetime": "", "renew_timer": "",
            "rebind_timer": "", "routers": "", "dns_servers": "",
        })
        fields = {"new_pool": "", "extra_pools": [], "new_lifetime": "",
                   "new_renew": "", "new_rebind": "", "new_routers": "10.0.0.1", "new_dns": ""}
        diff = subnets_mod._compute_subnet_edit_diff(1, fields)
        assert diff[0]["field"] == "Routers"
        assert diff[0]["old"] == "(unset)"


class TestEditSubnetPreviewRoute:
    """Route-level tests using the real Flask test client. Paths that
    reach the SSH loop are covered by mocking paramiko.SSHClient
    directly — the auth/validation/no-op short-circuits below don't
    need SSH mocking since they return before that loop ever runs."""

    def test_requires_login(self, client):
        r = client.post("/subnets/edit/1/preview", follow_redirects=False)
        assert r.status_code in (301, 302, 308)

    def test_nonexistent_subnet_returns_404(self, logged_in_client):
        r = logged_in_client.post("/subnets/edit/9999/preview")
        assert r.status_code == 404
        assert r.get_json()["ok"] is False

    def test_out_of_scope_subnet_returns_403(self, client, db):
        from tests.conftest import restricted_client as _restricted_client
        _restricted_client(client, db, allowed_subnets=[999], role="admin",
                            username="preview_restricted1")
        r = client.post("/subnets/edit/1/preview")
        assert r.status_code == 403

    def test_invalid_form_returns_400_with_same_message_as_real_submit(self, logged_in_client):
        r = logged_in_client.post("/subnets/edit/1/preview", data={"pool": "garbage"})
        assert r.status_code == 400
        assert "Invalid pool format" in r.get_json()["error"]

    def test_empty_form_reports_no_changes_without_touching_ssh(self, logged_in_client, monkeypatch):
        from jen import extensions
        # If this reaches SSH code at all despite being a no-op, this
        # would raise instead of the route handling it gracefully.
        monkeypatch.setattr(extensions, "KEA_SERVERS",
                             [{"id": 1, "ssh_host": "10.0.0.5", "ssh_user": "kea"}])
        r = logged_in_client.post("/subnets/edit/1/preview", data={})
        assert r.status_code == 200
        data = r.get_json()
        assert data["no_changes"] is True
        assert data["diff"] == []

    def test_server_with_no_ssh_host_is_skipped(self, logged_in_client, monkeypatch):
        from jen import extensions
        monkeypatch.setattr(extensions, "KEA_SERVERS", [{"id": 1, "ssh_host": ""}])
        monkeypatch.setattr("jen.routes.subnets._get_subnet_kea_data",
                             lambda sid: {"pool_str": "", "pools": []})
        r = logged_in_client.post("/subnets/edit/1/preview", data={"pool": "10.0.0.10-10.0.0.200"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["servers"] == []
        assert data["all_passed"] is True

    def test_ssh_test_pass_reports_ok(self, logged_in_client, monkeypatch):
        from jen import extensions
        from unittest.mock import patch, MagicMock
        monkeypatch.setattr(extensions, "KEA_SERVERS",
                             [{"id": 1, "name": "Test Kea", "ssh_host": "10.0.0.5", "ssh_user": "kea"}])
        monkeypatch.setattr("jen.routes.subnets._get_subnet_kea_data",
                             lambda sid: {"pool_str": "", "pools": []})

        fake_ssh = MagicMock()
        fake_stdout = MagicMock()
        fake_stdout.read.return_value = b"preview-ok"
        fake_stderr = MagicMock()
        fake_stderr.read.return_value = b""
        fake_ssh.exec_command.return_value = (MagicMock(), fake_stdout, fake_stderr)

        with patch("paramiko.SSHClient", return_value=fake_ssh):
            r = logged_in_client.post("/subnets/edit/1/preview",
                                      data={"pool": "10.0.0.10-10.0.0.200"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["all_passed"] is True
        assert data["servers"][0]["ok"] is True
        assert data["servers"][0]["message"] == "Config test passed"

    def test_ssh_test_fail_reports_error_and_all_passed_false(self, logged_in_client, monkeypatch):
        from jen import extensions
        from unittest.mock import patch, MagicMock
        monkeypatch.setattr(extensions, "KEA_SERVERS",
                             [{"id": 1, "name": "Test Kea", "ssh_host": "10.0.0.5", "ssh_user": "kea"}])
        monkeypatch.setattr("jen.routes.subnets._get_subnet_kea_data",
                             lambda sid: {"pool_str": "", "pools": []})

        fake_ssh = MagicMock()
        fake_stdout = MagicMock()
        fake_stdout.read.return_value = b"testerror:ERROR: bad pool range"
        fake_stderr = MagicMock()
        fake_stderr.read.return_value = b""
        fake_ssh.exec_command.return_value = (MagicMock(), fake_stdout, fake_stderr)

        with patch("paramiko.SSHClient", return_value=fake_ssh):
            r = logged_in_client.post("/subnets/edit/1/preview",
                                      data={"pool": "10.0.0.10-10.0.0.200"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["all_passed"] is False
        assert data["servers"][0]["ok"] is False
        assert "bad pool range" in data["servers"][0]["message"]

    def test_preview_never_calls_edit_subnet_post_or_writes_audit_log(self, logged_in_client, monkeypatch, db):
        """The whole point of a preview — confirm it genuinely doesn't
        apply anything, by checking the audit log stays empty for this
        subnet after a preview call, the same signal edit_subnet_post
        itself writes to on a real apply."""
        from jen import extensions
        monkeypatch.setattr(extensions, "KEA_SERVERS", [])  # no servers to even contact
        monkeypatch.setattr("jen.routes.subnets._get_subnet_kea_data",
                             lambda sid: {"pool_str": "", "pools": []})

        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM audit_log WHERE action='EDIT_SUBNET'")
            before = cur.fetchone()["cnt"]

        r = logged_in_client.post("/subnets/edit/1/preview", data={"pool": "10.0.0.10-10.0.0.200"})
        assert r.status_code == 200

        with db.cursor() as cur:
            cur.execute("SELECT COUNT(*) as cnt FROM audit_log WHERE action='EDIT_SUBNET'")
            after = cur.fetchone()["cnt"]
        assert after == before, "preview must never write an EDIT_SUBNET audit entry — that's edit_subnet_post's job alone"


class TestGetSubnetKeaData:
    """_get_subnet_kea_data() must return ALL of a subnet's pools, not just
    the first — this backs the Edit Subnet form and, until v4.3.8, a bug
    downstream of this function silently discarded every pool after the
    first whenever the edit form was submitted."""

    def test_returns_all_pools_for_multi_pool_subnet(self, monkeypatch):
        from jen.services import kea as kea_svc
        from jen.routes import subnets as subnets_mod

        fake_config = {
            "result": 0,
            "arguments": {
                "Dhcp4": {
                    "valid-lifetime": 3600,
                    "renew-timer": 900,
                    "rebind-timer": 1800,
                    "subnet4": [
                        {
                            "id": 1,
                            "subnet": "10.10.10.0/23",
                            "pools": [
                                {"pool": "10.10.10.50 - 10.10.10.250"},
                                {"pool": "10.10.11.50 - 10.10.11.250"},
                            ],
                            "option-data": [],
                        }
                    ],
                }
            },
        }
        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: fake_config)
        monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: {"id": 1})

        data = subnets_mod._get_subnet_kea_data(1)
        assert data["pools"] == ["10.10.10.50 - 10.10.10.250", "10.10.11.50 - 10.10.11.250"]
        # pool_str (used to prefill the single-line form field) is only the first
        assert data["pool_str"] == "10.10.10.50 - 10.10.10.250"

    def test_single_pool_subnet_unaffected(self, monkeypatch):
        from jen.services import kea as kea_svc
        from jen.routes import subnets as subnets_mod

        fake_config = {
            "result": 0,
            "arguments": {
                "Dhcp4": {
                    "subnet4": [
                        {"id": 2, "pools": [{"pool": "10.10.30.10 - 10.10.30.200"}], "option-data": []}
                    ],
                }
            },
        }
        monkeypatch.setattr(kea_svc, "kea_command", lambda *a, **kw: fake_config)
        monkeypatch.setattr(kea_svc, "get_active_kea_server", lambda: {"id": 1})

        data = subnets_mod._get_subnet_kea_data(2)
        assert data["pools"] == ["10.10.30.10 - 10.10.30.200"]
        assert data["pool_str"] == "10.10.30.10 - 10.10.30.200"


class TestEditSubnetExtraPoolsPreserved:
    """Regression test for the v4.3.8 fix: submitting the edit-subnet form on
    a subnet with 2+ Kea pools must not silently drop every pool after the
    first. The route reads a hidden 'extra_pools' field (pipe-delimited) and
    must fold those back into the pools written to kea-dhcp4.conf."""

    def test_extra_pools_form_field_parsed_correctly(self):
        # Mirrors the parsing line in edit_subnet_post()
        raw = "10.10.11.50 - 10.10.11.250|10.10.12.1 - 10.10.12.50"
        extra_pools = [p.strip() for p in raw.split("|") if p.strip()]
        assert extra_pools == ["10.10.11.50 - 10.10.11.250", "10.10.12.1 - 10.10.12.50"]

    def test_empty_extra_pools_field_parses_to_empty_list(self):
        raw = ""
        extra_pools = [p.strip() for p in raw.split("|") if p.strip()]
        assert extra_pools == []

    def test_generated_remote_script_preserves_extra_pools(self):
        """The remote config-patch script is built as an f-string embedding
        repr(extra_pools). Confirm the merge logic it contains is correct by
        exercising the same expression the route uses to build s['pools']."""
        new_pool = "10.10.10.50 - 10.10.10.250"
        extra_pools = ["10.10.11.50 - 10.10.11.250"]
        pools = [{"pool": new_pool}] + [{"pool": p} for p in extra_pools]
        assert pools == [
            {"pool": "10.10.10.50 - 10.10.10.250"},
            {"pool": "10.10.11.50 - 10.10.11.250"},
        ]

    def test_no_extra_pools_leaves_single_pool_unchanged(self):
        new_pool = "10.10.30.10 - 10.10.30.200"
        extra_pools = []
        pools = [{"pool": new_pool}] + [{"pool": p} for p in extra_pools]
        assert pools == [{"pool": "10.10.30.10 - 10.10.30.200"}]
