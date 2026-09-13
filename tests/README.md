# Jen test suite

~900 tests across ~55 files, run on every push/PR and as a gate on every
tagged release (`.github/workflows/tests.yml`).

## Running them

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt        # app deps + pytest/ruff/bandit

# needs a MariaDB/MySQL reachable with a jen_test database:
#   CREATE DATABASE jen_test;
#   GRANT ALL PRIVILEGES ON jen_test.* TO 'jen'@'%';
JEN_DB_HOST=127.0.0.1 JEN_DB_USER=jen JEN_DB_PASS=... python3 -m pytest tests/ -v
```

`jen_test` serves as **both** `jen_db` and `kea_db`; `conftest.py` creates
the Kea-side tables and repoints the `jen/extensions.py` globals at it.
Your real `jen` database is never touched. Credentials come from
`/etc/jen/jen.config` when the `JEN_DB_*` env vars aren't set.

One file / one test:

```bash
python3 -m pytest tests/test_auth.py -v
python3 -m pytest tests/test_auth.py::TestLogin::test_login_success -v
```

**Local dev on Windows:** the DB-backed suite and the Docker build only
run on CI. Locally you get `ruff check/format`, `py_compile`, and the
handful of no-DB source-scanning tests. See the *Local verification
(Windows dev box)* section of `CLAUDE.md` for the gotchas.

## How it works

- Flask test client — no server runs. Kea API calls are stubbed by the
  `mock_kea` fixture.
- `conftest.py`: `client` is function-scoped (fresh cookie jar);
  `app`/`test_database` are session-scoped. `logged_in_client` is an
  admin session; `restricted_client()` a subnet-scoped non-superadmin.
- Each test starts from clean state; the admin user is reset to
  `admin/admin` between tests. Schema is built at session start.
- `WTF_CSRF_ENABLED=False` in tests — CSRF is exercised directly in
  `test_csrf.py` / `test_plugin_template_csrf.py`.

## What's covered

| Area | Files |
|---|---|
| **Auth / sessions** | `test_auth.py`, `test_security_fixes.py`, `test_password_change_enforcement.py`, `test_csrf.py` |
| **MFA** | `test_mfa_methods.py`, `test_mfa_encryption.py`, `test_mfa_backup_codes.py`, `test_mfa_enrollment_gate.py` |
| **Users / API keys** | `test_users.py`, `test_api.py`, `test_api_key_authorization.py` |
| **Leases / reservations / devices / subnets** | `test_leases.py`, `test_reservations.py`, `test_devices_page.py`, `test_device_identity.py`, `test_subnets.py`, `test_dashboard.py` |
| **IPv6 (v5.0+)** | `test_kea6_config.py`, `test_kea6_service_toggle.py`, `test_kea6_leases_devices.py`, `test_kea6_reservations.py`, `test_kea6_subnets.py`, `test_kea6_search_metrics.py`, `test_kea_authoring.py` |
| **Kea comms / config** | `test_servers.py`, `test_config_drift.py`, `test_ddns.py`, `test_db_context.py` |
| **Settings** | `test_settings.py`, `test_settings_blueprint.py` (endpoint drift guard), `test_appconfig.py` |
| **Alerts** | `test_alerts.py`, `test_alert_channel_encryption.py` |
| **Migrations** | `test_migrations.py`, `test_plugin_migrations.py` |
| **Plugins** | `test_plugin_registry.py`, `test_plugin_template_csrf.py` |
| **DB / backup** | `test_database.py`, `test_dbexport.py` |
| **Serving / deploy** | `test_run_launcher.py`, `test_venv_isolation.py`, `test_jen_update_root.py`, `test_self_update.py`, `test_sudoers_command_matching.py`, `test_docker_config.py`, `test_dependency_consistency.py` |
| **Frontend / assets** | `test_htmx_vendoring.py`, `test_pwa_manifest.py`, `test_table_wrap_overflow.py`, `test_reports.py`, `test_small_hardening_fixes.py` |
| **Cross-cutting invariants** | `test_no_raw_exception_leaks.py`, `test_changelog.py`, `test_logging_config.py`, `test_background.py` |
