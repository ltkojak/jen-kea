# Changelog

## [2.2.25] - 2026-04-16

### Fixed
- Fix enrolled TOTP methods not showing on MFA settings page: DB schema uses column `name` but queries referenced non-existent column `device_name` — SELECT was failing silently (caught by bare `except`) returning empty list, and INSERT would also fail on new enrollments. Both corrected to use `name`.

## [2.2.24] - 2026-04-16

### Fixed
- Fix dashboard layout broken by malformed HTML from route restoration: closing `</div>` for stat cards was misplaced mid-template with a stray HTML comment, causing all subnet cards to render incorrectly
- Fix dashboard JS placed inside `{% block title %}` instead of `{% block scripts %}`, meaning `saveDashPrefs()` and related functions were injected into the page `<title>` tag rather than as executable JavaScript — Save Layout button silently did nothing
- Fix widget ID mismatch: HTML used `dash-subnet-stats` (hyphens) but JS referenced `dash-subnet_stats` (underscores); standardised to underscores throughout

## [2.2.23] - 2026-04-16

### Fixed
- Fix `mfa_verify` route rendering nonexistent `mfa_verify.html` — the template was always named `mfa_challenge.html`; route now renders the correct template and passes `has_totp` context variable it requires
- Fix field name collision in `mfa_challenge.html` — the "remember for" select was also named `remember_device` instead of `remember_days`, causing the days value to be lost on submit

## [2.2.22] - 2026-04-16

### Fixed
- Fix MFA verify route using `current_user` (who isn't logged in yet at verify time) — now correctly reads `mfa_pending_user_id` from session, calls `login_user()` only after successful code verification, and clears pending session keys on success
- Fix `mfa_enroll` template variable mismatches introduced during route restoration: `new_secret` → `secret`, action `setup_totp` → `enroll`, field `name` → `device_name` — enrollment form was silently broken and could not actually enroll a new authenticator

## [2.2.21] - 2026-04-16

### Fixed
- Fix login completely broken: `app.secret_key` was set to `os.urandom(24).hex()` on every startup, generating a new random key each time. This caused sessions to be invalidated on every restart and made login impossible with multiple gunicorn workers (each worker got a different key). Secret key is now generated once and persisted to `/etc/jen/secret_key`, then loaded on startup so sessions are stable across restarts and workers

## [2.2.20] - 2026-04-16

### Fixed
- Fix login form blanking username/password fields on failed login attempts — template now repopulates the username field and all failed login render paths pass `prefill_username` back to the template

## [2.2.19] - 2026-04-16

### Fixed
- Fix MFA redirect on login: `url_for("mfa_challenge")` corrected to `url_for("mfa_verify")`, resolving the "Could not build url for endpoint 'mfa_challenge'" error on the login page

## [1.0.0] - 2026-04-10

Initial public release.

### Features
- Dashboard with live subnet utilization, recently issued leases, Kea health indicator, auto-refresh
- Lease browser — filter by subnet, time window, search by IP/MAC/hostname
- Manual lease release and stale lease cleanup
- Lease history (expired leases)
- Visual IP address map per subnet
- Reservations — add, edit, delete with duplicate detection
- Per-reservation notes field
- Per-reservation DNS override
- Bulk CSV import and export for reservations
- Subnet editing via SSH — pool ranges, lease times, scope options
- Auto-backup and rollback on subnet edit failure
- Audit log — all changes tracked with user, timestamp, source IP
- DDNS status page with Technitium log viewer and hostname lookup
- Telegram alerts — Kea down/up, new device lease, utilization threshold
- Login rate limiting — configurable attempts, lockout duration, mode
- HTTPS via SSL certificate upload in UI
- SSH key generation for subnet editing in Settings
- Session timeout — global and per-user
- Dark/light mode toggle
- Sortable columns and pagination
- Prometheus metrics endpoint
- Guided installer with bare metal and Docker support
- Uninstaller
- Docker support (external MySQL and bundled MySQL modes)
- Full documentation
