"""
tests/test_no_raw_exception_leaks.py
──────────────────────────────────────
v5.2.14 — SECURITY FIX. Broad sweep across every route file for raw
Python exception text being shown directly to users or API clients via
flash(), jsonify(), or the REST API's api_error() helper. Roughly 60
call sites reviewed individually across 14 files.

The rule applied throughout: fix anything wrapping a database or
file-system operation — these can leak schema details, internal
paths, or connection info that's actionable for nobody and useful to
nobody except someone probing the app. Leave alone anything that's a
deliberate, already-constructed message about the user's own
submitted input (a validation error), or an error from communicating
with infrastructure the admin themselves configured (an SSH target,
a webhook/Discord/ntfy/Telegram integration) — that text is the
actionable diagnostic the admin actually needs, not an internal leak,
and hiding it behind "check server logs" would make the app measurably
less useful for a case that isn't a security concern in the first
place.

Two kinds of test here:
1. Spot checks on a representative sample of the actual fixes, mocking
   the DB layer to raise and confirming the generic message appears
   while the raw exception text does not.
2. A regression scanner (mirroring tests/test_sudoers_command_matching.py's
   approach from the v5.2.9 fix) that greps every route file for the
   leak patterns and fails on anything not in an explicit, individually
   justified allowlist — so a future re-introduction of this exact
   mistake is caught automatically rather than depending on someone
   remembering to check by hand.
"""

import pathlib
import re
from unittest.mock import patch


def _raise_only_outside_load_user(original_fn, exc):
    """v5.3.1 fix — a side_effect for mocking jen_db()/kea_db() that
    only raises when NOT called from jen/__init__.py's load_user().

    The bug this fixes: jen.__init__.load_user() does a LOCAL,
    per-call `from jen.models.db import jen_db` — meaning it always
    resolves the CURRENT attribute on the jen.models.db module, not a
    reference captured once at import time. For any route module that
    imports the db layer as `import jen.models.db as __db` (users.py,
    devices.py, dashboard.py — as opposed to api.py's
    `from jen.models.db import jen_db`, which creates an independent
    local name), patching `jen.routes.X.__db.jen_db` IS patching
    `jen.models.db.jen_db` directly, since `__db` is that exact module
    object, just aliased. That breaks authentication itself for the
    duration of the mock: Flask-Login's own load_user() callback runs
    on every request before the route body executes, and it also
    calls jen_db() (both a "fast path" token_version freshness check
    and, if that fails, a "slow path" full lookup) — so a mock meant
    to simulate ONE route's own database failure was actually making
    every request in the test appear unauthenticated, redirecting to
    login (302) before the route was ever reached at all, rather than
    exercising the exception-handling this test suite exists to check.

    Frame inspection distinguishes the two cases deterministically,
    without depending on exact call counts or the test user's current
    token_version state (both of which a naive "let the first N calls
    through" fix would have been fragile against): calls whose
    immediate caller is load_user() are delegated to the real
    function, so authentication proceeds normally; every other call
    (the route's own query) raises the test's distinctive exception.
    """
    import inspect

    def _inner(*args, **kwargs):
        # Walk the whole stack rather than checking f_back once — a
        # single-level check lands on unittest.mock's own internal
        # call machinery (__call__ -> _mock_call -> _execute_mock_call
        # -> this function), not the real caller, since MagicMock
        # introduces several frames of its own between the actual
        # caller and a side_effect function. Confirmed this the hard
        # way: an earlier version of this fix checked only
        # currentframe().f_back and never actually matched load_user
        # at all when run through a real patch(..., side_effect=...),
        # rather than a direct call — the frame it saw belonged to
        # mock.py, so it always raised regardless of the real caller.
        frame = inspect.currentframe().f_back
        while frame is not None:
            if frame.f_code.co_name == "load_user":
                return original_fn(*args, **kwargs)
            frame = frame.f_back
        raise exc

    return _inner


# Each entry: (file, line-content substring, reason it's intentionally safe)
ALLOWED_RAW_EXCEPTION_LINES = [
    (
        "jen/routes/database.py",
        'flash(f"Cannot read file: {err}"',
        "err here is parse_import_file()'s own deliberate, sanitized message "
        "about the user's own uploaded file (e.g. a JSON decode failure) — "
        "not a raw exception object, and it's about their own file's content, "
        "not Jen's internal state.",
    ),
    (
        "jen/routes/plugins.py",
        'flash(f"Could not fetch registry: {err}"',
        "err comes from services/plugins.py's fetch_registry(), which was "
        "fixed at the source to log the raw exception and return only a "
        "generic string — this is safe by construction, not by omission here.",
    ),
    (
        "jen/routes/reservations.py",
        "flash(str(e)",
        "e is a ValueError raised by kea6.normalize_duid() specifically to "
        "be surfaced as a form-validation message about the user's own "
        "submitted DUID — see that function's own docstring.",
    ),
    (
        "jen/routes/settings.py",
        'flash(f"Test error: {str(e)}"',
        "wraps sending a test message to a webhook/ntfy/Discord channel the "
        "admin themselves configured — the failure reason is the actionable "
        "diagnostic they need, not an internal leak.",
    ),
    (
        "jen/routes/settings.py",
        "Could not connect to {target_server",
        "SSH connection failure to a server the admin themselves configured in Settings — same category as above.",
    ),
    ("jen/routes/settings.py", '"message": str(e)}', "SSH config-test failure against an admin-configured server."),
    (
        "jen/routes/settings.py",
        'errors.append(f"❌ {name}: {str(e)}")',
        "SSH config-write failure against an admin-configured server.",
    ),
    ("jen/routes/settings.py", '"error": str(e)}', "SSH binary-check failure against an admin-configured server."),
    ("jen/routes/settings.py", '"output": str(e)}', "SSH binary-install failure against an admin-configured server."),
    (
        "jen/routes/settings.py",
        'flash(f"Telegram error {error_code}',
        "Telegram's own API error response (code + description) — the "
        "admin's own integration's diagnostic text, not a Python exception.",
    ),
]

# These aren't exception leaks at all — an integer error/success COUNT
# happening to be named "errors" matches a naive text search for the
# word, but there's no exception text involved anywhere in these lines.
KNOWN_FALSE_POSITIVE_SUBSTRINGS = [
    "failed or skipped",
    "{errors} failed.",
]


def _scan_route_file_for_raw_exception_leaks(path):
    """Return a list of (line_number, line_text) for lines that look
    like they interpolate a raw exception/error variable into
    user-facing output, excluding known-safe allowlisted lines and
    known false positives."""
    findings = []
    text = pathlib.Path(path).read_text()
    leak_pattern = re.compile(
        r'(flash\(f".*\{e\}|flash\(f".*\{str\(e\)\}|flash\(f".*\{err\}|'
        r"flash\(str\(e\)|jsonify\(.*str\(e\)|api_error\(str\(e\)|"
        # v5.3.3 addition — catches the exact shape that slipped past
        # every other pattern here: jen/__init__.py's global
        # @app.errorhandler(Exception) interpolated the raw exception
        # into a render_template(..., message=f"...{e}") call. Missed
        # originally because this scanner only checked jen/routes/*.py
        # (a route-file-shaped assumption), not the whole jen/ package
        # — see the widened glob in the test below — and because the
        # regex itself had no case for a bare `message=f"...{e}"`
        # keyword argument, only specific call-shapes like flash().
        r'message\s*=\s*f".*\{e\}|message\s*=\s*f".*\{str\(e\)\})'
    )
    for lineno, line in enumerate(text.splitlines(), start=1):
        if not leak_pattern.search(line):
            continue
        if any(fp in line for fp in KNOWN_FALSE_POSITIVE_SUBSTRINGS):
            continue
        if any(path.endswith(f) and sig in line for f, sig, _ in ALLOWED_RAW_EXCEPTION_LINES):
            continue
        findings.append((lineno, line.strip()))
    return findings


class TestNoUnexplainedRawExceptionLeaksInRoutes:
    def test_every_route_file_is_clean_or_explicitly_allowlisted(self):
        import glob

        # v5.3.3 — widened from "jen/routes/*.py" to the whole jen/
        # package (recursively). The exact bug that prompted this
        # widening lived in jen/__init__.py, outside jen/routes/
        # entirely — a global error handler, not a per-route pattern —
        # so scoping this scanner to "routes only" was itself part of
        # the gap, not just the regex pattern.
        route_files = sorted(glob.glob("jen/**/*.py", recursive=True))
        assert len(route_files) >= 10, "sanity check that glob actually found real files"

        all_findings = {}
        for path in route_files:
            findings = _scan_route_file_for_raw_exception_leaks(path)
            if findings:
                all_findings[path] = findings

        assert not all_findings, (
            f"Found raw exception leak(s) not covered by the allowlist "
            f"in ALLOWED_RAW_EXCEPTION_LINES: {all_findings}. If this is "
            f"a genuinely new, deliberate, safe case (e.g. relaying "
            f"another well-behaved subsystem's own sanitized error text), "
            f"add it to the allowlist with a specific justification. If "
            f"it's a real leak, fix it: log the exception server-side and "
            f"show a generic message instead."
        )

    def test_allowlist_entries_still_exist_in_their_files(self):
        """Catches the allowlist going stale — if a line moves or its
        exact text changes, this fails loudly rather than silently
        letting the allowlist stop meaning anything."""
        stale = []
        for filepath, signature, _reason in ALLOWED_RAW_EXCEPTION_LINES:
            text = pathlib.Path(filepath).read_text()
            if signature not in text:
                stale.append((filepath, signature))
        assert not stale, f"allowlist entries no longer found in their files (stale or moved): {stale}"


class TestRepresentativeFixesActuallyHideRawExceptionText:
    """Spot checks across a representative sample of the fixed files,
    each mocking the DB layer to raise a distinctive exception and
    confirming the generic message shows while the distinctive raw
    text does not reach the response."""

    def test_api_keys_listing_error_is_generic(self, logged_in_client):
        with patch("jen.routes.api.jen_db") as mock_db:
            mock_db.side_effect = RuntimeError("Table 'jen.api_keys' has no column named 'nonexistent_xyz123'")
            r = logged_in_client.get("/settings/api-keys")
        assert r.status_code == 200
        assert b"nonexistent_xyz123" not in r.data
        assert b"Could not load API keys" in r.data

    def test_users_list_error_is_generic(self, logged_in_client):
        import jen.models.db as db_module

        original = db_module.jen_db
        exc = RuntimeError("Access denied for user 'jen'@'10.10.11.251' — internal detail xyz456")
        with patch("jen.routes.users.__db.jen_db", side_effect=_raise_only_outside_load_user(original, exc)):
            r = logged_in_client.get("/users")
        assert r.status_code == 200
        assert b"xyz456" not in r.data
        assert b"10.10.11.251" not in r.data
        assert b"Could not load users" in r.data

    def test_reservations_list_error_is_generic(self, logged_in_client):
        with patch("jen.routes.reservations.__db.kea_db") as mock_db:
            mock_db.side_effect = RuntimeError("Connection refused at internal-host-marker-abc789")
            r = logged_in_client.get("/reservations")
        assert r.status_code == 200
        assert b"internal-host-marker-abc789" not in r.data
        assert b"Could not load reservations" in r.data

    def test_leases_list_error_is_generic(self, logged_in_client):
        with patch("jen.routes.leases.__db.kea_db") as mock_db:
            mock_db.side_effect = RuntimeError("Unknown column 'marker_def012' in field list")
            r = logged_in_client.get("/leases")
        assert r.status_code == 200
        assert b"marker_def012" not in r.data
        assert b"Could not load leases" in r.data

    def test_devices_list_error_is_generic(self, logged_in_client):
        import jen.models.db as db_module

        original = db_module.jen_db
        exc = RuntimeError("Deadlock found marker_ghi345")
        with patch("jen.routes.devices.__db.jen_db", side_effect=_raise_only_outside_load_user(original, exc)):
            r = logged_in_client.get("/devices")
        assert r.status_code == 200
        assert b"marker_ghi345" not in r.data
        assert b"Could not load device inventory" in r.data

    def test_rest_api_v1_leases_error_is_generic_json(self, logged_in_client, db):
        import hashlib
        import secrets

        raw_key = "jen_" + secrets.token_hex(20)
        key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
        with db.cursor() as cur:
            cur.execute(
                "INSERT INTO api_keys (name, key_hash, key_prefix, created_by, subnet_access, active) "
                "VALUES (%s, %s, %s, 1, NULL, 1)",
                ("leak-test-key", key_hash, raw_key[:8]),
            )
        db.commit()

        with patch("jen.routes.api.kea_db") as mock_db:
            mock_db.side_effect = RuntimeError("Internal marker jkl678 should never reach the API client")
            r = logged_in_client.get("/api/v1/leases", headers={"Authorization": f"Bearer {raw_key}"})
        assert r.status_code == 500
        assert b"jkl678" not in r.data
        assert b"Internal error" in r.data

    def test_dashboard_stats_widget_error_is_generic_json(self, logged_in_client):
        """api_stats() uses __db.kea_db(), not jen_db() — confirmed by
        reading the route directly rather than assuming. kea_db() is
        never touched by load_user() (only jen_db() is), so this can
        use a plain mock with no risk of also breaking authentication,
        matching the same safe pattern already used for the
        reservations/leases tests above."""
        with patch("jen.routes.dashboard.__db.kea_db") as mock_db:
            mock_db.side_effect = RuntimeError("Sensitive schema marker mno901")
            r = logged_in_client.get("/api/stats")
        assert r.status_code == 200
        assert b"mno901" not in r.data
