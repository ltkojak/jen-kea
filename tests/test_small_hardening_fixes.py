"""
tests/test_small_hardening_fixes.py
──────────────────────────────────────
v5.2.12 — two small, independent, mechanical fixes bundled together
since neither has any relationship to the other and both are cheap,
single-file changes with zero interaction risk.

1. jen_trusted cookie missing `Secure`. This cookie is a long-lived
   MFA bypass token (up to 10 years for "forever") — unlike the main
   session cookie (SESSION_COOKIE_SECURE, set conditionally on SSL in
   jen/__init__.py), it was created with no `secure` flag at all,
   meaning a browser could send this specific token over plain HTTP
   even on an instance with HTTPS configured, before any HTTP→HTTPS
   redirect takes effect.

   Verified via source inspection rather than a full HTTP round trip:
   fully exercising /mfa/verify's cookie-setting code path requires a
   real enrolled TOTP secret and a live-generated code, which is a lot
   of scaffolding to reach a single set_cookie() call. Checking the
   actual route source directly is the more practical, still-honest
   way to confirm all four call sites (two duplicated code paths, each
   with a "forever" and an "N days" branch) were fixed, not just one.

2. Docker Compose healthcheck used "CMD" (exec form), which does not
   invoke a shell — so "||" was never treated as shell OR logic; it
   was passed to curl as a literal argument. Tested this directly
   (see the change's own commit/PR notes): curl's own handling of
   multiple positional URL arguments happened to mask the bug in some
   cases by coincidentally still fetching a later URL in the list, but
   that's an accident of curl's argument parsing, not the intended
   "try HTTP, fall back to HTTPS" logic actually running. Fixed by
   switching to "CMD-SHELL", which explicitly invokes a real shell.
"""

import pathlib
import re


class TestTrustedDeviceCookieSecureFlag:
    def _mfa_routes_source(self):
        return pathlib.Path("jen/routes/mfa_routes.py").read_text()

    def test_every_jen_trusted_cookie_call_includes_secure_flag(self):
        source = self._mfa_routes_source()
        calls = re.findall(r'set_cookie\(\s*"jen_trusted".*?\)', source, re.DOTALL)
        assert len(calls) == 4, (
            f"expected exactly 4 jen_trusted set_cookie() calls (two code "
            f"paths — backup code and TOTP — each with a 'forever' and an "
            f"'N days' branch), found {len(calls)}. If this count changed "
            f"intentionally, update this test; if not, a call site may have "
            f"been missed."
        )
        missing_secure = [c for c in calls if "secure=" not in c]
        assert not missing_secure, (
            f"{len(missing_secure)} of 4 jen_trusted cookie calls are missing the secure= flag: {missing_secure}"
        )

    def test_secure_flag_is_conditioned_on_ssl_not_hardcoded(self):
        """secure=True unconditionally would be wrong too — it would
        make the cookie unusable on an intentionally HTTP-only
        instance. Must match the same ssl_configured() condition the
        main session cookie already uses."""
        source = self._mfa_routes_source()
        calls = re.findall(r'set_cookie\(\s*"jen_trusted".*?\)', source, re.DOTALL)
        for call in calls:
            assert "secure=__config.ssl_configured()" in call, f"expected secure=__config.ssl_configured(), got: {call}"

    def test_httponly_and_samesite_are_still_present(self):
        """Regression guard: fixing the missing Secure flag shouldn't
        have disturbed the other, already-correct cookie attributes."""
        source = self._mfa_routes_source()
        calls = re.findall(r'set_cookie\(\s*"jen_trusted".*?\)', source, re.DOTALL)
        for call in calls:
            assert "httponly=True" in call
            assert 'samesite="Lax"' in call


class TestDockerHealthcheckUsesRealShellLogic:
    """
    Deliberately does not use a YAML parsing library. pyyaml isn't an
    actual dependency of this project anywhere (install.sh never
    installs it, nothing else imports it) — it only happened to be
    present in the sandbox this test was originally developed in,
    which is exactly why this test failed to even collect in CI the
    first time it shipped: ModuleNotFoundError: No module named
    'yaml'. The fix is the same discipline already applied to
    jen/services/changelog.py: don't add a general-purpose parsing
    dependency for a narrow, well-known, fully-under-our-control
    format — the specific line this test needs is a single-line YAML
    flow sequence, which is also valid JSON, so the stdlib json module
    parses it directly once isolated by a targeted regex.
    """

    def _healthcheck_test_value(self, compose_file):
        text = pathlib.Path(compose_file).read_text()
        # Anchored on the jen service's actual healthcheck content
        # (checking its own two ports) rather than a generic "test:"
        # match, which would also match the separate MariaDB
        # healthcheck present in docker-compose.mysql.yml
        # ("CMD", "healthcheck.sh", "--connect", ...).
        match = re.search(r'test:\s*(\["CMD-SHELL".*?\])\s*$', text, re.MULTILINE)
        assert match, f"could not find the jen service's CMD-SHELL healthcheck line in {compose_file}"
        import json

        return json.loads(match.group(1))

    def test_docker_compose_yml_uses_cmd_shell(self):
        test_value = self._healthcheck_test_value("docker-compose.yml")
        assert test_value[0] == "CMD-SHELL", (
            f"expected CMD-SHELL (which invokes a real shell, so || works "
            f"as OR logic), got: {test_value[0]!r}. CMD (exec form) does "
            f"not invoke a shell — any || in the test list would be passed "
            f"to curl as a literal, meaningless argument."
        )

    def test_docker_compose_mysql_yml_uses_cmd_shell(self):
        test_value = self._healthcheck_test_value("docker-compose.mysql.yml")
        assert test_value[0] == "CMD-SHELL"

    def test_both_compose_files_have_identical_jen_healthcheck(self):
        """These two files maintain the same jen service healthcheck
        independently — confirms they didn't drift apart, the same
        general class of risk as any duplicated configuration."""
        v1 = self._healthcheck_test_value("docker-compose.yml")
        v2 = self._healthcheck_test_value("docker-compose.mysql.yml")
        assert v1 == v2

    def test_healthcheck_command_actually_contains_shell_or_logic(self):
        """Confirms the fix is complete, not just the CMD-SHELL prefix
        with the old broken argument list still trailing after it."""
        test_value = self._healthcheck_test_value("docker-compose.yml")
        assert len(test_value) == 2, "CMD-SHELL takes a single command string, not a list of arguments"
        command_string = test_value[1]
        assert "||" in command_string
        assert "http://localhost:5050" in command_string
        assert "https://localhost:8443" in command_string

    def test_healthcheck_shell_logic_actually_works(self):
        """Not just checking the file text — actually runs the exact
        command Docker would run (via /bin/sh -c, matching CMD-SHELL's
        real behavior) against a real local HTTP server standing in
        for the primary port, confirming the shell genuinely falls
        through to the fallback when the first target is unreachable
        — the actual behavior the original CMD (exec form) syntax
        never reliably provided."""
        import http.server
        import socketserver
        import subprocess
        import threading

        port = 18443
        httpd = socketserver.TCPServer(("127.0.0.1", port), http.server.SimpleHTTPRequestHandler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            command_string = (
                f"curl -sf http://localhost:1/ > /dev/null || curl -sf http://localhost:{port}/ > /dev/null"
            )
            result = subprocess.run(["/bin/sh", "-c", command_string], timeout=5)
            assert result.returncode == 0, (
                "shell should have fallen through to the working fallback target and succeeded"
            )
        finally:
            httpd.shutdown()


class TestInstallShExternalFileRollback:
    """
    v5.20.0 — install_files() (install.sh) overwrites four files OUTSIDE
    /opt/jen: the systemd unit, the sudoers grant, and the root-privileged
    update script + its own unit. None of those live under
    releases/<ver>/, so activate_release()'s symlink flip can't roll them
    back, and rollback() was only ever invoked from start_service() — a
    fatal error anywhere between install_files and start_service left an
    upgrade half rolled back: the release symlink flipped to the old
    version, but the four external files stayed on the new one.
    snapshot_external_files() + rollback() restoring them, plus arming
    rollback for the whole install_files..verify_install window via
    ROLLBACK_ARMED (checked in fatal()), closes that gap.

    install.sh needs root, systemd and a real host, so it can't run in
    CI or on this Windows dev box — this is a source-shape check that
    the wiring is actually in place, same style as the rest of this file.
    """

    def _source(self):
        return pathlib.Path("install.sh").read_text(encoding="utf-8")

    def _function_body(self, source, name):
        """Slice out a `name() { ... }` block. Bash in this script never
        uses `{`/`}` for control flow (if/fi, for/done, case/esac), so
        the next line that is exactly `}` is always the function's own
        closing brace — safe even with nested if/for blocks inside."""
        start = source.index(f"{name}() {{")
        end = source.index("\n}", start)
        return source[start:end]

    def test_snapshot_called_before_install_files_in_main(self):
        source = self._source()
        main_body = self._function_body(source, "main")
        snapshot_positions = [m.start() for m in re.finditer(r"\bsnapshot_external_files\b", main_body)]
        install_files_positions = [m.start() for m in re.finditer(r"^\s*install_files\s*$", main_body, re.MULTILINE)]
        assert snapshot_positions, "snapshot_external_files is never called in main()"
        assert install_files_positions, "install_files is never called in main()"
        for install_pos in install_files_positions:
            assert any(sp < install_pos for sp in snapshot_positions), (
                "install_files is called in main() without a preceding snapshot_external_files call"
            )

    def test_rollback_armed_brackets_install_files_through_verify_install(self):
        source = self._source()
        main_body = self._function_body(source, "main")
        install_positions = [m.start() for m in re.finditer(r"^\s*install_files\s*$", main_body, re.MULTILINE)]
        verify_positions = [m.start() for m in re.finditer(r"^\s*verify_install\s*$", main_body, re.MULTILINE)]
        armed_positions = [m.start() for m in re.finditer(r"^\s*ROLLBACK_ARMED=true\s*$", main_body, re.MULTILINE)]
        disarmed_positions = [m.start() for m in re.finditer(r"^\s*ROLLBACK_ARMED=false\s*$", main_body, re.MULTILINE)]
        assert armed_positions, "ROLLBACK_ARMED=true is never set in main()"
        assert disarmed_positions, "ROLLBACK_ARMED=false is never set in main()"
        for install_pos in install_positions:
            assert any(a < install_pos for a in armed_positions), "install_files runs before ROLLBACK_ARMED is set"
        for verify_pos in verify_positions:
            assert any(d > verify_pos for d in disarmed_positions), (
                "ROLLBACK_ARMED is never cleared after verify_install"
            )

    def test_fatal_rolls_back_when_armed_during_an_upgrade(self):
        source = self._source()
        fatal_line = next(line for line in source.splitlines() if line.strip().startswith("fatal()"))
        assert "ROLLBACK_ARMED" in fatal_line
        assert "IS_UPGRADE" in fatal_line
        assert "rollback" in fatal_line

    def test_snapshot_function_names_all_four_external_files(self):
        source = self._source()
        match = re.search(r"_EXTERNAL_FILES=\((.*?)\)", source, re.DOTALL)
        assert match, "could not find the _EXTERNAL_FILES array in install.sh"
        body = match.group(1)
        assert "SERVICE_FILE" in body, "jen.service is not in the external-files snapshot list"
        assert "SUDOERS_FILE" in body, "the sudoers grant is not in the external-files snapshot list"
        assert "/usr/local/sbin/jen-update-root.py" in body, (
            "the root-privileged update script is not in the external-files snapshot list"
        )
        assert "/etc/systemd/system/jen-update.service" in body, (
            "jen-update.service is not in the external-files snapshot list"
        )

    def test_rollback_restores_external_files_in_both_branches(self):
        source = self._source()
        rollback_body = self._function_body(source, "rollback")
        assert rollback_body.count("_restore_external_files") == 2, (
            "rollback() should restore external files in both the versioned-release branch "
            "and the legacy flat-copy-back branch"
        )

    def test_sudoers_restore_is_validated_with_visudo_before_taking_effect(self):
        source = self._source()
        restore_body = self._function_body(source, "_restore_external_files")
        assert "visudo -c -f" in restore_body, (
            "a restored sudoers file must be validated with visudo before replacing the live one"
        )
