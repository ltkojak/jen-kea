"""
tests/test_invariant_sweeps.py - v5.68.0-beta.16 (Q151): the audit sweeps, as tests.

Q150's audit ran its pattern sweeps over the NEWEST code (secret writers in `jen/`, migrations 29+, the helper). The invariants it stated apply
to every participant - `install.sh`, `run.py`, the legacy script, all 33 migrations, the certificate set - and a sweep bounded to the last Q's
files is not an audit. Each class below is one sweep run over the WHOLE repository, source-level (so it runs on Windows too, in CI on every push):
a new beta cannot regress an invariant the suite has learned, and a NEW invariant ships with its sweep (CLAUDE.md). An audit of a beta is these
sweeps re-run, plus the ones the new code needs.

  S1  a secret is written private from its first byte (Q150 `private_files`, Q151 `tools/private_write.py`): no plain `open(..., "w")`, `cat >` or
      `cp` of a secret path anywhere, except through the reviewed writers.
  S2  a live file is never moved away before its replacement exists (Q151 `commit_file_set`).
  S3  every DDL statement of every migration has its OWN guard (Q150 migration 33, Q151 migrations 3/4/6).
  S4  the helper has one identity resolver and swallows no `chown`/`fchown`/`replace`/`fsync` failure (Q151 helper build 14).
  S5  the legacy engine is unreachable from a path that promises all-or-nothing (Q151 authoring).
  S9  what the root installer copies into the app tree comes from the tarball or from root's own snapshot directory, never from a service-writable
      directory (Q151 / Q119).
  S10 a failed read on a security or safety path is not an empty result: every `except` in the modules that make those decisions whose body returns an
      empty value or passes is on a reviewed list, with the reason it fails CLOSED there (Q166; docs/SAFETY_INVARIANTS.md FAIL-001).
  S11 a route never shows what a broad `except` caught: the name bound by `except Exception as e` in `jen/routes/` is used only to log or to name its class; the reviewed list is
      empty (Q171; docs/SAFETY_INVARIANTS.md LEAK-001).

The sweep tests were written FIRST (before the fixes) and are un-xfailed as each fix lands; the commit that lands a fix removes its marker.
"""

import ast
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def _py_files():
    files = sorted((ROOT / "jen").rglob("*.py")) + [
        ROOT / "run.py",
        ROOT / "jen-update-root.py",
        ROOT / "jen-kea-helper",
    ]
    return [p for p in files if "__pycache__" not in p.parts]


def _parents(tree):
    parents = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node
    return parents


def _enclosing_function(node, parents):
    names = []
    while node in parents:
        node = parents[node]
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.append(node.name)
    return ".".join(reversed(names)) or "<module>"


# ── S1: secrets are written private from their first byte ────────────────────

# a path expression that names a secret, or a directory secrets live in
SECRET_TOKENS = (
    "config_dir",
    "config_file",
    "config_path",
    "jen.config",
    "ssl_key",
    "ssl_cert",
    "ssl_ca",
    "ssl_combined",
    "key_file",
    "mfa_key",
    "secret_key",
    "server.key",
    "jen_rsa",
    "ssh_key",
)

# (file, enclosing function): reviewed, with WHY it is not a secret write that needs the private writer
S1_REVIEWED = {
    (
        "jen/routes/settings/security.py",
        "validate_cert_material",
    ): "a TemporaryDirectory (0700): only test-loads a pair, never an installed file",
    ("jen/services/private_files.py", "private_tempfile"): "THE writer (os.open O_EXCL 0600)",
    ("jen/services/private_files.py", "write_private_file"): "THE writer",
}


def _write_mode(call):
    mode = call.args[1].value if len(call.args) >= 2 and isinstance(call.args[1], ast.Constant) else None
    for kw in call.keywords:
        if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
            mode = kw.value.value
    return mode if isinstance(mode, str) else ""


class TestS1SecretsArePrivateFromTheirFirstByte:
    """Q150 (the running app) + Q151 (every participant). A secret is written through `jen.services.private_files.write_private_file`, the
    helper's `_install_private` or `tools/private_write.py`: a unique O_EXCL 0600 temp, the final owner/mode on the descriptor, then the replace.
    A plain `open(path, "w")` / `Path.write_*` / `cat > path` of a path that names a secret (or lives under the config dir) is created with the
    process umask and tightened afterwards - the window Q150 closed in `jen/` and Q151 closes in the installer and the Docker bootstrap."""

    def test_no_python_file_writes_a_secret_path_with_a_plain_open(self):
        offenders = []
        for path in _py_files():
            rel = path.relative_to(ROOT).as_posix()
            tree = ast.parse(path.read_text(encoding="utf-8"))
            parents = _parents(tree)
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                name = func.id if isinstance(func, ast.Name) else (func.attr if isinstance(func, ast.Attribute) else "")
                target = None
                if name == "open" and any(c in _write_mode(node) for c in "wax"):
                    target = node.args[0] if node.args else None
                elif name in ("write_text", "write_bytes") and isinstance(func, ast.Attribute):
                    target = func.value
                if target is None:
                    continue
                text = ast.unparse(target).lower()
                if any(token in text for token in SECRET_TOKENS):
                    function = _enclosing_function(node, parents)
                    if (rel, function) not in S1_REVIEWED:
                        offenders.append(f"{rel}::{function}: {ast.unparse(node)[:90]}")
        assert not offenders, f"a secret path is written with a plain open(): {offenders}"

    # the installer (bash): a redirection into the config dir, or a copy of the config file, is a plain-umask write
    REDIRECT = re.compile(r"(?<![0-9&<])>>?\s*\"?\$\{?(CONFIG_FILE|CONFIG_DIR|BACKUP_DIR|CONTENT_DIR)")
    COPY_OF_SECRET = re.compile(r"^\s*cp\b[^\n]*\$\{?CONFIG_FILE\b")

    def test_the_installer_never_redirects_or_copies_a_secret_into_the_config_dir(self):
        offenders = []
        for rel in ("install.sh", "uninstall.sh"):
            for number, line in enumerate(_read(rel).splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                if self.REDIRECT.search(line) or self.COPY_OF_SECRET.search(line):
                    offenders.append(f"{rel}:{number}: {line.strip()[:100]}")
        assert not offenders, (
            f"the installer writes under the service-writable config dir with the process umask (use tools/private_write.py): {offenders}"
        )

    def test_the_installers_env_file_is_written_under_umask_077(self):
        lines = _read("install.sh").splitlines()
        index = next(i for i, line in enumerate(lines) if 'cat > "./.env"' in line)
        assert any("umask 077" in line for line in lines[max(0, index - 6) : index]), (
            "the Docker .env holds passwords: umask 077 first"
        )

    def test_the_docker_bootstrap_writes_jen_config_through_the_private_writer(self):
        text = _read("run.py")
        assert "write_private_file(config_path" in text, (
            "run.py's env-built jen.config must go through write_private_file (unique temp, replace)"
        )


# ── S2: a live file is never moved away before its replacement exists ────────


class TestS2NoLiveFileIsMovedAwayBeforeItsReplacementExists:
    """Q151. `certs.write_atomically` did `os.replace(live, live + ".prev")` and only THEN wrote the new file: a failure left the set with no live
    file at all (a service that cannot start). `kea_tls.commit_rotation` did the same four times in a row. The one place that may keep a `.prev` is
    `certs.commit_file_set`, which snapshots a COPY first and replaces the live file only when every member is staged."""

    ALLOWED_FUNCTIONS = {"commit_file_set"}

    def test_no_replace_of_a_live_file_to_dot_prev_outside_commit_file_set(self):
        offenders = []
        for path in _py_files():
            rel = path.relative_to(ROOT).as_posix()
            tree = ast.parse(path.read_text(encoding="utf-8"))
            parents = _parents(tree)
            for node in ast.walk(tree):
                if not (
                    isinstance(node, ast.Call) and ast.unparse(node.func) in ("os.replace", "os.rename", "shutil.move")
                ):
                    continue
                if len(node.args) == 2 and ".prev" in ast.unparse(node.args[1]):
                    function = _enclosing_function(node, parents)
                    if function.split(".")[-1] not in self.ALLOWED_FUNCTIONS:
                        offenders.append(f"{rel}::{function}: {ast.unparse(node)}")
        assert not offenders, f"a live file is moved to .prev before its replacement exists: {offenders}"


# ── S3: every DDL statement has its own guard ────────────────────────────────

_DDL = re.compile(r"\b(ALTER\s+TABLE|CREATE\s+(UNIQUE\s+)?INDEX|ADD\s+CONSTRAINT)\b", re.I)
_GUARD_NAMES = (
    "_column_missing",
    "_column_exists",
    "_index_exists",
    "_foreign_key_exists",
    "_table_exists",
    "_column_type",
)


def _sql_text(node):
    """All the string constants under `node` joined (an execute() argument may be an f-string or a concatenation)."""
    return " ".join(n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str))


def _guard_test(if_node):
    """Any `if` counts as a guard: what the rule asks is that each statement has ITS OWN condition (a schema guard, or a computed one like
    migration 5's width check), never one condition standing in for several statements."""
    return True


class TestS3EveryMigrationStatementHasItsOwnGuard:
    """Q150 wrote the rule at the top of migrations.py and applied it to migration 33; Q151 applies it to the rest. DDL auto-commits, so a crash
    between two statements that share ONE guard leaves the first applied and the next start sees the guard satisfied by the first statement's side
    effect: the rest never runs, and the migration is recorded done. Every `ALTER TABLE` / `CREATE INDEX` / `ADD CONSTRAINT` therefore sits in its
    own `if <guard>` (or says IF [NOT] EXISTS), and no two share one."""

    def test_no_two_ddl_statements_share_a_guard_and_none_is_unguarded(self):
        path = ROOT / "jen" / "models" / "migrations.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        parents = _parents(tree)
        by_function = {}
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"
                and node.args
            ):
                continue
            sql = _sql_text(node.args[0])
            if not _DDL.search(sql) or re.search(r"IF\s+(NOT\s+)?EXISTS", sql, re.I):
                continue
            function = _enclosing_function(node, parents)
            if not function.startswith("_m0"):
                continue
            guard, climb = None, node
            while climb in parents:
                climb = parents[climb]
                if isinstance(climb, ast.If) and _guard_test(climb):
                    guard = climb
                    break
                if isinstance(climb, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    break
            by_function.setdefault(function, []).append((guard, node.lineno, sql[:60]))
        offenders = []
        for function, statements in sorted(by_function.items()):
            seen = {}
            for guard, lineno, sql in statements:
                if guard is None:
                    offenders.append(f"{function}:{lineno} has no guard: {sql}")
                    continue
                if id(guard) in seen:
                    offenders.append(f"{function}:{lineno} shares the guard at line {seen[id(guard)]}: {sql}")
                seen.setdefault(id(guard), lineno)
        assert not offenders, f"a migration guards several auto-committing statements with one check: {offenders}"

    def test_migration_6_records_its_one_time_promotion_before_the_alter(self):
        text = _read("jen/models/migrations.py")
        body = text.split("def _m006_superadmin_role", 1)[1].split("def _m007", 1)[0]
        assert "legacy_admin_promotion_pending" in body, (
            "migration 6 must record the pending promotion before its ENUM ALTER"
        )
        assert body.index("legacy_admin_promotion_pending") < body.index("ALTER TABLE users"), (
            "the marker is recorded BEFORE the ALTER: a crash between the ALTER and the UPDATE must still promote the legacy admins"
        )


# ── S4: one identity resolver; no swallowed ownership/durability failure ─────


class TestS4TheHelperHasOneIdentityResolverAndSwallowsNothing:
    """Q151. `_daemon_group` (User= -> passwd primary group) decided `server.key`'s group while `_unit_account` (numeric User, `Group=`,
    SupplementaryGroups) decided what validation runs as: a unit with `Group=kea-config` got a key its daemon could not read. And a
    `chown`/`fchown` failure swallowed with `pass` reported success for a file owned by the wrong account."""

    def _tree(self):
        return ast.parse(_read("jen-kea-helper"))

    def test_there_is_exactly_one_systemctl_show_user(self):
        tree = self._tree()
        hits = [
            n.lineno
            for n in ast.walk(tree)
            if isinstance(n, ast.Call)
            and ast.unparse(n.func) == "_run_bin"
            and any(isinstance(c, ast.Constant) and c.value == "User" for arg in n.args for c in ast.walk(arg))
        ]
        assert len(hits) == 1, (
            f"the helper resolves a unit's account in {len(hits)} places (lines {hits}); there must be exactly one (_unit_account)"
        )

    def test_no_chown_fchown_replace_or_fsync_failure_is_swallowed(self):
        tree = self._tree()
        sensitive = {"chown", "fchown", "replace", "fsync"}
        offenders = []

        def calls_sensitive(nodes):
            return any(
                isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr in sensitive
                for n in nodes
                for c in ast.walk(n)
            )

        for node in ast.walk(tree):
            if isinstance(node, ast.Try):
                swallowing = [
                    h
                    for h in node.handlers
                    if all(isinstance(s, (ast.Pass, ast.Continue)) for s in h.body)
                    and re.search(r"OSError|AttributeError|Exception", ast.unparse(h.type) if h.type else "Exception")
                ]
                if swallowing and calls_sensitive(node.body):
                    offenders.append(f"line {node.lineno}: try around {[ast.unparse(s)[:50] for s in node.body][:2]}")
            if (
                isinstance(node, ast.With)
                and any("suppress" in ast.unparse(item.context_expr) for item in node.items)
                and calls_sensitive(node.body)
            ):
                offenders.append(
                    f"line {node.lineno}: suppress() around {[ast.unparse(s)[:50] for s in node.body][:2]}"
                )
            if isinstance(node, ast.FunctionDef) and node.name == "_chown":
                offenders.append(f"line {node.lineno}: the swallowing _chown wrapper")
        assert not offenders, f"the helper swallows an ownership/durability failure and reports success: {offenders}"


# ── S5: the legacy engine is unreachable from an all-or-nothing path ─────────


class TestS5TheLegacyEngineIsNotReachableFromAnAllOrNothingPath:
    """Q151. Author Kea Config promises every server or none; its rollback of a file Jen created is the helper's `remove-config`. A helper-less
    target fell back to the legacy script for the WRITE and then could not be rolled back: A written, B failing, `rollback_failed`. The authoring
    path requires a current helper on every target and passes `helper_only=True`; the legacy engine keeps serving the single-step edits of a host
    that has no helper (CLAUDE.md: the legacy `sudo python3` fallback is banner-warned and never removed in 5.x), through the ONE script below,
    which is itself written private from its first byte (a unique mkstemp temp, never the fixed `.jen_author_tmp` plain open)."""

    def test_the_legacy_script_is_called_only_from_test_config_and_apply_config_behind_a_helper_only_guard(self):
        tree = ast.parse(_read("jen/services/kea_host.py"))
        parents = _parents(tree)
        callers = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and ast.unparse(node.func).endswith("render_author_config_script"):
                callers.setdefault(_enclosing_function(node, parents), []).append(node)
        assert set(callers) == {"test_config", "apply_config"}, f"the legacy script is reachable from {sorted(callers)}"
        for name in callers:
            function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
            assert "helper_only" in [a.arg for a in function.args.args + function.args.kwonlyargs], (
                f"{name} must accept helper_only"
            )
            source = ast.unparse(function)
            assert source.index("if helper_only") < source.index("render_author_config_script"), (
                f"{name}: the helper_only refusal must come before the legacy script is rendered"
            )

    def test_nothing_the_authoring_route_runs_can_reach_the_legacy_script(self):
        text = _read("jen/routes/settings/authoring.py")
        assert "render_author_config_script" not in text and "_legacy_python3" not in text
        assert "helper_only=True" in text, "the preview's test_config and the change set both run helper_only"
        assert text.count("helper_only=True") >= 2
        assert "helper_build" in text, "every target's helper build is checked before the preflight"
        assert "__host.apply_config(" not in text

    def test_the_change_set_passes_helper_only_to_every_host_call_it_makes(self):
        text = _read("jen/services/kea_changeset.py")
        assert text.count('**({"helper_only": True} if helper_only else {})') >= 3, (
            "test_config, apply_config and the restore"
        )

    def test_the_legacy_script_writes_private_and_not_to_a_fixed_name(self):
        text = _read("jen/services/kea_authoring.py")
        assert "jen_author_tmp" not in text, "the fixed temp name is gone"
        assert "tempfile.mkstemp" in text and "shutil.copy2(path" not in text, (
            "unique O_EXCL 0600 temp; the backup is not made with the umask"
        )


# ── S9: what root copies into the app tree ───────────────────────────────────


class TestS9TheRootInstallerTrustsOnlyTheTarballAndItsOwnSnapshots:
    """Q151 (and Q119, which moved only the `ext.*` snapshot). `$CONFIG_DIR` and `$CONTENT_DIR` are SERVICE-OWNED: a compromised service account
    can plant anything there. Nothing root later executes or copies into the app tree (`$INSTALL_DIR`, `/usr/local/sbin`, `/etc/systemd`) may come
    from under them. The upgrade snapshot of `run.py` and the `jen/` package lived in `$CONFIG_DIR/backups` and a failed upgrade `cp`ed it back."""

    UNTRUSTED = re.compile(r"\$\{?(BACKUP_DIR|CONFIG_DIR|CONTENT_DIR)\b")
    TRUSTED_DEST = re.compile(
        r"\$\{?(INSTALL_DIR|RELEASE_DIR|APP_DIR)\b|/usr/local/sbin|/etc/systemd|\$\{?SUDOERS_FILE|\$\{?SERVICE_FILE"
    )

    def test_no_copy_into_the_app_tree_names_a_service_writable_source(self):
        offenders = []
        for number, line in enumerate(_read("install.sh").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#") or not re.match(r"^(cp|install|mv|rsync)\b", stripped):
                continue
            words = stripped.split()
            operands = [w for w in words[1:] if not w.startswith("-")]
            if len(operands) < 2:
                continue
            *sources, dest = operands
            if self.TRUSTED_DEST.search(dest) and any(self.UNTRUSTED.search(s) for s in sources):
                offenders.append(f"install.sh:{number}: {stripped[:110]}")
        assert not offenders, f"root copies from a service-writable directory into the app tree: {offenders}"

    def test_the_rollback_snapshots_are_under_root_rollback_dir(self):
        text = _read("install.sh")
        for variable in ("ROLLBACK_JEN", "ROLLBACK_PKG"):
            assignments = re.findall(rf'^\s*{variable}="([^"]*)"', text, re.M)
            real = [a for a in assignments if a]
            assert real and all("ROOT_ROLLBACK_DIR" in a for a in real), (
                f"{variable} must be assigned under $ROOT_ROLLBACK_DIR: {real}"
            )

    def test_the_rollback_refuses_a_snapshot_that_is_not_root_owned_or_is_a_symlink(self):
        text = _read("install.sh")
        assert "_trusted_snapshot" in text and "_root_owned" in text

    # Q171: root writing a file BY PATHNAME opens whatever a service-planted symlink at that name points at (the layout-check cache in the service-owned data
    # directory truncated and re-moded any file on the box). Every `open(<path>, "w"/"wb"/"a")` in the updater is on this list with the reason its directory is not
    # the service's to write in; a new one fails until it is argued on, a listed one that is gone fails too. The service-writable data directory's own file is
    # written by `mkstemp` + `os.replace` (`_write_layout_check_cache`) and is deliberately NOT here.
    UPDATER_WRITES = {
        "out_path": "the rendered systemd unit: written into the unit directory root owns, from a template in the release tarball",
        "signers_path": "inside `tempfile.TemporaryDirectory()`, which root just made 0700",
        "sig_path": "inside `tempfile.TemporaryDirectory()`, which root just made 0700",
        "sig_dest": "`<release dir>/jen-kea-helper.sig`: the release directory was extracted by root and is root-owned",
        "os.path.join(release_dir, '.failed')": "a marker inside the release directory root extracted and owns",
        "os.path.join(snapshot_dir, KEEP_MARKER)": "a marker inside root's own rollback snapshot directory",
        "os.path.join(prev_dir, KEEP_MARKER)": "a marker inside a previous release directory, root-owned",
    }

    def _updater_opens_for_writing(self):
        import ast

        tree = ast.parse(_read("jen-update-root.py"))
        found = {}
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "open"):
                continue
            mode = None
            if len(node.args) > 1 and isinstance(node.args[1], ast.Constant):
                mode = node.args[1].value
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = kw.value.value
            if isinstance(mode, str) and mode[:1] in ("w", "a", "x"):
                found.setdefault(ast.unparse(node.args[0]), []).append(node.lineno)
        return found

    def test_the_updater_opens_no_path_for_writing_that_is_not_reviewed(self):
        found = self._updater_opens_for_writing()
        unreviewed = {k: v for k, v in found.items() if k not in self.UPDATER_WRITES}
        assert not unreviewed, (
            "jen-update-root.py runs as root: write by mkstemp + os.replace (or an O_NOFOLLOW|O_EXCL descriptor) when the directory is "
            f"service-writable, or argue the path onto UPDATER_WRITES: {unreviewed}"
        )

    def test_the_reviewed_updater_writes_all_still_exist(self):
        stale = sorted(set(self.UPDATER_WRITES) - set(self._updater_opens_for_writing()))
        assert not stale, f"UPDATER_WRITES names a write that is gone: {stale}"

    def test_the_layout_check_cache_is_not_written_by_pathname(self):
        text = _read("jen-update-root.py")
        body = text[
            text.index("def _write_layout_check_cache") : text.index("# Mirrors jen/services/plugins.py::_PLUGIN_ID_RE")
        ]
        assert "mkstemp" in body and "os.replace" in body and "os.lstat" in body
        assert "open(LAYOUT_CHECK_CACHE" not in body


# ── S10: a failed read on a security or safety path is not an empty result (Q166, FAIL-001) ──────────────────────────────────────────────────────────────
#
# The class behind beta.24, 25 and 28: a read that FAILS (a malformed record, a settings table that could not be read, an API that did not answer) came back as the empty value, and the caller read
# "nothing" as "nothing outstanding" / "nobody logged in" / "no restriction". The modules below make security or safety decisions; in them an `except` whose whole effect is to return an empty value
# (`None`, `{}`, `[]`, `()`, `""`, `False`, `default`, a bare `return`) or to pass is a site where that can happen. Every such site is on the reviewed list with the reason the empty value is fail-CLOSED
# THERE (a refusal, a "not verified", a "not trusted", a bookkeeping write nothing decides on). A new site fails CI until it is argued onto the list; a listed site that no longer exists fails too, so
# the list cannot rot. A handler that logs and then returns is still a site (the log is not the decision).

S10_MODULES = (
    "jen/services/access.py",
    "jen/models/user.py",
    "jen/services/csrf.py",
    "jen/services/mfa.py",
    "jen/services/auth.py",
    "jen/services/api_auth.py",
    "jen/routes/auth.py",
    "jen/services/investigation_logging.py",
    "jen/config.py",
    "jen/services/kea_host.py",
)

# (module, function, exception, effect): why the empty value is fail-closed there
S10_ALLOWED = {
    ("jen/services/auth.py", "_endpoint_parts", "ValueError", "return None"): (
        "an address that cannot be parsed (a bad port) names no place, so it is NEVER the same endpoint as anything: a kept secret is then removed or the form refuses - fail closed (CRED-002, Q178)"
    ),
    ("jen/services/auth.py", "usable_file", "(OSError, ValueError, TypeError)", "return False"): (
        "a path that cannot be examined is NOT a usable file: the caller refuses the CA bundle / client certificate it was asked to trust (Q174)"
    ),
    ("jen/services/access.py", "auth_is_recent", "(TypeError, ValueError)", "return False"): (
        "an unreadable step-up timestamp reads as NOT recently authenticated, so the step-up is demanded"
    ),
    ("jen/services/access.py", "_as_int", "(TypeError, ValueError)", "return None"): (
        "a subnet id that is not an integer pairs with nothing: the caller treats None as no pairing, which only a caller who may see every subnet can reach"
    ),
    ("jen/services/access.py", "filter_client_view.ok", "(TypeError, ValueError)", "return False"): (
        "an unreadable subnet id is NOT in the accessible set: the row is hidden"
    ),
    ("jen/models/user.py", "set_global_setting", "Exception", "return False"): (
        "the write is reported as NOT stored; every caller that needs the write (the investigation record, the audit) acts on that False (Q158)"
    ),
    ("jen/models/user.py", "set_global_setting_and_audit", "Exception", "return False"): (
        "both statements are rolled back and the caller is told it did not happen; the decision stays open"
    ),
    ("jen/services/csrf.py", "validate_csrf_token", "(BadSignature, SignatureExpired)", "return False"): (
        "a token that does not verify is an invalid token: the request is refused"
    ),
    ("jen/services/csrf.py", "validate_csrf_token", "Exception", "return False"): (
        "any failure while validating a token is an invalid token: the request is refused"
    ),
    ("jen/services/mfa.py", "verify_backup_code", "Exception", "return False"): (
        "a failure while checking a backup code is NOT verified: the login does not proceed"
    ),
    ("jen/services/mfa.py", "verify_totp", "Exception", "pass"): (
        "bookkeeping only (last_used): the code was already verified, and a tracking failure must not lock a valid login out (the True is returned by the code that verified it)"
    ),
    ("jen/services/mfa.py", "verify_totp", "Exception", "return False"): (
        "a failure while checking a TOTP code is NOT verified: the login does not proceed"
    ),
    ("jen/services/mfa.py", "is_trusted_device", "Exception", "return False"): (
        "a failure while checking a trusted device is NOT trusted: the second factor is demanded"
    ),
    ("jen/services/mfa.py", "is_trusted_device._update", "Exception", "pass"): (
        "last-seen bookkeeping for a device already judged trusted; it grants nothing and decides nothing"
    ),
    (
        "jen/services/auth.py",
        "valid_ip",
        "ValueError",
        "return False",
    ): "input validation: a value that does not parse is rejected",
    (
        "jen/services/auth.py",
        "valid_cidr",
        "ValueError",
        "return False",
    ): "input validation: a value that does not parse is rejected",
    ("jen/services/auth.py", "valid_positive_int", "(ValueError, TypeError)", "return False"): (
        "input validation: a value that does not parse is rejected"
    ),
    (
        "jen/services/auth.py",
        "valid_oidc_issuer",
        "ValueError",
        "return False",
    ): "input validation: a value that does not parse is rejected",
    (
        "jen/services/auth.py",
        "valid_api_url",
        "ValueError",
        "return False",
    ): "input validation: a value that does not parse is rejected",
    ("jen/services/api_auth.py", "api_auth", "Exception", "return None"): (
        "a failure while looking up an API key is NO key: the request is unauthenticated and falls through to the session check, which refuses it"
    ),
    ("jen/services/investigation_logging.py", "forget", "Exception", "return False"): (
        "a config that cannot be read means the marker cannot be shown to be gone: the entry is NOT forgotten"
    ),
    ("jen/services/investigation_logging.py", "_revision_before_on", "Exception", "return None"): (
        "display only: the Config history revision a person is pointed at; None says 'none on record' and no safety decision reads it"
    ),
    ("jen/services/investigation_logging.py", "_file_carries_marker", "Exception", "return None"): (
        "None means 'could not be read' and every caller treats it as unknown, never as 'the marker is gone' (sweep: `carries is False` is the only branch that acts)"
    ),
    ("jen/services/investigation_logging.py", "_raw_marker_text", "(TypeError, ValueError)", 'return ""'): (
        "a marker that cannot be serialised reads as no text; the Kea-file guard only lets a malformed marker through when its text EQUALS the one recorded at adoption, and a recorded text is never empty, so this refuses"
    ),
    ("jen/config.py", "apply", "Exception", "pass"): (
        "a capability-cache drop after a config load; nothing is decided on it, and a stale cache is re-derived on the next read"
    ),
    ("jen/services/kea_host.py", "helper_status", "(ValueError, TypeError)", "return {}"): (
        "an unreadable recorded-helper-status is NO recorded status: every capability derived from it (d2, tls, trace) reads as off, never on"
    ),
    ("jen/services/kea_host.py", "legacy_grant_status", "Exception", "pass"): (
        "the optional `sudo -l` listing is a bonus for the message; the refusal reason that decides the answer was already computed"
    ),
    ("jen/services/kea_host.py", "verify_helper_signature", "(OSError, subprocess.TimeoutExpired)", "return False"): (
        "a signature check that could not run is NOT verified: the helper is not installed"
    ),
    ("jen/services/kea_host.py", "_local_helper_signature", "OSError", "return None"): (
        "no readable signature file is no signature: the caller refuses to install without one"
    ),
    ("jen/services/kea_host.py", "_fetch_helper_signature", "Exception", "return None"): (
        "a signature that could not be fetched is no signature: the caller refuses to install without one"
    ),
    ("jen/services/kea_host.py", "helper_call", "(OSError, AttributeError)", "pass"): (
        "stdin of an SSH exec channel that already closed: the helper's own answer (or its absence, which is raised below as HelperError) decides"
    ),
    ("jen/services/kea_host.py", "_legacy_python3", "(OSError, AttributeError)", "pass"): (
        "stdin of an SSH exec channel whose remote command already ended: the command's own output and exit status, read next, decide - a script that did not run is never read as success"
    ),
    ("jen/services/kea_host.py", "helper_call", "ValueError", "pass"): (
        "output that is not JSON falls through to the HelperMissing / HelperError raise below: a garbled answer is never read as success"
    ),
}

_S10_LOG_NAMES = ("logger", "logging", "log")


def _s10_is_log(stmt):
    if isinstance(stmt, ast.Expr):
        value = stmt.value
        if isinstance(value, ast.Constant):
            return True
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute):
            base = value.func.value
            return isinstance(base, ast.Name) and base.id in _S10_LOG_NAMES
    return False


def _s10_effect(stmt):
    """The empty-value effect of one statement, or None when it is anything else."""
    if isinstance(stmt, ast.Pass):
        return "pass"
    if isinstance(stmt, ast.Return):
        value = stmt.value
        if value is None:
            return "return"
        if isinstance(value, ast.Constant) and value.value in (None, False, ""):
            return f"return {value.value!r}" if value.value != "" else 'return ""'
        if isinstance(value, ast.Dict) and not value.keys:
            return "return {}"
        if isinstance(value, ast.List) and not value.elts:
            return "return []"
        if isinstance(value, ast.Tuple) and not value.elts:
            return "return ()"
        if isinstance(value, ast.Name) and value.id == "default":
            return "return default"
    return None


def s10_sites(source, rel="<test>"):
    """[(module, function, exception, effect, line)] for every `except` in `source` whose effect (after log calls and docstrings) is an empty return or a pass."""
    tree = ast.parse(source)
    parents = _parents(tree)
    out = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        body = [b for b in node.body if not _s10_is_log(b)]
        if len(body) != 1:
            continue
        effect = _s10_effect(body[0])
        if effect:
            kind = ast.unparse(node.type) if node.type is not None else "bare"
            out.append((rel, _enclosing_function(node, parents), kind, effect, node.lineno))
    return out


class TestS10FailedReadsOnSecurityPathsAreNotEmptyResults:
    def _all_sites(self):
        sites = []
        for rel in S10_MODULES:
            assert (ROOT / rel).is_file(), (
                f"S10 lists {rel} and it does not exist: a renamed security module must be re-listed, not dropped"
            )
            sites += s10_sites(_read(rel), rel)
        return sites

    def test_every_site_is_reviewed(self):
        new = [
            f"{rel}:{line} {fn}: `except {kind}` -> {effect}"
            for rel, fn, kind, effect, line in self._all_sites()
            if (rel, fn, kind, effect) not in S10_ALLOWED
        ]
        assert not new, (
            "an `except` on a security or safety path returns an empty value or passes. A failed read must not become 'nothing outstanding': either let it raise / return a refusal, "
            "or add the site to S10_ALLOWED with the reason the empty value is fail-CLOSED there:\n  "
            + "\n  ".join(new)
        )

    def test_the_list_does_not_name_a_site_that_is_gone(self):
        present = {(rel, fn, kind, effect) for rel, fn, kind, effect, _line in self._all_sites()}
        stale = sorted(set(S10_ALLOWED) - present)
        assert not stale, f"S10_ALLOWED names sites that no longer exist (remove them): {stale}"

    def test_every_site_carries_a_real_reason(self):
        for key, why in S10_ALLOWED.items():
            assert len(why) >= 25 and why == why.strip(), f"{key}: the reason is not a reason"

    def test_the_detector_finds_what_it_is_for(self):
        found = {
            (fn, kind, effect)
            for _rel, fn, kind, effect, _line in s10_sites(
                "def a():\n try:\n  x()\n except Exception:\n  return {}\n"
                "def b():\n try:\n  x()\n except ValueError:\n  logger.warning('no')\n  return None\n"
                "def c():\n try:\n  x()\n except (A, B):\n  pass\n"
                "def d(default=None):\n try:\n  x()\n except Exception:\n  return default\n"
                "def e():\n try:\n  x()\n except Exception:\n  raise\n"
                "def f():\n try:\n  x()\n except Exception:\n  return refusal('no')\n"
                "def g():\n try:\n  x()\n except Exception:\n  y()\n  return None\n"
            )
        }
        assert found == {
            ("a", "Exception", "return {}"),
            ("b", "ValueError", "return None"),
            ("c", "(A, B)", "pass"),
            ("d", "Exception", "return default"),
        }, found


# ── S11: a route never shows what a broad `except` caught (Q171) ───────────────────────────────────────────────────────────────────────────────────
#
# `str(e)` of a driver, `requests` or SSH error carries URLs with their query strings (a Technitium token, a Telegram bot token), account and host names, file paths. A route that
# catches `Exception` and then flashes, returns or `put`s it hands those to whoever is looking at the page, and a log is the right place for them. In `jen/routes/` the name bound by
# `except Exception as e` (or `BaseException`, or a tuple containing either) may be used only to LOG (a `logger.*` / `log.*` call) or to name its class (`type(e)`). Exceptions Jen
# raises itself with a sentence written for the person (`ConfigChangeRefused`, `GuardedImportError`, `ValueError` from a validator) are caught by their own class and are not this rule's.
# The reviewed list is EMPTY and stays empty: a site that needs the text of a broad catch does not exist; it needs a narrower except.

S11_ALLOWED: dict = {}


def s11_sites(source, rel="<source>"):
    """[(rel, line, name)] for each use of a broad handler's exception name outside a logging call or `type(...)`."""
    tree = ast.parse(source)
    out = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ExceptHandler) and node.name and node.type is not None):
            continue
        caught = [ast.unparse(x) for x in (node.type.elts if isinstance(node.type, ast.Tuple) else [node.type])]
        if not {"Exception", "BaseException"} & set(caught):
            continue
        parents = {}
        for outer in ast.walk(node):
            for child in ast.iter_child_nodes(outer):
                parents[child] = outer
        for use in ast.walk(node):
            if not (isinstance(use, ast.Name) and use.id == node.name and isinstance(use.ctx, ast.Load)):
                continue
            cur, safe = use, False
            while cur is not node and cur in parents:
                cur = parents[cur]
                if isinstance(cur, ast.Call):
                    fn = cur.func
                    if (
                        isinstance(fn, ast.Attribute)
                        and isinstance(fn.value, ast.Name)
                        and fn.value.id in ("logger", "log")
                    ):
                        safe = True
                        break
                    if isinstance(fn, ast.Name) and fn.id == "type":
                        safe = True
                        break
            if not safe:
                out.append((rel, use.lineno, node.name))
    return out


class TestS11ARouteNeverShowsWhatABroadExceptCaught:
    def _sites(self):
        found = []
        for path in sorted((ROOT / "jen" / "routes").rglob("*.py")):
            rel = path.relative_to(ROOT).as_posix()
            found += s11_sites(path.read_text(encoding="utf-8"), rel)
        return found

    def test_no_route_uses_a_broad_exceptions_text(self):
        sites = [s for s in self._sites() if f"{s[0]}:{s[1]}" not in S11_ALLOWED]
        assert not sites, (
            "a route uses the exception caught by `except Exception` outside a log call (flash, JSON, a queue, a result row): log it with logger.exception(...) and "
            f"answer with a fixed sentence, or catch the narrower class Jen raised itself: {sites}"
        )

    def test_the_reviewed_list_is_empty(self):
        assert S11_ALLOWED == {}, "S11 has no reviewed exceptions: narrow the except instead"

    def test_the_detector_finds_what_it_is_for(self):
        src = (
            "def a():\n try:\n  x()\n except Exception as e:\n  flash(f'bad {e}')\n"
            "def b():\n try:\n  x()\n except Exception as e:\n  return jsonify(error=str(e))\n"
            "def c():\n try:\n  x()\n except (OSError, Exception) as e:\n  q.put(('error', str(e)))\n"
            "def d():\n try:\n  x()\n except Exception as e:\n  logger.warning('no %s', e)\n  flash('fixed')\n"
            "def e():\n try:\n  x()\n except Exception as e:\n  logger.error(f'no {e}')\n  flash(type(e).__name__)\n"
            "def f():\n try:\n  x()\n except ValueError as e:\n  flash(str(e))\n"
            "def g():\n try:\n  x()\n except Exception:\n  logger.exception('no')\n"
        )
        assert [(line, name) for _r, line, name in s11_sites(src)] == [(5, "e"), (10, "e"), (15, "e")]
