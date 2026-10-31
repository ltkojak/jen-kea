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
  S16 the subnets THEMSELVES are scoped: every read of `SUBNET_MAP` / `SUBNET6_MAP` in `jen/` and `plugins/` is in a function that asks a scoping question, or is on a reviewed list with the
      reason (Q204; docs/SAFETY_INVARIANTS.md RBAC-005).

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
    "jen/services/kea_changeset.py",  # Q202 (AR8): the incident store the rotation's bookkeeping rides on
    "jen/services/kea_tls.py",  # Q202 (AR8): the certificate records a rotation, a recovery and the setup decide on
)

# (module, function, exception, effect): why the empty value is fail-closed there
S10_ALLOWED = {
    ("jen/services/auth.py", "_endpoint_parts", "ValueError", "return None"): (
        "an address that cannot be parsed (a bad port) names no place, so it is NEVER the same endpoint as anything: a kept secret is then removed or the form refuses - fail closed (CRED-002, Q178)"
    ),
    ("jen/services/auth.py", "_plain_host", "Exception", "return False"): (
        "a host that has no IDNA 2008 A-label, or does not survive the round trip, is NOT a plain name: `valid_api_url` then refuses the address, so a credential is never sent to a name nobody can read the same way twice (Q184, Z3; Q199 AO4: the `idna` package, what `requests` dials)"
    ),
    ("jen/services/auth.py", "idna_a_label", "Exception", "return None"): (
        "a name with no A-label (the `idna` package refuses it, or is missing) has NO form `requests` can dial: the callers read None as 'not a name' - `_plain_host` refuses the address, `verifier_accepts_name` says no, `_san_for` puts nothing in the leaf (Q199 AO4)"
    ),
    ("jen/services/auth.py", "is_v4_mapped_literal", "ValueError", "return False"): (
        "text that is not an IP address is not a MAPPED one; the caller's own check of the host (`valid_hostname` / `valid_ip`, `verifier_accepts_name`) refuses it as a name, so the answer 'not mapped' never admits it (Q204 AT5)"
    ),
    ("jen/services/auth.py", "kea_url_shape_ok", "ValueError", "return False"): (
        "an address `urlsplit` cannot parse (a bad port, a bracket) is NOT a Kea URL shape: the saver and the probe refuse it - fail closed (Q204 AT8 d)"
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
    ("jen/services/auth.py", "dns_name_sentence", "ValueError", 'return ""'): (
        "an address `urlparse` cannot parse gets no DNS-name SENTENCE, and `valid_api_url` - which parses the same address first and refuses it on its own `ValueError` before it ever calls this - has already said no; the sentence only chooses which refusal to show (Q197, AM2)"
    ),
    ("jen/services/auth.py", "userinfo_sentence", "ValueError", 'return ""'): (
        "an address `urlsplit` cannot parse gets no user-info SENTENCE, and `valid_api_url` - which refuses it first on its own `ValueError` - has already said no; the sentence only chooses which refusal to show (Q190)"
    ),
    ("jen/config.py", "_warn_userinfo_urls", "Exception", "return"): (
        "the legacy-URL warning is a LOG LINE; a failure to look for user-info must never break a config load, and nothing is decided from it - the credential rule is untouched and Health looks again (Q190)"
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
    ("jen/services/kea_changeset.py", "_is_timestamp", "ValueError", "return False"): (
        "an entry whose time does not parse is NOT a recognised incident: it is kept and counted as unrecognised, never cleared by a clean run (Q190, AF3)"
    ),
    ("jen/services/kea_changeset.py", "_with_attention", "Exception", "return False"): (
        "the transaction is reported as NOT done: `record_attention`, `resolve_attention`, `acknowledge_recovery` and the clears turn it into their own False/0/None, which the rotation and the routes act on (refuse, audit, say so); `record_outcome`'s only caller drops it by design - a rollback note that cannot be stored is logged and the route's own flash is all there is - and an unreadable note is refused, never read as empty and written over (Q189)"
    ),
    ("jen/services/kea_changeset.py", "record_outcome", "Exception", "return False"): (
        "best-effort telemetry: the change set's own result is never changed by it, and False says the outcome was NOT recorded - nothing reads the False as 'nothing to record'"
    ),
    ("jen/services/kea_changeset.py", "record_attention", "Exception", "return False"): (
        "the incident is reported as NOT stored: the rotation refuses before it stages, the other callers say so in a flash and an audit row (Q187, Q189, Q201 AQ3)"
    ),
    ("jen/services/kea_changeset.py", "resolve_attention", "Exception", "return 0"): (
        "'cleared 0' leaves the incident standing: a failed clear is never read as cleared (the rotation's check reads the store strict and counts an unreadable one as still there)"
    ),
    ("jen/services/kea_changeset.py", "acknowledge_recovery", "Exception", "return None"): (
        "None means the acknowledgement could not be written: the incident is still shown and the route says so"
    ),
    ("jen/services/kea_changeset.py", "dismiss_rollback_notes", "Exception", "return False"): (
        "False means the note was NOT dismissed: it stays on the Servers page"
    ),
    ("jen/services/kea_changeset.py", "_listed_count", "Exception", "return 0"): (
        "a count for the Servers banner's 'an incident Jen cannot read is on record' line only; every writer and Health read the note strictly and refuse text that is not a note (Q189)"
    ),
    ("jen/services/kea_changeset.py", "attention", "Exception", "return None"): (
        "the Servers banner reads it and a banner that cannot be read shows nothing; the safety callers (the rotation's dependencies and reconcile, Forget, Health's note state) read `recovery_incidents(strict=True)` and refuse or say 'unknown' (Q202 AR8)"
    ),
    ("jen/services/kea_changeset.py", "clear_attention", "Exception", "return False"): (
        "False means the note was NOT cleared (an unreadable note is refused, not cleared)"
    ),
    ("jen/services/kea_changeset.py", "set_aside_unreadable_note", "MalformedNote", "pass"): (
        "the one sanctioned reset: reaching it means the stored value IS malformed, which is exactly what the superadmin asked to set aside - the copy and the clear that follow are each checked"
    ),
    ("jen/services/kea_tls.py", "cert_expiry", "(OSError, ValueError)", "return None"): (
        "None is 'no expiry known': Health says the certificate cannot be read; it never shows a date it did not read"
    ),
    ("jen/services/kea_tls.py", "issued_by", "Exception", "return False"): (
        "'not issued by that CA': a certificate that cannot be verified is never called Jen's (a rotation refuses it, a recovery judges its destination, an unverified pair is never installed)"
    ),
    ("jen/services/kea_tls.py", "_run_openssl", "OSError", "return None"): (
        "NO OPINION from an informational CLI second opinion: the library's own verdict stands, and the CLI can only REJECT, never accept (Q196, Q197)"
    ),
    ("jen/services/kea_tls.py", "openssl_gate_rejection", "OSError", 'return ""'): (
        "a gate that can only REJECT: no answer is no rejection, and the library's verdict (which already ran) stands - it never turns a damaged CA into an ok one"
    ),
    ("jen/services/kea_tls.py", "openssl_second_opinion", "OSError", 'return ""'): (
        "informational: the second opinion adds a Health warning when it disagrees; no decision reads its absence"
    ),
    (
        "jen/services/kea_tls.py",
        "_ca_material_for_opinion",
        "(OSError, ValueError, TypeError, UnsupportedAlgorithm)",
        "return None",
    ): ("no material for the informational second opinion: no opinion, the library's verdict stands"),
    ("jen/services/kea_tls.py", "_name_types_ok", "(IndexError, ValueError)", "return False"): (
        "a CA whose names cannot be compared is NOT accepted: it reads as damaged"
    ),
    ("jen/services/kea_tls.py", "_same_name", "(IndexError, ValueError)", "return False"): (
        "two names that cannot be compared are NOT the same name: the CA is judged damaged"
    ),
    ("jen/services/kea_tls.py", "_cn", "(OSError, ValueError)", 'return ""'): (
        "a label for a log line and a sentence; nothing is decided from it"
    ),
    ("jen/services/kea_tls.py", "_san_for", "ValueError", "pass"): (
        "a candidate that is not an IP literal is tried as a DNS name next; a name neither can carry gets no SAN, and `verifier_accepts_name` and the setup's wall refuse it before anything is issued"
    ),
    ("jen/services/kea_tls.py", "_san_for", "ValueError", "return None"): (
        "a name no certificate can carry gets NO SAN: the callers read None as 'not a name' (`verifier_accepts_name` says no; a leaf with no names is refused wherever a role is judged - Q202 AR2)"
    ),
    (
        "jen/services/kea_tls.py",
        "verifier_accepts_name",
        "(ValueError, TypeError, UnsupportedAlgorithm)",
        "return False",
    ): (
        "a name the verifier cannot build for is NOT accepted: the setup and the rotation refuse it with the name sentence"
    ),
    ("jen/services/kea_tls.py", "_is_ip", "ValueError", "return False"): (
        "'not an IP literal': the setup's form refuses it and `issue_server_cert` raises (Q202 AR9 c)"
    ),
    ("jen/services/kea_tls.py", "_material", "(OSError, ValueError, TypeError, UnsupportedAlgorithm)", "return None"): (
        "None is 'no payload': a pair that does not load or does not belong together is NEVER put on a host"
    ),
    (
        "jen/services/kea_tls.py",
        "fingerprint",
        "(OSError, ValueError, TypeError, UnsupportedAlgorithm)",
        "return None",
    ): (
        "no fingerprint is never 'the same one': callers read None as not identical or unknown (the reconcile then finishes a note from the files, which errs toward attention)"
    ),
    ("jen/services/kea_tls.py", "presented_fingerprint", "(OSError, ssl.SSLError, ValueError)", "return None"): (
        "the listener's certificate could not be read: a setup is NOT reported as completed on it (Q188 AD2)"
    ),
    ("jen/services/kea_tls.py", "_open_incident_categories", "Exception", "return None"): (
        "None is logged and `host_material` answers UNKNOWN: Jen then does not claim to know which pair the host holds (the same fail-closed reading the strict read already gives)"
    ),
    (
        "jen/services/kea_tls.py",
        "trust_bundle",
        "(OSError, ValueError, TypeError, UnsupportedAlgorithm)",
        "return None",
    ): (
        "None is 'Jen cannot read the CA bundle': the rotation inventory refuses the endpoints whose CA it cannot tell (Q190 AF1)"
    ),
    (
        "jen/services/kea_tls.py",
        "_certificate_names",
        "(x509.ExtensionNotFound, x509.DuplicateExtension, ValueError)",
        "return []",
    ): (
        "a certificate that names nothing proves nothing: every role judgment REFUSES it when there is a name to compare (Q202 AR2)"
    ),
    ("jen/services/kea_tls.py", "_known_again", "FileNotFoundError", "pass"): (
        "the marker being absent is the state the call wants"
    ),
    ("jen/services/kea_tls.py", "_ip_address_or_none", "ValueError", "return None"): (
        "a name that is not an IP address is compared as a DNS name (equal A-labels), never as an address, and two names are the same place only when they are identical or equal under that comparison: an unparsable literal matches nothing but itself (Q204 AT5)"
    ),
    ("jen/services/kea_tls.py", "trust_kind", "(OSError, ValueError, TypeError, UnsupportedAlgorithm)", "pass"): (
        "a bundle that does not load falls through to 'unreadable', which the rotation inventory refuses"
    ),
    ("jen/services/kea_tls.py", "_group_certificate.loaded", "(OSError, ValueError)", "return None"): (
        "a certificate that does not load is no evidence: `record_group_refusal` refuses a group with files and none, and `record_destination_refusal` leaves that to it (Q201 AQ2)"
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


# ── S11b (Q186, AB2): a socket's own entry never reaches text ───────────────────────────────────────────────────────────────────────────────────
# A control-sockets entry carries a Basic client's password and TLS file paths. beta.16's by-hand recovery sentence printed the raw removed entry into a flash and an audit row (LEAK-001's family,
# but the object was never an exception). `describe_socket(entry)` is the only way a socket enters a sentence: type, address and port.
_S11B_NAMES = re.compile(
    r"^(snapshot|snapshots|removed|removed_sockets?|api_sockets?|existing_api|control_sockets?|sockets|api|named|kept)$"
)
_S11B_ENTRY = (
    "entry"  # a socket entry in the file that builds one; in the other routes an `entry` is a plugin's or a subnet's
)
_S11B_SINKS = {"flash", "audit", "debug", "info", "warning", "error", "exception", "critical", "print", "log"}
_S11B_FORMATTERS = {"str", "repr", "format", "dumps", "pformat"}
_S11B_SAFE = {"describe_socket", "len", "bool", "isinstance"}


def s11b_sites(source: str, rel: str) -> list[tuple[str, int, str]]:
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]

    def callee(call):
        f = call.func
        return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")

    def risky_names(node):
        """Names in `node` that look like a socket entry and are not under a describe_socket()/len() call."""
        found = []
        for sub in ast.walk(node):
            if isinstance(sub, ast.Name) and (
                _S11B_NAMES.search(sub.id) or (sub.id == _S11B_ENTRY and rel.endswith("settings/infrastructure.py"))
            ):
                cur, safe = getattr(sub, "parent", None), False
                while cur is not None and cur is not node.parent:
                    if isinstance(cur, ast.Call) and callee(cur) in _S11B_SAFE:
                        safe = True
                        break
                    cur = getattr(cur, "parent", None)
                if not safe:
                    found.append(sub.id)
        return found

    sites = []
    for node in ast.walk(tree):
        text_exprs = []
        if isinstance(node, ast.FormattedValue):
            text_exprs.append(node.value)
        elif isinstance(node, ast.Call) and callee(node) in _S11B_FORMATTERS:
            text_exprs += list(node.args)
        elif isinstance(node, ast.Call) and callee(node) in _S11B_SINKS:
            text_exprs += list(node.args) + [k.value for k in node.keywords]
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            text_exprs.append(node.right)
        for expr in text_exprs:
            for name in risky_names(expr):
                sites.append((rel, getattr(expr, "lineno", getattr(node, "lineno", 0)), name))
    return sorted(set(sites))


class TestS11bASocketEntryNeverReachesText:
    def test_no_route_prints_a_socket_entry(self):
        found = []
        for path in sorted((ROOT / "jen" / "routes").rglob("*.py")):
            found += s11b_sites(path.read_text(encoding="utf-8"), path.relative_to(ROOT).as_posix())
        assert found == [], (
            "a control-socket entry (it holds a Basic client's password and TLS paths) reaches an f-string, str(), a flash, an audit row or a log call: "
            f"name it with kea_config_edit.describe_socket(entry) instead: {found}"
        )

    def test_the_detector_finds_what_it_is_for(self):
        src = (
            "def a(removed_sockets):\n flash(f'by hand: {removed_sockets[0]}')\n"
            "def b(entry):\n __user.audit('X', 'y', str(entry))\n"
            "def c(snapshot):\n logger.warning('socket %s', snapshot)\n"
            "def d(entry):\n flash(f'ok {describe_socket(entry)}')\n"
            "def e(entry):\n msg = 'n=%d' % len(entry)\n"
            "def f(socket_url):\n flash(f'{socket_url}')\n"
        )
        assert [(line, name) for _r, line, name in s11b_sites(src, "jen/routes/settings/infrastructure.py")] == [
            (2, "removed_sockets"),
            (4, "entry"),
            (6, "snapshot"),
        ]


# ── S14: an address is shown by ONE helper; a URL never carries a password (Q190, AF2; LEAK-001, CRED-005) ─────────────────────────────────────────

S14_ALLOWED: dict = {}  # the reviewed list is EMPTY: a route shows an address through `auth.shown_url`, always
_S14_SINKS = {"flash", "audit", "_record_incident", "record_attention"}
_S14_LOG_METHODS = {"debug", "info", "warning", "error", "exception", "critical"}
_S14_SAFE_CALLEES = {
    "shown_url",
    "_shown",  # jen/services/kea.py's one-line wrapper of `auth.shown_url`
    "scrub_urls",
    "host_of",
    "len",
    "bool",
    "userinfo_sentence",
    "dns_name_sentence",  # a fixed sentence about the host, never the address (Q197, AM2)
    "url_refusal_sentence",  # which PART of an address is wrong, in fixed sentences that never echo it (Q199, AO4)
}  # what turns an address into something that cannot carry user-info


def s14_sites(source: str, rel: str) -> list[tuple[str, int, str]]:
    """Every place a name that holds an address (`url`, `api_url`, `new_url`, `x['url']`, `x.api_url`, `.get('url')`) reaches the text of a `flash(`, an audit row, a log call or
    `_record_incident(` without going through `shown_url` - directly, or through a name assigned from such an expression in the same function (`msg = f"... {url}"; flash(msg)`)."""
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]

    def callee(call):
        f = call.func
        return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")

    def is_sink(call):
        name = callee(call)
        if name in _S14_SINKS:
            return True
        f = call.func
        return (
            name in _S14_LOG_METHODS
            and isinstance(f, ast.Attribute)
            and isinstance(f.value, ast.Name)
            and "log" in f.value.id.lower()
        )

    valued_now: set = (
        set()
    )  # the function being scanned: names assigned from a place that holds an address (filled below)

    def unsafe(expr, include_valued=False):
        """The address-holding sub-expressions of `expr` that are not under a safe callee. `include_valued` (the chain `now = <address setting>; msg = f"... {now}"; flash(msg)`, second pass of Q191) also
        counts a name read from an address setting."""
        out = []
        for sub in ast.walk(expr):
            holder = None
            if isinstance(sub, ast.Name):
                holder = sub.id
                if include_valued and sub.id in valued_now:
                    out.append((sub, holder))
                    continue
            elif isinstance(sub, ast.Attribute):
                holder = sub.attr
            elif (
                isinstance(sub, ast.Subscript)
                and isinstance(sub.slice, ast.Constant)
                and isinstance(sub.slice.value, str)
            ):
                holder = sub.slice.value
            elif (
                isinstance(sub, ast.Call)
                and callee(sub) == "get"
                and sub.args
                and isinstance(sub.args[0], ast.Constant)
                and isinstance(sub.args[0].value, str)
            ):
                holder = sub.args[0].value
            if not holder or not holder.lower().endswith("url"):
                continue
            cur, safe = sub, False
            while cur is not expr and getattr(cur, "parent", None) is not None:
                cur = cur.parent
                if isinstance(cur, ast.Call) and callee(cur) in _S14_SAFE_CALLEES:
                    safe = True
                    break
            if not safe:
                out.append((sub, holder))
        return out

    def builds_text(expr, hits):
        """Is any of `hits` (address-holding sub-expressions of `expr`) put into TEXT by `expr` - an f-string, `%`, `+`, `.format` - rather than handed to a call that answers something else
        (`valid_api_url(url)` answers a bool and builds no text)?"""
        for sub, _holder in hits:
            cur = sub
            text = sub is expr  # a plain copy (`msg = now`) carries the address as it is
            while cur is not expr and getattr(cur, "parent", None) is not None:
                cur = cur.parent
                if isinstance(cur, (ast.JoinedStr, ast.BinOp)):
                    text = True  # (second pass of Q191: a bare mention in a `bool` / comparison / comprehension builds no text - `twins = [... if _socket_now and same_endpoint(...)]` is not a sentence)
                if isinstance(cur, ast.Call) and callee(cur) not in {"str", "repr", "format", "join"}:
                    text = False
                    break
            if text:
                return True
        return False

    def url_valued(value):
        """Is `value` ITSELF an address READ from a place that holds one - `<anything>.get(<sec>, <key>)` / `.get(<key>)` whose key is (or is named) something with `url` in it, or a
        `urlparse`/`urlsplit` result's `geturl()`, possibly behind `.strip()` / `.rstrip(...)`, `x if c else y` or `a or b`? (Q191, AG2: the name grammar missed
        `_socket_now = _live.get(_sec, _url_key, ...)` - an address is an address whatever the variable is called. A sentence BUILT from an address by a function is not one.)"""
        if isinstance(value, ast.IfExp):
            return url_valued(value.body) or url_valued(value.orelse)
        if isinstance(value, ast.BoolOp):
            return any(url_valued(v) for v in value.values)
        if not isinstance(value, ast.Call):
            return False
        name = callee(value)
        if name == "geturl":
            return True
        if name == "get":
            for a in value.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, str) and "url" in a.value.lower():
                    return True
                if isinstance(a, ast.Name) and "url" in a.id.lower():
                    return True
        if isinstance(value.func, ast.Attribute):
            return url_valued(value.func.value)  # a chain: .get(...).strip()
        return False

    sites = []
    for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))] + [tree]:
        tainted = set()
        valued = set()  # names assigned (anywhere in the function) from a place that holds an address
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and url_valued(node.value):
                valued |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        valued_now.clear()
        valued_now.update(valued)
        for node in ast.walk(fn):
            if isinstance(node, (ast.Assign, ast.AugAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                carried = isinstance(node.value, (ast.JoinedStr, ast.BinOp)) and any(
                    isinstance(s, ast.Name) and s.id in tainted for s in ast.walk(node.value)
                )
                if builds_text(node.value, unsafe(node.value, include_valued=True)) or carried:
                    tainted |= {t.id for t in targets if isinstance(t, ast.Name)}
        for node in ast.walk(fn):
            if isinstance(node, ast.Call) and is_sink(node):
                for arg in list(node.args) + [k.value for k in node.keywords]:
                    for sub, holder in unsafe(arg):
                        sites.append((rel, sub.lineno, holder))
                    for sub in ast.walk(arg):
                        if isinstance(sub, ast.Name) and sub.id in valued and sub.id not in tainted:
                            cur, safe = sub, False
                            while cur is not arg and getattr(cur, "parent", None) is not None:
                                cur = cur.parent
                                if isinstance(cur, ast.Call) and callee(cur) in _S14_SAFE_CALLEES:
                                    safe = True
                                    break
                            if not safe and builds_text(arg, [(sub, sub.id)]):
                                sites.append((rel, sub.lineno, sub.id + " (read from an address setting)"))
                        if isinstance(sub, ast.Name) and sub.id in tainted:
                            cur, safe = sub, False
                            while cur is not arg and getattr(cur, "parent", None) is not None:
                                cur = cur.parent
                                if isinstance(cur, ast.Call) and callee(cur) in _S14_SAFE_CALLEES:
                                    safe = True
                                    break
                            if not safe:
                                sites.append((rel, sub.lineno, sub.id + " (built from an address)"))
    return sorted(set(sites))


class TestS14AnAddressIsShownByOneHelper:
    def test_no_route_puts_an_address_into_text_without_shown_url(self):
        found = []
        for path in sorted((ROOT / "jen" / "routes").rglob("*.py")):
            rel = path.relative_to(ROOT).as_posix()
            found += [s for s in s14_sites(path.read_text(encoding="utf-8"), rel) if (s[0], s[2]) not in S14_ALLOWED]
        assert found == [], (
            "an address reaches a flash, an audit row, a log line or an incident without `auth.shown_url` - a URL typed with user-info would print its password "
            f"(CRED-005 / LEAK-001): {found}"
        )

    def test_the_sweep_refuses_a_planted_fstring(self):
        """The sweep's own test: it breaks the rule on purpose and sees it refused - directly, through a message variable, in an audit row and a log line - and passes the safe shapes."""
        planted = (
            "def a(new_url):\n flash(f'it is at {new_url}', 'error')\n"
            "def b(api_url):\n msg = f'failed: {api_url}'\n flash(msg)\n"
            "def c(srv):\n __user.audit('X', 'y', f\"url={srv['api_url']}\")\n"
            "def d(url):\n logger.warning('x %s', url)\n"
            "def e(new_url):\n flash(f'ok {__auth.shown_url(new_url)}')\n"
            "def f(endpoint):\n flash(f'host {__credentials.host_of(endpoint.url)}')\n"
            "def g(dns_url):\n r = req.get(f'{dns_url}/api')\n"
            "def h(url):\n _record_incident(1, 's', f'at {url}', 'x')\n"
            "def i(_live, _sec, _url_key):\n _socket_now = _live.get(_sec, _url_key, fallback='').strip()\n flash(f'uses this same socket ({_socket_now})', 'error')\n"
            "def j(request):\n typed = request.form.get('ca_url')\n flash(f'at {typed}')\n"
            "def k(_live, _sec, _url_key):\n _now = _live.get(_sec, _url_key, fallback='')\n flash(f'at {__auth.shown_url(_now)}', 'error')\n"
            "def m(cfg):\n port = cfg.get('kea', 'port')\n flash(f'on {port}')\n"
            "def n(_live, _sec, _url_key):\n now = _live.get(_sec, _url_key, fallback='')\n msg = f'uses {now}'\n flash(msg)\n"
        )
        got = [(line, name) for _r, line, name in s14_sites(planted, "jen/routes/x.py")]
        assert got == [
            (2, "new_url"),
            (5, "msg (built from an address)"),
            (7, "api_url"),
            (9, "url"),
            (17, "url"),
            # Q191 (AG2): provenance, not the name - i is the shape beta.21 shipped at the Remove form's twin refusals, j a typed address; k (through shown_url) and m (a setting that is not an address) pass
            (20, "_socket_now (read from an address setting)"),
            (23, "typed (built from an address)"),  # (the form key names `url`: the older grammar sees this one too)
            (
                33,
                "msg (built from an address)",
            ),  # n: the chain `now = <address setting>; msg = f"uses {now}"; flash(msg)` (second pass of Q191)
        ], got


# ── S13: whose CA a trust path is, is decided by certificate identity - never by comparing the path (Q190, AF1; REMOTE-001) ───────────────────────

#: (file, function): the ONE place a trust path is interpreted. `trust_kind` is allowed to say whether a path is Jen's own file because it has ALREADY judged the certificates in it.
S13_ALLOWED = {("jen/services/kea_tls.py", "trust_kind"), ("jen/services/kea_tls.py", "client_kind")}
#: the settings an identity is made of (Q191, AG1: Jen's identity to a daemon is its CA bundle AND its client pair) - the globals and the config keys
_S13_NAMES = {"KEA_API_CA", "KEA_API_CLIENT_CERT", "KEA_API_CLIENT_KEY"}
_S13_KEYS = {"api_ca", "api_client_cert", "api_client_key"}
_S13_PATH_FUNCS = {"normpath", "realpath", "abspath", "samefile", "commonpath", "relpath", "expanduser", "resolve"}


def s13_sites(source: str, rel: str) -> list[tuple[str, int, str]]:
    """Every comparison of `[kea] api_ca` (`KEA_API_CA`, or a name assigned from it) with something that is not a constant, and every path function applied to it, outside the reviewed list."""
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]
    parents = _parents(tree)

    def mentions(expr, tainted):
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Name) and (sub.id in _S13_NAMES or sub.id in tainted):
                return True
            if isinstance(sub, ast.Attribute) and sub.attr in _S13_NAMES:
                return True
            if isinstance(sub, ast.Constant) and sub.value in (_S13_NAMES | _S13_KEYS):
                return True  # (the config key too: `cfg.get("kea", "api_ca") != ca_crt` is the same comparison - second pass of Q190)
        return False

    def derived(expr, tainted):
        """Is `expr` the bundle path itself (or the path with a `.strip()` / `or` / `getattr` around it) - not a dict, a sentence or a comparison that merely mentions it?"""
        if isinstance(expr, ast.Name):
            return expr.id in _S13_NAMES or expr.id in tainted
        if isinstance(expr, ast.Attribute):
            return expr.attr in _S13_NAMES or derived(expr.value, tainted)
        if isinstance(expr, ast.BoolOp):
            return any(derived(v, tainted) for v in expr.values)
        if isinstance(expr, ast.IfExp):
            return derived(expr.body, tainted) or derived(expr.orelse, tainted)
        if isinstance(expr, ast.Call):
            f = expr.func
            if isinstance(f, ast.Name) and f.id == "getattr":
                return any(isinstance(a, ast.Constant) and a.value in _S13_NAMES for a in expr.args)
            if any(isinstance(a, ast.Constant) and a.value in _S13_KEYS for a in expr.args):
                return True  # cfg.get("kea", "api_ca", fallback="") - and the client pair's keys
            return derived(f, tainted) or any(derived(a, tainted) for a in expr.args)
        return False

    def own(scope):
        """The nodes of one scope: a function's whole body, but for the module only what is NOT inside a function or class (their names are theirs - a `cert` in one function is not the `cert` in another)."""
        if not isinstance(scope, ast.Module):
            yield from ast.walk(scope)
            return
        stack = [scope]
        while stack:
            n = stack.pop()
            yield n
            stack.extend(
                c
                for c in ast.iter_child_nodes(n)
                if not isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            )

    sites = []
    scopes = [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))] + [tree]
    for scope in scopes:
        tainted: set = set()
        for node in own(scope):
            if isinstance(node, ast.Assign) and derived(node.value, tainted):
                tainted |= {t.id for t in node.targets if isinstance(t, ast.Name)}
        for node in own(scope):
            hit = None
            if isinstance(node, ast.Compare) and any(
                isinstance(op, (ast.Eq, ast.NotEq, ast.Is, ast.IsNot, ast.In, ast.NotIn)) for op in node.ops
            ):
                operands = [node.left, *node.comparators]
                if any(mentions(o, tainted) for o in operands) and any(
                    not isinstance(o, ast.Constant) and not mentions(o, tainted) for o in operands
                ):
                    hit = "comparison"
            elif isinstance(node, ast.Call):
                f = node.func
                name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                if name in _S13_PATH_FUNCS and any(mentions(a, tainted) for a in list(node.args) + [f]):
                    hit = name
            if hit:
                fn = _enclosing_function(node, parents)
                if (rel, fn.split(".")[-1]) not in S13_ALLOWED:
                    sites.append((rel, node.lineno, hit))
    return sorted(set(sites))


class TestS13ATrustPathIsNeverComparedAsAString:
    def test_no_module_compares_the_ca_bundle_path(self):
        found = []
        for path in _py_files():
            if path.suffix == ".py" and "jen" in path.parts:
                found += s13_sites(path.read_text(encoding="utf-8"), path.relative_to(ROOT).as_posix())
        assert found == [], (
            "a module compares `[kea] api_ca` as a path (or normalises it): a symlink, a copy or a bundle of Jen's own CA is 'not Jen's', and Rotate leaves every Jen-issued endpoint behind "
            f"(Q190, AF1). Ask `kea_tls.trust_includes_jens_ca()` / `trust_kind()` instead: {found}"
        )

    def test_the_sweep_refuses_the_pattern_that_shipped_in_beta20(self):
        planted = (
            "def _trust_is_jens():\n"
            "    configured = getattr(extensions, 'KEA_API_CA', '') or ''\n"
            "    return bool(configured) and os.path.normpath(configured) == os.path.normpath(ca_paths()[0])\n"
            "def page(ca_crt):\n"
            "    return {'external_ca': bool(extensions.KEA_API_CA) and ca_crt != extensions.KEA_API_CA}\n"
            "def fine():\n"
            "    return bool(extensions.KEA_API_CA) and extensions.KEA_API_CA != ''\n"
            "def writer(cfg, ca_crt):\n"
            "    if cfg.get('kea', 'api_ca', fallback='') != ca_crt:\n"
            "        pass\n"
            "def gate(jen_client_cert):\n"
            "    if extensions.KEA_API_CLIENT_CERT and jen_client_cert != extensions.KEA_API_CLIENT_CERT:\n"
            "        pass\n"
            "def spelled(cfg, mine):\n"
            "    return os.path.realpath(cfg.get('kea', 'api_client_key', fallback='')) == mine\n"
        )
        got = [(line, what) for _r, line, what in s13_sites(planted, "jen/routes/x.py")]
        assert got == [
            (3, "comparison"),
            (3, "normpath"),
            (5, "comparison"),
            (9, "comparison"),
            (12, "comparison"),
            (15, "comparison"),
            (15, "realpath"),
        ], got  # (the last two functions are the client pair: Q191, AG1)


# ── S14b: the same rule for the SERVICES that build the text a route shows (Q190, second pass; LEAK-001, CRED-005) ───────────────────────────────

#: (file, holder): an f-string over an address that is NOT text a person reads, with the reason. Everything else in jen/services/ shows an address through `shown_url`.
S14B_ALLOWED = {
    (
        "jen/services/alerts.py",
        "url",
    ): "the request target of a webhook the operator configured (`f'{url}/{topic}'`), never shown",
    (
        "jen/services/plugins.py",
        "download_url",
    ): "the request target of a plugin download (`f'{download_url}/plugin.zip'`), never shown",
}


def s14b_sites(source: str, rel: str) -> list[tuple[str, int, str]]:
    """Every f-string that formats a name holding an address (`url`, `api_url`, `x['url']`, `x.url`) without `shown_url` / `scrub_urls` / `host_of` around it - in a SERVICE module, where the
    text is returned to a route (`{"text": f"Cannot connect to Kea API at {url}"}`) and no sink call names it."""
    tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore[attr-defined]

    def callee(call):
        f = call.func
        return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")

    sites = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        for sub in ast.walk(node):
            holder = None
            if isinstance(sub, ast.Name):
                holder = sub.id
            elif isinstance(sub, ast.Attribute):
                holder = sub.attr
            elif (
                isinstance(sub, ast.Subscript)
                and isinstance(sub.slice, ast.Constant)
                and isinstance(sub.slice.value, str)
            ):
                holder = sub.slice.value
            if not holder or not holder.lower().endswith("url"):
                continue
            cur, safe = sub, False
            while cur is not node and getattr(cur, "parent", None) is not None:
                cur = cur.parent
                if isinstance(cur, ast.Call) and callee(cur) in _S14_SAFE_CALLEES:
                    safe = True
                    break
            if not safe:
                sites.append((rel, sub.lineno, holder))
    return sorted(set(sites))


class TestS14bAServiceShowsAnAddressByTheHelperToo:
    def test_no_service_formats_an_address_without_shown_url(self):
        found = []
        for path in sorted((ROOT / "jen" / "services").rglob("*.py")):
            rel = path.relative_to(ROOT).as_posix()
            if rel == "jen/services/auth.py":
                continue  # the helper's own home
            found += [s for s in s14b_sites(path.read_text(encoding="utf-8"), rel) if (s[0], s[2]) not in S14B_ALLOWED]
        assert found == [], (
            "a service formats an address into text without `auth.shown_url` - a legacy URL with user-info would print its password (CRED-005 / LEAK-001, second pass of Q190): "
            f"{found}"
        )

    def test_the_sweep_refuses_the_pattern_that_shipped_in_the_first_pass(self):
        planted = (
            "def a(url):\n return {'text': f'Cannot connect to Kea API at {url}'}\n"
            "def b(srv):\n return f\"at {srv['api_url']}\"\n"
            "def c(url):\n return f'at {shown_url(url)} and {host_of(url)}'\n"
        )
        got = [(line, name) for _r, line, name in s14b_sites(planted, "jen/services/x.py")]
        assert got == [(2, "url"), (4, "api_url")], got

    def test_the_reviewed_list_names_sites_that_still_exist(self):
        for (rel, holder), _why in S14B_ALLOWED.items():
            assert holder in (ROOT / rel).read_text(encoding="utf-8"), f"{rel} no longer formats {holder}: remove it"


# ── S15: Jen's CA is read through `ca_state` - no caller loads the two files independently (Q192, AH2; REMOTE-001) ──────────────────────────────────

#: the functions of kea_tls that may name `ca_paths()` AND `load_key(` together: the one definition (`ca_state`), the signer (`_load_ca`, which asks `ca_state` first), the pair check, and the
#: three that read the CA CERTIFICATE only for a comparison and load a LEAF's key (`_material`, `client_state`, `client_kind`).
S15_ALLOWED = {
    "ca_state",
    "_load_ca",
    "ca_consistent",
    "_material",
    "client_state",
    "client_kind",
    "_ca_material_for_opinion",  # Q196: the second opinion reads a CA the verifier has judged DAMAGED - it is about exactly that case
}


def s15_sites(source: str) -> list[str]:
    tree = ast.parse(source)
    found = []
    for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
        names = {
            (c.func.id if isinstance(c.func, ast.Name) else getattr(c.func, "attr", ""))
            for c in ast.walk(fn)
            if isinstance(c, ast.Call)
        }
        if "ca_paths" in names and "load_key" in names and fn.name not in S15_ALLOWED:
            found.append(fn.name)
    return sorted(found)


class TestS15TheCaIsReadThroughCaState:
    def test_ca_present_is_gone_and_no_new_function_loads_the_ca_files_by_itself(self):
        for path in _py_files():
            if path.suffix == ".py" and "jen" in path.parts:
                text = path.read_text(encoding="utf-8")
                assert "ca_present" not in text, (
                    f"{path.name} still names `ca_present` (deleted in Q192: ask `ca_state`)"
                )
        assert s15_sites((ROOT / "jen" / "services" / "kea_tls.py").read_text(encoding="utf-8")) == []

    def test_the_sweep_refuses_a_function_that_loads_the_two_files_independently(self):
        planted = (
            "def ca_present():\n    crt, key = ca_paths()\n    load_cert(crt)\n    load_key(key)\n    return True\n"
            "def ok(path):\n    return load_key(path)\n"
        )
        assert s15_sites(planted) == ["ca_present"]


# ── S16: the subnets THEMSELVES are scoped (Q204, RBAC-005) ──────────────────────────────────────────────────────────────────────────────────────────────────────────
# A subnet's id, name, CIDR and counts are shown to an account only for the subnets it may see. Q156 applied the definition to the About page (`current_user.filter_subnet_map`) and four more readers
# had not asked it (Compare Leases, three Health checks, the drift route, the metrics token) - Opus's M1-M4. This is the sweep that asks it of EVERY read of the map: every `extensions.SUBNET_MAP` /
# `SUBNET6_MAP` read (iteration, `.items()`, `.keys()`, `.values()`, `.get`, a subscript, a membership test, a `len`) in a function under `jen/` or `plugins/` is in a function that scopes it - it
# mentions one of the names below - or the function is on the reviewed list with the reason. The reasons are the 140-use classification of the Q204 report: the accepted SHAPES are
#   (a) a WRITE route or its helper that looks a subnet up by the id it was given and then asserts access (`assert_subnet_access` / `can_access_subnet` in the same function), the common one;
#   (b) a route that requires every subnet (`all_subnets`) or is a superadmin's - a whole-config surface (docs/ARCHITECTURE.md §2) - and the helper only such routes call;
#   (c) a background loop with no principal (alerts, snapshots, the drift alert), whose delivery is the channel's own scope;
#   (d) the definition (`extensions`, `config.apply`, the `access` helpers) and a lookup by an id the caller already holds.
S16_SCOPERS = (
    "filter_subnet_map",
    "get_accessible_subnet_map",
    "can_access_subnet",
    "assert_subnet_access",
    "assert_subnet6_access",
    "add_subnet_restriction",
    "accessible_subnet_ids",
    "accessible_subnet6_map",
    "subnet_filter",
    "all_subnets",
    "unrestricted",
    "_api_key_subnet_ids",
    "_api_scope_allows",
    "filter_subnet_ids",
)
S16_MAPS = ("SUBNET_MAP", "SUBNET6_MAP")

S16_REVIEWED = {
    ("jen/routes/dashboard.py", "prometheus_metrics"): (
        "a scrape endpoint has no user: it is authorised by the metrics token or the open flag and emits every subnet by design; who may HOLD the token or set the flag is the scope (Q204 AT1 d: the metrics card and "
        "`save_metrics_settings` need `all_subnets`), pinned by tests/test_authz_matrix.py::TestTheBranchesRun"
    ),
    ("jen/routes/reservations.py", "_address_outside_subnet"): (
        "a lookup by the subnet id the write route was given; both callers (`add_reservation_post`, `import_reservations`) assert the caller's access to that id first (shape a)"
    ),
    ("jen/routes/settings/authoring.py", "_author_kea_subnets_and_db"): (
        "the starter-config builder of Author Kea Config, a superadmin's whole-config surface (`author_kea_config*` carry `_superadmin_required`, shape b)"
    ),
    ("jen/routes/subnets.py", "_finish_windows_import"): (
        "the last step of the superadmin's import wizard, which writes the whole subnet map it just built (shape b)"
    ),
    ("jen/routes/subnets.py", "_class_scope_rows"): (
        "the 'Applies to' checklist of the class editor, a whole-config surface: its one caller `dhcp_class_edit_page` returns before it unless `_classes_check_access()` (`all_subnets`) holds (shape b)"
    ),
    ("jen/routes/subnets.py", "_suggested_subnet_names"): (
        "the import wizard's name suggestions for the plan being imported, a superadmin's route (shape b)"
    ),
    ("jen/routes/users.py", "users"): (
        "the user administration page lists the subnets an access list can name; `@_superadmin_required` (shape b)"
    ),
    (
        "jen/services/access.py",
        "paired_v4_id",
    ): "the definition of the v4/v6 pairing the scoping helpers read (shape d)",
    ("jen/services/alerts.py", "check_pool_forecast_alerts"): (
        "the background alert loop: no principal, an alert goes to a channel whose own subnet scope is applied at delivery (shape c)"
    ),
    ("jen/services/alerts.py", "take_lease6_snapshot"): "the background snapshot job, no principal (shape c)",
    ("jen/services/alerts.py", "check_utilization_alerts"): "the background alert loop, no principal (shape c)",
    ("jen/services/alerts.py", "_end_states_of_departed_subnets"): "the background alert loop, no principal (shape c)",
    (
        "jen/services/alerts.py",
        "_build_daily_summary",
    ): "the daily summary goes to a channel, whose subnet scope is applied at delivery (shape c)",
    ("jen/services/alerts.py", "take_lease_snapshot"): "the background snapshot job, no principal (shape c)",
    ("jen/services/alerts.py", "check_alerts"): "the background alert loop, no principal (shape c)",
    ("jen/services/config_drift.py", "check_config_drift"): (
        "one of the four readers Q204 names: reached only through `check_config_drift_route` (needs `all_subnets`), the Health check `_kea_config_drift` (skips for a restricted ctx), the background drift alert "
        "and the superadmin's support bundle (shape b/c)"
    ),
    ("jen/services/health.py", "_subnet_label"): (
        "a label for a subnet id a capacity check already filtered by `ctx['subnet_filter']` (`pool_exhaustion`, `pool_exhaustion_forecast`) (shape d)"
    ),
    ("jen/services/kea6.py", "count_lease6_by_subnet"): (
        "an aggregate counter whose one caller is the background snapshot job; its `subnet_ids` argument is how a scoped caller would narrow it (shape c)"
    ),
    (
        "jen/services/kea6.py",
        "count_reservations6_by_subnet",
    ): "an aggregate counter beside `count_lease6_by_subnet`: the same one caller, the background snapshot job (shape c)",
    ("jen/services/setup_wizard.py", "discover"): "the first-run setup wizard, a superadmin's (shape b)",
    ("jen/services/setup_wizard.py", "save_subnets"): "the first-run setup wizard, a superadmin's (shape b)",
    ("jen/services/setup_wizard.py", "probe_v6"): "the first-run setup wizard, a superadmin's (shape b)",
    ("jen/services/setup_wizard.py", "enable_v6"): "the first-run setup wizard, a superadmin's (shape b)",
    (
        "jen/services/setup_wizard.py",
        "kea_connected",
    ): "the first-run setup wizard's progress check, a superadmin's (shape b)",
    ("jen/services/subnet_context.py", "subnet_context"): (
        "a lookup by the id the caller holds: the two plugin callers (ipam, network-discovery) reach it through `plugin_helpers.subnet_or_404`, which asserts access (shape d)"
    ),
    (
        "jen/services/support_bundle.py",
        "_collect_lease_history",
    ): "the support bundle is a superadmin's download (shape b)",
}


def s16_reads(source, rel="<test>"):
    """[(module, outermost function, line)] for every READ of SUBNET_MAP / SUBNET6_MAP in `source` that is not in a function mentioning a scoping name."""
    tree = ast.parse(source)
    parents = _parents(tree)
    out = []
    for node in ast.walk(tree):
        name = node.attr if isinstance(node, ast.Attribute) else node.id if isinstance(node, ast.Name) else None
        if name not in S16_MAPS or isinstance(getattr(node, "ctx", None), ast.Store):
            continue
        outer, cur = None, node
        while cur in parents:
            cur = parents[cur]
            if isinstance(cur, ast.FunctionDef | ast.AsyncFunctionDef):
                outer = cur
        body = ast.unparse(outer) if outer is not None else ""
        if any(s in body for s in S16_SCOPERS):
            continue
        out.append((rel, outer.name if outer is not None else "<module>", node.lineno))
    return out


def _s16_files():
    return [p for sub in ("jen", "plugins") for p in sorted((ROOT / sub).rglob("*.py")) if "__pycache__" not in p.parts]


class TestS16TheSubnetsThemselvesAreScoped:
    #: the modules that DEFINE the map or are its single writer: a Store, not a read
    DEFINITION = ("jen/extensions.py", "jen/config.py")

    def _all(self):
        found = []
        for path in _s16_files():
            rel = path.relative_to(ROOT).as_posix()
            if rel in self.DEFINITION:
                continue
            found += s16_reads(path.read_text(encoding="utf-8"), rel)
        return found

    def test_every_read_is_scoped_or_reviewed(self):
        new = [f"{rel}:{line} {fn}" for rel, fn, line in self._all() if (rel, fn) not in S16_REVIEWED]
        assert not new, (
            "a read of SUBNET_MAP / SUBNET6_MAP in a function that asks no scoping question (RBAC-005): a subnet's name, CIDR and counts are shown only for the subnets the caller may see. Scope it "
            "(`current_user.filter_subnet_map`, `can_access_subnet`, `assert_subnet_access`, `add_subnet_restriction`) or add the function to S16_REVIEWED with the reason:\n  "
            + "\n  ".join(new)
        )

    def test_the_reviewed_list_names_no_function_that_is_gone_or_now_scoped(self):
        present = {(rel, fn) for rel, fn, _line in self._all()}
        stale = sorted(set(S16_REVIEWED) - present)
        assert not stale, f"S16_REVIEWED names functions that no longer read the map unscoped (remove them): {stale}"

    def test_every_reviewed_function_carries_a_real_reason(self):
        for key, reason in S16_REVIEWED.items():
            assert len(reason) > 40 and ("shape" in reason or "scrape" in reason), key

    def test_the_four_readers_Q204_names_are_scoped_or_on_the_list_by_name(self):
        reviewed_names = {fn for (_rel, fn) in S16_REVIEWED}
        assert {"check_config_drift", "prometheus_metrics"} <= reviewed_names
        unscoped = {fn for _rel, fn, _line in self._all()}
        # `compare_assigned` takes `subnet_filter`; `run_checks` hands the filter to every check and the three that name subnets skip - neither reads the map unscoped
        assert "compare_assigned" not in unscoped and "_kea_subnets_declared" not in unscoped
        assert "_kea_config_drift" not in unscoped and "_config_doctor" not in unscoped

    def test_the_sweep_sees_the_reads_it_is_about(self):
        """The scan is not blind: it finds the iteration, `.items()`, `.get`, subscript and membership shapes in an unscoped function."""
        for body in (
            "for k in extensions.SUBNET_MAP: pass",
            "x = extensions.SUBNET_MAP.items()",
            "x = extensions.SUBNET_MAP.get(1)",
            "x = extensions.SUBNET_MAP[1]",
            "x = 1 in extensions.SUBNET_MAP",
            "x = len(extensions.SUBNET_MAP)",
            "x = extensions.SUBNET6_MAP.values()",
        ):
            src = f"@bp.route('/x')\n@login_required\ndef planted():\n    {body}\n"
            assert s16_reads(src, "jen/routes/planted.py") == [("jen/routes/planted.py", "planted", 4)], body

    def test_a_scoped_read_is_not_flagged_and_an_unfiltered_one_planted_in_a_route_is(self):
        scoped = "@bp.route('/x')\ndef r():\n    m = current_user.filter_subnet_map(extensions.SUBNET_MAP)\n"
        assert s16_reads(scoped) == []
        planted = "@bp.route('/x')\n@login_required\ndef r():\n    return jsonify(extensions.SUBNET_MAP)\n"
        assert [fn for _r, fn, _l in s16_reads(planted)] == ["r"]
        # and the scan finds it in a file of the real tree's shape: a new unreviewed route is refused by the main test
        assert ("jen/routes/planted.py", "r") not in S16_REVIEWED
