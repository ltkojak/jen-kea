"""
tests/test_no_root_jen_imports.py
───────────────────────────────────
v5.67.0-beta.7 (Q119, item a) — Fable's audit found verify_install()'s own
template- and module-check snippets called `"$PYBIN" -c "from jen import
create_app; ..."` with no `runuser`, unlike the correct `_seed_jen_db`
step right above them. create_app() -> load_plugins() imports every
enabled plugin out of $CONTENT_DIR/plugins, a directory the SERVICE USER
owns — running that unwrapped, as root, means a compromised service
account that planted a plugin there gets it imported as uid 0 on the
very next install.sh run (upgrade, --unattended, --repair all reach
verify_install()).

The invariant going forward: any inline `"$PYBIN"`/`python3`/`python`
`-c "..."` snippet in install.sh or uninstall.sh whose own source
imports the `jen` package runs through `runuser -u "$JEN_USER"`. This
deliberately does NOT cover `-m module` invocations like `jen.tools.
restore` (run directly by `sudo ./install.sh --restore`, already an
established, separately-reasoned-about root tool that needs real root
for os.chown/systemctl) or `jen-update-root.py` itself (a dedicated,
pure-stdlib root script, never sourced or -c'd) — those are a different,
already-reviewed trust boundary, not an inline snippet newly introduced
by accident.
"""

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parent.parent
INSTALL_SH = (REPO / "install.sh").read_text(encoding="utf-8")
UNINSTALL_SH = (REPO / "uninstall.sh").read_text(encoding="utf-8")
JEN_UPDATE_ROOT_PY = (REPO / "jen-update-root.py").read_text(encoding="utf-8")

# A logical line: physical lines joined where a `\` continuation stitches
# them into one bash statement (exactly how runuser/env/"$PYBIN" -c spans
# three physical lines in the real _seed_jen_db step).
_CONTINUATION = re.compile(r"\\\n[ \t]*")

# The start of an inline `-c "..."` invocation — "$PYBIN" or a literal
# python/python3, followed by -c and an opening double quote. The closing
# quote is on its own line (possibly followed by more bash) in every
# shipped snippet, so the body is collected line-by-line below rather
# than matched with a single multi-line regex (none of these bodies use
# a bare `"` internally — they're all single-quoted python strings).
_INVOCATION_START = re.compile(r'(?:"\$PYBIN"|python3?)\s+-c\s+"\s*$')
# A static `from jen import X` / `import jen.x` statement — used as the
# strict "does this Python source import the jen package" check.
_JEN_IMPORT = re.compile(r"^\s*(?:import jen\b|from jen\b)", re.MULTILINE)
# The module-check snippet imports dynamically — `__import__(m)` where m
# is drawn from a list of string literals like 'jen.extensions' — so
# snippet BODIES (always real Python source, never a config-file-name
# reference the way jen-update-root.py's prose/log strings can be) are
# scanned with this broader pattern instead of the strict one above.
_JEN_IMPORT_OR_DYNAMIC = re.compile(r"^\s*(?:import jen\b|from jen\b)|['\"]jen\.[\w.]+['\"]", re.MULTILINE)


def _inline_c_snippets(source: str):
    """Yields (opening_logical_line, body) for every inline `-c "..."`
    invocation whose opening double quote starts a multi-line block —
    the shape every jen-importing snippet in this codebase actually
    takes. A single-line `-c '...'` (python3 -c 'import sys; ...') never
    matches _INVOCATION_START (its quote closes on the same line), so
    those are correctly never yielded at all."""
    joined = _CONTINUATION.sub(" ", source)
    lines = joined.split("\n")
    i = 0
    while i < len(lines):
        if _INVOCATION_START.search(lines[i]):
            opening = lines[i]
            body_lines = []
            j = i + 1
            while j < len(lines) and not lines[j].lstrip().startswith('"'):
                body_lines.append(lines[j])
                j += 1
            yield opening, "\n".join(body_lines)
            i = j
        else:
            i += 1


class TestScannerFindsTheRealShapes:
    def test_finds_the_two_bugs_fixed_this_q_in_a_hand_built_sample(self):
        sample = """
tpl_result=$(env JEN_ROOT="x" "$PYBIN" -c "
from jen import create_app
app = create_app()
" 2>&1) && tpl_status=0 || tpl_status=$?
"""
        found = list(_inline_c_snippets(sample))
        assert len(found) == 1
        opening, body = found[0]
        assert "runuser" not in opening
        assert _JEN_IMPORT_OR_DYNAMIC.search(body)

    def test_finds_the_dynamic_import_shape_too(self):
        """The real module-check snippet never writes "import jen" as
        literal text — it calls __import__(m) with m drawn from a list of
        string literals like 'jen.extensions'."""
        sample = """
mod_result=$(env JEN_ROOT="x" "$PYBIN" -c "
for m in ['jen.extensions', 'jen.config']:
    __import__(m)
" 2>&1) && mod_status=0 || mod_status=$?
"""
        found = list(_inline_c_snippets(sample))
        assert len(found) == 1
        opening, body = found[0]
        assert "runuser" not in opening
        assert not _JEN_IMPORT.search(body), "this shape never uses a literal import statement"
        assert _JEN_IMPORT_OR_DYNAMIC.search(body)

    def test_finds_the_correct_wrapped_shape_too(self):
        sample = """
out=$(runuser -u "$JEN_USER" -- env \\
    JEN_ROOT="x" \\
    "$PYBIN" -c "
from jen import create_app
create_app()
" 2>&1) || true
"""
        found = list(_inline_c_snippets(sample))
        assert len(found) == 1
        opening, body = found[0]
        assert "runuser" in opening
        assert _JEN_IMPORT_OR_DYNAMIC.search(body)

    def test_ignores_a_single_line_invocation_with_no_jen_import(self):
        sample = """pyver=$(python3 -c 'import sys; print(sys.version_info)')"""
        assert list(_inline_c_snippets(sample)) == []


class TestEveryJenImportingSnippetRunsAsTheServiceUser:
    def _offenders(self, source: str, label: str) -> list[str]:
        offenders = []
        for opening, body in _inline_c_snippets(source):
            if _JEN_IMPORT_OR_DYNAMIC.search(body) and "runuser" not in opening:
                offenders.append(f"{label}: {opening.strip()}")
        return offenders

    def test_install_sh(self):
        offenders = self._offenders(INSTALL_SH, "install.sh")
        assert not offenders, "a jen-importing inline python snippet runs as root, unwrapped:\n" + "\n".join(offenders)

    def test_uninstall_sh(self):
        offenders = self._offenders(UNINSTALL_SH, "uninstall.sh")
        assert not offenders, "a jen-importing inline python snippet runs as root, unwrapped:\n" + "\n".join(offenders)

    def test_at_least_two_wrapped_snippets_exist_in_install_sh(self):
        """A vacuous pass (zero snippets found at all) would be as useless
        as no test — pin that the scanner actually sees the real,
        correctly-wrapped verify_install() checks plus the seed step."""
        wrapped = [
            opening
            for opening, body in _inline_c_snippets(INSTALL_SH)
            if _JEN_IMPORT_OR_DYNAMIC.search(body) and "runuser" in opening
        ]
        assert len(wrapped) >= 3, wrapped


class TestOnlyJenUpdateRootPyRunsAsRootAndImportsNothingFromJen:
    def test_jen_update_root_py_never_imports_the_jen_package(self):
        assert not _JEN_IMPORT.search(JEN_UPDATE_ROOT_PY), (
            "jen-update-root.py is the only Python root ever runs directly — "
            "it must stay pure stdlib with respect to the jen package"
        )
