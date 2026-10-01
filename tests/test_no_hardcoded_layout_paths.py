"""
tests/test_no_hardcoded_layout_paths.py
────────────────────────────────────────
v5.67.0 (Q114) — every shipped file's actual CODE (not a comment or a
docstring, which may freely describe "the default is /opt/jen" for a
human reader) must derive app_dir/config_dir/data_dir from the layout
system (extensions.CONFIG_DIR/CONTENT_DIR/JEN_ROOT, or
jen-update-root.py's own load_layout()) rather than hardcoding
/opt/jen, /etc/jen or /var/lib/jen — the whole point of Q114 was making
every one of these relocatable, and a stray literal would be a silent
regression the next time someone edits nearby code.

Checked with `ast`, not a text grep: a comment (`#...`) never reaches
the AST at all, and a module/class/function docstring is recognized by
position (the first statement of a body) and excluded the same way —
so this test needs no per-line allowlist and tolerates any future
comment or docstring that mentions a default path for a reader.

install.sh, uninstall.sh, jen-update-root.py and jen/extensions.py are
exempt: they ARE the layout system, where these three strings are the
canonical defaults (absent a layout file). Dockerfile and docs/** are
exempt per Q114's own spec (Docker's own layout is fixed inside the
container; docs describe history and defaults for humans, in prose that
isn't meaningfully "code"). Tests aren't shipped at all — install.sh's
own install_files() excludes tests/ (and .git, .github, venvs) from the
release tarball — and neither is legacy/ (retired pre-2.6.0 monolith,
`.gitattributes export-ignore`) — both routinely need the literal
defaults as fixtures or predate the whole concept.

run.py is exempt too, for one specific reason rather than a blanket
one: `_VENV_DIR = "/opt/jen/venv"` is the flat-layout/Docker fallback
venv path, and neither case can ever have a *relocated* app_dir to
begin with — a flat install predates the versioned layout (and Q114)
entirely, and Docker's own internal filesystem is fixed regardless of
what the host relocates. It's a permanent literal, not a missed
derivation.
"""

import ast
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

FORBIDDEN = ("/opt/jen", "/etc/jen", "/var/lib/jen")

# Relative to ROOT, forward-slash. These are the layout system itself —
# see the module docstring for why each one legitimately owns the
# literal defaults.
EXEMPT_FILES = {
    "install.sh",
    "uninstall.sh",
    "jen-update-root.py",
    "jen/extensions.py",
    "run.py",
}

_EXCLUDED_DIRS = {".git", ".github", "tests", ".venv", "venv", "node_modules", "legacy"}


def _shipped_python_files():
    """Mirrors install.sh's install_files(): the whole repo minus what
    it explicitly excludes when building a release."""
    for path in sorted(ROOT.rglob("*.py")):
        rel = path.relative_to(ROOT)
        if any(part in _EXCLUDED_DIRS for part in rel.parts):
            continue
        if rel.as_posix() in EXEMPT_FILES:
            continue
        yield rel


def _docstring_constant_ids(tree: ast.AST) -> set:
    """id() of every ast.Constant that IS a module/class/function
    docstring (the first statement of some node's body, itself a bare
    string-literal expression) — by identity, so a later structurally
    identical string elsewhere is never mistaken for one."""
    ids = set()
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if not isinstance(body, list) or not body:
            continue
        first = body[0]
        if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
            ids.add(id(first.value))
    return ids


def _violations(path: pathlib.Path):
    """Yields (lineno, snippet) for every string literal containing a
    forbidden substring that is not a docstring. Covers f-string pieces
    too — an f-string is ast.JoinedStr with ast.Constant chunks for its
    literal parts, and ast.walk descends into it like anything else."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    docstring_ids = _docstring_constant_ids(tree)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        if id(node) in docstring_ids:
            continue
        if any(f in node.value for f in FORBIDDEN):
            yield node.lineno, node.value[:120]


@pytest.mark.parametrize("rel_path", list(_shipped_python_files()), ids=lambda p: p.as_posix())
def test_no_hardcoded_layout_path_in_shipped_code(rel_path):
    violations = list(_violations(ROOT / rel_path))
    assert not violations, (
        f"{rel_path} hardcodes a layout path in real code (not a docstring) — "
        f"derive it from extensions.CONFIG_DIR/CONTENT_DIR/JEN_ROOT instead: {violations}"
    )


class TestSanityOfTheCheckItself:
    """A test whose whole job is finding an absence needs its own proof
    it isn't just vacuously passing."""

    def test_the_shipped_file_list_is_not_suspiciously_small(self):
        files = list(_shipped_python_files())
        assert len(files) > 50, f"only found {len(files)} shipped .py files — the walk is probably broken"

    def test_a_hardcoded_literal_is_actually_caught(self, tmp_path):
        bad = tmp_path / "bad.py"
        bad.write_text('CONFIG_FILE = "/etc/jen/jen.config"\n', encoding="utf-8")
        assert list(_violations(bad))

    def test_a_docstring_mentioning_the_default_is_not_caught(self, tmp_path):
        good = tmp_path / "good.py"
        good.write_text('"""The default config dir is /etc/jen."""\nCONFIG_FILE = "x"\n', encoding="utf-8")
        assert not list(_violations(good))

    def test_a_comment_mentioning_the_default_is_not_caught(self, tmp_path):
        good = tmp_path / "good2.py"
        good.write_text('# historically /etc/jen\nCONFIG_FILE = "x"\n', encoding="utf-8")
        assert not list(_violations(good))

    def test_an_fstring_literal_chunk_is_caught(self, tmp_path):
        bad = tmp_path / "bad_fstring.py"
        bad.write_text('x = 1\nmsg = f"writable to /etc/jen? ({x})"\n', encoding="utf-8")
        assert list(_violations(bad))
