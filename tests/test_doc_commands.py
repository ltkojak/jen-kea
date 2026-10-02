"""
tests/test_doc_commands.py
──────────────────────────
v5.67.0-beta.10 (Q122) — docs/manual-install.md is executable now: tools/doc_commands.py turns its
`<!-- ci:run -->` blocks into one script and CI's `manual-install` job runs it on a clean runner.
This file pins the pieces that can be checked without that runner: the extractor's own rules, that the
page and the job's stand-in hooks agree on names, that nothing runnable still contains a placeholder or a
never-ending command, and that the page keeps the three corrections the audit found in it.

Pure — no DB: `py -m pytest --noconftest tests/test_doc_commands.py`.
"""

import importlib.util
import pathlib
import re
import shutil
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAGE = ROOT / "docs" / "manual-install.md"
HOOKS = ROOT / ".github" / "scripts" / "manual-install-hooks.sh"
TESTS_YML = ROOT / ".github" / "workflows" / "tests.yml"

_spec = importlib.util.spec_from_file_location("doc_commands", ROOT / "tools" / "doc_commands.py")
doc_commands = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(doc_commands)


def _page_items():
    return doc_commands.extract(PAGE.read_text(encoding="utf-8"))


class TestTheExtractor:
    def test_a_marked_block_is_extracted_verbatim_and_an_unmarked_one_is_not(self):
        text = "<!-- ci:run -->\n```bash\necho one\n```\n\n```bash\necho two\n```\n"
        assert doc_commands.extract(text) == [("run", "echo one", 2)]

    def test_a_hook_becomes_a_call_at_its_place_in_the_order(self):
        text = "<!-- ci:run -->\n```bash\na\n```\n<!-- ci:hook edit-config -->\n<!-- ci:run -->\n```bash\nb\n```\n"
        assert [(k, b) for k, b, _ in doc_commands.extract(text)] == [
            ("run", "a"),
            ("hook", "edit-config"),
            ("run", "b"),
        ]
        script = doc_commands.render(doc_commands.extract(text))
        assert script.index("\na\n") < script.index("ci_hook edit-config") < script.index("\nb\n")

    @pytest.mark.parametrize(
        "text, why",
        [
            ("<!-- ci:run -->\nprose first\n```bash\nx\n```\n", "prose between the marker and the block"),
            ("<!-- ci:run -->\n", "a marker at the end of the page"),
            ("<!-- ci:run -->\n```sql\nSELECT 1;\n```\n", "a marked block that is not bash"),
            ("<!-- ci:run -->\n```bash\nnever closed\n", "an unterminated fence"),
            ("<!-- ci:hook Bad_Name -->\n", "a malformed hook name"),
            ("<!-- ci:run -->\n<!-- ci:run -->\n```bash\nx\n```\n", "two markers for one block"),
            ("<!-- ci:runn -->\n", "a mistyped marker"),
        ],
    )
    def test_a_marker_that_does_not_keep_its_promise_is_an_error_not_a_skipped_block(self, text, why):
        with pytest.raises(doc_commands.DocError):
            doc_commands.extract(text)


class TestTheManualInstallPage:
    def test_it_parses(self):
        runs = [i for i in _page_items() if i[0] == "run"]
        assert len(runs) >= 7, "the page lost most of its runnable blocks"

    def test_the_pages_hooks_are_exactly_the_ones_the_ci_job_defines(self):
        used = {name for kind, name, _ in _page_items() if kind == "hook"}
        defined = set(re.findall(r"^\s+([a-z][a-z0-9-]*)\)\s*$", HOOKS.read_text(encoding="utf-8"), re.M))
        defined.discard("*")
        assert used == defined, (
            f"page uses {sorted(used)}, .github/scripts/manual-install-hooks.sh defines {sorted(defined)} — "
            "a hook with no stand-in fails CI; a stand-in with no hook is dead code"
        )

    def test_the_unit_is_rendered_by_the_one_renderer_not_copied(self):
        runnable = "\n".join(b for k, b, _ in _page_items() if k == "run")
        assert "--render-unit" in runnable
        assert "jen.service.template" in runnable
        assert not re.search(r'cp\s+"?\$REL/app/jen\.service"?\s', runnable), (
            "jen.service stopped shipping in 5.67.0 — copying it is the bug this page was rebuilt to remove"
        )

    def test_the_version_is_the_whole_version_never_truncated_at_the_beta_suffix(self):
        page = PAGE.read_text(encoding="utf-8")
        assert "[0-9.]+" not in page, "a [0-9.]+ capture cuts 5.67.0-beta.10 down to 5.67.0"
        bash = shutil.which("bash")
        if not bash:
            pytest.skip("needs bash")
        runnable = "\n".join(b for k, b, _ in _page_items() if k == "run")
        line = next(ln for ln in runnable.splitlines() if ln.startswith("VER="))
        try:
            got = subprocess.run(
                [bash, "-c", f"cd '{ROOT.as_posix()}' && {line} && printf %s \"$VER\""],
                capture_output=True,
                text=True,
                timeout=20,
            )
        except OSError:
            pytest.skip("bash is not runnable here")
        if got.returncode != 0:
            pytest.skip(f"this bash/grep cannot run the capture: {got.stderr.strip()[:120]}")
        declared = re.search(r'^JEN_VERSION\s*=\s*"([^"]+)"', (ROOT / "jen" / "__init__.py").read_text("utf-8"), re.M)
        assert got.stdout == declared.group(1)

    def test_the_sudoers_grants_are_counted_as_the_file_has_them(self):
        grants = [
            ln for ln in (ROOT / "jen-sudoers").read_text(encoding="utf-8").splitlines() if ln.startswith("www-data")
        ]
        assert len(grants) == 3
        assert "three" in PAGE.read_text(encoding="utf-8")

    def test_every_oneshot_unit_the_installer_places_is_placed_by_the_page_too(self):
        runnable = "\n".join(b for k, b, _ in _page_items() if k == "run")
        for unit in ("jen-update.service", "jen-plugin-install.service"):
            assert unit in runnable

    def test_nothing_runnable_is_a_placeholder_an_editor_or_a_command_that_never_returns(self):
        for kind, body, line in _page_items():
            if kind != "run":
                continue
            assert not re.search(r"<[A-Za-z.]+>|YOUR-|\bnano\b|X\.Y\.Z", body), f"page line {line}: a placeholder"
            assert not re.search(r"journalctl\b.*\s-f\b|tail\s+-f", body), f"page line {line}: follows a log forever"

    def test_the_rendered_script_is_syntactically_valid_bash(self):
        bash = shutil.which("bash")
        if not bash:
            pytest.skip("needs bash")
        script = HOOKS.read_text(encoding="utf-8") + doc_commands.render(_page_items())
        try:
            got = subprocess.run([bash, "-n"], input=script, capture_output=True, text=True, timeout=20)
        except OSError:
            pytest.skip("bash is not runnable here")
        assert got.returncode == 0, got.stderr


class TestTheCiJob:
    def test_the_job_exists_and_runs_the_extracted_page_then_checks_the_version(self):
        text = TESTS_YML.read_text(encoding="utf-8")
        assert re.search(r"^  manual-install:$", text, re.M)
        start = text.index("\n  manual-install:\n")
        end = text.index("\n  bandit:\n")
        job = text[start:end]
        assert "tools/doc_commands.py docs/manual-install.md" in job
        assert ".github/scripts/manual-install-hooks.sh" in job
        assert "expect_eq" in job and "jen_version" in job, "the job must compare the VALUE of jen_version"
