"""
tests/test_workflow_hygiene.py
───────────────────────────────
v5.67.0-beta.10 (Q122, Part 1) — the CI workflows' own steps, held to the rule
that an assertion must be able to fail.

An audit of the shipped workflows found checks that could not: a relocated
install piped through `tee` under `bash -e` with no `pipefail` (the step's
status was tee's), five `! grep -q "…"` "no Docker wording" assertions (bash
exempts a negated command from errexit — reproduced: exit 0 with the forbidden
text present), and an upgrade leg whose installer failure was swallowed by
`|| echo`. This file refuses each spelling, so the next workflow edit cannot
bring them back.
"""

import pathlib
import re

import pytest
import yaml

REPO = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = sorted((REPO / ".github" / "workflows").glob("*.yml"))
ACTIONS = sorted((REPO / ".github" / "actions").glob("*/action.yml"))


def _load(path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _run_blocks(doc):
    """(where, run_text, effective_shell_has_pipefail, step) for every `run:` step in a workflow or composite action."""
    out = []
    default_shell = ((doc.get("defaults") or {}).get("run") or {}).get("shell", "")
    if "jobs" in doc:
        for job_name, job in doc["jobs"].items():
            job_shell = ((job.get("defaults") or {}).get("run") or {}).get("shell", default_shell)
            for i, step in enumerate(job.get("steps") or []):
                if "run" in step:
                    shell = step.get("shell", job_shell)
                    out.append((f"{job_name}[{i}] {step.get('name', '')}", step["run"], "pipefail" in shell, step))
    else:  # a composite action
        for i, step in enumerate((doc.get("runs") or {}).get("steps") or []):
            if "run" in step:
                out.append(
                    (f"step[{i}] {step.get('name', '')}", step["run"], "pipefail" in step.get("shell", ""), step)
                )
    return out


def _code_lines(run_text):
    """The step's script with comment lines dropped and `\\`-continued lines joined — what bash actually parses."""
    joined = re.sub(r"\\\n\s*", " ", run_text)
    return [ln for ln in joined.splitlines() if ln.strip() and not ln.strip().startswith("#")]


ALL = [(p, _load(p)) for p in (*WORKFLOWS, *ACTIONS)]
IDS = [str(p.relative_to(REPO)) for p, _ in ALL]


class TestScannerSeesTheRealSpellings:
    def test_a_negated_grep_is_recognised(self):
        assert re.search(NEGATED, '! grep -q "x" <<< "$page"')
        assert re.search(NEGATED, "   ! grep -q 'x' file")
        assert not re.search(NEGATED, 'if ! grep -q "x" <<< "$p"; then')

    def test_a_pipeline_into_grep_q_is_recognised(self):
        assert re.search(PIPE_GREP_Q, "curl -sf http://x | grep -q jen_version")
        assert re.search(PIPE_GREP_Q, "x | grep -Pq 'a'")
        assert re.search(PIPE_GREP_Q, "x | grep -qP 'a'")
        assert not re.search(PIPE_GREP_Q, "grep -q jen_version < <(curl -sf http://x)")
        assert not re.search(PIPE_GREP_Q, 'grep -q a <<< "$x"')


# A negated command at the start of a statement: exempt from errexit, so the "assertion" never fails.
NEGATED = re.compile(r"^\s*!\s+\S")
# `producer | grep -q`: under pipefail an early-exiting grep SIGPIPEs the producer, so the pipeline can
# fail for the wrong reason (and without pipefail it can pass for the wrong one).
PIPE_GREP_Q = re.compile(r"\|\s*grep\s+(?:-\w*q\w*|--quiet)\b")


@pytest.mark.parametrize("path,doc", ALL, ids=IDS)
class TestEveryWorkflowStep:
    def test_pipefail_is_the_default_and_nothing_overrides_it(self, path, doc):
        if "jobs" in doc:
            shell = ((doc.get("defaults") or {}).get("run") or {}).get("shell", "")
            assert "pipefail" in shell, f"{path.name} must set defaults.run.shell to a bash with -o pipefail"
        for where, _run, has_pipefail, step in _run_blocks(doc):
            assert has_pipefail, f"{path.name}: {where} runs without pipefail (shell: {step.get('shell')!r})"

    def test_no_negated_command_as_an_assertion(self, path, doc):
        bad = []
        for where, run, _pf, _step in _run_blocks(doc):
            bad += [f"{where}: {ln.strip()}" for ln in _code_lines(run) if NEGATED.search(ln)]
        assert not bad, (
            "bash exempts a `!`-negated command from errexit, so these can never fail the step — "
            'write `if cmd; then echo "::error::…"; exit 1; fi` (or .github/scripts/ci-lib.sh\'s `refuse`):\n'
            + "\n".join(bad)
        )

    def test_no_pipeline_into_grep_q(self, path, doc):
        bad = []
        for where, run, _pf, _step in _run_blocks(doc):
            bad += [f"{where}: {ln.strip()}" for ln in _code_lines(run) if PIPE_GREP_Q.search(ln)]
        assert not bad, (
            "`producer | grep -q` is racy under pipefail (grep exits at the first match and SIGPIPEs the "
            'producer); capture first (`x=$(…)`; `grep -q … <<< "$x"`) or `grep -q … < <(…)`:\n' + "\n".join(bad)
        )

    def test_a_tee_is_only_allowed_under_pipefail(self, path, doc):
        for where, run, has_pipefail, _step in _run_blocks(doc):
            if any(re.search(r"\|\s*tee\b", ln) for ln in _code_lines(run)):
                assert has_pipefail, (
                    f"{path.name}: {where} pipes into tee without pipefail — tee's status would be the step's"
                )


class TestTheStablePin:
    def _tests_yml(self):
        return _load(REPO / ".github" / "workflows" / "tests.yml")

    def test_the_pin_is_a_plain_release_version(self):
        pin = self._tests_yml()["env"]["JEN_STABLE_VERSION"]
        assert re.fullmatch(r"\d+\.\d+\.\d+", str(pin)), pin

    def test_the_pin_is_never_newer_than_the_tree(self):
        pin = tuple(int(n) for n in str(self._tests_yml()["env"]["JEN_STABLE_VERSION"]).split("."))
        version = re.search(
            r'^JEN_VERSION = "(\d+)\.(\d+)\.(\d+)', (REPO / "jen" / "__init__.py").read_text(encoding="utf-8"), re.M
        )
        assert version
        assert pin <= tuple(int(n) for n in version.groups()), "the stable pin must not be ahead of the code under test"

    def test_the_release_recipe_says_to_move_it_at_promotion(self):
        claude = (REPO / "CLAUDE.md").read_text(encoding="utf-8")
        assert "JEN_STABLE_VERSION" in claude and "promot" in claude

    def test_the_job_downloads_the_pinned_tag_not_latest(self):
        text = (REPO / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
        assert 'gh release download "v${JEN_STABLE_VERSION}"' in text
        job = self._tests_yml()["jobs"]["upgrade-from-stable"]
        assert "latest" not in " ".join(str(s.get("run", "")) for s in job["steps"]).lower().replace(
            "latest stable", ""
        )


class TestTheUpgradeFromStableJob:
    def _job(self):
        return _load(REPO / ".github" / "workflows" / "tests.yml")["jobs"]["upgrade-from-stable"]

    def test_it_is_its_own_job_with_both_ways_up(self):
        job = self._job()
        vias = {m["via"] for m in job["strategy"]["matrix"]["include"]}
        assert vias == {"installer", "updater"}

    def test_the_install_job_no_longer_carries_the_stable_legs(self):
        text = (REPO / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8")
        install = _load(REPO / ".github" / "workflows" / "tests.yml")["jobs"]["install"]
        assert not any("stable" in str(s.get("name", "")).lower() for s in install["steps"]), (
            "the upgrade-from-stable legs belong to their own clean job"
        )
        assert "interim reset before the stable jump" not in text

    def test_nothing_in_it_is_masked(self):
        job = self._job()
        for step in job["steps"]:
            if "failure()" in str(step.get("if", "")):
                continue  # log dumps on failure may tolerate their own failure
            run = str(step.get("run", ""))
            masks = [ln.strip() for ln in _code_lines(run) if re.search(r"\|\|\s*(true|echo|:)\b", ln)]
            assert not masks, f"{step.get('name')}: {masks}"

    def test_the_signature_is_checked_against_the_repos_pinned_key(self):
        job = self._job()
        verify = next(s for s in job["steps"] if "signature" in str(s.get("name", "")).lower())
        assert "jen-update-root.py" in verify["run"] and "RELEASE_SIGNERS" in verify["run"]
        assert "tar xzf" not in verify["run"], "the key must not come out of the tarball being verified"

    def test_it_compares_the_value_of_jen_version(self):
        text = "\n".join(str(s.get("run", "")) for s in self._job()["steps"])
        assert "expect_eq" in text and "jen_version" in text
        assert "grep -q jen_version" not in text, "a key-presence check is not a version check"

    def test_the_updater_leg_drives_the_stable_releases_own_updater_through_two_hops(self):
        steps = [s for s in self._job()["steps"] if s.get("if") == "matrix.via == 'updater'"]
        hops = [s for s in steps if "ci_updater_hop.py hop" in str(s.get("run", ""))]
        assert len(hops) == 2
        assert "/usr/local/sbin/jen-update-root.py" in hops[0]["run"], (
            "hop 1 uses the updater the stable install put there"
        )
        assert "--prerelease" in hops[0]["run"]
        assert "bump" in steps[2]["run"] or any("ci_updater_hop.py bump" in str(s["run"]) for s in steps)
        assert any("JEN_SERVICE_MANAGER=systemd" in str(s.get("run", "")) for s in steps)

    def test_both_jobs_share_one_fixture(self):
        doc = _load(REPO / ".github" / "workflows" / "tests.yml")
        for job in ("install", "upgrade-from-stable"):
            uses = [s.get("uses") for s in doc["jobs"][job]["steps"]]
            assert "./.github/actions/kea-fixture" in uses, job

    def test_the_ci_library_defines_what_the_steps_source(self):
        lib = (REPO / ".github" / "scripts" / "ci-lib.sh").read_text(encoding="utf-8")
        for fn in ("jen_version()", "expect_eq()", "refuse()", "require()", "jen_login()"):
            assert fn in lib, fn
