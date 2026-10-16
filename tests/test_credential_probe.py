"""
tests/test_credential_probe.py
──────────────────────────────
v5.69.0-beta.14 (Q183, Y7) - every scenario of `tests/probe/credential_probe.py` is asserted. The probe is the executing second pass made permanent: the real writer, resolver and
transport on crafted configurations, one function per scenario that returns what it observed. A scenario's observation changing is a change in what the credential rule DOES - this is the
test that says so, with the scenario's name. Pure: `py -m pytest --noconftest tests/test_credential_probe.py`.
"""

import pathlib

import pytest

from tests.probe import credential_probe as probe

ROOT = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def observed():
    return probe.run_all()


def test_every_scenario_has_an_expectation_and_every_expectation_a_scenario():
    assert set(probe.SCENARIOS) == set(probe.EXPECTED)
    assert len(probe.SCENARIOS) >= 30, "the executed scenarios of the beta.12, beta.13 and beta.14 passes"


@pytest.mark.parametrize("name", sorted(probe.EXPECTED))
def test_the_scenario_observes_what_the_rule_says(name, observed):
    assert observed[name] == probe.EXPECTED[name], f"{name}: observed {observed[name]!r}"


def test_what_the_probe_does_not_run_is_pinned_somewhere_that_exists():
    """The scenarios that need a Flask request or a database are named with the test that pins them instead; the class (or file) must exist."""
    for what, where in probe.NOT_PROBED.items():
        path, _, cls = where.partition("::")
        text = (ROOT / path).read_text(encoding="utf-8")
        assert not cls or f"class {cls}" in text, f"{what}: {where} does not exist"


def test_the_release_audit_says_the_second_pass_executes_the_probe():
    audit = (ROOT / "docs" / "RELEASE_AUDIT.md").read_text(encoding="utf-8")
    assert "tests/probe/credential_probe.py" in audit and "EXECUTES" in audit
    assert audit.count("EXECUTES") >= 2, "step (n) AND the second-pass prompt say it"
    assert "a finding reported from reading alone is a hypothesis" in audit


def test_the_probe_runs_as_a_script():
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "probe" / "credential_probe.py")], capture_output=True, text=True
    )
    assert proc.returncode == 0, proc.stdout[-800:] + proc.stderr[-400:]
    assert "scenarios as the rule says" in proc.stdout
