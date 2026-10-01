"""
tests/test_readme_compat_table.py
───────────────────────────────────
v5.67.0-beta.4 (Q116) — the README's compatibility table is generated
from the truth, not hand-maintained prose that quietly drifts: this
reads the actual CI matrices (.github/workflows/kea-compat.yml's Kea
versions, tests.yml's install-job OS list and pytest-job Python/database
matrix) and fails if the README's own table doesn't mention every one of
them. A version bumped in the workflow without a matching README edit
fails here instead of just being wrong forever.

Regex over the raw YAML text, not a real parser — the CI `pytest` job
installs only requirements.txt + bare pytest (not requirements-dev.txt,
which every other job's own install step covers separately), so adding
a YAML-parsing dependency here would mean adding PyYAML to Jen's actual
runtime requirements.txt for a test-only need. The workflow files are
simple and stable enough that a few targeted patterns, scoped to each
job's own line range, are both simpler and dependency-free.

Pure, no DB: `py -m pytest --noconftest tests/test_readme_compat_table.py`.
"""

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
TESTS_YML = ROOT / ".github" / "workflows" / "tests.yml"
KEA_COMPAT_YML = ROOT / ".github" / "workflows" / "kea-compat.yml"

_JOB_RE = re.compile(r"^  [a-z0-9_-]+:$", re.M)


def _job_block(text: str, job: str) -> str:
    """The lines belonging to one top-level job in a workflow file —
    from its own `  <job>:` line up to the next top-level job (or EOF)."""
    starts = [(m.start(), m.group().strip(" :")) for m in _JOB_RE.finditer(text)]
    for i, (pos, name) in enumerate(starts):
        if name == job:
            end = starts[i + 1][0] if i + 1 < len(starts) else len(text)
            return text[pos:end]
    raise AssertionError(f"no top-level job {job!r} found")


def _compat_table_text() -> str:
    """The README's own Compatibility section — scoped so a version
    number appearing elsewhere in the page (a badge, a changelog blurb)
    can't accidentally satisfy this test."""
    text = README.read_text(encoding="utf-8")
    m = re.search(r"## Compatibility\n(.*?)(?=\n## |\Z)", text, re.S)
    assert m, "README.md has no '## Compatibility' section"
    return m.group(1)


def _kea_compat_versions() -> list[str]:
    text = KEA_COMPAT_YML.read_text(encoding="utf-8")
    block = _job_block(text, "compat")
    return re.findall(r"^\s*- kea:\s*([\d.]+)", block, re.M)


def _install_os_list() -> list[str]:
    text = TESTS_YML.read_text(encoding="utf-8")
    block = _job_block(text, "install")
    m = re.search(r"os:\s*\[([^\]]+)\]", block)
    assert m, "install job has no 'os: [...]' matrix line"
    return [tok.strip() for tok in m.group(1).split(",")]


def _pytest_python_versions() -> list[str]:
    text = TESTS_YML.read_text(encoding="utf-8")
    block = _job_block(text, "pytest")
    return sorted(set(re.findall(r"python-version:\s*'([\d.]+)'", block)))


def _tested_db_images() -> list[str]:
    text = TESTS_YML.read_text(encoding="utf-8")
    pytest_block = _job_block(text, "pytest")
    images = set(re.findall(r"db-image:\s*(\S+)", pytest_block))
    # the install job's own service container — a real fresh-install run
    # against a different MariaDB line than the pytest job exercises,
    # equally "tested".
    install_block = _job_block(text, "install")
    m = re.search(r"database:\s*\n\s*image:\s*(\S+)", install_block)
    assert m, "install job has no database service image"
    images.add(m.group(1))
    return sorted(images)


class TestCompatibilityTableMatchesCI:
    def test_every_kea_compat_version_is_in_the_table(self):
        table = _compat_table_text()
        versions = _kea_compat_versions()
        assert len(versions) >= 2, versions  # a parsing regression would silently pass an empty list
        missing = [v for v in versions if v not in table]
        assert not missing, f"kea-compat.yml tests {missing}, not mentioned in README's Compatibility table"

    def test_every_install_os_is_in_the_table(self):
        table = _compat_table_text()
        os_list = _install_os_list()
        assert len(os_list) >= 1, os_list
        missing = [os_ for os_ in os_list if os_.replace("ubuntu-", "Ubuntu ") not in table]
        assert not missing, f"the install CI job runs on {missing}, not mentioned in README's Compatibility table"

    def test_every_tested_python_version_is_in_the_table(self):
        table = _compat_table_text()
        versions = _pytest_python_versions()
        assert len(versions) >= 1, versions
        missing = [v for v in versions if v not in table]
        assert not missing, f"the pytest CI job tests Python {missing}, not mentioned in README's Compatibility table"

    def test_every_tested_database_is_in_the_table(self):
        table = _compat_table_text()
        images = _tested_db_images()
        assert len(images) >= 1, images
        missing = []
        for image in images:
            engine, _, version = image.partition(":")
            label = {"mariadb": "MariaDB", "mysql": "MySQL"}.get(engine, engine)
            if f"{label} {version}" not in table:
                missing.append(image)
        assert not missing, f"CI tests {missing}, not mentioned in README's Compatibility table"
