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

Pure, no DB: `py -m pytest --noconftest tests/test_readme_compat_table.py`.
"""

import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
README = ROOT / "README.md"


def _compat_table_text() -> str:
    """The README's own Compatibility section — scoped so a version
    number appearing elsewhere in the page (a badge, a changelog blurb)
    can't accidentally satisfy this test."""
    text = README.read_text(encoding="utf-8")
    m = re.search(r"## Compatibility\n(.*?)(?=\n## |\Z)", text, re.S)
    assert m, "README.md has no '## Compatibility' section"
    return m.group(1)


def _kea_compat_versions() -> list[str]:
    with open(ROOT / ".github" / "workflows" / "kea-compat.yml") as f:
        wf = yaml.safe_load(f)
    return [entry["kea"] for entry in wf["jobs"]["compat"]["strategy"]["matrix"]["include"]]


def _tests_workflow() -> dict:
    with open(ROOT / ".github" / "workflows" / "tests.yml") as f:
        return yaml.safe_load(f)


def _install_os_list() -> list[str]:
    return _tests_workflow()["jobs"]["install"]["strategy"]["matrix"]["os"]


def _pytest_python_versions() -> list[str]:
    include = _tests_workflow()["jobs"]["pytest"]["strategy"]["matrix"]["include"]
    return sorted({entry["python-version"] for entry in include})


def _tested_db_images() -> list[str]:
    include = _tests_workflow()["jobs"]["pytest"]["strategy"]["matrix"]["include"]
    images = {entry["db-image"] for entry in include}
    # the install job's own service container — a real fresh-install run against
    # a different MariaDB line than the pytest job exercises, equally "tested".
    install_job = _tests_workflow()["jobs"]["install"]
    images.add(install_job["services"]["database"]["image"])
    return sorted(images)


class TestCompatibilityTableMatchesCI:
    def test_every_kea_compat_version_is_in_the_table(self):
        table = _compat_table_text()
        missing = [v for v in _kea_compat_versions() if v not in table]
        assert not missing, f"kea-compat.yml tests {missing}, not mentioned in README's Compatibility table"

    def test_every_install_os_is_in_the_table(self):
        table = _compat_table_text()
        missing = [os_ for os_ in _install_os_list() if os_.replace("ubuntu-", "Ubuntu ") not in table]
        assert not missing, f"the install CI job runs on {missing}, not mentioned in README's Compatibility table"

    def test_every_tested_python_version_is_in_the_table(self):
        table = _compat_table_text()
        missing = [v for v in _pytest_python_versions() if v not in table]
        assert not missing, f"the pytest CI job tests Python {missing}, not mentioned in README's Compatibility table"

    def test_every_tested_database_is_in_the_table(self):
        table = _compat_table_text()
        missing = []
        for image in _tested_db_images():
            engine, _, version = image.partition(":")
            label = {"mariadb": "MariaDB", "mysql": "MySQL"}.get(engine, engine)
            if f"{label} {version}" not in table:
                missing.append(image)
        assert not missing, f"CI tests {missing}, not mentioned in README's Compatibility table"
