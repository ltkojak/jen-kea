"""
tests/test_dependency_consistency.py
────────────────────────────────────
v5.4.1 — runtime dependency pins live in exactly one place,
`requirements.txt`. Before this, the same ~14 packages were pinned
independently in install.sh, Dockerfile, and the CI workflow, and had
already drifted (werkzeug pinned in one place, absent in another;
cryptography pinned in two, unpinned in CI).

These tests fail if any consumer re-introduces an inline pin, and if
the version strings that must move together fall out of sync.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

REQUIREMENTS = REPO / "requirements.txt"
REQUIREMENTS_DEV = REPO / "requirements-dev.txt"

# Every file that installs the runtime dependency set. Each must do it
# via `-r requirements.txt`, never by listing packages inline.
CONSUMERS = [
    REPO / "install.sh",
    REPO / "Dockerfile",
    REPO / ".github" / "workflows" / "tests.yml",
]


def _runtime_package_names():
    names = []
    for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        # "qrcode[pil]>=8.2" -> "qrcode"; "flask-login>=0.6.3" -> "flask-login"
        name = re.split(r"[<>=!\[ ]", line, maxsplit=1)[0].strip().lower()
        if name:
            names.append(name)
    return names


class TestSingleSourceOfTruth:
    def test_requirements_file_exists_and_is_floor_pinned(self):
        assert REQUIREMENTS.is_file()
        pkgs = _runtime_package_names()
        assert "flask" in pkgs and "cryptography" in pkgs and "werkzeug" in pkgs
        # Floor pins, never exact: no "==" anywhere in the runtime file.
        for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s and not s.startswith("#"):
                assert "==" not in s, f"requirements.txt must floor-pin, not exact-pin: {s!r}"

    def test_dev_requirements_includes_runtime(self):
        assert REQUIREMENTS_DEV.is_file()
        assert "-r requirements.txt" in REQUIREMENTS_DEV.read_text(encoding="utf-8")

    def test_consumers_reference_requirements_txt(self):
        for path in CONSUMERS:
            assert path.is_file(), f"missing consumer: {path}"
            assert "requirements.txt" in path.read_text(encoding="utf-8"), (
                f"{path.name} must install deps via `-r requirements.txt`"
            )

    def test_no_consumer_reinlines_a_runtime_pin(self):
        """The whole point of v5.4.1 — no file may carry its own copy of
        a `flask>=x` / `pyotp>=x` style pin. requirements.txt itself and
        the dev file are the only places a version specifier is allowed."""
        pkgs = _runtime_package_names()
        offenders = []
        for path in CONSUMERS:
            text = path.read_text(encoding="utf-8")
            for pkg in pkgs:
                # match e.g.  flask>=   "flask-login>=   flask ==   qrcode[pil]>=
                if re.search(rf'["\' ]{re.escape(pkg)}(\[[a-z]+\])?\s*[<>=!]=?', text):
                    offenders.append(f"{path.name}: inline pin for '{pkg}'")
        assert not offenders, "inline dependency pins must move to requirements.txt:\n" + "\n".join(offenders)


class TestVersionStringsInSync:
    """The Dockerfile LABEL and both docker-compose image tags sat stale
    at 5.3.3 through the entire 5.4.0 release. These strings must all
    move together in one commit."""

    def _jen_version(self):
        m = re.search(
            r'JEN_VERSION\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"', (REPO / "jen" / "__init__.py").read_text(encoding="utf-8")
        )
        assert m
        return m.group(1)

    def test_install_sh_matches(self):
        m = re.search(r'JEN_VERSION="([0-9]+\.[0-9]+\.[0-9]+)"', (REPO / "install.sh").read_text(encoding="utf-8"))
        assert m and m.group(1) == self._jen_version()

    def test_dockerfile_label_matches(self):
        m = re.search(r'LABEL version="([0-9]+\.[0-9]+\.[0-9]+)"', (REPO / "Dockerfile").read_text(encoding="utf-8"))
        assert m and m.group(1) == self._jen_version()

    def test_docker_compose_image_tags_match(self):
        for name in ("docker-compose.yml", "docker-compose.mysql.yml"):
            text = (REPO / name).read_text(encoding="utf-8")
            m = re.search(r"image:\s*jen-dhcp:([0-9]+\.[0-9]+\.[0-9]+)", text)
            assert m and m.group(1) == self._jen_version(), f"{name} jen-dhcp image tag out of sync"

    def test_readme_badge_matches(self):
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        m = re.search(r"Version-([0-9]+\.[0-9]+\.[0-9]+)-blue", readme)
        assert m and m.group(1) == self._jen_version()

    def test_changelog_has_an_entry_for_current_version(self):
        changelog = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
        assert f"[{self._jen_version()}]" in changelog, (
            "CHANGELOG.md needs a section for the version currently in jen/__init__.py"
        )
