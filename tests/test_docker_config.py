"""
tests/test_docker_config.py
───────────────────────────
v5.6.0 — the Docker install path had drifted: install.sh built
`jen.config`, the compose files used `env_file: .env` with the config
mount commented out, and neither the external nor the bundled path
could be followed from the README as written. Docker is now `.env` /
`JEN_*` only; run.py generates jen.config inside the container.

These tests fail if any piece of that drifts back apart. Compose files
are parsed as text (no pyyaml in the CI pytest env — same reason
test_small_hardening_fixes.py regex-parses the healthcheck).
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
COMPOSE = ["docker-compose.yml", "docker-compose.mysql.yml"]


def _text(name):
    return (REPO / name).read_text(encoding="utf-8")


class TestComposeFilesUseEnvFile:
    def test_jen_service_reads_env_file(self):
        for name in COMPOSE:
            assert re.search(r"env_file:\s*\n\s*-\s*\.env", _text(name)), f"{name}: jen must use env_file: [.env]"

    def test_no_active_jen_config_mount(self):
        # An active `- ./jen.config:...` line would start with `-`; the
        # escape-hatch line is commented (`# - ./jen.config:...`).
        for name in COMPOSE:
            assert not re.search(r"^\s*-\s*\./jen\.config:", _text(name), re.M), (
                f"{name}: the ./jen.config mount must stay commented"
            )

    def test_image_tag_matches_jen_version(self):
        ver = re.search(
            r'JEN_VERSION\s*=\s*"([0-9.]+)"', (REPO / "jen" / "__init__.py").read_text(encoding="utf-8")
        ).group(1)
        for name in COMPOSE:
            m = re.search(r"image:\s*jen-dhcp:([0-9.]+)", _text(name))
            assert m and m.group(1) == ver, f"{name}: image tag {m and m.group(1)} != {ver}"


class TestBundledDbWiring:
    def test_bundled_compose_wires_jen_db_via_environment(self):
        t = _text("docker-compose.mysql.yml")
        assert re.search(r"JEN_DB_HOST:\s*jen-mysql", t)
        assert re.search(r"JEN_DB_USER:\s*jen", t)
        assert re.search(r"JEN_DB_NAME:\s*jen", t)
        # JEN_DB_PASS comes from ${JEN_MYSQL_PASSWORD} so .env carries it once
        assert re.search(r"JEN_DB_PASS:\s*\$\{JEN_MYSQL_PASSWORD", t)

    def test_jen_mysql_password_shared_both_sides(self):
        t = _text("docker-compose.mysql.yml")
        assert re.search(r"MARIADB_PASSWORD:\s*\$\{JEN_MYSQL_PASSWORD", t)
        assert re.search(r"JEN_DB_PASS:\s*\$\{JEN_MYSQL_PASSWORD", t)


class TestEnvExample:
    def test_has_the_keys_the_compose_files_and_run_py_need(self):
        text = (REPO / ".env.example").read_text(encoding="utf-8")
        for key in (
            "JEN_KEA_API_URL",
            "JEN_DB_HOST",
            "JEN_INITIAL_ADMIN_PASSWORD",
            "MYSQL_ROOT_PASSWORD",
            "JEN_MYSQL_PASSWORD",
            "HTTP_PORT",
        ):
            assert re.search(rf"^{key}=", text, re.M), f".env.example missing {key}"


class TestInstallerWritesEnvNotJenConfig:
    def test_docker_install_writes_dot_env(self):
        sh = (REPO / "install.sh").read_text(encoding="utf-8")
        docker_fn = sh[sh.index("docker_install()") :]
        docker_fn = docker_fn[: docker_fn.index("\n_docker_pick_compose_and_run()")]
        assert 'cat > "./.env"' in docker_fn, "docker_install must write .env"
        assert 'cat > "./jen.config"' not in docker_fn, "docker_install must not write jen.config anymore"

    def test_installer_passes_admin_password_through_env_var(self):
        sh = (REPO / "install.sh").read_text(encoding="utf-8")
        assert "JEN_INITIAL_ADMIN_PASSWORD=${ADMIN_PASS}" in sh


class TestDocsDoNotTellDockerUsersToEditJenConfig:
    def test_readme_docker_section_uses_env(self):
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        docker_section = readme[readme.index("### Docker") : readme.index("## First Login")]
        assert "cp .env.example .env" in docker_section
        assert "cp jen.config.example jen.config" not in docker_section

    def test_docker_md_uses_env(self):
        md = (REPO / "docs" / "docker.md").read_text(encoding="utf-8")
        assert "cp jen.config.example jen.config" not in md
        assert ".env" in md


class TestSeedHonoursInitialAdminPassword:
    def test_init_jen_db_reads_the_env_var(self):
        src = (REPO / "jen" / "models" / "db.py").read_text(encoding="utf-8")
        assert "JEN_INITIAL_ADMIN_PASSWORD" in src
        assert src.count("must_change_password") >= 3  # both seed branches still set it
