"""
tests/test_docs_claims.py
──────────────────────────
v5.67.0-beta.10 (Q122) — statements the code contradicted, each held by a check that reads the code, so the
next one that drifts fails here instead of staying wrong. Every claim below was found false by the 2026-10-02
audit: a "6 alert types" with 21 defined, "fuller answers with lease_cmds" when no lease4-* command is sent
anywhere, "nothing runs on your Kea servers" beside a paragraph describing the helper that does, an about page
that understated the helper's operations, templates printing a literal /opt/jen, an installer that wrote a
config key the app never read, an image without the directory its own download route serves from, and two
documents describing the same third-party product in different words.

Pure — no DB: `py -m pytest --noconftest tests/test_docs_claims.py`.
"""

import ast
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _dict_keys(rel: str, name: str) -> list[str]:
    """The string keys of a module-level `name = {...}` — by AST, so nothing needs importing."""
    tree = ast.parse(_read(rel))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return [k.value for k in node.value.keys if isinstance(k, ast.Constant)]
    raise AssertionError(f"{rel} defines no module-level {name}")


class TestTheAlertTypeCount:
    def test_the_readme_and_the_features_page_state_the_real_number(self):
        n = len(_dict_keys("jen/services/alerts.py", "ALERT_TYPE_LABELS"))
        assert n >= 20
        assert f"{n} alert types" in _read("README.md")
        assert f"{n} alert types" in _read("docs/features.md")

    def test_the_old_number_is_gone(self):
        assert "6 alert types" not in _read("README.md")


class TestHooksTheCodeActuallyNeeds:
    def test_no_lease_command_is_sent_anywhere_so_no_page_claims_lease_cmds_is_needed(self):
        sent = []
        for path in sorted((ROOT / "jen").rglob("*.py")) + sorted((ROOT / "plugins").rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            for m in re.finditer(r"""["']lease[46]-[a-z-]+["']""", text):
                sent.append(f"{path.relative_to(ROOT)}: {m.group()}")
        assert not sent, (
            f"a lease4-*/lease6-* command is sent now ({sent}) — setup_wizard.HOOK_LOSS, "
            "health._REQUIRED_HOOKS and the README row must be revisited together"
        )

    def test_the_wizard_and_health_do_not_claim_a_dependency_that_is_not_there(self):
        assert "lease_cmds" not in _dict_keys("jen/services/setup_wizard.py", "HOOK_LOSS")
        assert "libdhcp_lease_cmds.so" not in _dict_keys("jen/services/health.py", "_REQUIRED_HOOKS")

    def test_the_readme_does_not_promise_fuller_answers_from_lease_cmds(self):
        assert "lease_cmds" not in _read("README.md")


class TestTheHelpersOperationsAreAllNamedOnTheAboutPage:
    # one phrase per op, as docs/about.md words it. A new op in jen-kea-helper fails this until the page names it.
    PHRASES = {
        "version": "report its version",
        "read-config": "read, test and\n  apply a Kea config",
        "test-config": "read, test and\n  apply a Kea config",
        "apply-config": "read, test and\n  apply a Kea config",
        "remove-config": "remove a config file Jen itself just created",
        "service": "control the Kea service",
        "tail-log": "tail a Kea log",
        "install-package": "install\n  the Kea packages",
        "install-tls": "a TLS certificate",
        "update": "update itself",
        "investigation-arm": "arm, disarm and\n  report a self-restore of the log level",
        "investigation-disarm": "arm, disarm and\n  report a self-restore of the log level",
        "investigation-status": "arm, disarm and\n  report a self-restore of the log level",
        "investigation-timer": "arm, disarm and\n  report a self-restore of the log level",
    }

    def test_the_phrase_table_covers_exactly_the_helpers_ops(self):
        assert sorted(self.PHRASES) == sorted(_dict_keys("jen-kea-helper", "_OPS"))

    def test_the_about_page_says_every_one(self):
        about = _read("docs/about.md").replace("\r\n", "\n")
        missing = sorted({op for op, phrase in self.PHRASES.items() if phrase not in about})
        assert not missing, f"docs/about.md does not describe the helper's {missing}"

    def test_the_readme_does_not_say_nothing_runs_on_a_kea_server(self):
        assert "nothing runs on your Kea servers" not in _read("README.md")


class TestNoTemplatePrintsAFixedPath:
    def test_no_template_prints_a_literal_install_directory(self):
        offenders = []
        for path in sorted((ROOT / "templates").glob("*.html")):
            for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"/(opt|etc|var/lib)/jen", line):
                    offenders.append(f"{path.name}:{n}")
        assert not offenders, (
            f"a page prints a path that is wrong on a relocated install: {offenders} — use jen_layout.* "
            "(jen/extensions.py layout())"
        )

    def test_the_five_pages_the_audit_named_use_the_layout(self):
        for name in ("settings_system.html", "database.html", "plugins.html", "base.html", "about.html"):
            assert "jen_layout." in _read(f"templates/{name}"), f"{name} no longer uses the layout"

    def test_database_backups_are_not_said_to_be_under_the_app_directory(self):
        assert "/opt/jen/backups" not in _read("templates/database.html")

    def test_the_layout_is_in_every_templates_context(self):
        assert '"jen_layout": extensions.layout()' in _read("jen/__init__.py")


class TestTheInstallersDdnsKeyIsTheOneTheAppReads:
    def test_both_writers_use_dns_provider(self):
        for rel in ("install.sh", "run.py"):
            text = _read(rel)
            assert re.search(r"^dns_provider\s*=", text, re.M), f"{rel} no longer writes [ddns] dns_provider"
            assert not re.search(r"^provider\s*=", text, re.M), f"{rel} writes the key nothing reads"

    def test_the_app_reads_that_key(self):
        assert '"dns_provider"' in _read("jen/routes/ddns.py")


class TestTheImageShipsWhatItsRoutesServe:
    def test_the_dockerfile_copies_contrib_for_the_grafana_download(self):
        assert re.search(r"^COPY\s+contrib/\s+/opt/jen/contrib/", _read("Dockerfile"), re.M)
        assert '"contrib", "grafana", "jen-kea.json"' in _read("jen/routes/settings/__init__.py")
        assert (ROOT / "contrib" / "grafana" / "jen-kea.json").is_file()

    def test_the_contributor_notes_say_where_config_is_read_with_jen_root_set(self):
        for rel in ("CONTRIBUTING.md", "CLAUDE.md"):
            assert "$JEN_ROOT/etc" in _read(rel), rel


class TestStorkIsDescribedOnceAndWithItsSources:
    SOURCES = (
        "https://www.isc.org/stork/",
        "https://stork.readthedocs.io/en/latest/overview.html",
        "https://stork.readthedocs.io/en/latest/usage.html",
        "https://stork.readthedocs.io/en/latest/dhcp.html",
        "https://stork.readthedocs.io/en/latest/install.html",
    )

    def test_both_pages_cite_every_page_the_comparison_rests_on(self):
        for rel in ("README.md", "docs/about.md"):
            text = _read(rel)
            for url in self.SOURCES:
                assert url in text, f"{rel} does not cite {url}"

    def test_the_two_descriptions_agree(self):
        readme, about = _read("README.md"), _read("docs/about.md").replace("\r\n", "\n").replace("\n", " ")
        readme = readme.replace("\r\n", "\n").replace("\n", " ")
        for text in (readme, about):
            assert "graphical monitoring and management tool for Kea and BIND 9" in re.sub(r"\s+", " ", text)
            assert "official monitoring" not in text

    def test_statements_ISC_does_not_make_are_not_made_for_it(self):
        for rel in ("README.md", "docs/about.md", "docs/faq.md", "templates/about.html"):
            text = _read(rel)
            for claim in (
                "added more recently",
                "early stage",
                "Built to centralize",
                "built to centralize",
                "large enterprise and ISP",
                "overly complex",
                "practical alternative to ISC Stork",
            ):
                assert claim not in text, f"{rel} still says {claim!r}, which no ISC page does"
