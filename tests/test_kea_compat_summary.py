"""
tests/test_kea_compat_summary.py
────────────────────────────────
Q211 - the "Configuration over the API" tables the kea-compat job writes into its summary are rendered from the per-version
config-write-<version>.json files (tests/kea_compat/test_config_write.py). Pure: no daemon, no database.
"""

import json
import pathlib

from tests.kea_compat import summarize

REPO = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = (REPO / ".github" / "workflows" / "kea-compat.yml").read_text(encoding="utf-8")


def _results():
    return {
        "3.0.5": {
            "rows": {
                "test_01_config_get_is_not_redacted": "passed",
                "test_03_config_write_persists_and_a_restart_keeps_it": "failed",
            },
            "config_get_lease_password_in_plain_text": True,
            "hash_on_config_get": True,
            "hash_on_config_get_where": "arguments.hash",
            "config_write_as_shipped": {"result": 1, "text": "Permission | denied"},
            "chown_needed": True,
            "chown": {"to_uid": 100},
        },
        "3.2.1": {"rows": {"test_01_config_get_is_not_redacted": "passed"}},
    }


class TestTheTables:
    def test_a_row_per_row_and_a_column_per_version(self):
        text = summarize.render_config_write(_results())
        assert "| row | 3.0.5 | 3.2.1 |" in text
        assert "| 01_config_get_is_not_redacted | ✅ | ✅ |" in text
        assert "| 03_config_write_persists_and_a_restart_keeps_it | ❌ | — |" in text

    def test_a_fact_the_version_did_not_record_is_a_dash_not_a_guess(self):
        text = summarize.render_config_write(_results())
        assert "| digest on config-set | — | — |" in text
        assert "| config-get redacted? | no: plain text | — |" in text

    def test_a_refusal_is_shown_in_the_daemons_own_words_and_cannot_break_the_table(self):
        text = summarize.render_config_write(_results())
        assert "| config-write as shipped | refused (1): Permission \\| denied | — |" in text
        assert "| chown of the file needed? | yes, to uid 100 | — |" in text

    def test_files_are_read_by_their_version_and_a_missing_one_is_said(self, tmp_path):
        for version, data in _results().items():
            (tmp_path / f"config-write-{version}.json").write_text(json.dumps(data), encoding="utf-8")
        paths = sorted(str(p) for p in tmp_path.iterdir())
        assert "| row | 3.0.5 | 3.2.1 |" in summarize.main_config_write(paths)
        assert "No configuration-over-the-API results" in summarize.main_config_write([str(tmp_path / "nope.json")])


class TestTheWorkflowRunsIt:
    def test_the_write_step_sits_between_the_read_only_suite_and_the_log_level_step(self):
        suite = WORKFLOW.index("name: Run the compatibility suite")
        write = WORKFLOW.index("name: Configuration over the API")
        levels = WORKFLOW.index("name: What Kea's log carries at each level")
        assert suite < write < levels

    def test_only_the_read_only_steps_mount_the_directory_read_only_and_the_write_step_says_it_restores(self):
        assert (
            WORKFLOW.count('-v "$PWD/kea-conf:/etc/kea:ro"') == 1
        )  # the daemon's first start; the write step recreates it read-write from Python
        assert "python -m pytest tests/kea_compat/test_config_write.py -m kea_write -v" in WORKFLOW
        header = WORKFLOW.split("\non:\n")[0]
        assert "Configuration over the API" in header and "puts the original file back" in header

    def test_the_summary_job_renders_the_facts_and_puts_them_in_the_log_too(self):
        assert "summarize --config-write artifacts/*/config-write-*.json" in WORKFLOW
        assert 'cat "$GITHUB_STEP_SUMMARY"' in WORKFLOW

    def test_the_marker_is_registered_and_the_default_collection_skips_it(self):
        ini = (REPO / "pytest.ini").read_text(encoding="utf-8")
        assert "kea_write:" in ini
        conf = (REPO / "tests" / "kea_compat" / "conftest.py").read_text(encoding="utf-8")
        assert '"kea_write" in item.keywords' in conf
