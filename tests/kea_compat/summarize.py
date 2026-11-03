"""
tests/kea_compat/summarize.py
──────────────────────────────
Q50 — turn the per-version result files the compat job collects into a
Markdown version x check table for $GITHUB_STEP_SUMMARY.

    python -m tests.kea_compat.summarize results/*.json > table.md

Each file is named <kea-version>.json and maps test name -> outcome.

Q211 adds `--config-write`: the per-version config-write-<version>.json files (rows + recorded facts, written by test_config_write.py)
become the "Configuration over the API" tables, one row per ordered row and one per recorded fact, one column per Kea version.

    python -m tests.kea_compat.summarize --config-write results/config-write-*.json
"""

import json
import os
import sys

MARK = {"passed": "✅", "failed": "❌", "skipped": "⏭️", "xfailed": "🐞"}  # 🐞 = a known bug, expected to fail


def render(results: dict) -> str:
    """results: {version: {test_name: outcome}} -> Markdown table."""
    versions = sorted(results)
    checks = sorted({name for r in results.values() for name in r})
    lines = ["| check | " + " | ".join(versions) + " |", "|---|" + "---|" * len(versions)]
    for name in checks:
        cells = [MARK.get(results[v].get(name, ""), "—") for v in versions]
        lines.append(f"| {name.replace('test_', '')} | " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def main(paths) -> str:
    results = {}
    for p in paths:
        try:
            with open(p) as fh:
                results[os.path.splitext(os.path.basename(p))[0]] = json.load(fh)
        except (OSError, ValueError):
            continue
    return render(results) if results else "No compatibility results were produced.\n"


def _yn(value):
    return "—" if value is None else ("yes" if value else "no")


def _answer(brief):
    """A recorded reply ({"result", "text"}) as one cell: `ok`, or the daemon's refusal in its own words."""
    if not isinstance(brief, dict):
        return "—"
    if brief.get("result") == 0:
        return "ok"
    return f"refused ({brief.get('result')}): {(brief.get('text') or '').strip()[:90]}"


def _redacted(data):
    plain = data.get("config_get_lease_password_in_plain_text")
    return "—" if plain is None else ("no: plain text" if plain else "yes")


def _chown(data):
    if data.get("chown_needed") is None:
        return "—"
    if not data["chown_needed"]:
        return "no"
    return f"yes, to uid {(data.get('chown') or {}).get('to_uid')}"


def _where(data, key_flag, key_where):
    flag = data.get(key_flag)
    if flag is None:
        return "—"
    return f"yes ({data.get(key_where)})" if flag else "no"


# (label, how a cell is read from one version's recorded facts)
WRITE_FACTS = [
    ("config-get redacted?", _redacted),
    ("digest on config-get", lambda d: _where(d, "hash_on_config_get", "hash_on_config_get_where")),
    ("digest on config-set", lambda d: _where(d, "hash_on_config_set", "hash_on_config_set_where")),
    ("config-set moved the digest", lambda d: _yn(d.get("hash_moved_by_config_set"))),
    (
        "daemon runs as",
        lambda d: str((d.get("daemon_runs_as") or {}).get("name") or (d.get("daemon_runs_as") or {}).get("uid") or "—"),
    ),
    ("mounted file, as the daemon sees it", lambda d: _owner_mode(d.get("mounted_file_as_the_daemon_sees_it"))),
    ("mounted directory, as the daemon sees it", lambda d: _owner_mode(d.get("mounted_dir_as_the_daemon_sees_it"))),
    ("config-write as shipped", lambda d: _answer(d.get("config_write_as_shipped"))),
    ("chown of the file needed?", _chown),
    ("config-write after the chown", lambda d: _answer(d.get("config_write_after_chown"))),
    ("what the write needed", lambda d: str(d.get("write_needed") or "—")),
    (
        "the file carries the subnet and the password in plain text",
        lambda d: _yn(
            d.get("file_carries_the_new_subnet") and d.get("file_password_in_plain_text")
            if "file_carries_the_new_subnet" in d
            else None
        ),
    ),
    ("subnet back after a restart", lambda d: _yn(d.get("subnet_after_restart"))),
    ("digest the same after a restart", lambda d: _yn(d.get("hash_survives_restart"))),
    (
        "bad config-set refused, old config serving",
        lambda d: _yn(
            d.get("subnets_unchanged_after_bad_set") and d.get("hash_unchanged_after_bad_set")
            if "subnets_unchanged_after_bad_set" in d
            else None
        ),
    ),
    ("config-write outside the directory", lambda d: _answer(d.get("config_write_outside_the_directory"))),
    ("sibling name in the directory", lambda d: _answer(d.get("sibling_write"))),
    ("sibling name, directory writable", lambda d: _answer(d.get("sibling_write_directory_writable"))),
    ("a stale config-set accepted by the daemon", lambda d: _yn(d.get("a_stale_set_is_accepted_by_the_daemon"))),
    ("marker in config-get", lambda d: _yn(d.get("marker_in_config_get"))),
    ("marker in the written file", lambda d: _yn(d.get("marker_in_file_after_write"))),
    ("keys config-get adds at the top of Dhcp4", lambda d: _keys(d.get("keys_added_top"))),
    ("keys config-get adds to a subnet", lambda d: _keys(d.get("keys_added_subnet"))),
    ("keys config-get adds to a pool", lambda d: _keys(d.get("keys_added_pool"))),
    ("hash beside Dhcp4 in config-get", lambda d: _yn(d.get("hash_beside_dhcp4"))),
    ("config-set with a hash key sent back", lambda d: _answer(d.get("config_set_accepts_hash_key"))),
    ("config-set seconds", lambda d: str(d.get("config_set_seconds", "—"))),
    (
        "digest of a daemon started on Jen's rendering equals config-set's",
        lambda d: _yn(d.get("reload_digest_equals_set_digest")),
    ),
    (
        "why the second daemon did not run",
        lambda d: str(
            d.get("reload_error") or ("did not start" if d.get("reload_second_daemon_started") is False else "—")
        ),
    ),
    ("original file restored byte for byte", lambda d: _yn(d.get("original_file_restored_byte_for_byte"))),
    (
        "unprivileged daemon (uid 100): config-write as the file stands",
        lambda d: _answer(d.get("nonroot_config_write_as_shipped")),
    ),
    (
        "unprivileged daemon: after the daemon's group + g+w on the file",
        lambda d: _answer(d.get("nonroot_config_write_after_grant")),
    ),
    ("unprivileged daemon: written in place (same inode)", lambda d: _yn(d.get("nonroot_written_in_place"))),
    ("unprivileged daemon: sibling name", lambda d: _answer(d.get("nonroot_sibling_write"))),
    (
        "unprivileged daemon: why the probe did not run",
        lambda d: str(d.get("nonroot_error") or ("did not start" if d.get("nonroot_started") is False else "—")),
    ),
]


def _keys(value):
    if value is None:
        return "—"
    return ", ".join(value) if value else "none"


def _owner_mode(facts):
    if not isinstance(facts, dict):
        return "—"
    return f"{facts.get('owner')}:{facts.get('group')} {facts.get('mode')}"


def _cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_config_write(results: dict) -> str:
    """results: {version: {"rows": {row: outcome}, <fact>: value ...}} -> the rows table, then the recorded-facts table (Markdown)."""
    versions = sorted(results)
    head = "| {} | " + " | ".join(versions) + " |"
    sep = "|---|" + "---|" * len(versions)
    rows = sorted({name for r in results.values() for name in (r.get("rows") or {})})
    lines = [head.format("row"), sep]
    for name in rows:
        cells = [MARK.get((results[v].get("rows") or {}).get(name, ""), "—") for v in versions]
        lines.append(f"| {name.replace('test_', '')} | " + " | ".join(cells) + " |")
    lines += ["", head.format("recorded fact"), sep]
    for label, read in WRITE_FACTS:
        lines.append(f"| {label} | " + " | ".join(_cell(read(results[v])) for v in versions) + " |")
    return "\n".join(lines) + "\n"


def main_config_write(paths) -> str:
    results = {}
    for p in paths:
        try:
            with open(p) as fh:
                results[os.path.splitext(os.path.basename(p))[0][len("config-write-") :]] = json.load(fh)
        except (OSError, ValueError):
            continue
    return render_config_write(results) if results else "No configuration-over-the-API results were produced.\n"


if __name__ == "__main__":
    if sys.argv[1:2] == ["--config-write"]:
        sys.stdout.write(main_config_write(sys.argv[2:]))
    else:
        sys.stdout.write(main(sys.argv[1:]))
