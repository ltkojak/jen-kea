"""
tests/system/summarize.py
──────────────────────────
Q84 — turn the result file the system-boundary run writes into a Markdown
scenario table for $GITHUB_STEP_SUMMARY.

    python -m tests.system.summarize system-results/results.json > table.md

The file maps test name -> {"status", "seconds", "detail"?}. Statuses:
passed, failed, skipped, and known-bug (an xfail(strict) scenario that
failed the way its marker says — Jen really has the bug it names).
"""

import json
import sys

MARK = {"passed": "✅ pass", "failed": "❌ FAIL", "skipped": "⏭️ skipped", "known-bug": "🐞 known bug"}


def render(results: dict) -> str:
    lines = ["| scenario | result | seconds |", "|---|---|---|"]
    for name in sorted(results):
        row = results[name]
        label = MARK.get(row.get("status", ""), row.get("status", "—"))
        lines.append(f"| {name.replace('test_', '', 1)} | {label} | {row.get('seconds', '')} |")
    failed = [n for n, r in sorted(results.items()) if r.get("status") == "failed"]
    out = "\n".join(lines) + "\n"
    for n in failed:
        detail = (results[n].get("detail") or "").strip()
        if detail:
            out += f"\n<details><summary>{n}</summary>\n\n```\n{detail}\n```\n</details>\n"
    bugs = [n for n, r in sorted(results.items()) if r.get("status") == "known-bug"]
    if bugs:
        out += "\n🐞 known bug = the scenario fails today because Jen really has the bug it names; see the marker's reason in the test.\n"
    return out


def main(paths) -> str:
    results = {}
    for p in paths:
        try:
            with open(p) as fh:
                results.update(json.load(fh))
        except (OSError, ValueError):
            continue
    return (
        render(results)
        if results
        else "No results were produced (the stack may not have come up; see the run log and the container logs in the artifact).\n"
    )


if __name__ == "__main__":
    sys.stdout.write(main(sys.argv[1:]))
