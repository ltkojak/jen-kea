"""
tests/kea_compat/summarize.py
──────────────────────────────
Q50 — turn the per-version result files the compat job collects into a
Markdown version x check table for $GITHUB_STEP_SUMMARY.

    python -m tests.kea_compat.summarize results/*.json > table.md

Each file is named <kea-version>.json and maps test name -> outcome.
"""

import json
import os
import sys

MARK = {"passed": "✅", "failed": "❌", "skipped": "⏭️"}


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


if __name__ == "__main__":
    sys.stdout.write(main(sys.argv[1:]))
