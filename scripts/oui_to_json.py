#!/usr/bin/env python3
"""
scripts/oui_to_json.py
──────────────────────
Regenerate jen/services/oui_db.json from jen.services.fingerprint.OUI_DB.

v5.11.1 moved the ~1,350-entry OUI table out of fingerprint.py (a
hand-edited Python dict that dominated the file) into a plain JSON data
file the module loads once at import. This script is how that file gets
(re)written: it imports the live OUI_DB — which after 5.11.1 is itself
loaded from the JSON — and dumps it back out sorted, one OUI per line,
UTF-8 (emoji stay literal). Running it with no source change is a
no-op reformat; to add or correct a vendor, edit the JSON and run this
to normalise it.
"""

import json
import os
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from jen.services.fingerprint import OUI_DB  # noqa: E402

_OUT = os.path.join(_REPO, "jen", "services", "oui_db.json")


def dumps(table: dict) -> str:
    """One `"oui": ["vendor", "type", "icon"]` per line, sorted."""
    items = sorted(table.items())
    lines = ["{"]
    for i, (key, value) in enumerate(items):
        tail = "," if i < len(items) - 1 else ""
        lines.append(f"  {json.dumps(key)}: {json.dumps(list(value), ensure_ascii=False)}{tail}")
    lines.append("}\n")
    return "\n".join(lines)


def main() -> None:
    with open(_OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(dumps(OUI_DB))
    print(f"wrote {len(OUI_DB)} OUI entries -> {os.path.relpath(_OUT, _REPO)}")


if __name__ == "__main__":
    main()
