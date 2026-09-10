"""
tests/test_oui_db.py
────────────────────
v5.11.1 — the OUI table moved from a ~1,350-entry hand-edited dict in
jen/services/fingerprint.py into jen/services/oui_db.json, loaded once
at import. These guard the data file's shape and that the module still
resolves a lookup through it — and that the dict didn't creep back into
the .py.
"""

import json
import pathlib
import re

from jen.services import fingerprint

_OUI_JSON = pathlib.Path(fingerprint.__file__).parent / "oui_db.json"
_KEY_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){2}$")


def test_json_file_exists():
    assert _OUI_JSON.is_file()


def test_has_a_real_table():
    data = json.loads(_OUI_JSON.read_text(encoding="utf-8"))
    assert len(data) >= 1000


def test_every_key_is_a_lowercase_oui():
    data = json.loads(_OUI_JSON.read_text(encoding="utf-8"))
    bad = [k for k in data if not _KEY_RE.match(k)]
    assert not bad, bad[:10]


def test_every_value_is_a_three_item_list_of_strings():
    data = json.loads(_OUI_JSON.read_text(encoding="utf-8"))
    bad = [
        k for k, v in data.items() if not (isinstance(v, list) and len(v) == 3 and all(isinstance(x, str) for x in v))
    ]
    assert not bad, bad[:10]


def test_module_loads_it_into_oui_db_as_tuples():
    assert fingerprint.OUI_DB["00:00:0c"] == ("Cisco", "network", "🌐")
    assert isinstance(fingerprint.OUI_DB["00:00:0c"], tuple)


def test_lookup_oui_resolves_through_the_file():
    assert fingerprint.lookup_oui("00:00:0c:aa:bb:cc")[0] == "Cisco"


def test_dict_did_not_creep_back_into_the_module():
    src = pathlib.Path(fingerprint.__file__).read_text(encoding="utf-8")
    assert '"00:00:0c"' not in src
    assert "'00:00:0c'" not in src
