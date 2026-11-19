"""
tests/test_the_readiness_sentence_is_masked.py
──────────────────────────────────────────────
Q241 (AZ2 of the executing pass on v7.1.0-beta.9).

The readiness check stores one sentence about where a server's file and its running daemon differ (`agree_at`), Settings -> Kea prints it and the support
bundle's `servers.json` carries it. Its two values went through `without_userinfo` only, so the sentence printed what Config history masks: a token after `#`,
a query value and the password of an address that is not http(s). The values go through `without_credentials` now, the ONE rule Config history uses, and a
sentence a release before this one stored has its values withheld wherever it is read.
"""

import json

import pytest

from jen.models import user
from jen.services import kea_api_config as api
from jen.services import support_bundle as sb
from jen.services.secret_keys import without_credentials

PATH = "Dhcp4.hooks-libraries[0].parameters.url"

# (what, the file's value, the daemon's value, what must not be printed)
WORLDS = [
    ("a token after #", "https://h/x#STANDINTOKa", "https://h/x#STANDINTOKb", ("STANDINTOK",)),
    ("a bare query token", "https://h/x?STANDINTOKa", "https://h/x?STANDINTOKb", ("STANDINTOK",)),
    ("a named query value", "https://h/x?sig=STANDINSIGa", "https://h/x?sig=STANDINSIGb", ("STANDINSIG",)),
    ("an ldap password", "ldap://u:STANDINPWa@h/", "ldap://u:STANDINPWb@h/", ("STANDINPW",)),
    ("an http password", "http://alice:STANDINPWa@h/", "http://alice:STANDINPWb@h/", ("STANDINPW", "alice")),
]


def _diff(mine, theirs):
    file_cfg = {"Dhcp4": {"hooks-libraries": [{"library": "/l.so", "parameters": {"url": mine}}]}}
    daemon = {"Dhcp4": {"hooks-libraries": [{"library": "/l.so", "parameters": {"url": theirs}}]}}
    return api.difference_text(file_cfg, daemon, "dhcp4", frozenset())


class TestTheSentence:
    @pytest.mark.parametrize("what,mine,theirs,secrets", WORLDS, ids=[w[0] for w in WORLDS])
    def test_it_prints_nothing_config_history_masks(self, what, mine, theirs, secrets):
        text = _diff(mine, theirs)
        assert text.startswith(f"at {PATH}: the file and the daemon differ only in what is not shown"), text
        for secret in secrets:
            assert secret not in text, text

    @pytest.mark.parametrize("what,mine,theirs,secrets", WORLDS, ids=[w[0] for w in WORLDS])
    def test_each_value_is_shown_as_config_history_shows_it(self, what, mine, theirs, secrets):
        assert json.dumps(without_credentials(mine)) in _diff(mine, theirs)

    def test_a_difference_outside_what_is_masked_prints_both_values(self):
        text = _diff("https://h:8004/x#one", "https://h:8005/x#two")
        assert text == f'at {PATH}: the file says "https://h:8004/x#********", the daemon "https://h:8005/x#********"'

    def test_the_sentence_that_says_two_values_print_alike_names_what_is_masked_now(self):
        assert (
            "a user name or password inside an address, a query value or what follows its #, or past the 60th character"
            in _diff("https://h/x#a", "https://h/x#b")
        )

    def test_the_leaf_asks_the_one_masker(self):
        import inspect

        source = inspect.getsource(api._leaf)
        assert "value = without_credentials(value)" in source and "without_userinfo(" not in source


SID = 9241


@pytest.fixture
def stored(app):
    """The real settings table: what `store_probe` writes is what `stored_probe` reads."""
    key = api.PROBE_KEY.format(SID)
    yield lambda data: user.set_global_setting(key, json.dumps(data, sort_keys=True))
    user.set_global_setting(key, "")


OLD = f'at {PATH}: the file says "https://h/x#STANDINTOKa", the daemon "https://h/x#STANDINTOKb"'


class TestASentenceAnEarlierReleaseStored:
    def test_its_values_are_withheld_and_its_path_is_kept(self, stored):
        stored({"at": "2026-11-17T10:00:00+00:00", "agree": False, "agree_at": OLD})
        said = api.stored_probe(SID)["agree_at"]
        assert said == f"at {PATH}: {api.AGREE_AT_WITHHELD}"
        assert "STANDINTOK" not in said and "://" not in said

    def test_a_sentence_with_no_path_is_withheld_whole(self, stored):
        stored({"agree": False, "agree_at": "the daemon at https://h/x?STANDINTOKa could not be asked"})
        assert api.stored_probe(SID)["agree_at"] == api.AGREE_AT_WITHHELD

    def test_a_sentence_that_holds_no_address_is_read_as_stored(self, stored):
        plain = "at Dhcp4.valid-lifetime: the file says 3600, the daemon 7200"
        stored({"agree": False, "agree_at": plain})
        assert api.stored_probe(SID)["agree_at"] == plain

    def test_a_sentence_stored_under_this_rule_is_read_as_stored(self, stored):
        new = _diff("https://h:8004/x#one", "https://h:8005/x#two")
        stored({"agree": False, "agree_at": new, "agree_at_rule": api.AGREE_AT_RULE})
        assert api.stored_probe(SID)["agree_at"] == new

    def test_what_was_read_and_stored_again_reads_the_same(self, stored):
        stored({"agree": False, "agree_at": OLD})
        first = api.stored_probe(SID)
        assert api.store_probe(SID, first)
        assert api.stored_probe(SID) == first

    def test_the_bundle_carries_the_withheld_sentence(self, stored, monkeypatch):
        """The exported layer, through the real `stored_probe` and the real settings table."""
        from jen import extensions
        from jen.services import kea_host, kea_tls

        monkeypatch.setattr(kea_host, "helper_status", dict)
        monkeypatch.setattr(kea_tls, "issued_server_copies", list)
        stored({"at": "2026-11-17T10:00:00+00:00", "agree": False, "agree_at": OLD})
        monkeypatch.setattr(
            extensions,
            "KEA_SERVERS",
            [{"id": SID, "name": "kea-q241", "api_url": "http://127.0.0.1:1", "ssh_host": "", "role": "primary"}],
        )
        rows = sb._collect_servers()
        facts = [r for r in rows if r.get("id") == SID][0]["write_mode_facts"]
        assert facts["agree_at"] == f"at {PATH}: {api.AGREE_AT_WITHHELD}"
        assert "STANDINTOK" not in json.dumps(rows)


class TestTheProbeMarksItsSentence:
    def test_the_marker_is_set_on_the_line_that_sets_the_sentence(self):
        import inspect

        lines = inspect.getsource(api.probe).splitlines()
        at = [i for i, line in enumerate(lines) if 'out["agree_at"] =' in line]
        assert len(at) == 1 and 'out["agree_at_rule"] = AGREE_AT_RULE' in lines[at[0] + 1]

    def test_every_reader_of_the_stored_result_goes_through_stored_probe(self):
        """Whole tree: the settings key is read in one function."""
        import pathlib

        root = pathlib.Path(api.__file__).resolve().parents[2]
        hits = []
        for folder in ("jen", "plugins"):
            for p in sorted((root / folder).rglob("*.py")):
                text = p.read_text(encoding="utf-8")
                if "PROBE_KEY" in text or "config_transport_probe" in text:
                    hits.append(p.relative_to(root).as_posix())
        assert hits == ["jen/services/kea_api_config.py"], hits
        source = (root / "jen/services/kea_api_config.py").read_text(encoding="utf-8")
        assert source.count("PROBE_KEY.format(") == 2, "one reader (`stored_probe`) and one writer (`store_probe`)"
