"""
tests/test_config_merge.py
──────────────────────────
v5.68.0-beta.18 (Q153) - `tools/config_merge.py`: the installer wizard's answers merged INTO the live jen.config. `install.sh --configure` used to
rewrite the file from the wizard's variables alone: a Settings save made while the wizard was open was overwritten by the installer's older copy,
and everything Jen keeps in that file that the wizard never asks about ([oidc], extra Kea servers, [kea6] ...) was dropped. Pure stdlib:
`pytest --noconftest tests/test_config_merge.py`.
"""

import configparser
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("config_merge", ROOT / "tools" / "config_merge.py")
cm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cm)

SNAPSHOT = """[kea]
api_url = http://old:8000
api_user = u

[kea_db]
password = kea-old

[server]
http_port = 5050
https_port = 8443

[subnets]
1 = LAN, 10.0.0.0/24
2 = IoT, 10.0.1.0/24
"""


def _ini(text):
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(text)
    return parser


def _wizard(**overrides):
    """The complete file the wizard writes: the snapshot's values for everything, with `overrides` as {"section.key": value}."""
    parser = _ini(SNAPSHOT)
    parser.add_section("ddns")
    parser.set("ddns", "dns_provider", "none")
    for dotted, value in overrides.items():
        section, key = dotted.split(".", 1)
        parser.set(section, key, value)
    import io

    out = io.StringIO()
    parser.write(out)
    return out.getvalue()


def _live(extra=""):
    return SNAPSHOT + extra


class TestWhatTheWizardDidNotAskAbout:
    def test_a_section_the_wizard_never_writes_survives(self):
        live = _live("\n[oidc]\nenabled = true\nissuer = https://idp\n\n[kea_server_2]\napi_url = http://kea2:8000\n")
        merged = _ini(cm.merge(SNAPSHOT, live, _wizard()))
        assert (
            merged.get("oidc", "issuer") == "https://idp"
            and merged.get("kea_server_2", "api_url") == "http://kea2:8000"
        )

    def test_a_key_in_a_section_the_wizard_does_write_survives(self):
        live = _live().replace("[server]\n", "[server]\nthreads = 12\nmetrics_token = abc\n")
        merged = _ini(cm.merge(SNAPSHOT, live, _wizard()))
        assert merged.get("server", "threads") == "12" and merged.get("server", "metrics_token") == "abc"


class TestAKeyTheOperatorChanged:
    def test_the_wizards_new_value_wins_over_the_snapshot_and_the_live_file(self):
        merged = _ini(cm.merge(SNAPSHOT, SNAPSHOT, _wizard(**{"kea_db.password": "kea-new"})))
        assert merged.get("kea_db", "password") == "kea-new"

    def test_it_wins_even_when_a_save_changed_the_same_key_meanwhile(self):
        live = SNAPSHOT.replace("http_port = 5050", "http_port = 6000")
        merged = _ini(cm.merge(SNAPSHOT, live, _wizard(**{"server.http_port": "7000"})))
        assert merged.get("server", "http_port") == "7000", "the operator typed it just now"

    def test_a_new_key_is_added(self):
        merged = _ini(cm.merge(SNAPSHOT, SNAPSHOT, _wizard()))
        assert merged.get("ddns", "dns_provider") == "none"


class TestAKeyTheOperatorLeftAlone:
    def test_a_settings_save_made_during_the_wizard_survives(self):
        live = SNAPSHOT.replace("api_url = http://old:8000", "api_url = http://saved-meanwhile:8000")
        merged = _ini(cm.merge(SNAPSHOT, live, _wizard()))
        assert merged.get("kea", "api_url") == "http://saved-meanwhile:8000", (
            "the wizard still says 'old' (it accepted the default)"
        )

    def test_a_subnet_added_meanwhile_is_kept_and_one_removed_meanwhile_stays_removed(self):
        live = SNAPSHOT.replace("2 = IoT, 10.0.1.0/24\n", "3 = Guest, 10.0.2.0/24\n")
        merged = _ini(cm.merge(SNAPSHOT, live, _wizard()))
        subnets = dict(merged.items("subnets"))
        assert subnets == {"1": "LAN, 10.0.0.0/24", "3": "Guest, 10.0.2.0/24"}

    def test_unchanged_everything_is_the_live_file_unchanged(self):
        merged = _ini(cm.merge(SNAPSHOT, SNAPSHOT, _wizard()))
        original = _ini(SNAPSHOT)
        for section in original.sections():
            assert dict(merged.items(section)) == dict(original.items(section))


class TestFreshAndOddInputs:
    def test_no_snapshot_means_every_wizard_key_applies_and_live_only_keys_stay(self):
        merged = _ini(cm.merge("", "[oidc]\nenabled = true\n", _wizard()))
        assert merged.get("kea", "api_url") == "http://old:8000" and merged.get("oidc", "enabled") == "true"

    def test_percent_signs_in_a_password_are_not_interpolated(self):
        wizard = "[jen_db]\npassword = p%ss%word\n"
        assert _ini(cm.merge("", "", wizard)).get("jen_db", "password") == "p%ss%word"

    def test_an_unreadable_live_file_is_an_error_not_a_silent_overwrite(self):
        import pytest

        with pytest.raises(SystemExit):
            cm.merge("", "this is not an ini file\n", _wizard())

    def test_the_cli_prints_the_merged_file_with_the_wizards_header(self, tmp_path, monkeypatch, capsys):
        live = tmp_path / "live.ini"
        live.write_text(_live("\n[oidc]\nenabled = true\n"))
        snap = tmp_path / "snap.ini"
        snap.write_text(SNAPSHOT)
        import io

        monkeypatch.setattr("sys.stdin", io.StringIO("# Jen - header\n# generated\n# edit\n\n" + _wizard()))
        assert cm.main(["--snapshot", str(snap), "--live", str(live)]) == 0
        out = capsys.readouterr().out
        assert out.startswith("# Jen - header\n# generated\n# edit\n\n") and "[oidc]" in out
