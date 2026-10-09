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

import pytest

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
    """The complete file the wizard writes: the snapshot's values for everything, with `overrides` as {"section.key": value}.

    NOT what install.sh's wizard really writes (v5.68.0-beta.21, Q156): this builds the wizard's file FROM THE SNAPSHOT, a wizard install.sh does not
    have - the real one writes every key from variables it filled itself, and for the Kea connection, the Kea database, the SSH target and DDNS
    those are empty unless an answers file or the environment supplied them (`_cfgval`). `_real_wizard` below has that shape; this helper is only
    for what the merge does with values that ARE the snapshot's."""
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


def _real_wizard(seeded):
    """A TRANSCRIPTION of the heredoc in install.sh's `write_config`, not its output - what that function writes on an interactive `--configure` if
    it is fed the live values (seeded) or nothing (unseeded). Every key is written; the Kea, Kea-database, SSH and DDNS answers are the live file's
    values when the wizard was SEEDED from it (`--answers`), and BLANK (with the wizard's own defaults) when it was not. This pure fixture can drift
    from the heredoc; the bash harness in tests/test_installer_trust.py (`TestConfigureSeedsTheWizardFromTheLiveFile`, `TestConfigureKeepsThePromptedAnswersToo`)
    runs the REAL `write_config` and is the test that would notice."""
    answers = dict(cm.answers_from(CONFIGURED)) if seeded else {}

    def value(name, default=""):
        return answers.get(name, default)

    return f"""[kea]
api_url  = {value("JEN_KEA_API_URL")}
api_user = {value("JEN_KEA_API_USER")}
api_pass = {value("JEN_KEA_API_PASS")}

[kea_db]
host     = {value("JEN_KEA_DB_HOST")}
user     = {value("JEN_KEA_DB_USER")}
password = {value("JEN_KEA_DB_PASS")}
database = {value("JEN_KEA_DB_NAME", "kea")}

[jen_db]
host     = db
user     = jen
password = jen-secret
database = jen

[server]
http_port  = 5050
https_port = 8443

[kea_ssh]
host     = {value("JEN_KEA_SSH_HOST")}
user     = {value("JEN_KEA_SSH_USER")}
kea_conf = {value("JEN_KEA_CONF", "/etc/kea/kea-dhcp4.conf")}

[subnets]
1 = LAN, 10.0.0.0/24

[ddns]
log_path    = {value("JEN_DDNS_LOG", "/var/log/kea/kea-ddns.log")}
dns_provider = {value("JEN_DDNS_PROVIDER", "none")}
api_url     = {value("JEN_DDNS_URL")}
api_token   = {value("JEN_DDNS_TOKEN")}
forward_zone = {value("JEN_DDNS_ZONE")}
"""


CONFIGURED = """[kea]
api_url = http://kea.lan:8000
api_user = jen-api
api_pass = api-secret

[kea_db]
host = db.lan
user = kea
password = kea-secret
database = kea

[jen_db]
host = db
user = jen
password = jen-secret
database = jen

[server]
http_port = 5050
https_port = 8443

[kea_ssh]
host = kea.lan
user = svc
kea_conf = /etc/kea/kea-dhcp4.conf

[subnets]
1 = LAN, 10.0.0.0/24

[ddns]
log_path = /var/log/kea/kea-ddns.log
dns_provider = technitium
api_url = http://dns.lan:5380
api_token = ddns-token-1234
forward_zone = lan.example

[oidc]
enabled = true
issuer = https://idp.example
"""


class TestTheRealShapeOfTheWizard:
    """v5.68.0-beta.21 (Q156, item 1): `--configure` on a configured box blanked [kea], [kea_db], [kea_ssh] and [ddns]. The merge test above builds the
    wizard's file from the snapshot, so it could not see it."""

    def test_an_unseeded_wizard_wipes_the_kea_connection_and_the_ddns_token(self):
        """The bug, reproduced against the real shape: the merge faithfully applies what the wizard wrote, and the wizard wrote blanks."""
        merged = _ini(cm.merge(CONFIGURED, CONFIGURED, _real_wizard(seeded=False)))
        assert merged.get("kea", "api_url") == "" and merged.get("ddns", "api_token") == ""
        assert merged.get("ddns", "dns_provider") == "none"

    def test_a_seeded_wizard_keeps_the_connection_the_ssh_target_and_the_token(self):
        merged = _ini(cm.merge(CONFIGURED, CONFIGURED, _real_wizard(seeded=True)))
        assert merged.get("kea", "api_url") == "http://kea.lan:8000"
        assert merged.get("kea", "api_user") == "jen-api" and merged.get("kea", "api_pass") == "api-secret"
        assert merged.get("kea_db", "host") == "db.lan" and merged.get("kea_db", "password") == "kea-secret"
        assert merged.get("kea_ssh", "host") == "kea.lan" and merged.get("kea_ssh", "user") == "svc"
        assert (
            merged.get("ddns", "dns_provider") == "technitium" and merged.get("ddns", "api_token") == "ddns-token-1234"
        )
        assert merged.get("oidc", "issuer") == "https://idp.example", "and what the wizard never asks about"

    def test_a_save_made_while_the_wizard_was_open_still_wins_over_a_seeded_value(self):
        """The merge's "operator accepted the default, live wins" rule is reachable only now: the seeded wizard value EQUALS the snapshot's."""
        live_now = CONFIGURED.replace("http://kea.lan:8000", "http://kea2.lan:8000")
        merged = _ini(cm.merge(CONFIGURED, live_now, _real_wizard(seeded=True)))
        assert merged.get("kea", "api_url") == "http://kea2.lan:8000"

    def test_a_value_the_operator_changed_in_the_wizard_wins(self):
        wizard = _real_wizard(seeded=True).replace("http://dns.lan:5380", "http://dns2.lan:5380")
        merged = _ini(cm.merge(CONFIGURED, CONFIGURED, wizard))
        assert merged.get("ddns", "api_url") == "http://dns2.lan:5380"


class TestAnswersFrom:
    def test_the_fifteen_answers_a_configured_file_holds(self):
        pairs = dict(cm.answers_from(CONFIGURED))
        assert len(pairs) == 15 == len(cm.WIZARD_ANSWERS)
        assert pairs["JEN_KEA_API_URL"] == "http://kea.lan:8000" and pairs["JEN_DDNS_TOKEN"] == "ddns-token-1234"
        assert pairs["JEN_KEA_CONF"] == "/etc/kea/kea-dhcp4.conf" and pairs["JEN_DDNS_ZONE"] == "lan.example"

    def test_a_key_the_file_does_not_hold_is_not_listed(self):
        pairs = dict(cm.answers_from("[kea]\napi_url = http://x:8000\n"))
        assert pairs == {"JEN_KEA_API_URL": "http://x:8000"}

    def test_every_name_is_one_the_wizard_reads(self):
        """The names are exactly the `_cfgval` calls of the wizard's Kea, Kea-database, SSH and DDNS sections in install.sh."""
        import pathlib
        import re

        text = (pathlib.Path(__file__).resolve().parent.parent / "install.sh").read_text(encoding="utf-8")
        read = set(re.findall(r'_cfgval "(JEN_(?:KEA|DDNS)_[A-Z_]+)"', text))
        assert {name for _s, _k, name in cm.WIZARD_ANSWERS} == read

    def test_the_command_line_prints_name_value_lines(self, tmp_path, capsys):
        f = tmp_path / "live.ini"
        f.write_text(CONFIGURED)
        assert cm.main(["--answers", str(f)]) == 0
        lines = capsys.readouterr().out.splitlines()
        assert "JEN_KEA_API_URL=http://kea.lan:8000" in lines and "JEN_DDNS_TOKEN=ddns-token-1234" in lines

    def test_a_missing_file_prints_nothing(self, tmp_path, capsys):
        assert cm.main(["--answers", str(tmp_path / "nope")]) == 0
        assert capsys.readouterr().out == ""


class TestThePromptedDefaults:
    """v5.68.0-beta.22 (Q157, item 9): `--answers` also prints the five answers the wizard prompts for as `DEFAULT_<name>` lines."""

    def test_the_five_defaults_come_from_the_live_file(self):
        defaults = dict(cm.defaults_from(CONFIGURED.replace("https_port = 8443", "https_port = 9443")))
        assert defaults == {
            "DEFAULT_JEN_HTTP_PORT": "5050",
            "DEFAULT_JEN_HTTPS_PORT": "9443",
            "DEFAULT_JEN_DB_HOST": "db",
            "DEFAULT_JEN_DB_USER": "jen",
            "DEFAULT_JEN_DB_NAME": "jen",
        }
        assert len(cm.WIZARD_DEFAULTS) == 5

    def test_an_empty_or_missing_value_is_not_a_default(self):
        assert cm.defaults_from("[server]\nhttp_port =\n[jen_db]\nhost = h\n") == [("DEFAULT_JEN_DB_HOST", "h")]

    def test_the_command_line_prints_the_answers_then_the_defaults(self, tmp_path, capsys):
        f = tmp_path / "live.ini"
        f.write_text(CONFIGURED)
        assert cm.main(["--answers", str(f)]) == 0
        lines = capsys.readouterr().out.splitlines()
        assert "DEFAULT_JEN_HTTPS_PORT=8443" in lines and "JEN_KEA_API_URL=http://kea.lan:8000" in lines
        assert lines.index("JEN_KEA_API_URL=http://kea.lan:8000") < lines.index("DEFAULT_JEN_HTTPS_PORT=8443")

    def test_a_prompted_name_is_not_also_an_answer(self):
        names = {name for _s, _k, name in cm.WIZARD_ANSWERS}
        assert not names & {name for _s, _k, name in cm.WIZARD_DEFAULTS}, (
            "a defaulted value must stay changeable by the wizard"
        )

    def test_every_default_name_is_one_the_wizard_asks(self):
        import pathlib
        import re

        text = (pathlib.Path(__file__).resolve().parent.parent / "install.sh").read_text(encoding="utf-8")
        asked = set(re.findall(r'_ask\s+"(JEN_[A-Z_]+)"', text))
        assert {name for _s, _k, name in cm.WIZARD_DEFAULTS} <= asked


class TestAMultiLineValueTravelsOnOneLine:
    def test_newlines_and_backslashes_are_escaped(self):
        assert cm.escape_line("a\nb\\c\r\nd") == "a\\nb\\\\c\\nd"

    def test_the_command_line_prints_one_line_per_answer(self, tmp_path, capsys):
        f = tmp_path / "live.ini"
        f.write_text("[kea]\napi_url = http://x\napi_pass = one\n    two\n")
        cm.main(["--answers", str(f)])
        out = capsys.readouterr().out.splitlines()
        assert out == ["JEN_KEA_API_URL=http://x", "JEN_KEA_API_PASS=one\\ntwo"]


class TestTheIdentityDiff:
    """v5.68.0-beta.29 (Q165, edge 1): `--identity-diff BEFORE AFTER` lists every change to WHICH Kea Jen reaches. The installer refuses a `--configure` that makes one
    without `--change-endpoints` (tests/test_install_endpoint_guard.py), so this has to be exactly the set Jen's own guard protects (`jen.config.identity_view`)."""

    LIVE = """[kea]
api_url = http://1.1.1.1:8000
connection_mode = ca

[kea_ssh]
host = kea-a.lan
user = jen
kea_conf = /etc/kea/kea-dhcp4.conf

[kea_server_2]
name = kea-b
api_url = http://2.2.2.2:8000
ssh_host = kea-b.lan
ssh_user = jen

[jen_db]
password = secret
"""

    def test_nothing_changed_prints_nothing(self):
        assert cm.identity_diff(self.LIVE, self.LIVE) == []

    @pytest.mark.parametrize(
        "old,new,line",
        [
            (
                "api_url = http://1.1.1.1:8000",
                "api_url = http://9.9.9.9:8000",
                "[kea] api_url: http://1.1.1.1:8000 -> http://9.9.9.9:8000",
            ),
            ("connection_mode = ca", "connection_mode = direct", "[kea] connection_mode: ca -> direct"),
            ("host = kea-a.lan", "host = kea-z.lan", "[kea_ssh] host: kea-a.lan -> kea-z.lan"),
            ("user = jen\nkea_conf", "user = ops\nkea_conf", "[kea_ssh] user: jen -> ops"),
            (
                "kea_conf = /etc/kea/kea-dhcp4.conf",
                "kea_conf = /srv/kea.conf",
                "[kea_ssh] kea_conf: /etc/kea/kea-dhcp4.conf -> /srv/kea.conf",
            ),
            ("ssh_host = kea-b.lan", "ssh_host = kea-q.lan", "[kea_server_2] ssh_host: kea-b.lan -> kea-q.lan"),
        ],
    )
    def test_each_identity_field_is_reported(self, old, new, line):
        assert old in self.LIVE
        assert cm.identity_diff(self.LIVE, self.LIVE.replace(old, new)) == [line]

    def test_credentials_the_name_and_the_database_are_not_identity(self):
        changed = self.LIVE.replace("password = secret", "password = other-secret").replace(
            "name = kea-b", "name = renamed"
        )
        assert cm.identity_diff(self.LIVE, changed) == []

    def test_a_blank_config_path_is_the_default_one(self):
        blank = self.LIVE.replace("kea_conf = /etc/kea/kea-dhcp4.conf\n", "kea_conf =\n")
        assert cm.identity_diff(self.LIVE, blank) == []

    def test_a_server_removed_or_added_is_one_line(self):
        gone = self.LIVE.split("[kea_server_2]")[0] + "[jen_db]\npassword = secret\n"
        assert cm.identity_diff(self.LIVE, gone) == ["[kea_server_2] removed"]
        assert cm.identity_diff(gone, self.LIVE) == ["[kea_server_2] added"]

    def test_the_command_line_prints_the_lines_and_exits_zero(self, tmp_path, capsys):
        before, after = tmp_path / "before.ini", tmp_path / "after.ini"
        before.write_text(self.LIVE)
        after.write_text(self.LIVE.replace("connection_mode = ca", "connection_mode = direct"))
        assert cm.main(["--identity-diff", str(before), str(after)]) == 0
        assert capsys.readouterr().out == "[kea] connection_mode: ca -> direct\n"
        assert cm.main(["--identity-diff", str(before), str(before)]) == 0
        assert capsys.readouterr().out == ""

    def test_it_agrees_with_the_identity_the_apps_own_guard_compares(self):
        """The same set of changes as `jen.config.identity_view`: the installer's check is not a second opinion about what identity is."""
        import jen.config as jconfig

        def view(text):
            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(text)
            parser.set("kea", "api_user", "u") if parser.has_section("kea") else None
            return jconfig.identity_view(parser)

        variants = [
            self.LIVE.replace("api_url = http://1.1.1.1:8000", "api_url = http://9.9.9.9:8000"),
            self.LIVE.replace("connection_mode = ca", "connection_mode = direct"),
            self.LIVE.replace("host = kea-a.lan", "host = kea-z.lan"),
            self.LIVE.replace("ssh_user = jen", "ssh_user = ops"),
            self.LIVE.replace("password = secret", "password = x"),
            self.LIVE.replace("name = kea-b", "name = renamed"),
        ]
        for variant in variants:
            assert bool(cm.identity_diff(self.LIVE, variant)) == (view(self.LIVE) != view(variant)), variant
