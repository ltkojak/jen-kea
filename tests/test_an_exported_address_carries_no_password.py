"""v5.70.1 (Q215 carrying Q221's AE7; CRED-005) - an address never carries its user name or password out of the box.

A legacy `api_url` that carries user-info (`https://admin:secret@10.0.0.5:8004/`) is supported input: Jen warns about it, Health names it, and Jen keeps dialing it as written. The support bundle - the
file the product asks an operator to attach to a bug report - exported that address in the clear in `config.ini.redacted` and in `servers.json`, beside a masked `api_pass`. The rule is held at the
one place every member of the bundle is made (`support_bundle._json` and `redact_ini_text`), by ONE definition (`secret_keys.scrub_urls` for text, `secret_keys.without_userinfo` for a value), so a
section added later is covered by being a member. Every test here seeds a marker in the user-info and asserts two things: the marker is gone, and the host is still there (a test that only looked
for the marker would pass on an empty file)."""

import io
import pathlib
import zipfile

import pytest

from jen.services import auth, secret_keys
from jen.services import support_bundle as sb

ROOT = pathlib.Path(__file__).resolve().parent.parent
MARK = "Q221MARKER"
HOST = "10.0.0.5:8004"
#: what a password may carry: the plain case, and every character the pattern of 7.0.0-beta.6 stopped at (a quote, an angle bracket) or split on (an `@`, a colon)
PASSWORDS = [MARK, f"a'{MARK}", f'a"{MARK}', f"a@{MARK}", f"a<{MARK}>", f"{MARK}:x"]
#: a password with a space in it: only a VALUE can be split around it (`urlsplit`), never an address inside a sentence
SPACED = f"a {MARK}"


def _url(password, scheme="https", tail="/"):
    return f"{scheme}://admin:{password}@{HOST}{tail}"


class TestTheOneDefinition:
    @pytest.mark.parametrize("password", [*PASSWORDS, SPACED])
    def test_a_value_that_is_an_address_loses_its_user_info_whatever_it_carries(self, password):
        out = secret_keys.without_userinfo(_url(password))
        assert out == f"https://{HOST}/"
        assert secret_keys.without_userinfo(out) == out, "idempotent"

    @pytest.mark.parametrize("password", PASSWORDS)
    def test_an_address_inside_text_loses_its_user_info(self, password):
        text = f"the request to '{_url(password, tail='/x?y=1')}' failed: timed out"
        out = secret_keys.scrub_urls(text)
        assert MARK not in out and "admin" not in out
        assert out == f"the request to 'https://{HOST}/x?y=1' failed: timed out"
        assert secret_keys.scrub_urls(out) == out, "idempotent"

    def test_an_ipv6_host_keeps_its_brackets(self):
        assert secret_keys.without_userinfo(f"https://u:{MARK}@[2001:db8::1]:8004/x") == "https://[2001:db8::1]:8004/x"

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "http://10.0.0.5:8000",
            " http://10.0.0.5:8000/ ",
            "https://[2001:db8::1]:8004/",
            "jen@10.0.0.6",
            "mail admin@example.com about it",
            "/etc/jen/ssl/kea-client.key",
            "ftp://u:p@files.example/x",
        ],
    )
    def test_what_carries_no_http_user_info_comes_back_as_it_was(self, value):
        assert secret_keys.without_userinfo(value) == value and secret_keys.scrub_urls(value) == value

    def test_none_is_the_empty_string(self):
        assert secret_keys.without_userinfo(None) == "" and secret_keys.scrub_urls(None) == ""

    @pytest.mark.parametrize("password", [*PASSWORDS, SPACED])
    def test_the_names_in_auth_are_the_same_definition(self, password):
        value = _url(password)
        assert auth.without_userinfo(value) == secret_keys.without_userinfo(value)
        assert auth.scrub_urls(value) == secret_keys.scrub_urls(value)

    def test_the_pattern_that_stopped_at_a_quote_is_gone_from_the_whole_tree(self):
        """A fix to a definition is a fix to every use: the pattern of 7.0.0-beta.6 treated `'`, `"`, `<` and `>` as the end of an address, so a password that carried one stayed. No file under
        jen/ or plugins/ may carry it, and the user-info pattern exists in exactly one module."""
        old = "[^\\s/?#'\\\"<>]*@"
        new = "[^\\s/?#]*@"
        holders = []
        for top in ("jen", "plugins"):
            for path in sorted((ROOT / top).rglob("*.py")):
                text = path.read_text(encoding="utf-8")
                assert old not in text, (
                    f"{path.relative_to(ROOT).as_posix()} still carries the pattern that stops at a quote"
                )
                if new in text:
                    holders.append(path.relative_to(ROOT).as_posix())
        assert holders == ["jen/services/secret_keys.py"]


def _collected(password):
    url = _url(password)
    return {
        "notes": [],
        "jen": {"version": "7.0.0-beta.7", "channel": "beta", "hostname": "jen"},
        "config_text": (
            f"[kea]\napi_url = {url}\napi_pass = hunter2\n\n"
            f"[server_2]\nname = second\napi_url = {url}\napi6_url = {_url(password, 'http')}\napi_d2_url = {url}\n\n"
            f"[oidc]\ndiscovery = {url}.well-known/openid-configuration\n"
        ),
        "servers": [
            {
                "id": 1,
                "name": "kea-a",
                "api_url": url,
                "api6_url": url,
                "api_d2_url": url,
                "ssh_host": "10.0.0.5",
                "write_mode_facts": {
                    "agree_at": f'at Dhcp4.hooks-libraries[0].parameters.url: the file says "{url}", the daemon nothing'
                },
            }
        ],
        "health": {
            "summary": {"warn": 1},
            "checks": [{"id": "kea_reachable", "detail": f"could not reach {url} (refused)"}],
        },
        "drift": [{"subnet_id": 1, "detail": f"read from {url}"}],
        "kea_configs": [
            {
                "server_id": 1,
                "server": "kea-a",
                "service": "dhcp4",
                "config": {
                    "Dhcp4": {
                        "hooks-libraries": [
                            {
                                "library": "/usr/lib/kea/hooks/libdhcp_ha.so",
                                "parameters": {"high-availability": [{"peers": [{"name": "kea-b", "url": url}]}]},
                            }
                        ]
                    }
                },
            }
        ],
        "plugins": [{"id": "dns-sync", "path": "/opt/jen/plugins/dns-sync", "note": f"posts to {url}"}],
        "db": {"server_version": "10.11", "note": f"seen at {url}"},
        "audit": [{"id": 1, "action": "SETTINGS", "details": f"api_url={url} saved"}],
        "alerts": [{"id": 1, "status": "failed", "error": f"HTTPSConnectionPool: {url} timed out"}],
        "lease_history": [],
        "log_text": f"2026-11-06T00:00:00Z WARNING jen.services.kea: {url} did not answer\n",
    }


def _members(collected):
    data, _names = sb.build_bundle(collected)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        return {n: zf.read(n).decode("utf-8") for n in zf.namelist()}


#: every member that carries an address in `_collected`: the host must still be in each (the test is not passed by an empty member)
CARRIERS = (
    "config.ini.redacted",
    "servers.json",
    "health.json",
    "drift.json",
    "kea/1-dhcp4.json",
    "plugins.json",
    "db.json",
    "audit-tail.json",
    "alerts-tail.json",
    "logs/jen.log.tail",
)


class TestNoMemberOfTheBundleCarriesAPassword:
    @pytest.mark.parametrize("password", PASSWORDS)
    def test_the_marker_is_in_no_member_and_the_host_is_in_every_carrier(self, password):
        members = _members(_collected(password))
        leaks = [name for name, body in members.items() if MARK in body or "admin:" in body]
        assert leaks == [], leaks
        for name in CARRIERS:
            assert HOST in members[name], f"{name} lost the address itself"

    def test_the_two_members_of_the_finding(self):
        """AE7 as it was reproduced: `config.ini.redacted` and `servers.json`, the address beside a masked `api_pass`."""
        members = _members(_collected(MARK))
        ini = members["config.ini.redacted"]
        assert (
            f"api_url = https://{HOST}/" in ini
            and f"api6_url = http://{HOST}/" in ini
            and f"api_pass = {sb.MASK}" in ini
        )
        assert f'"api_url": "https://{HOST}/"' in members["servers.json"]

    def test_a_password_with_a_space_in_it_leaves_no_value(self):
        """A VALUE is split by `urlsplit`, so even a space goes: the INI's values, the three address fields of `servers.json` and a Kea `url` key."""
        collected = _collected(SPACED)
        for key in ("health", "drift", "plugins", "db", "audit", "alerts"):
            collected[key] = [] if isinstance(collected[key], list) else {}
        collected["log_text"] = None
        collected["servers"][0].pop("write_mode_facts")
        members = _members(collected)
        for name in ("config.ini.redacted", "servers.json", "kea/1-dhcp4.json"):
            assert MARK not in members[name] and HOST in members[name], name

    def test_a_clean_address_is_exported_as_it_is(self):
        out = sb.redact_ini_text("[kea]\napi_url = http://10.0.0.5:8000\nssh_host = jen@10.0.0.6\n")
        assert "api_url = http://10.0.0.5:8000" in out and "ssh_host = jen@10.0.0.6" in out

    def test_the_readme_says_so(self):
        assert "a user name or password inside an address" in sb.readme_text("7.0.0-beta.7", "beta", "jen", "now", [])

    def test_every_json_member_goes_through_the_one_pass(self):
        """The choke point, as source: `_json` is the only `json.dumps` in the module, and it dumps `_scrubbed(data)`."""
        import ast

        tree = ast.parse((ROOT / "jen/services/support_bundle.py").read_text(encoding="utf-8"))
        dumps = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "dumps"
        ]
        assert len(dumps) == 1
        first = dumps[0].args[0]
        assert isinstance(first, ast.Call) and isinstance(first.func, ast.Name) and first.func.id == "_scrubbed"
