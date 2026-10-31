"""
tests/test_secret_keys.py
─────────────────────────
Q204 (AT4, M7): ONE definition of "this key's value is a secret", for every masker that decides by a key NAME - the Kea-config masker (`kea_authoring.redact_secrets`: the config-history diff and
download a non-superadmin reads, the authoring preview, the support bundle's Kea configs) and the bundle's INI mask (`support_bundle.redact_ini_text`). Pure: no database, no Flask.
`py -m pytest --noconftest tests/test_secret_keys.py`.
"""

import ast
import pathlib

import pytest

from jen.services import kea_authoring, support_bundle
from jen.services.secret_keys import is_secret_key

ROOT = pathlib.Path(__file__).resolve().parent.parent

SECRET = [
    "password",
    "pass",
    "passwd",
    "secret",
    "token",
    "api_key",
    "api-key",
    "API-Key",
    "api_token",
    "api-token",
    "client_secret",
    "client-secret",
    "metrics_token",
    "basic-auth-password",
    "smtp_password",
    "db-password",
    "tsig-secret",
    "bearer_token",
    "api_pass",
    "db_passwd",
    "Password",
    "secret_key",
    "private_key",
    "private-key",
    "passphrase",
    "pwd",
    "apikey",
    "clientSecret",
    "apiKey",
    "Authorization",
    "credentials",
]
NOT_SECRET = [
    "password-file",
    "password_file",
    "key_path",
    "api_client_key",
    "ssl_key",
    "cert-file",
    "key-file",
    "token_lifetime",
    "user",
    "api_url",
    "mypassword",
    "bypass",
    "tokens-per-second",
    "keyboard",
    "",
]


class TestTheUnionTable:
    @pytest.mark.parametrize("key", SECRET)
    def test_a_secret_is_a_secret(self, key):
        assert is_secret_key(key) is True

    @pytest.mark.parametrize("key", NOT_SECRET)
    def test_a_name_that_is_a_path_or_not_a_secret_is_not(self, key):
        assert is_secret_key(key) is False

    def test_hyphen_and_underscore_read_alike_and_the_case_is_ignored(self):
        for key in SECRET:
            assert is_secret_key(key.replace("-", "_")) is is_secret_key(key.replace("_", "-")) is True
            if (
                key == key.lower() or "-" in key or "_" in key
            ):  # (camelCase is read at its case boundaries, so an all-upper spelling of it is a different word)
                assert is_secret_key(key.upper()) is True

    def test_a_non_string_key_is_not_a_secret(self):
        assert is_secret_key(None) is False and is_secret_key(7) is False


KEA_CONFIG = {
    "Dhcp4": {
        "lease-database": {
            "type": "mysql",
            "user": "kea",
            "password": "lease-pw-sentinel",
            "password-file": "/etc/kea/db.pw",
        },
        "hooks-libraries": [
            {
                "library": "/usr/lib/kea/hooks/libdhcp_x.so",
                "parameters": {
                    "token": "hook-token-sentinel",
                    "api-key": "hook-apikey-sentinel",
                    "passwd": "hook-passwd-sentinel",
                },
            }
        ],
        "control-sockets": [
            {
                "socket-type": "http",
                "socket-address": "10.0.0.5",
                "authentication": {
                    "type": "basic",
                    "clients": [{"user": "jen", "password": "client-pw-sentinel", "password-file": "/etc/kea/jen.pw"}],
                },
                "trust-anchor": "/etc/kea/tls/ca.crt",
                "cert-file": "/etc/kea/tls/server.crt",
                "key-file": "/etc/kea/tls/server.key",
            }
        ],
        "user-context": {"client_secret": "uc-secret-sentinel", "api_token": "uc-token-sentinel", "comment": "keep me"},
        "subnet4": [{"id": 1, "subnet": "10.0.0.0/24", "user-context": {"pass": "uc-pass-sentinel"}}],
        "hooks": [{"basic-auth-password": "ha-pw-sentinel", "name": "peer"}],
    },
    "dhcp-ddns": {"tsig-keys": [{"name": "k", "algorithm": "HMAC-SHA256", "secret": "tsig-sentinel"}]},
}
SENTINELS = [
    "lease-pw-sentinel",
    "hook-token-sentinel",
    "hook-apikey-sentinel",
    "hook-passwd-sentinel",
    "client-pw-sentinel",
    "uc-secret-sentinel",
    "uc-token-sentinel",
    "uc-pass-sentinel",
    "ha-pw-sentinel",
    "tsig-sentinel",
]
PATH_VALUES = [
    "/etc/kea/db.pw",
    "/etc/kea/jen.pw",
    "/etc/kea/tls/ca.crt",
    "/etc/kea/tls/server.crt",
    "/etc/kea/tls/server.key",
]


class TestEveryMaskerUsesIt:
    def test_the_kea_config_masker_masks_every_key_and_keeps_every_path_key(self):
        import json

        masked = json.dumps(kea_authoring.redact_secrets(KEA_CONFIG))
        for s in SENTINELS:
            assert s not in masked, s
        for p in PATH_VALUES:
            assert p in masked, p
        assert "keep me" in masked

    def test_the_input_is_not_mutated(self):
        import copy

        before = copy.deepcopy(KEA_CONFIG)
        kea_authoring.redact_secrets(KEA_CONFIG)
        assert before == KEA_CONFIG

    def test_the_bundle_masks_an_ini_carrying_every_key_and_keeps_the_path_keys(self):
        ini = (
            "[kea]\napi_url = http://10.0.0.5:8000\napi_pass = ini-pw-sentinel\napi_client_key = /etc/jen/ssl/kea-client.key\n"
            "[server]\nmetrics_token = ini-metrics-sentinel\nsecret_key = not-a-pattern\n"
            "[oidc]\nclient_secret = ini-oidc-sentinel\nclient_id = abc\n"
            "[mail]\nsmtp_password = ini-smtp-sentinel\nsmtp_passwd = ini-smtp2-sentinel\napi-key = ini-apikey-sentinel\napi_token = ini-apitoken-sentinel\n"
            "[tls]\nssl_key = /etc/jen/ssl/jen.key\nkey_path = /etc/jen/ssh/jen_rsa\n"
        )
        out = support_bundle.redact_ini_text(ini)
        for s in (
            "ini-pw-sentinel",
            "ini-metrics-sentinel",
            "ini-oidc-sentinel",
            "ini-smtp-sentinel",
            "ini-smtp2-sentinel",
            "ini-apikey-sentinel",
            "ini-apitoken-sentinel",
        ):
            assert s not in out, s
        for kept in (
            "api_client_key = /etc/jen/ssl/kea-client.key",
            "ssl_key = /etc/jen/ssl/jen.key",
            "key_path = /etc/jen/ssh/jen_rsa",
            "client_id = abc",
        ):
            assert kept in out, kept

    def test_the_bundle_and_the_masker_name_the_same_function(self):
        assert support_bundle.is_secret_key is is_secret_key

    def test_the_two_maskers_agree_on_every_key_of_the_table(self):
        for key in SECRET + NOT_SECRET:
            if not key or key != key.lower() and "-" not in key and "_" not in key and not key.istitle():
                continue  # (an INI parser lower-cases option names, so a camelCase key is a Kea-config key only)
            via_config = kea_authoring.redact_secrets({key: "v"})[key] == "********"
            via_ini = support_bundle.redact_ini_text(f"[s]\n{key} = value\n").count(support_bundle.MASK) == 1
            assert via_config is via_ini is is_secret_key(key), key


def _py_files():
    for sub in ("jen", "plugins"):
        yield from (ROOT / sub).rglob("*.py")


class TestNoSecondKeyListExists:
    #: the names the two old lists were bound to
    GONE = ("_SECRET_KEYS", "_SECRET_SUFFIXES", "_SECRET_KEY_RE", "_is_secret_key")

    def test_the_old_lists_are_gone(self):
        for path in _py_files():
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Assign):
                    names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                elif isinstance(node, ast.FunctionDef):
                    names = [node.name]
                assert not [n for n in names if n in self.GONE], (path, names)

    def test_no_module_but_the_definition_spells_the_secret_words_as_a_list(self):
        """A second list shows as a collection literal (tuple / list / set / frozenset) holding two or more of the words, or a compiled regex naming `passwd` and `token` in one pattern, outside secret_keys.py.
        Two reviewed exceptions, each masking by something other than a key NAME in a Kea or INI document: the bundle's LOG scrub (a pattern over free text, where there is no key to ask about) and the
        alert channels' Q172 redaction (`alerts._SECRET_KEY_HINTS`: substring hints over the FIXED field set of a channel's own config - a Telegram token, a webhook URL, a header value - wider than a
        Kea key's rule on purpose, because a URL is a secret there)."""
        words = {"password", "passwd", "secret", "token", "api_key", "client_secret", "metrics_token"}
        reviewed = {
            ("jen/services/support_bundle.py", "free text of a log line, no key name"),
            ("jen/services/alerts.py", "a channel's own fixed fields (Q172), a URL is a secret there"),
        }
        for path in _py_files():
            rel = path.relative_to(ROOT).as_posix()
            if rel == "jen/services/secret_keys.py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Tuple | ast.List | ast.Set):
                    held = {e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
                    if len(held & words) >= 2:
                        assert any(rel == r for r, _why in reviewed), (rel, node.lineno, sorted(held & words))
                if (
                    isinstance(node, ast.Constant)
                    and isinstance(node.value, str)
                    and "passwd" in node.value
                    and "token" in node.value
                ):
                    assert any(rel == r for r, _why in reviewed), (rel, node.lineno, node.value[:60])

    def test_both_callers_import_the_one_function(self):
        for rel in ("jen/services/kea_authoring.py", "jen/services/support_bundle.py"):
            tree = ast.parse((ROOT / rel).read_text(encoding="utf-8"))
            imported = [
                a.name
                for n in ast.walk(tree)
                if isinstance(n, ast.ImportFrom) and n.module == "jen.services.secret_keys"
                for a in n.names
            ]
            assert "is_secret_key" in imported, rel
