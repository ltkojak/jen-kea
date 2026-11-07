r"""v5.70.1 (Q215 carrying Q222's AG1) - a secret leaves the box masked whatever its first character.

AG1 (P1, in stable 5.70.0): the INI masker took a secret-named key whose VALUE began with `/` or `X:\` for a path and wrote it in clear - a password that starts with a slash was exported by the
file an operator attaches to a bug report. The name rule (`secret_keys.is_secret_key`) already excludes every path-naming key, so the value is never consulted now. (The main line's file also holds
the rows for AG2 and AG11 - the README's notes and a dict key - which need the bundle's single writer `put`, which 5.70 does not have.)"""

import ast
import pathlib

import pytest

from jen.services import support_bundle as sb
from tests.test_an_exported_address_carries_no_password import HOST, _collected, _members

ROOT = pathlib.Path(__file__).resolve().parent.parent
MARKER = "MARKER-9c1f"
#: the first characters of a password that read as a path to the old masker, and two that never did
PREFIXES = ["/", "//", "C:\\", "x:\\", " /", "", "pw"]
#: secret-named keys of jen.config (`jen/config.py`) and of the alert channels
KEYS = [
    "api_pass",
    "api6_pass",
    "api_d2_pass",
    "password",
    "client_secret",
    "metrics_token",
    "api_token",
    "smtp_password",
]
#: keys that NAME a path: kept, by name, whatever the value
PATH_KEYS = ["key_path", "api_client_key", "ssl_key", "password_file", "cert_file"]


class TestASecretIsMaskedByNameAlone:
    @pytest.mark.parametrize("key", KEYS)
    @pytest.mark.parametrize("prefix", PREFIXES)
    def test_the_ini_masker_masks_it(self, key, prefix):
        out = sb.redact_ini_text(f"[kea]\n{key} = {prefix}{MARKER}\n")
        assert MARKER not in out and f"{key} = {sb.MASK}" in out, out

    @pytest.mark.parametrize("key", PATH_KEYS)
    def test_a_path_under_a_path_naming_key_is_kept(self, key):
        out = sb.redact_ini_text(f"[kea_ssh]\n{key} = /etc/jen/ssh/{MARKER}\n")
        assert f"{key} = /etc/jen/ssh/{MARKER}" in out

    @pytest.mark.parametrize("prefix", PREFIXES)
    def test_through_the_whole_archive(self, prefix):
        collected = _collected("pw")
        collected["config_text"] = f"[kea]\napi_url = http://{HOST}\napi_pass = {prefix}{MARKER}\n"
        members = _members(collected)
        assert all(MARKER not in text for text in members.values()), [n for n, t in members.items() if MARKER in t]
        assert f"api_pass = {sb.MASK}" in members["config.ini.redacted"]

    def test_the_value_is_never_consulted_as_source(self):
        src = (ROOT / "jen/services/support_bundle.py").read_text(encoding="utf-8")
        assert "_PATH_VALUE_RE" not in src
        fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "redact_ini_text")
        tests = [
            ast.unparse(n.test)
            for n in ast.walk(fn)
            if isinstance(n, ast.If) and "is_secret_key" in ast.unparse(n.test)
        ]
        assert tests == ["is_secret_key(key) and value"], tests
