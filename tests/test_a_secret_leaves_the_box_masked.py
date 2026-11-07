"""7.0.0-beta.8 (Q222: AG1, AG2, AG11) - a secret leaves the box masked whatever its first character, and every member of the support bundle is written through one pass.

AG1 (P1, in stable 5.70.0 too): the INI masker took a secret-named key whose VALUE began with `/` or `X:\\` for a path and wrote it in clear - a password that starts with a slash was exported
by the file an operator attaches to a bug report. The name rule (`secret_keys.is_secret_key`) already excludes every path-naming key, so the value is never consulted now. AG2: `README.txt` (the
collectors' notes, a driver's error verbatim) and `logs/README.txt` were made by no scrubbing pass, and the README was written after the size cap. AG11: a dict KEY and an object the encoder
printed with `default=str` went past the pass. Every member is now written by `put`, which scrubs, and the notes are scrubbed like log lines and cut."""

import ast
import pathlib

import pytest

from jen.services import support_bundle as sb
from tests.test_an_exported_address_carries_no_password import HOST, _collected, _members, _url

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


def _readme(collected):
    return _members(collected)["README.txt"]


class TestEveryMemberIsWrittenThroughOnePass:
    def test_a_note_with_an_address_reaches_the_readme_without_its_password(self):
        collected = _collected("pw")
        collected["notes"] = [f"db: OperationalError: could not connect to {_url(MARKER)}"]
        text = _readme(collected)
        assert MARKER not in text and HOST in text and "could not connect to" in text

    def test_a_note_is_scrubbed_like_a_log_line(self):
        collected = _collected("pw")
        collected["notes"] = [f"db: OperationalError: password={MARKER} refused", f"kea: Bearer {MARKER}"]
        text = _readme(collected)
        assert MARKER not in text and "[redacted]" in text

    def test_a_long_note_is_cut_and_the_readme_stays_small(self):
        collected = _collected("pw")
        collected["notes"] = ["db: " + "word " * 40_000]
        text = _readme(collected)
        assert len(text) < 4 * sb.NOTE_MAX_CHARS and "db: " + "word " * 20 in text

    def test_the_log_note_is_scrubbed(self):
        collected = _collected("pw")
        collected["log_text"] = None
        collected["log_note"] = f"journald only; the last line named {_url(MARKER)} and password={MARKER}\n"
        members = _members(collected)
        assert "logs/jen.log.tail" not in members
        assert MARKER not in members["logs/README.txt"] and HOST in members["logs/README.txt"]

    def test_put_is_the_one_writer_of_a_member_and_it_scrubs(self):
        """As source: in `build_bundle` every assignment into `members` is inside `put`, and `put` calls `scrub_urls` - so a member added later is covered by being written."""
        src = (ROOT / "jen/services/support_bundle.py").read_text(encoding="utf-8")
        build = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "build_bundle")
        put = next(n for n in ast.walk(build) if isinstance(n, ast.FunctionDef) and n.name == "put")
        inside_put = {id(n) for n in ast.walk(put)}
        writes = [
            n
            for n in ast.walk(build)
            if isinstance(n, ast.Assign)
            and any(isinstance(t, ast.Subscript) and ast.unparse(t.value) == "members" for t in n.targets)
        ]
        assert writes and all(id(n) in inside_put for n in writes), [ast.unparse(n) for n in writes]
        assert any(isinstance(n, ast.Call) and ast.unparse(n.func) == "scrub_urls" for n in ast.walk(put))

    def test_the_readme_lists_the_members_it_is_in(self):
        """The sentence the README makes about itself is made by `put` too: a bundle with an address in every note and in no member of the archive."""
        collected = _collected(MARKER)
        collected["notes"] = [f"health: {_url(MARKER)}"]
        members = _members(collected)
        assert all(MARKER not in text for text in members.values()), [n for n, t in members.items() if MARKER in t]


class TestWhatTheEncoderAddsIsScrubbed:
    def test_a_dict_key_that_is_an_address(self):
        collected = _collected("pw")
        collected["health"] = {"checks": {_url(MARKER): "refused"}}
        text = _members(collected)["health.json"]
        assert MARKER not in text and HOST in text

    def test_an_object_the_encoder_prints(self):
        collected = _collected("pw")
        collected["db"] = {"error": OSError(f"could not connect to {_url(MARKER)}")}
        text = _members(collected)["db.json"]
        assert MARKER not in text and HOST in text

    def test_scrubbed_prints_an_object_as_text(self):
        out = sb._scrubbed({"e": ValueError(_url(MARKER)), "n": 3, "b": True, "z": None})
        assert out["n"] == 3 and out["b"] is True and out["z"] is None
        assert isinstance(out["e"], str) and MARKER not in out["e"] and HOST in out["e"]
