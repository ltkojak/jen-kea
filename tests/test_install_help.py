"""
tests/test_install_help.py
───────────────────────────
v5.67.0 (Q113, item d) — install.sh's --help is required to print every
flag main()'s own argument parser recognizes, and the header comment (the
first thing a person reads before running this as root) is required to
say the same. Pure text check against install.sh's source — no DB, no
execution of the script, no shell involved.
"""

import pathlib
import re

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_INSTALL_SH = _ROOT / "install.sh"

_FLAG = re.compile(r"--[a-z][a-z-]*")


def _parsed_flags() -> set[str]:
    """Every flag the `case "$1" in ... esac` argument parser matches."""
    text = _INSTALL_SH.read_text(encoding="utf-8")
    m = re.search(r'case "\$1" in\n(.*?)\n    esac', text, re.DOTALL)
    assert m, "could not find the flag-parsing case block in install.sh"
    return set(re.findall(r"--[a-z][a-z-]*(?=\)|\|)", m.group(1)))


def _help_flags() -> set[str]:
    """Every flag print_help()'s own heredoc mentions."""
    text = _INSTALL_SH.read_text(encoding="utf-8")
    m = re.search(r"cat << 'HELPEOF'\n(.*?)\nHELPEOF", text, re.DOTALL)
    assert m, "could not find print_help()'s heredoc in install.sh"
    return set(_FLAG.findall(m.group(1)))


def _header_comment_flags() -> set[str]:
    """Every flag the top-of-file Usage banner comment mentions."""
    text = _INSTALL_SH.read_text(encoding="utf-8")
    m = re.search(r"#  Usage:\n((?:#.*\n)+?)# .{3,}\n\nset -euo pipefail", text)
    assert m, "could not find the header Usage comment in install.sh"
    return set(_FLAG.findall(m.group(1)))


class TestHelpMatchesWhatMainParses:
    def test_every_parsed_flag_is_in_help(self):
        parsed = _parsed_flags()
        helped = _help_flags()
        missing = parsed - helped
        assert not missing, f"--help never mentions: {missing}"

    def test_help_never_mentions_a_flag_main_does_not_parse(self):
        parsed = _parsed_flags()
        helped = _help_flags()
        extra = helped - parsed
        assert not extra, f"--help documents a flag main() never parses: {extra}"

    def test_header_comment_agrees_with_help(self):
        header = _header_comment_flags()
        helped = _help_flags()
        assert header == helped, (
            f"header comment vs --help mismatch: header-only={header - helped}, help-only={helped - header}"
        )


class TestHelpFlagItselfWorks:
    def test_help_and_h_both_route_to_print_help(self):
        text = _INSTALL_SH.read_text(encoding="utf-8")
        assert re.search(r"--help\|-h\)\s*print_help; exit 0", text), (
            "--help/-h should call print_help() and exit 0 from the argument parser"
        )

    def test_print_help_is_defined_before_the_argument_parser_calls_it(self):
        # bash executes top-level statements in order — a function has to
        # be DEFINED before something earlier in the file can call it.
        text = _INSTALL_SH.read_text(encoding="utf-8")
        define_pos = text.index("print_help() {")
        parser_pos = text.index('case "$1" in')
        assert define_pos < parser_pos, "print_help() must be defined before the flag-parsing loop calls it"
