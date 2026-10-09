#!/usr/bin/env python3
"""
tools/config_merge.py - merge the installer wizard's answers into the LIVE jen.config (v5.68.0-beta.18, Q153). Pure stdlib; shipped in the release tarball.

`install.sh --configure` runs its interactive wizard while Jen is RUNNING, then rewrote jen.config from the wizard's variables alone: everything
Jen itself keeps in that file that the wizard never asks about ([oidc], extra Kea servers, [kea6], [subnets6], the update channel ...) was
dropped, and a Settings save made while the wizard was open was overwritten by the installer's older copy. This writes the result of the wizard
ONTO the file as it is now:

    python3 tools/config_merge.py --snapshot SNAP --live LIVE  < wizard.ini  > merged.ini

  * SNAP is the copy of the live file taken when --configure began (before the wizard ran), LIVE the file as it is at commit time, stdin the
    complete file the wizard produced.
  * a key the wizard did not write keeps its LIVE value (a section the wizard never mentions is carried over whole);
  * a key the wizard wrote takes the wizard's value - the operator just typed or accepted it - UNLESS the live value changed since SNAP and the
    wizard's value is still the one SNAP had (the operator accepted the old default; the Settings save is newer and wins);
  * a key that is in SNAP but gone from LIVE (removed since) is not put back when the wizard's value is still SNAP's.

    python3 tools/config_merge.py --answers LIVE        # the wizard's answers the live file already holds, as JEN_NAME=value lines

v5.68.0-beta.21 (Q156): the merge rules above only help if the wizard's value for a key the operator did not touch EQUALS what the snapshot had. The
wizard never asks for the Kea connection, the Kea database, the SSH target or the DDNS settings (`_cfgval`: an answers file, else the JEN_* environment,
else EMPTY), so an interactive `--configure` wrote them blank - and a blank differs from the snapshot, so the merge applied it: a configured box was
disconnected from Kea and lost its DDNS token. `--answers` lists the fifteen answers the file already holds so `install.sh --configure` can seed the
wizard with them before it runs; an answers file or an environment variable still wins over the seed.

v5.68.0-beta.29 (Q165, edge 1): `--identity-diff BEFORE AFTER` prints one line for every change to WHICH Kea Jen reaches - the connection mode, each server's API URL,
SSH host, SSH user and config path, and a server added or removed - between two jen.config files, and nothing when there is none. `install.sh --configure` compares the live
file with the merged result before it writes: a changed endpoint while investigation logging may be on (on the OLD Kea, which the new settings would stop Jen reaching)
needs `--change-endpoints`. It reads the INI only - no database, no running Jen - so the guard holds exactly when Jen's own is not running to refuse.

Comments are not kept (Jen's own writer, `configparser`, does not keep them either). Exit status: 0 merged text on stdout; 2 usage; 3 a file
could not be read as an INI.
"""

import argparse
import configparser
import io
import sys


def _parse(text, label):
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error as e:
        raise SystemExit(f"config_merge: {label} is not a readable INI file: {e}") from e
    return parser


def _read(path):
    if not path:
        return ""
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return ""


DEFAULT_KEA_CONF = "/etc/kea/kea-dhcp4.conf"
_PRIMARY_IDENTITY = (("kea", "api_url"), ("kea_ssh", "host"), ("kea_ssh", "user"), ("kea_ssh", "kea_conf"))
_EXTRA_IDENTITY = ("api_url", "ssh_host", "ssh_user", "kea_conf")


def identity_view(text, label="the file"):
    """{label: value} for everything that decides WHICH Kea Jen reaches: the connection mode, the primary's API URL / SSH host / SSH user / config path, and the same four for
    every `[kea_server_N]` (N >= 2). Stripped; a blank config path is the default one; the mode is "direct" or "ca" as Jen reads it. The same values
    `jen.config.identity_view` compares (tests/test_config_merge.py holds the two together)."""
    parser = _parse(text, label)
    view = {}
    mode = parser.get("kea", "connection_mode", fallback="ca").strip().lower() if parser.has_section("kea") else "ca"
    view["[kea] connection_mode"] = mode if mode in ("ca", "direct") else "ca"
    for section, key in _PRIMARY_IDENTITY:
        value = parser.get(section, key, fallback="").strip() if parser.has_section(section) else ""
        view[f"[{section}] {key}"] = value or (DEFAULT_KEA_CONF if key == "kea_conf" else "")
    for section in parser.sections():
        if (
            section.startswith("kea_server_")
            and section[len("kea_server_") :].isdigit()
            and int(section[len("kea_server_") :]) >= 2
        ):
            for key in _EXTRA_IDENTITY:
                value = parser.get(section, key, fallback="").strip()
                view[f"[{section}] {key}"] = value or (DEFAULT_KEA_CONF if key == "kea_conf" else "")
            view[f"[{section}]"] = "present"
    return view


def identity_diff(before_text, after_text):
    """The lines that say how the Kea Jen reaches differs between two files: `[section] key: old -> new`, `[kea_server_2] removed` / `added`. Empty when nothing does."""
    before, after = identity_view(before_text, "the live file"), identity_view(after_text, "the new file")
    lines = []
    for key in sorted(set(before) | set(after)):
        old, new = before.get(key), after.get(key)
        if old == new:
            continue
        if key.endswith("]"):  # a whole server section
            lines.append(f"{key} {'added' if old is None else 'removed'}")
        elif key.split("] ")[0].startswith("[kea_server_") and (old is None or new is None):
            continue  # said once, by the section line
        else:
            lines.append(
                f"{key}: {old if old not in (None, '') else '(not set)'} -> {new if new not in (None, '') else '(not set)'}"
            )
    return lines


def merge(snapshot_text, live_text, wizard_text):
    snap = _parse(snapshot_text, "the snapshot")
    live = _parse(live_text, "the live file")
    wizard = _parse(wizard_text, "the wizard's file")

    for section in wizard.sections():
        for key, wizard_value in wizard.items(section):
            if snap.has_option(section, key) and wizard_value == snap.get(section, key):
                # the operator left this one as it was: whatever the file says NOW is newer (a Settings save), including "removed"
                continue
            if not live.has_section(section):
                live.add_section(section)
            live.set(section, key, wizard_value)
    out = io.StringIO()
    live.write(out)
    return out.getvalue()


#: (section, key) in jen.config -> the JEN_* name install.sh's wizard reads that value from (`_cfgval`). These are the fifteen answers the wizard
#: writes into [kea], [kea_db], [kea_ssh] and [ddns] - the ones it never PROMPTS for any more (Jen's own /setup connects Kea) and so can only get from
#: an answers file or the environment, which an interactive `--configure` does not have.
WIZARD_ANSWERS = (
    ("kea", "api_url", "JEN_KEA_API_URL"),
    ("kea", "api_user", "JEN_KEA_API_USER"),
    ("kea", "api_pass", "JEN_KEA_API_PASS"),
    ("kea_db", "host", "JEN_KEA_DB_HOST"),
    ("kea_db", "user", "JEN_KEA_DB_USER"),
    ("kea_db", "password", "JEN_KEA_DB_PASS"),
    ("kea_db", "database", "JEN_KEA_DB_NAME"),
    ("kea_ssh", "host", "JEN_KEA_SSH_HOST"),
    ("kea_ssh", "user", "JEN_KEA_SSH_USER"),
    ("kea_ssh", "kea_conf", "JEN_KEA_CONF"),
    ("ddns", "dns_provider", "JEN_DDNS_PROVIDER"),
    ("ddns", "api_url", "JEN_DDNS_URL"),
    ("ddns", "api_token", "JEN_DDNS_TOKEN"),
    ("ddns", "log_path", "JEN_DDNS_LOG"),
    ("ddns", "forward_zone", "JEN_DDNS_ZONE"),
)


#: v5.68.0-beta.22 (Q157): the five answers the wizard PROMPTS for (or defaults) rather than reads silently. They are not seeded as answers - the operator
#: may change them - but the prompt's DEFAULT is what is configured: `--configure` showed 5050/8443/localhost/jen/jen and Enter (or `--unattended` with no
#: answers file) wrote them, which differs from the snapshot and so was applied by the merge. Printed as `DEFAULT_<name>`.
WIZARD_DEFAULTS = (
    ("server", "http_port", "JEN_HTTP_PORT"),
    ("server", "https_port", "JEN_HTTPS_PORT"),
    ("jen_db", "host", "JEN_DB_HOST"),
    ("jen_db", "user", "JEN_DB_USER"),
    ("jen_db", "database", "JEN_DB_NAME"),
)


def answers_from(live_text):
    """[(JEN_NAME, value)] for every wizard answer the live file HAS, in `WIZARD_ANSWERS` order (v5.68.0-beta.21, Q156). A key the file does not
    carry is not listed, so the wizard falls back to its own default for it."""
    live = _parse(live_text, "the live file")
    return [(name, live.get(section, key)) for section, key, name in WIZARD_ANSWERS if live.has_option(section, key)]


def defaults_from(live_text):
    """[("DEFAULT_JEN_NAME", value)] for the prompted answers (`WIZARD_DEFAULTS`) the live file holds and that are not empty."""
    live = _parse(live_text, "the live file")
    return [
        (f"DEFAULT_{name}", live.get(section, key))
        for section, key, name in WIZARD_DEFAULTS
        if live.has_option(section, key) and live.get(section, key) != ""
    ]


def escape_line(value):
    """A value on ONE line: a backslash is doubled and a newline (a continuation line of a multi-line INI value) becomes the two characters `\\n`. install.sh
    unescapes it with `printf %b`, so a multi-line value is seeded whole instead of as its first line."""
    return value.replace("\\", "\\\\").replace("\r", "").replace("\n", "\\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Merge the installer wizard's jen.config into the live one.")
    ap.add_argument(
        "--snapshot", default="", help="the live file as it was when --configure began (empty or missing = none)"
    )
    ap.add_argument("--live", help="the live file as it is now")
    ap.add_argument(
        "--answers",
        default=None,
        help="print the wizard's answers (JEN_NAME=value lines) that this live file already holds, and exit",
    )
    ap.add_argument(
        "--identity-diff",
        nargs=2,
        metavar=("BEFORE", "AFTER"),
        help="print how the Kea Jen reaches differs between two config files (nothing when it does not), and exit",
    )
    args = ap.parse_args(argv)
    if args.identity_diff:
        before, after = (_read(path) for path in args.identity_diff)
        for line in identity_diff(before, after):
            sys.stdout.write(line + "\n")
        return 0
    if args.answers is not None:
        text = _read(args.answers)
        for name, value in [*answers_from(text), *defaults_from(text)]:
            sys.stdout.write(f"{name}={escape_line(value)}\n")
        return 0
    if not args.live:
        ap.error("--live is required unless --answers is given")
    wizard_text = sys.stdin.read()
    header = "".join(line + "\n" for line in wizard_text.splitlines()[:3] if line.startswith("#"))
    merged = merge(_read(args.snapshot), _read(args.live), wizard_text)
    sys.stdout.write(header + ("\n" if header else "") + merged)
    return 0


if __name__ == "__main__":
    sys.exit(main())
