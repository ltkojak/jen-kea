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


def answers_from(live_text):
    """[(JEN_NAME, value)] for every wizard answer the live file HAS, in `WIZARD_ANSWERS` order (v5.68.0-beta.21, Q156). A key the file does not
    carry is not listed, so the wizard falls back to its own default for it."""
    live = _parse(live_text, "the live file")
    return [(name, live.get(section, key)) for section, key, name in WIZARD_ANSWERS if live.has_option(section, key)]


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
    args = ap.parse_args(argv)
    if args.answers is not None:
        for name, value in answers_from(_read(args.answers)):
            sys.stdout.write(f"{name}={value}\n")
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
