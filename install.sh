#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  Jen - The Kea DHCP Management Console
#  Copyright (C) 2026 Matthew Thibodeau — GPLv3
# ─────────────────────────────────────────────────────────────────────────────
#  Usage:
#    sudo ./install.sh               Auto-detect fresh install or upgrade
#    sudo ./install.sh --upgrade     Non-interactive upgrade, keep config
#    sudo ./install.sh --configure   Re-run config wizard only
#    sudo ./install.sh --repair      Reinstall files + restart, keep config
#    sudo ./install.sh --unattended  Fully silent upgrade (CI/CD)
#    sudo ./install.sh --docker      Docker installation path
#    sudo ./install.sh --answers <file>
#                                    Fresh install from a KEY=value file (the
#                                    same JEN_* names as .env.example) instead
#                                    of the interactive wizard. With a TTY,
#                                    only what the file leaves out is still
#                                    asked; without one, a missing required
#                                    value is a fatal error naming it. The
#                                    same JEN_* names also work as plain
#                                    environment variables, with the file
#                                    (when given) taking priority.
#    sudo ./install.sh --app-dir <dir> --config-dir <dir> --data-dir <dir>
#                                    Fresh-install-only: install the app tree,
#                                    /etc/jen equivalent, and user-writable
#                                    data directory somewhere other than the
#                                    defaults (/opt/jen, /etc/jen, /var/lib/jen
#                                    — any left unset keeps its default). The
#                                    choice is recorded root-owned in
#                                    /etc/jen-layout.conf and every later run
#                                    (--upgrade/--repair/--configure) reads it
#                                    back; passing one of these flags again
#                                    with a different value is refused —
#                                    relocating an existing install is a
#                                    runbook (docs/runbooks.md), not a flag.
#                                    Same JEN_APP_DIR / JEN_CONFIG_DIR /
#                                    JEN_DATA_DIR names in --answers or the
#                                    environment.
#    sudo ./install.sh --restore <bundle.tar.enc>
#                                    Restore a recovery bundle (Settings → Databases
#                                    → Recovery) onto this install — run AFTER a normal
#                                    install/upgrade, not instead of one.
#                                    Stops Jen, snapshots what it replaces, restarts and
#                                    health-checks, and rolls back on failure. Flags:
#                                    --no-stop (Docker / not a systemd unit), --start, --force
#    sudo ./install.sh --rollback <snapshot dir>
#                                    Undo a restore from its pre-restore snapshot
#    sudo ./install.sh --help        Show this message
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

JEN_VERSION="5.67.0-beta.9"

JEN_USER="www-data"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROLLBACK_JEN=""
ROLLBACK_PKG=""

# v5.67.0 (Q114) — /etc/jen-layout.conf, NOT under $CONFIG_DIR: see
# docs/ARCHITECTURE.md §3.1 — $CONFIG_DIR is chowned to $JEN_USER, so a
# root-trusted "where do app/config/data live" file has to sit outside it,
# at a fixed path both this script and the root updater always agree on.
LAYOUT_FILE="/etc/jen-layout.conf"

# ── Mode flags ────────────────────────────────────────────────────────────────
MODE_UPGRADE=false
MODE_CONFIGURE=false
MODE_REPAIR=false
MODE_UNATTENDED=false
MODE_DOCKER=false
MODE_RESTORE=false
RESTORE_BUNDLE=""
IS_UPGRADE=false
CONFIGURE=false
EXISTING_VERSION=""
# v5.20.0 — true for the whole install_files..verify_install mutation window
# on an upgrade; fatal() rolls back automatically while this is set (below).
ROLLBACK_ARMED=false

# v5.67.0 (Q113) — a fresh install can be driven from a file instead of the
# interactive wizard. Same KEY=value vocabulary as .env.example/run.py's
# JEN_* Docker variables (see _cfgval below) so there is exactly one set of
# names to learn across bare metal and Docker.
ANSWERS_FILE=""
declare -A ANSWERS

# v5.67.0 (Q114) — an explicit --app-dir/--config-dir/--data-dir, if given.
# Resolved against any existing $LAYOUT_FILE / --answers / JEN_*_DIR env in
# _resolve_layout_dirs below, once the flag loop and _cfgval both exist.
OPT_APP_DIR=""
OPT_CONFIG_DIR=""
OPT_DATA_DIR=""

# v5.67.0 (Q113) — defined this early, before any other function, so
# --help can print and exit from the flag-parsing loop below it: bash
# executes top-level statements in order, and a function has to be
# DEFINED before something earlier in the file can call it. The text is
# the header comment above, restated as real output instead of only a
# comment a person has to open the file to read — tests/test_install_help.py
# greps both and fails if a flag is in one but not the other.
print_help() {
    cat << 'HELPEOF'
Jen - The Kea DHCP Management Console

Usage:
  sudo ./install.sh               Auto-detect fresh install or upgrade
  sudo ./install.sh --upgrade     Non-interactive upgrade, keep config
  sudo ./install.sh --configure   Re-run config wizard only
  sudo ./install.sh --repair      Reinstall files + restart, keep config
  sudo ./install.sh --unattended  Fully silent upgrade (CI/CD)
  sudo ./install.sh --docker      Docker installation path
  sudo ./install.sh --answers <file>
                                   Fresh install from a KEY=value file (the
                                   same JEN_* names as .env.example) instead
                                   of the interactive wizard. With a TTY,
                                   only what the file leaves out is still
                                   asked; without one, a missing required
                                   value is a fatal error naming it. The
                                   same JEN_* names also work as plain
                                   environment variables, with the file
                                   (when given) taking priority.
  sudo ./install.sh --app-dir <dir> --config-dir <dir> --data-dir <dir>
                                   Fresh-install-only: relocate the app tree,
                                   /etc/jen equivalent, or data directory
                                   (defaults: /opt/jen, /etc/jen,
                                   /var/lib/jen). Recorded in
                                   /etc/jen-layout.conf; a later run that
                                   disagrees with it is refused. Same
                                   JEN_APP_DIR / JEN_CONFIG_DIR /
                                   JEN_DATA_DIR names in --answers or the
                                   environment.
  sudo ./install.sh --restore <bundle.tar.enc>
                                   Restore a recovery bundle (Settings → Databases
                                   → Recovery) onto this install — run AFTER a normal
                                   install/upgrade, not instead of one.
                                   Stops Jen, snapshots what it replaces, restarts and
                                   health-checks, and rolls back on failure. Flags:
                                   --no-stop (Docker / not a systemd unit), --start, --force
  sudo ./install.sh --rollback <snapshot dir>
                                   Undo a restore from its pre-restore snapshot
  sudo ./install.sh --help        Show this message
HELPEOF
}

# v5.44.0 (Q45) — --restore takes the bundle path as its own next
# argument, unlike every other flag here, so this loop is index-based
# (shift) rather than the plain `for arg in "$@"` every other flag
# still uses. --answers (Q113) needs the same shift.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)     print_help; exit 0 ;;
        --upgrade)     MODE_UPGRADE=true ;;
        --configure)   MODE_CONFIGURE=true ;;
        --repair)      MODE_REPAIR=true ;;
        --unattended)  MODE_UNATTENDED=true ;;
        --docker)      MODE_DOCKER=true ;;
        --answers)
            shift
            ANSWERS_FILE="${1:-}"
            ;;
        --app-dir)
            shift
            OPT_APP_DIR="${1:-}"
            ;;
        --config-dir)
            shift
            OPT_CONFIG_DIR="${1:-}"
            ;;
        --data-dir)
            shift
            OPT_DATA_DIR="${1:-}"
            ;;
        --restore)
            MODE_RESTORE=true
            shift
            RESTORE_BUNDLE="${1:-}"
            ;;
        --force)       RESTORE_FORCE="--force" ;;
        --no-stop)     RESTORE_NOSTOP="--no-stop" ;;
        --start)       RESTORE_START="--start" ;;
        --rollback)
            MODE_RESTORE=true
            shift
            RESTORE_ROLLBACK="${1:-}"
            ;;
    esac
    shift
done

# ── ANSI colors ──────────────────────────────────────────────────────────────
R='\033[0;31m'    # red
G='\033[0;32m'    # green
Y='\033[1;33m'    # yellow
C='\033[0;36m'    # cyan
B='\033[1m'       # bold
DIM='\033[2m'     # dim
NC='\033[0m'      # reset
BG_T='\033[46m'   # teal background

# ── Output helpers ────────────────────────────────────────────────────────────
ok()      { echo -e "  ${G}[  OK  ]${NC}  $*"; }
info()    { echo -e "  ${C}[ INFO ]${NC}  $*"; }
warn()    { echo -e "  ${Y}[ WARN ]${NC}  $*"; }
err()     { echo -e "  ${R}[ FAIL ]${NC}  $*"; }
fatal()   { echo -e "  ${R}[ FATAL]${NC}  $*"; [[ "$ROLLBACK_ARMED" == "true" && "$IS_UPGRADE" == "true" ]] && rollback; exit 1; }
step()    { echo -e "\n  ${B}${C}$*${NC}"; }
divider() { echo -e "  ${DIM}${C}$(printf '─%.0s' {1..54})${NC}"; }
blank()   { echo ""; }

# ── .env value emit ─────────────────────────────────────────────────────────
# Docker Compose >= 2.24 interpolates .env values (project file AND
# env_file:), so `$` in a password would be mangled. But it also strips
# surrounding quotes — whereas Compose < 2.24 does NOT strip quotes on
# env_file values, so blindly quoting everything (the v5.8.0 approach)
# broke plain passwords on older Compose.
#
# So: emit bare when the value is "obviously inert" (letters, digits, and
# a handful of safe punctuation — covers hostnames, ports, hex passwords),
# which is byte-identical on every Compose version. Only quote when the
# value actually contains something Compose or dotenv would touch ($,
# whitespace, #, quotes, backslash) — and the Docker path requires
# Compose >= 2.24 so those quotes are stripped back off.
env_value() {
    local v="$1"
    if [[ -z "$v" ]]; then
        printf ''
    elif [[ "$v" =~ ^[A-Za-z0-9_.:/@%+=-]+$ ]]; then
        printf '%s' "$v"
    elif [[ "$v" != *"'"* ]]; then
        printf "'%s'" "$v"          # single-quote: everything literal
    else
        v="${v//\\/\\\\}"           # has a ' -> double-quote + escape
        v="${v//\$/\$\$}"
        v="${v//\"/\\\"}"
        v="${v//\`/\\\`}"
        printf '"%s"' "$v"
    fi
}

prompt_input() {
    # prompt_input "Question" "default" -> echoes answer
    local q="$1" default="$2" answer
    if [[ "$MODE_UNATTENDED" == "true" ]]; then echo "$default"; return; fi
    printf "  ${Y}  ▸${NC} %s [${C}%s${NC}]: " "$q" "$default" > /dev/tty
    read -r answer < /dev/tty
    echo "${answer:-$default}"
}

prompt_secret() {
    local q="$1" answer
    printf "  ${Y}  ▸${NC} %s: " "$q" > /dev/tty
    read -rs answer < /dev/tty
    echo "" > /dev/tty
    echo "$answer"
}

prompt_yn() {
    # prompt_yn "Question" "y|n" -> echoes y or n
    # Valid inputs: y Y yes YES (or Enter when default=y) -> y
    #               n N no  NO  (or Enter when default=n) -> n
    # Any other input re-prompts.
    local q="$1" default="${2:-y}" answer
    if [[ "$MODE_UNATTENDED" == "true" ]]; then echo "$default"; return; fi
    local opts="[Y/n]"; [[ "$default" == "n" ]] && opts="[y/N]"
    while true; do
        printf "  ${Y}  ▸${NC} %s %s: " "$q" "$opts" > /dev/tty
        read -r answer < /dev/tty
        answer="${answer:-$default}"
        case "${answer,,}" in
            y|yes) echo "y"; return ;;
            n|no)  echo "n"; return ;;
            *) printf "  ${Y}  Please enter y or n.${NC}\n" > /dev/tty ;;
        esac
    done
}

prompt_choice() {
    # prompt_choice "default" -> echoes choice
    local default="$1" answer
    if [[ "$MODE_UNATTENDED" == "true" ]]; then echo "$default"; return; fi
    printf "  ${Y}  ▸${NC} Choice [${C}%s${NC}]: " "$default" > /dev/tty
    read -r answer < /dev/tty
    echo "${answer:-$default}"
}

# ── Answers file (v5.67.0, Q113) ─────────────────────────────────────────────
# A fresh install's non-interactive source of truth: KEY=value lines, the
# same JEN_* names .env.example and run.py's Docker env-var path already
# use. Read line by line, never sourced — no character an answer's value
# might contain (`$`, backticks, `;`) is ever handed to the shell to
# interpret. Refused unless it is a regular file, not a symlink, and not
# writable by group or other (it can carry passwords).
HAVE_TTY=false
[[ -t 0 ]] && HAVE_TTY=true

_load_answers_file() {
    local f="$1"
    [[ -e "$f" ]] || fatal "Answers file not found: $f"
    [[ -L "$f" ]] && fatal "Answers file must be a regular file, not a symlink: $f"
    [[ -f "$f" ]] || fatal "Answers file is not a regular file: $f"
    local mode
    mode=$(stat -c '%a' "$f" 2>/dev/null || stat -f '%OLp' "$f" 2>/dev/null || echo "")
    # Group-write is octal 0020, other-write is 0002 — refuse if either bit
    # is set, however many permission digits this stat happened to print.
    if [[ -n "$mode" ]] && (( (8#$mode & 8#0022) != 0 )); then
        fatal "Answers file is writable by group or other (mode $mode) — refusing: $f  (fix: chmod 600 $f)"
    fi

    # v5.67.0-beta.9 (Q121, item h) — the parser used to take `KEY = value` with the value's leading space
    # (so a password gained one), keep surrounding quotes literally (a quoted value was installed WITH its
    # quotes), and drop an `export KEY=value` line outright (the first word made the "key" something no
    # caller asks for). It now trims whitespace around the value, strips ONE matching pair of surrounding
    # quotes, and accepts a leading `export`. Still read line by line, never sourced.
    local line key value first last
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%$'\r'}"                          # tolerate a CRLF file
        line="${line#"${line%%[![:space:]]*}"}"       # leading whitespace
        [[ -z "$line" ]] && continue
        [[ "$line" == \#* ]] && continue
        if [[ "$line" == export[[:space:]]* ]]; then
            line="${line#export}"
            line="${line#"${line%%[![:space:]]*}"}"
        fi
        [[ "$line" != *=* ]] && continue
        key="${line%%=*}"
        key="${key//[[:space:]]/}"
        value="${line#*=}"
        value="${value#"${value%%[![:space:]]*}"}"    # whitespace after the =
        value="${value%"${value##*[![:space:]]}"}"    # trailing whitespace
        if [[ ${#value} -ge 2 ]]; then
            first="${value:0:1}"; last="${value: -1}"
            if [[ ( "$first" == '"' || "$first" == "'" ) && "$last" == "$first" ]]; then
                value="${value:1:${#value}-2}"
            fi
        fi
        [[ -n "$key" ]] && ANSWERS["$key"]="$value"
    done < "$f"
}

# _cfgval NAME — the raw resolved value (answers file, else JEN_<NAME> env,
# else empty) with no prompting and no default. Used where a value's mere
# presence matters (e.g. "was SSH configured at all?").
_cfgval() {
    local name="$1"
    if [[ -n "${ANSWERS[$name]+x}" ]]; then
        printf '%s' "${ANSWERS[$name]}"
    elif [[ -n "${!name:-}" ]]; then
        printf '%s' "${!name}"
    fi
}

# _ask NAME "Question" "default" [required]
# Resolution order: --answers file, then the JEN_<NAME> environment
# variable — either one is used silently, with no prompt, matching the
# non-interactive contract. Only when NEITHER supplies a value does this
# fall back to the interactive prompt (when a TTY is available) or to
# "default" (or a named fatal error, when "required" is passed and
# "default" is empty).
_ask() {
    local name="$1" question="$2" default="$3" required="${4:-}"
    if [[ -n "${ANSWERS[$name]+x}" ]]; then
        printf '%s' "${ANSWERS[$name]}"; return
    fi
    if [[ -n "${!name:-}" ]]; then
        printf '%s' "${!name}"; return
    fi
    if [[ "$HAVE_TTY" == "true" && "$MODE_UNATTENDED" == "false" ]]; then
        prompt_input "$question" "$default"; return
    fi
    if [[ -z "$default" && "$required" == "required" ]]; then
        fatal "Missing required value for $name — set it in --answers or the $name environment variable."
    fi
    printf '%s' "$default"
}

# _ask_secret NAME "Question" [required] — same resolution order as _ask,
# but the interactive fallback never echoes and there is no "default" to
# fall back to (a secret has none).
_ask_secret() {
    local name="$1" question="$2" required="${3:-}"
    if [[ -n "${ANSWERS[$name]+x}" ]]; then
        printf '%s' "${ANSWERS[$name]}"; return
    fi
    if [[ -n "${!name:-}" ]]; then
        printf '%s' "${!name}"; return
    fi
    if [[ "$HAVE_TTY" == "true" && "$MODE_UNATTENDED" == "false" ]]; then
        prompt_secret "$question"; return
    fi
    if [[ "$required" == "required" ]]; then
        fatal "Missing required value for $name — set it in --answers or the $name environment variable."
    fi
    printf ''
}

# ── Layout (v5.67.0, Q114; ONE checker since v5.67.0-beta.5, Q117) ──────────
# v5.67.0-beta.5 — every validation rule (the forbidden/shared-root list,
# the path grammar, ancestor ownership, the dedicated-directory/marker
# contract) now lives in exactly one place: jen-update-root.py's own
# check_layout(), called below. install.sh used to carry its own bash copy
# of this logic alongside the Python one in load_layout() — a ChatGPT
# review of 5.67.0-beta.3 found the two had already drifted (the bash
# side's forbidden-prefix list let `--config-dir /etc` through, which this
# script then recursively chown'd). Calling the one real implementation
# instead of re-deriving it in bash is what keeps that from happening
# again. tests/test_layout.py now exercises this through the checker, not
# through bash functions that no longer exist.
PYBIN_FOR_LAYOUT="python3"

# _layout_checker [ARGS...] — the extracted tarball's own copy of
# jen-update-root.py (it ships at the repo root, same place jen-kea-helper
# does). install.sh is already running as root (sudo ./install.sh), so
# this is a direct function call, never the sudoers-gated path — see that
# script's own module comment above check_layout_cli() for why a new argv
# mode there is still safe.
_layout_checker() {
    "$PYBIN_FOR_LAYOUT" "$SCRIPT_DIR/jen-update-root.py" --check-layout "$@"
}

# _layout_kv TEXT KEY — one "key=value" line (the checker's own stdout
# format) picked out by key.
_layout_kv() {
    printf '%s\n' "$1" | sed -n "s/^${2}=//p"
}

# _resolve_layout_dirs — sets LAYOUT_MODE and INSTALL_DIR/CONFIG_DIR/
# CONTENT_DIR, all from the checker's own answer to
# `--check-layout --for auto [--app-dir ...]` (v5.67.0-beta.9, Q121, item b).
# An existing $LAYOUT_FILE (a prior install, of any mode) is authoritative;
# any --app-dir/--config-dir/--data-dir (or JEN_*_DIR answers/env) that
# disagrees with it is refused by the checker itself — relocating is a
# runbook (docs/runbooks.md §5), not a flag, so there is never a partial
# move. With no layout file (fresh install, or one from before Q114), an
# explicit value wins, else today's literal default — unchanged for every
# install that never asks for this.
#
# Install versus upgrade is the CHECKER's decision, by the same marker-or-
# content rule the rest of the layout contract uses — never "does the
# directory exist": install.sh used to ask `[[ -d "$INSTALL_DIR" ]]`, so a
# pre-created EMPTY --app-dir (which the contract allows) was refused as
# "relocating an existing install", and a non-Jen /opt/jen with no layout
# file was treated as an upgrade, tolerated, then chowned and stamped. A
# pre-Q114 box (no $LAYOUT_FILE, a real app_dir) is recognised by content
# and so reads as an upgrade without being asked to prove anything else.
#
# Must be called AFTER the flags and the answers file have been read (main()
# does both first): a JEN_APP_DIR/JEN_CONFIG_DIR/JEN_DATA_DIR in --answers
# used to be silently ignored, because this ran at top level, before the
# answers file was loaded — `--answers` with JEN_APP_DIR=/srv/jen/app
# installed to the defaults and recorded them.
LAYOUT_MODE="install"
_resolve_layout_dirs() {
    local want_app want_config want_data out rc=0
    local args=(--for auto)
    want_app=$(_cfgval JEN_APP_DIR); [[ -n "$OPT_APP_DIR" ]] && want_app="$OPT_APP_DIR"
    want_config=$(_cfgval JEN_CONFIG_DIR); [[ -n "$OPT_CONFIG_DIR" ]] && want_config="$OPT_CONFIG_DIR"
    want_data=$(_cfgval JEN_DATA_DIR); [[ -n "$OPT_DATA_DIR" ]] && want_data="$OPT_DATA_DIR"

    [[ -n "$want_app"    ]] && args+=(--app-dir "$want_app")
    [[ -n "$want_config" ]] && args+=(--config-dir "$want_config")
    [[ -n "$want_data"   ]] && args+=(--data-dir "$want_data")

    out=$(_layout_checker "${args[@]}" 2>&1) || rc=$?
    [[ $rc -ne 0 ]] && fatal "$out"
    LAYOUT_MODE=$(_layout_kv "$out" mode)
    INSTALL_DIR=$(_layout_kv "$out" app_dir)
    CONFIG_DIR=$(_layout_kv "$out" config_dir)
    CONTENT_DIR=$(_layout_kv "$out" data_dir)
    [[ -n "$INSTALL_DIR" && -n "$CONFIG_DIR" && -n "$CONTENT_DIR" ]] \
        || fatal "The layout checker did not return all three directories: $out"
    return 0
}

# write_layout_markers — stamps .jen-directory into each of
# INSTALL_DIR/CONFIG_DIR/CONTENT_DIR once they genuinely exist (called
# late in the fresh-install sequence, after install_files/migrate_content
# have created them — check_layout's own --for install validation runs
# BEFORE anything is created, so it never writes a marker itself). An
# upgrade never calls this: an upgrade's own _resolve_layout_dirs call
# above (--for upgrade) retroactively stamps a pre-Q117 install the first
# time it recognizes one by content, and a post-Q117 install already
# carries its markers from here.
write_layout_markers() {
    [[ "$IS_UPGRADE" == "true" ]] && return 0
    local out
    out=$("$PYBIN_FOR_LAYOUT" "$SCRIPT_DIR/jen-update-root.py" --write-layout-markers \
        --app-dir "$INSTALL_DIR" --config-dir "$CONFIG_DIR" --data-dir "$CONTENT_DIR" \
        --version "$JEN_VERSION" 2>&1) || fatal "$out"
    ok "Layout directories marked as Jen's own"
}

# ── Paths ────────────────────────────────────────────────────────────────────
# v5.67.0-beta.9 (Q121, items a/h) — everything below derives from the three
# layout directories, so it lives in a function main() calls AFTER the flags,
# the answers file and root have all been dealt with and the layout is
# resolved. It used to run at top level, before any of them: the layout was
# resolved before the answers file was read, and before require_root, and for
# --docker too (which has no layout at all). The three assignments right below
# are today's historical defaults — what every variable holds until
# _resolve_layout_dirs replaces them, and what --docker keeps (it never
# touches any of them).
INSTALL_DIR="/opt/jen"
CONFIG_DIR="/etc/jen"
CONTENT_DIR="/var/lib/jen"

_set_paths() {
    SERVICE_FILE="/etc/systemd/system/jen.service"
    SUDOERS_FILE="/etc/sudoers.d/jen"
    CONFIG_FILE="$CONFIG_DIR/jen.config"
    BACKUP_DIR="$CONFIG_DIR/backups"    # jen.config backups (NOT the DB backups — those are $CONTENT_DIR/backups)
    # v5.67.0-beta.7 (Q119, item c) — the external-files rollback snapshot
    # (jen-sudoers, the systemd units, jen-update-root.py itself) is NOT a
    # config backup and must never live under $CONFIG_DIR: that directory is
    # service-user-owned (§6.1), so a compromised service account could edit
    # a snapshotted copy of jen-update-root.py or a unit file and wait for
    # ANY later rollback to have root restore its payload straight into
    # /usr/local/sbin or /etc/systemd/system. $INSTALL_DIR is root-owned
    # throughout (install_files's own chown -R root:root covers this
    # subdirectory too, on every run), so that's where root's own rollback
    # material belongs.
    ROOT_ROLLBACK_DIR="$INSTALL_DIR/.rollback"

    # v5.14.0 — versioned release directories. Each release is built whole
    # under releases/<X.Y.Z>/{app,venv}; `current` is a relative symlink to
    # the live one, flipped atomically (ln -s + mv -T). A rollback is one
    # flip back — the previous release dir is never touched.
    RELEASES_DIR="$INSTALL_DIR/releases"
    CURRENT_LINK="$INSTALL_DIR/current"
    RELEASE_DIR="$RELEASES_DIR/$JEN_VERSION"   # the release THIS run installs
    APP_DIR="$RELEASE_DIR/app"

    # v5.8.0 — bare-metal Jen runs from its own venv, not system site-packages
    # (no more --break-system-packages). VENV_PY is this release's interpreter;
    # PYBIN is whatever's usable right now for the installer's own inline
    # python helpers — the currently-live release's venv (pre-upgrade DB
    # backup needs pymysql), else a flat pre-5.14 venv, else system python.
    VENV_DIR="$RELEASE_DIR/venv"
    VENV_PY="$VENV_DIR/bin/python"
    PYBIN="python3"
    [[ -x "$INSTALL_DIR/venv/bin/python" ]] && PYBIN="$INSTALL_DIR/venv/bin/python"
    [[ -x "$CURRENT_LINK/venv/bin/python" ]] && PYBIN="$CURRENT_LINK/venv/bin/python"
    return 0    # the line above is a bare `[[ ]] && ...`: false would otherwise be this function's status, fatal under set -e
}

# The app tree the installer's inline python helpers should import from:
# this run's release once install_files has populated it, else the live
# release, else a flat pre-5.14 tree.
app_pyroot() {
    if   [[ -d "$APP_DIR/jen" ]]; then echo "$APP_DIR"
    elif [[ -d "$CURRENT_LINK/app/jen" ]]; then echo "$CURRENT_LINK/app"
    else echo "$INSTALL_DIR"; fi
}

_set_paths

# ── Spinner ───────────────────────────────────────────────────────────────────
_spinner_pid=""
spinner_start() {
    local msg="$1"
    # v5.67.0-beta.9 (Q121) — CI caught this running --repair for the first
    # time without --unattended and without a terminal: the spinner writes
    # every frame to /dev/tty, which does not exist there ("No such device or
    # address"), and under set -e that killed the install. --upgrade and
    # --repair are "non-interactive" modes but not --unattended, so they hit it
    # from cron, Ansible or any ssh without -t. No terminal on stdin (HAVE_TTY,
    # the same signal every prompt already uses) means no animation, just the
    # line.
    if [[ "$MODE_UNATTENDED" == "true" || "$HAVE_TTY" != "true" ]]; then
        info "$msg"
        return
    fi
    (
        local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
        local i=0
        while true; do
            printf "\r  ${C}  %s${NC}  %s  " "${frames[$i % ${#frames[@]}]}" "$msg" > /dev/tty
            i=$((i + 1))
            sleep 0.08
        done
    ) &
    _spinner_pid=$!
}
spinner_stop() {
    if [[ -n "$_spinner_pid" ]]; then
        kill "$_spinner_pid" 2>/dev/null || true
        wait "$_spinner_pid" 2>/dev/null || true
        _spinner_pid=""
        printf "\r%60s\r" "" > /dev/tty
    fi
}

# ── Box drawing helpers ──────────────────────────────────────────────────────
# Visible length of a string — strips ANSI codes, handles UTF-8 multibyte chars
_vlen() {
    printf '%s' "$(echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g' | tr -d '\n')"         | python3 -c "import sys; print(len(sys.stdin.read()))"
}

# Print a single box line with content padded to exactly 54 visible chars.
# Usage: _box_line "  ${B}Some text${NC}" ["$C"|"$R"]
_box_line() {
    local content="$1"
    local bc="${2:-$C}"   # border color
    local vis pad
    vis=$(_vlen "$content")
    pad=$(printf '%*s' $((54 - vis)) '')
    printf "  ${bc}║${NC}${content}${pad}${bc}║${NC}\n"
}

# ── BBS/ANSI banner ───────────────────────────────────────────────────────────
show_banner() {
    # v5.67.0 (Q113) — `clear` looks up the terminal's capabilities via
    # $TERM/terminfo and exits non-zero ("'unknown': I need something more
    # specific.") when it can't resolve one — which every real operator's
    # SSH session always has and no CI runner does. install.sh had never
    # run anywhere without a real terminal before this Q's CI job, so
    # nothing ever hit this: under `set -e` it killed the whole script
    # before a single line of output. Purely cosmetic either way.
    clear 2>/dev/null || true
    echo ""
    echo -e "  ${C}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${C}║${NC}${B}                                                      ${NC}${C}║${NC}"
    echo -e "  ${C}║${NC}  ${BG_T}${B}  J E N  ${NC}  ${B}The Kea DHCP Management Console${NC}          ${C}║${NC}"
    echo -e "  ${C}║${NC}${B}                                                      ${NC}${C}║${NC}"
    _box_line "  ${DIM}Version ${JEN_VERSION}   •   github.com/ltkojak/jen-kea${NC}"
    _box_line "  ${DIM}GPLv3 — Copyright (C) 2026 Matthew Thibodeau${NC}"
    echo -e "  ${C}║${NC}${B}                                                      ${NC}${C}║${NC}"
    echo -e "  ${C}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}
# ── Mode banner ───────────────────────────────────────────────────────────────
show_mode_banner() {
    if   [[ "$MODE_REPAIR"    == "true" ]]; then
        echo -e "  ${Y}  ▐▌  REPAIR MODE  ▐▌${NC}  Reinstalling files, keeping config"
    elif [[ "$MODE_CONFIGURE" == "true" ]]; then
        echo -e "  ${C}  ▐▌  CONFIGURE MODE  ▐▌${NC}  Re-running configuration wizard"
    elif [[ "$IS_UPGRADE"     == "true" ]]; then
        echo -e "  ${G}  ▐▌  UPGRADE MODE  ▐▌${NC}  ${Y}${EXISTING_VERSION}${NC}  ${B}${C}==>${NC}  ${G}${B}${JEN_VERSION}${NC}"
    else
        echo -e "  ${G}  ▐▌  FRESH INSTALL  ▐▌${NC}  Welcome to Jen!"
    fi
    blank
    divider
    blank
}

# ── Require root ──────────────────────────────────────────────────────────────
require_root() {
    if [[ $EUID -ne 0 ]]; then
        fatal "This installer must be run as root.  →  sudo ./install.sh"
    fi
}

# ── Detect existing install ───────────────────────────────────────────────────
detect_existing() {
    # v5.67.0-beta.9 (Q121, item b) — the checker's own answer (LAYOUT_MODE:
    # marker, or recognised by content) says whether an install is recorded
    # here at all; the files below say whether there is anything TO upgrade.
    # A box whose app was removed (uninstall.sh level 1) but whose layout
    # file and config were kept is "upgrade" to the checker and a reinstall
    # to everything below — it has no release to back up, snapshot or roll
    # back to.
    if [[ "$LAYOUT_MODE" == "upgrade" ]] && \
       { [[ -f "$CURRENT_LINK/app/run.py" ]] || [[ -f "$INSTALL_DIR/run.py" ]] || [[ -f "$INSTALL_DIR/jen.py" ]] || [[ -d "$INSTALL_DIR/jen" ]]; }; then
        IS_UPGRADE=true
        # Version: the versioned layout's current/app first (v5.14.0), then
        # the flat jen/__init__.py (2.6.x+), jen.py (pre-2.6), legacy/jen.py.
        local ver_file=""
        if   [[ -f "$CURRENT_LINK/app/jen/__init__.py" ]]; then ver_file="$CURRENT_LINK/app/jen/__init__.py"
        elif [[ -f "$INSTALL_DIR/jen/__init__.py"      ]]; then ver_file="$INSTALL_DIR/jen/__init__.py"
        elif [[ -f "$INSTALL_DIR/jen.py"               ]]; then ver_file="$INSTALL_DIR/jen.py"
        elif [[ -f "$INSTALL_DIR/legacy/jen.py"        ]]; then ver_file="$INSTALL_DIR/legacy/jen.py"
        fi
        if [[ -n "$ver_file" ]]; then
            # jen/version.py::parse_version is the grammar this mirrors: X.Y.Z,
            # optionally -beta.N or -rc.N (v5.56.1, Q68j — this used to drop
            # the suffix entirely, so an installed beta showed as "unknown").
            EXISTING_VERSION=$(grep -m1 'JEN_VERSION' "$ver_file" 2>/dev/null                 | grep -oP '"[0-9]+\.[0-9]+\.[0-9]+(-(beta|rc)\.[0-9]+)?"' | tr -d '"' || echo "unknown")
        else
            EXISTING_VERSION="unknown"
        fi
    fi
}

# ── Pre-flight checks ─────────────────────────────────────────────────────────
preflight_checks() {
    blank
    echo -e "  ${B}${C}PRE-FLIGHT CHECKS${NC}"
    divider
    blank

    local failed=0

    # Root
    [[ $EUID -eq 0 ]] && ok "Running as root" || { err "Must run as root"; failed=$((failed+1)); }

    # OS
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "${ID:-}:${VERSION_ID:-}" in
            ubuntu:22.04|ubuntu:24.04) ok "OS: Ubuntu ${VERSION_ID}" ;;
            ubuntu:*)                  warn "OS: Ubuntu ${VERSION_ID} — not officially tested" ;;
            *)                         warn "OS: ${PRETTY_NAME:-unknown} — not officially supported" ;;
        esac
    else
        warn "Could not detect OS — proceeding anyway"
    fi

    # Python
    if command -v python3 &>/dev/null; then
        local pyver
        pyver=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
            ok "Python ${pyver}"
        else
            err "Python ${pyver} found — 3.10+ required"; failed=$((failed+1))
        fi
    else
        err "Python3 not found"; failed=$((failed+1))
    fi

    # systemd
    command -v systemctl &>/dev/null && ok "systemd" || { err "systemd not found"; failed=$((failed+1)); }

    # pip
    command -v pip3 &>/dev/null || python3 -m pip --version &>/dev/null 2>&1 \
        && ok "pip3" || warn "pip3 not found — will attempt install"

    # venv (v5.8.0 — Jen installs into /opt/jen/venv). Ubuntu ships this
    # as a separate python3-venv package; install_dependencies pulls it.
    if python3 -c 'import venv, ensurepip' &>/dev/null; then
        ok "python3 venv"
    else
        warn "python3-venv not available — will install"
    fi

    # Tools
    command -v ssh-keygen &>/dev/null && ok "ssh-keygen" || warn "ssh-keygen not found — will install"
    command -v curl       &>/dev/null && ok "curl"       || warn "curl not found — connection tests unavailable"
    command -v mysql      &>/dev/null && ok "mysql client" || warn "mysql client not found — DB tests unavailable"

    # Disk space — v5.67.0 (Q113): the real targets, not a hardcoded /opt.
    # $INSTALL_DIR/$CONFIG_DIR/$CONTENT_DIR don't exist yet on a fresh
    # box, so walk each up to the nearest existing ancestor (its mount
    # point, in practice) and check THAT — /etc or /var/lib can genuinely
    # be a separate, smaller partition than /opt. Reports the tightest.
    local target avail_kb min_avail_kb="" tightest="" check_path
    for target in "$INSTALL_DIR" "$CONFIG_DIR" "$CONTENT_DIR"; do
        check_path="$target"
        while [[ ! -d "$check_path" && "$check_path" != "/" ]]; do
            check_path="$(dirname "$check_path")"
        done
        avail_kb=$(df "$check_path" 2>/dev/null | awk 'NR==2{print $4}')
        avail_kb="${avail_kb:-0}"
        if [[ -z "$min_avail_kb" || "$avail_kb" -lt "$min_avail_kb" ]]; then
            min_avail_kb="$avail_kb"
            tightest="$target (on $check_path)"
        fi
    done
    if [[ "$min_avail_kb" -gt 102400 ]]; then
        ok "Disk space: $(( min_avail_kb / 1024 ))MB free  ${DIM}(tightest: ${tightest})${NC}"
    else
        warn "Low disk space: $(( min_avail_kb / 1024 ))MB free on ${tightest} — recommend 100MB+"
    fi

    blank
    [[ $failed -gt 0 ]] && fatal "$failed pre-flight check(s) failed. Fix the above and re-run."
    ok "All required checks passed"
    blank
}

# ── Install dependencies ──────────────────────────────────────────────────────
install_dependencies() {
    blank
    echo -e "  ${B}${C}DEPENDENCIES${NC}"
    divider
    blank

    # Only refresh package lists on fresh installs — on upgrades all deps
    # are already present and apt-get update just adds unnecessary delay
    if [[ "$IS_UPGRADE" == "false" ]]; then
        spinner_start "Updating package lists..."
        apt-get update -qq 2>/dev/null
        spinner_stop
        ok "Package lists updated"
    else
        ok "Skipping package list update (upgrade mode)"
    fi

    local pkgs=()
    command -v pip3        &>/dev/null || pkgs+=(python3-pip)
    command -v mysql       &>/dev/null || pkgs+=(mariadb-client-core)
    command -v ssh-keygen  &>/dev/null || pkgs+=(openssh-client)
    command -v curl        &>/dev/null || pkgs+=(curl)
    command -v openssl     &>/dev/null || pkgs+=(openssl)
    python3 -c 'import venv, ensurepip' &>/dev/null || pkgs+=(python3-venv)

    if [[ ${#pkgs[@]} -gt 0 ]]; then
        spinner_start "Installing system packages: ${pkgs[*]}"
        apt-get install -y -qq "${pkgs[@]}" 2>/dev/null
        spinner_stop
        ok "System packages installed: ${pkgs[*]}"
    else
        ok "All system packages present"
    fi
    blank
}

# ── Python virtualenv ────────────────────────────────────────────────────────
# v5.8.0 — Jen's Python dependencies live in /opt/jen/venv, isolated from
# apt-managed site-packages. Replaces the old `pip install
# --break-system-packages` into system python. Idempotent: re-run on every
# install/upgrade; `venv --upgrade` re-points an existing venv at the
# current system python (so an OS python bump doesn't strand it), and pip
# is a fast no-op when the pins are already satisfied.
#
# The venv is left root:root — the www-data service account only needs to
# read and execute the interpreter and site-packages, never write them.
# A writable venv would be a persistence foothold for a compromised
# www-data (swap a package, Jen runs it every restart). Only this script
# and the root self-updater ever modify it.
setup_venv() {
    blank
    echo -e "  ${B}${C}PYTHON ENVIRONMENT${NC}"
    divider
    blank

    mkdir -p "$RELEASE_DIR"
    local req_file="$SCRIPT_DIR/requirements.txt"
    [[ -f "$req_file" ]] || fatal "requirements.txt not found beside install.sh"

    if [[ -x "$VENV_PY" ]] && "$VENV_PY" -c '' 2>/dev/null; then
        spinner_start "Refreshing virtualenv ($VENV_DIR)..."
        python3 -m venv --upgrade "$VENV_DIR" 2>/dev/null || true
    else
        [[ -e "$VENV_DIR" ]] && rm -rf "$VENV_DIR"
        spinner_start "Creating virtualenv ($VENV_DIR)..."
        if ! python3 -m venv "$VENV_DIR"; then
            spinner_stop
            fatal "Could not create $VENV_DIR — is python3-venv installed?"
        fi
    fi
    "$VENV_PY" -m pip install -q --upgrade pip >/dev/null 2>&1 || true
    spinner_stop
    ok "Virtualenv ready  ${DIM}($("$VENV_PY" --version 2>&1))${NC}"

    spinner_start "Installing Python dependencies into the venv..."
    if "$VENV_PY" -m pip install -q -r "$req_file"; then
        spinner_stop
        ok "Python dependencies installed"
    else
        spinner_stop
        fatal "pip install into the venv failed — see output above"
    fi

    # Byte-compile now, as root — the venv is not writable by www-data, so
    # the service can't lazily write .pyc on first import.
    "$VENV_PY" -m compileall -q "$VENV_DIR/lib" >/dev/null 2>&1 || true

    # PYBIN now points at the venv for the rest of this run (admin
    # password hashing, template/module verification).
    PYBIN="$VENV_PY"
    # Deliberately root:root — see the header comment. Undo any prior
    # www-data ownership from a 5.8.0 pre-release install.
    chown -R root:root "$VENV_DIR" 2>/dev/null || true
    blank
}

# ── Connection tests ──────────────────────────────────────────────────────────
test_kea_api() {
    local url="$1" user="$2" pass="$3"
    command -v curl &>/dev/null || return 1
    local result
    result=$(curl -s -u "${user}:${pass}" -X POST "${url}/" \
        -H "Content-Type: application/json" \
        -d '{"command":"version-get","service":["dhcp4"]}' \
        --connect-timeout 5 2>/dev/null || echo "CONN_FAILED")
    echo "$result" | grep -q '"result": 0'
}

test_mysql() {
    local host="$1" user="$2" pass="$3" db="$4"
    command -v mysql &>/dev/null || return 1
    mysql -h"$host" -u"$user" -p"$pass" "$db" -e "SELECT 1;" &>/dev/null 2>&1
}

# v5.67.0 (Q113) — a value still equal to the placeholder default it was
# never actually changed from is never written to jen.config; the key is
# left blank instead, so Jen's own Health/Getting-started pages say what's
# missing rather than a literal "YOUR-KEA-SERVER" reaching the config file.
_blank_if_placeholder() {
    local -n _ref="$1"
    [[ "$_ref" == "$2" ]] && _ref=""
}

# v5.67.0 (Q113) — what collect_config does after a connection test fails.
# Non-interactive (answers file, JEN_* env, or --unattended): nobody to
# ask, so warn and continue — the value is left exactly as given (it came
# from a deliberate source, not a default the operator never touched).
# Interactive: a real choice, explicitly recorded in the transcript
# (never a silent fall-through) — retry the same values, edit and try
# again, or continue without it. Sets _RETRY_ACTION to retry|edit|continue.
_connection_failure_choice() {
    local what="$1" detail="$2"
    if [[ "$HAVE_TTY" != "true" || "$MODE_UNATTENDED" == "true" ]]; then
        warn "Could not reach $what ($detail) — continuing; configure it later in Jen"
        _RETRY_ACTION="continue"
        return
    fi
    warn "Could not reach $what ($detail)"
    blank
    while true; do
        echo -e "    ${B}r)${NC}  Retry with the same values"
        echo -e "    ${B}e)${NC}  Edit and try again"
        echo -e "    ${B}c)${NC}  Continue without it — I will finish in Jen"
        blank
        printf "  ${Y}  ▸${NC} Choice [${C}c${NC}]: " > /dev/tty
        local choice; read -r choice < /dev/tty
        choice="${choice:-c}"
        case "${choice,,}" in
            r) ok "Retrying $what"; _RETRY_ACTION="retry"; return ;;
            e) ok "Editing $what"; _RETRY_ACTION="edit"; return ;;
            c) ok "Continuing without $what — configure it later in Jen"; _RETRY_ACTION="continue"; return ;;
            *) echo -e "  ${R}  Please enter r, e or c.${NC}" > /dev/tty ;;
        esac
    done
}

# v5.67.0 (Q113) — when the Jen database can't be reached AND it's local
# with working root-socket auth, offer to create it instead of just
# printing SQL for the operator to run by hand afterward. Never attempted
# for a remote host — this only ever touches a database on THIS box.
_jen_db_can_self_create() {
    local host="$1"
    [[ "$host" == "localhost" || "$host" == "127.0.0.1" || "$host" == "::1" ]] || return 1
    command -v mysql &>/dev/null || return 1
    mysql -u root -e "SELECT 1;" &>/dev/null 2>&1
}

# v5.67.0-beta.9 (Q121, item h) — a SQL string literal for MySQL/MariaDB:
# backslash and the quote itself doubled. The self-create below used to put
# the password straight into the statement, so a password containing a quote
# broke the statement (or, worse, was part of it).
_sql_quote() {
    local s="$1" q="'"
    s="${s//\\/\\\\}"
    s="${s//$q/$q$q}"
    printf "'%s'" "$s"
}

_jen_db_offer_create() {
    blank
    warn "Could not connect to Jen database. The SQL to create it:"
    blank
    echo -e "    ${C}CREATE DATABASE \`${JEN_DB_NAME}\`;${NC}"
    echo -e "    ${C}CREATE USER '${JEN_DB_USER}'@'%' IDENTIFIED BY 'yourpassword';${NC}"
    echo -e "    ${C}GRANT ALL PRIVILEGES ON \`${JEN_DB_NAME}\`.* TO '${JEN_DB_USER}'@'%';${NC}"
    echo -e "    ${C}FLUSH PRIVILEGES;${NC}"
    blank
    if [[ "$HAVE_TTY" == "true" && "$MODE_UNATTENDED" == "false" ]] && _jen_db_can_self_create "$JEN_DB_HOST"; then
        # Identifiers (the database and user names) are interpolated, never
        # quoted — so only names that cannot carry SQL are accepted; the
        # password goes through _sql_quote. The statement is fed on stdin, so
        # the password never appears in a process listing.
        if [[ ! "$JEN_DB_NAME" =~ ^[A-Za-z0-9_.-]+$ || ! "$JEN_DB_USER" =~ ^[A-Za-z0-9_.-]+$ ]]; then
            warn "Not creating it for you: the database or user name has characters this installer will not put into SQL — use the statements above by hand."
            return 1
        fi
        if [[ "$(prompt_yn "MariaDB is local and root can connect without a password — create it now?" "y")" == "y" ]]; then
            local create_sql
            create_sql="CREATE DATABASE IF NOT EXISTS \`${JEN_DB_NAME}\`;
CREATE USER IF NOT EXISTS '${JEN_DB_USER}'@'%' IDENTIFIED BY $(_sql_quote "$JEN_DB_PASS");
GRANT ALL PRIVILEGES ON \`${JEN_DB_NAME}\`.* TO '${JEN_DB_USER}'@'%';
FLUSH PRIVILEGES;"
            if printf '%s\n' "$create_sql" | mysql -u root 2>/dev/null; then
                ok "Database and user created"
                return 0
            else
                err "Could not create the database — check the MariaDB error log"
            fi
        fi
    fi
    return 1
}

# ── Configuration wizard ──────────────────────────────────────────────────────
collect_config() {
    blank
    echo -e "  ${B}${C}CONFIGURATION${NC}"
    divider
    blank

    # On upgrade with existing config — offer choices. v5.67.0 (Q113):
    # MODE_UNATTENDED must short-circuit this the same way every other
    # prompt in this script already does — this raw read was the one
    # place that didn't, so `--unattended` on a box that already has a
    # config tried to read /dev/tty and aborted under set -e instead of
    # silently keeping the existing config the way the doc comment for
    # --unattended promises.
    #
    # v5.67.0-beta.9 (Q121, item c) — "an existing jen.config is KEPT" is no
    # longer an UPGRADE-only rule. uninstall.sh level 1 keeps the config and
    # promises "your existing config will be detected automatically"; a
    # reinstall onto it is a fresh install as far as IS_UPGRADE goes (there is
    # no app to upgrade), and collect_config used to rewrite jen.config from
    # blank Kea sections on a marked box. Now: a config that exists is kept
    # unless --configure was given, an answers file included (it feeds a NEW
    # config, and says so). No TTY to ask on is treated like --unattended,
    # since the menu below reads /dev/tty.
    if [[ -f "$CONFIG_FILE" && "$MODE_CONFIGURE" == "false" && -n "$ANSWERS_FILE" ]]; then
        blank
        ok "Keeping existing configuration  ${DIM}(${CONFIG_FILE}; --answers only feeds a NEW config — --configure rewrites this one)${NC}"
        CONFIGURE=false
        return
    fi
    if [[ -f "$CONFIG_FILE" && \
          "$MODE_UPGRADE" == "false" && "$MODE_REPAIR" == "false" && \
          "$MODE_UNATTENDED" == "false" && "$HAVE_TTY" == "true" ]]; then
        echo -e "  ${G}Existing config found:${NC} ${DIM}${CONFIG_FILE}${NC}"
        blank
        echo -e "    ${B}1)${NC}  Keep existing config  ${DIM}(recommended)${NC}"
        echo -e "    ${B}2)${NC}  Reconfigure — re-run the setup wizard"
        blank
        local choice
        while true; do
            printf "  ${Y}  ▸${NC} Choice [${C}1${NC}]: " > /dev/tty
            read -r choice < /dev/tty
            choice="${choice:-1}"
            case "$choice" in
                1)
                    blank
                    ok "Keeping existing configuration"; CONFIGURE=false; return ;;
                2)   break ;;
                *)   echo -e "  ${R}  Invalid — please enter 1 or 2.${NC}" > /dev/tty ;;
            esac
        done
        warn "This will overwrite your existing configuration."
        [[ "$(prompt_yn "Are you sure?" "n")" == "n" ]] && \
            { blank; ok "Keeping existing configuration"; CONFIGURE=false; return; }
        CONFIGURE=true
    elif [[ "$MODE_UPGRADE" == "true" || "$MODE_REPAIR" == "true" || \
            ( -f "$CONFIG_FILE" && ( "$MODE_UNATTENDED" == "true" || "$HAVE_TTY" == "false" ) ) ]]; then
        blank
        ok "Keeping existing configuration"
        CONFIGURE=false
        return
    else
        CONFIGURE=true
    fi

    blank
    if [[ -n "$ANSWERS_FILE" ]]; then
        info "Configuring Jen from ${C}${ANSWERS_FILE}${NC}. Anything it leaves out is still asked below."
    else
        info "Let's set up Jen. Press Enter to accept defaults shown in ${C}cyan${NC}."
    fi
    blank

    # v5.67.0 (Q113) — one function per section (each under ~60 lines),
    # called in the order the wizard has always asked them. Every one
    # reads/writes the same globals write_config() expects afterward
    # (KEA_API_URL, SUBNET_LINES, ADMIN_PASS, ...) — no parameters to
    # thread through, same as when this was one long function.
    _configure_kea_api
    _configure_kea_db
    _configure_jen_db
    _configure_admin
    _configure_subnets
    _configure_ssh
    _configure_ddns
    _configure_ports
}

# v5.67.0 (Q115) — Kea's API/database/subnets/SSH/DDNS are no longer asked
# here interactively at all (an answers file or JEN_* env var still fills
# them in silently, same as before — _cfgval, never _ask, so a TTY never
# prompts for any of the five sections below): Jen's own /setup wizard is
# now where a fresh install connects Kea, live, with the same validation
# and a real retry loop in the browser instead of a terminal. A value given
# here is still tested once, informationally, so an operator scripting an
# install still sees whether it actually worked.
_configure_kea_api() {
    echo -e "  ${B}Kea Control Agent${NC}  ${DIM}(the Kea REST API — connect it later from Jen's own /setup)${NC}"
    blank
    KEA_API_URL=$(_cfgval "JEN_KEA_API_URL")
    KEA_API_USER=$(_cfgval "JEN_KEA_API_USER")
    KEA_API_PASS=$(_cfgval "JEN_KEA_API_PASS")
    if [[ -z "$KEA_API_URL" ]]; then
        ok "Skipped — connect Kea from Jen's own /setup after you log in"
        return
    fi
    spinner_start "Testing Kea API connection..."
    sleep 0.5
    if test_kea_api "$KEA_API_URL" "$KEA_API_USER" "$KEA_API_PASS"; then
        spinner_stop; ok "Kea API connection successful"
    else
        spinner_stop; warn "Could not reach the Kea API — connect it later from Jen's own /setup"
    fi
}

_configure_kea_db() {
    blank
    echo -e "  ${B}Kea MySQL Database${NC}  ${DIM}(connect it later from Jen's own /setup)${NC}"
    blank
    KEA_DB_HOST=$(_cfgval "JEN_KEA_DB_HOST")
    KEA_DB_USER=$(_cfgval "JEN_KEA_DB_USER")
    KEA_DB_PASS=$(_cfgval "JEN_KEA_DB_PASS")
    KEA_DB_NAME=$(_cfgval "JEN_KEA_DB_NAME"); KEA_DB_NAME="${KEA_DB_NAME:-kea}"
    if [[ -z "$KEA_DB_HOST" ]]; then
        ok "Skipped — connect Kea's database from Jen's own /setup after you log in"
        return
    fi
    spinner_start "Testing Kea database connection..."
    sleep 0.5
    if test_mysql "$KEA_DB_HOST" "$KEA_DB_USER" "$KEA_DB_PASS" "$KEA_DB_NAME"; then
        spinner_stop; ok "Kea database connection successful"
    else
        spinner_stop; warn "Could not reach the Kea database — connect it later from Jen's own /setup"
    fi
}

# Skipped for the Docker "bundled MariaDB" path — docker-compose.mysql.yml
# owns those credentials and wires them into the jen container itself.
_configure_jen_db() {
    if [[ "${SKIP_JEN_DB:-false}" == "true" ]]; then
        JEN_DB_HOST="jen-mysql"; JEN_DB_USER="jen"; JEN_DB_PASS=""; JEN_DB_NAME="jen"
        return
    fi
    blank
    echo -e "  ${B}Jen MySQL Database${NC}  ${DIM}(users, audit log, settings)${NC}"
    blank
    local _edit=false
    while true; do
        if [[ "$_edit" == "true" ]]; then
            JEN_DB_HOST=$(prompt_input  "Host"     "$JEN_DB_HOST")
            JEN_DB_USER=$(prompt_input  "Username" "$JEN_DB_USER")
            JEN_DB_PASS=$(prompt_secret "Password")
            JEN_DB_NAME=$(prompt_input  "Database" "$JEN_DB_NAME")
        else
            JEN_DB_HOST=$(_ask  "JEN_DB_HOST" "Host"     "${KEA_DB_HOST:-localhost}")
            JEN_DB_USER=$(_ask  "JEN_DB_USER" "Username" "jen")
            JEN_DB_PASS=$(_ask_secret "JEN_DB_PASS" "Password" required)
            JEN_DB_NAME=$(_ask  "JEN_DB_NAME" "Database" "jen")
        fi
        _edit=false
        blank
        spinner_start "Testing Jen database connection..."
        sleep 0.5
        if test_mysql "$JEN_DB_HOST" "$JEN_DB_USER" "$JEN_DB_PASS" "$JEN_DB_NAME"; then
            spinner_stop; ok "Jen database connection successful"
            return
        fi
        spinner_stop
        if _jen_db_offer_create; then
            continue
        fi
        _connection_failure_choice "Jen database" "${JEN_DB_USER}@${JEN_DB_HOST}/${JEN_DB_NAME}"
        case "$_RETRY_ACTION" in
            retry) continue ;;
            edit) _edit=true; continue ;;
            continue) _blank_if_placeholder JEN_DB_HOST "YOUR-KEA-SERVER"; return ;;
        esac
    done
}

# v5.67.0 (Q113) — JEN_INITIAL_ADMIN_PASSWORD, same name the Docker path
# (.env.example, run.py) already uses. Left blank, Jen generates one
# itself on first start and writes it to $CONTENT_DIR/initial-admin-password
# (see write_config/_seed_jen_db) — the wizard's own confirm-twice loop
# stays for the TTY path since that is the one place a typo is invisible.
_configure_admin() {
    [[ "$IS_UPGRADE" == "true" ]] && return
    blank
    echo -e "  ${B}Admin Account${NC}"
    blank
    local admin_pass
    if [[ -n "${ANSWERS[JEN_INITIAL_ADMIN_PASSWORD]+x}" || -n "${JEN_INITIAL_ADMIN_PASSWORD:-}" ]]; then
        admin_pass=$(_cfgval "JEN_INITIAL_ADMIN_PASSWORD")
        if [[ -n "$admin_pass" && ${#admin_pass} -lt 8 ]]; then
            fatal "JEN_INITIAL_ADMIN_PASSWORD must be at least 8 characters."
        fi
    elif [[ "$HAVE_TTY" == "true" && "$MODE_UNATTENDED" == "false" ]]; then
        local admin_pass2
        while true; do
            admin_pass=$(prompt_secret "Admin password (min 8 chars, Enter to auto-generate one)")
            [[ -z "$admin_pass" ]] && break
            if [[ ${#admin_pass} -lt 8 ]]; then
                warn "Password must be at least 8 characters."; continue
            fi
            admin_pass2=$(prompt_secret "Confirm admin password")
            [[ "$admin_pass" == "$admin_pass2" ]] && break
            warn "Passwords do not match — try again."
        done
    else
        admin_pass=""
    fi
    ADMIN_PASS="$admin_pass"
    if [[ -n "$ADMIN_PASS" ]]; then
        ok "Admin password set"
    else
        ok "No admin password given — Jen will generate one on first start"
    fi
}

# v5.67.0 (Q113, trimmed Q115) — JEN_SUBNETS, same "id=Name,CIDR;id=Name,CIDR"
# format run.py's Docker env-var path already parses. No answers given: Jen's
# own /setup wizard reads Kea's live subnet4 list instead (see
# jen.services.setup_wizard.discover()) — this no longer asks interactively.
_configure_subnets() {
    blank
    echo -e "  ${B}Subnet Map${NC}  ${DIM}(add these later from Jen's own /setup, or here now)${NC}"
    blank
    SUBNET_LINES=""
    if [[ -n "${ANSWERS[JEN_SUBNETS]+x}" || -n "${JEN_SUBNETS:-}" ]]; then
        local subnets_raw entry sid rest added=0
        subnets_raw=$(_cfgval "JEN_SUBNETS")
        IFS=';' read -ra _subnet_entries <<< "$subnets_raw"
        for entry in "${_subnet_entries[@]}"; do
            entry="${entry#"${entry%%[![:space:]]*}"}"
            [[ -z "$entry" || "$entry" != *=* ]] && continue
            sid="${entry%%=*}"; rest="${entry#*=}"
            SUBNET_LINES="${SUBNET_LINES}${sid} = ${rest}\n"
            ok "Added: ${sid} = ${rest}"
            added=$((added+1))
        done
        [[ $added -eq 0 ]] && warn "JEN_SUBNETS set but no entries parsed from it — check the id=Name,CIDR format"
    fi
    if [[ -z "$SUBNET_LINES" ]]; then
        ok "Skipped — add subnets from Jen's own /setup after you log in"
        SUBNET_LINES="# 1 = Production, 10.10.10.0/24\n# 30 = IoT, 10.10.30.0/24\n"
    fi
}

_configure_ssh() {
    blank
    echo -e "  ${B}SSH Access${NC}  ${DIM}(optional — connect it later from Jen's own /setup)${NC}"
    blank
    KEA_SSH_HOST=$(_cfgval "JEN_KEA_SSH_HOST")
    KEA_SSH_USER=$(_cfgval "JEN_KEA_SSH_USER")
    KEA_CONF_PATH=$(_cfgval "JEN_KEA_CONF"); KEA_CONF_PATH="${KEA_CONF_PATH:-/etc/kea/kea-dhcp4.conf}"
    if [[ -z "$KEA_SSH_HOST" ]]; then
        ok "Skipped — set this up from Jen's own /setup after you log in"
    fi
}

_configure_ddns() {
    blank
    echo -e "  ${B}DDNS Integration${NC}  ${DIM}(optional — Technitium, Pi-hole, AdGuard, SSH; configure later in Settings)${NC}"
    blank
    DDNS_PROVIDER=$(_cfgval "JEN_DDNS_PROVIDER"); DDNS_PROVIDER="${DDNS_PROVIDER:-none}"
    DDNS_URL=$(_cfgval "JEN_DDNS_URL")
    DDNS_TOKEN=$(_cfgval "JEN_DDNS_TOKEN")
    DDNS_LOG=$(_cfgval "JEN_DDNS_LOG"); DDNS_LOG="${DDNS_LOG:-/var/log/kea/kea-ddns.log}"
    DDNS_ZONE=$(_cfgval "JEN_DDNS_ZONE")
    if [[ "$DDNS_PROVIDER" == "none" ]]; then
        ok "Skipped — configure DDNS later in Settings"
    fi
}

_configure_ports() {
    blank
    echo -e "  ${B}Server Ports${NC}"
    blank
    HTTP_PORT=$(_ask  "JEN_HTTP_PORT"  "HTTP port"  "5050")
    HTTPS_PORT=$(_ask "JEN_HTTPS_PORT" "HTTPS port" "8443")
    blank
}

# ── Write config ──────────────────────────────────────────────────────────────
write_config() {
    [[ "$CONFIGURE" == "false" ]] && return

    blank
    echo -e "  ${B}${C}WRITING CONFIGURATION${NC}"
    divider
    blank

    mkdir -p "$CONFIG_DIR"

    if [[ -f "$CONFIG_FILE" ]]; then
        local bak; bak="${BACKUP_DIR}/jen.config.$(date +%Y%m%d_%H%M%S).bak"
        mkdir -p "$BACKUP_DIR"
        cp "$CONFIG_FILE" "$bak"
        ok "Backed up existing config → ${DIM}${bak}${NC}"
    fi

    # v5.67.0-beta.5 (Q117) — [kea_ssh] key_path is deliberately NOT
    # written here: AppConfig.load() and jen/extensions.py::SSH_KEY_PATH
    # already fall back to os.path.join(CONFIG_DIR, "ssh", "jen_rsa"),
    # which IS relocation-aware. A literal "/etc/jen/ssh/jen_rsa" here
    # would silently override that correct default with a wrong one on
    # any relocated install.
    cat > "$CONFIG_FILE" << CONFEOF
# Jen - The Kea DHCP Management Console
# Configuration file — generated by installer $(date)
# Edit with: sudo nano $CONFIG_FILE

[kea]
api_url  = ${KEA_API_URL}
api_user = ${KEA_API_USER}
api_pass = ${KEA_API_PASS}

[kea_db]
host     = ${KEA_DB_HOST}
user     = ${KEA_DB_USER}
password = ${KEA_DB_PASS}
database = ${KEA_DB_NAME}

[jen_db]
host     = ${JEN_DB_HOST}
user     = ${JEN_DB_USER}
password = ${JEN_DB_PASS}
database = ${JEN_DB_NAME}

[server]
http_port  = ${HTTP_PORT}
https_port = ${HTTPS_PORT}

[kea_ssh]
host     = ${KEA_SSH_HOST}
user     = ${KEA_SSH_USER}
kea_conf = ${KEA_CONF_PATH}

[subnets]
$(echo -e "$SUBNET_LINES")
[ddns]
log_path    = ${DDNS_LOG}
provider    = ${DDNS_PROVIDER}
api_url     = ${DDNS_URL}
api_token   = ${DDNS_TOKEN}
forward_zone = ${DDNS_ZONE}
CONFEOF

    # v5.10.4 — jen.config is the app's file: the running service rewrites
    # it on every Settings save. It must be owned by the service user, not
    # root. (Fresh installs 5.9.0–5.10.3 left it root:www-data 0640 here,
    # AFTER install_files' `chown -R www-data`, so every Settings save
    # failed with EACCES until the next `install.sh --upgrade`. AppConfig
    # now also writes atomically via os.replace so an affected box
    # self-heals on its first save — see jen/config.py::_write_parser.)
    # v5.67.0 (Q113) — 0600, not 0640: owner and group are the SAME user
    # (www-data:www-data), so the group-read bit never granted anyone
    # anything; tightened here and in AppConfig's own writer (which
    # re-applies the mode on every Settings save) so a file holding every
    # DB password, API credential and DDNS token this install has stays
    # owner-only for good, not just until the next save.
    chown "$JEN_USER:$JEN_USER" "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    ok "Config written → ${DIM}${CONFIG_FILE}${NC}"

    # Initialize the database on a fresh install: run migrations and seed
    # the admin account (see _seed_jen_db below for why this replaced a
    # direct UPDATE against `users`).
    [[ "$IS_UPGRADE" == "false" ]] && _seed_jen_db "${ADMIN_PASS:-}"
    blank
}

# v5.67.0 (Q113) — a real finding from wiring up the first CI job that
# actually runs a fresh install: the OLD _set_admin_password ran a raw
# `UPDATE users SET password=... WHERE username='admin'` at exactly this
# point in the flow, but nothing has EVER called create_app() yet on a
# fresh box — jen/models/db.py::init_jen_db() (which runs migrations and
# seeds the 'admin' row) only runs the first time create_app() does, which
# was always later, inside start_service()'s systemctl start. So the UPDATE
# always hit a `users` table that didn't exist yet: on an existing (kea_db-
# only) MySQL server it raised "table doesn't exist" and was silently
# swallowed by `|| true`; on a from-scratch database it wouldn't even have
# connected. Either way, whatever password the operator just typed was
# thrown away, and Jen booted with the auto-generated
# $CONTENT_DIR/initial-admin-password token instead — while the summary at
# the end of a successful run still claimed "Login: admin / (password you
# set above)". A fresh install has never actually honored a typed admin
# password.
#
# The fix reuses the exact mechanism the Docker path already has instead
# of re-implementing password hashing and raw DB access in bash:
# JEN_INITIAL_ADMIN_PASSWORD is read by init_jen_db() itself, at seed time,
# so calling create_app() here — once, as $JEN_USER (the user that will
# actually run the app, so any file it creates, like
# initial-admin-password, ends up correctly owned) — runs the real
# migrations and the real seed logic in one step. Left blank, Jen falls
# back to its own generated-token path exactly as it always has for
# Docker. A failure here is fatal, not a swallowed warning: an install
# that "completes" without an initialized database only fails later, more
# confusingly, inside start_service.
_seed_jen_db() {
    local pass="$1" out
    # v5.67.0-beta.9 (Q121, item h) — the admin password goes to the child on
    # its STDIN (printf is a shell builtin: no process ever carries it in its
    # argument list), and the snippet puts it into the environment of its OWN
    # process before create_app(). It used to be `env JEN_INITIAL_ADMIN_PASSWORD=
    # "$pass" ...`, visible to every local user in `ps` for the whole run.
    #
    # v5.67.0 (Q114) — JEN_ROOT/JEN_CONFIG_DIR/JEN_CONTENT_DIR exported
    # for the same reason every python one-liner install.sh shells out to
    # needs them: this subprocess has no systemd Environment= lines to
    # inherit a relocated layout from, so without this create_app() would
    # silently fall back to the historical defaults instead of reading
    # THIS install's own jen.config.
    out=$(printf '%s' "$pass" | runuser -u "$JEN_USER" -- env \
        JEN_ROOT="$(app_pyroot)" JEN_CONFIG_DIR="$CONFIG_DIR" JEN_CONTENT_DIR="$CONTENT_DIR" \
        "$PYBIN" -c "
import os, sys
sys.path.insert(0, '$(app_pyroot)')
_pw = sys.stdin.read()
if _pw:
    os.environ['JEN_INITIAL_ADMIN_PASSWORD'] = _pw
from jen import create_app
create_app()
print('JEN_DB_SEED_OK')
" 2>&1) || true
    if [[ "$out" != *JEN_DB_SEED_OK* ]]; then
        err "Could not initialize the Jen database:"
        echo "$out"
        fatal "Database initialization failed — see above. Check jen_db in $CONFIG_FILE and that the database exists."
    fi
    if [[ -n "$pass" ]]; then
        ok "Admin account created"
    else
        ok "Admin account created — initial password in ${CONTENT_DIR}/initial-admin-password"
    fi
}

# ── Backup existing install ───────────────────────────────────────────────────
backup_existing() {
    [[ "$IS_UPGRADE" == "false" ]] && return

    blank
    echo -e "  ${B}${C}BACKUP${NC}"
    divider
    blank

    mkdir -p "$BACKUP_DIR"
    local ts; ts=$(date +%Y%m%d_%H%M%S)

    # v5.14.0 — the real rollback is the previous release dir + a symlink
    # flip (rollback(), below). This copy to /etc/jen/backups is kept one
    # more release as cheap belt-and-braces. Read from current/app if the
    # box is already on the versioned layout, else the flat tree.
    local src="$INSTALL_DIR"
    [[ -d "$CURRENT_LINK/app" ]] && src="$CURRENT_LINK/app"

    if [[ -f "$src/run.py" ]]; then
        cp "$src/run.py" "${BACKUP_DIR}/run.py.${ts}.bak"
        ok "Backed up run.py"
    fi

    if [[ -d "$src/jen" ]]; then
        cp -r "$src/jen" "${BACKUP_DIR}/jen.${ts}.bak"
        ok "Backed up jen/ package"
    fi

    ROLLBACK_JEN="${BACKUP_DIR}/run.py.${ts}.bak"
    ROLLBACK_PKG="${BACKUP_DIR}/jen.${ts}.bak"
    export ROLLBACK_JEN ROLLBACK_PKG
    blank
}

# ── Snapshot external files (v5.20.0) ────────────────────────────────────────
# install_files (below) overwrites files OUTSIDE $INSTALL_DIR — the systemd
# unit, the sudoers grant, the root-privileged update script and its own
# unit. None of those live under releases/<ver>/, so activate_release's
# symlink flip can't roll them back. Snapshot them here so rollback() can
# put them back too.
_EXTERNAL_FILES=(
    "$SERVICE_FILE"
    "$SUDOERS_FILE"
    "/usr/local/sbin/jen-update-root.py"
    "/etc/systemd/system/jen-update.service"
    "/etc/systemd/system/jen-plugin-install.service"
)
snapshot_external_files() {
    [[ "$IS_UPGRADE" == "false" ]] && return

    # v5.67.0-beta.7 (Q119, item c) — a pre-fix install may still have
    # snapshot directories sitting under the OLD, service-owned location;
    # they're not trustworthy (the whole point of this fix) and not
    # needed (nothing references them — $ROLLBACK_EXT is only ever this
    # run's own fresh snapshot), so they're removed rather than migrated.
    rm -rf "${BACKUP_DIR:?}"/ext.* 2>/dev/null || true

    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local dir="${ROOT_ROLLBACK_DIR}/ext.${ts}"
    local f found=false
    for f in "${_EXTERNAL_FILES[@]}"; do
        if [[ -f "$f" ]]; then
            mkdir -p "$dir"
            cp -p "$f" "$dir/$(basename "$f")"
            found=true
        fi
    done
    if [[ "$found" == "true" ]]; then
        chown -R root:root "$ROOT_ROLLBACK_DIR"
        chmod -R go-rwx "$ROOT_ROLLBACK_DIR"
        ROLLBACK_EXT="$dir"
        export ROLLBACK_EXT
    fi
}

# ── Restore external files (used by rollback(), both branches) ──────────────
# v5.67.0 (Q113) — found auditing the same bug class this Q fixed in
# _confirm_upgrade_or_exit: `|| return` with no explicit code inherits the
# FAILED condition's own exit status, which is fatal under set -e when the
# caller (rollback(), called bare from both a normal failure and the
# INT/TERM trap) reaches it as a bare statement. Only reachable if
# $ROLLBACK_EXT is set but its directory is somehow gone by the time a
# rollback runs — snapshot_external_files() always mkdir's it right when
# it sets the variable, so this was likely never hit in practice, but a
# rollback that silently stops rolling back is exactly the wrong failure
# mode to leave sitting in the one path this Q's own set -e audit exists
# to catch.
_restore_external_files() {
    [[ -z "${ROLLBACK_EXT:-}" ]] && return
    [[ -d "$ROLLBACK_EXT" ]] || return 0
    local f base dest
    for f in "$ROLLBACK_EXT"/*; do
        [[ -f "$f" ]] || continue
        base=$(basename "$f")
        case "$base" in
            "$(basename "$SERVICE_FILE")") dest="$SERVICE_FILE" ;;
            "$(basename "$SUDOERS_FILE")") dest="$SUDOERS_FILE" ;;
            jen-update-root.py) dest="/usr/local/sbin/jen-update-root.py" ;;
            jen-update.service) dest="/etc/systemd/system/jen-update.service" ;;
            jen-plugin-install.service) dest="/etc/systemd/system/jen-plugin-install.service" ;;
            *) continue ;;
        esac
        if [[ "$dest" == "$SUDOERS_FILE" ]]; then
            local tmp; tmp=$(mktemp)
            cp -p "$f" "$tmp"
            if visudo -c -f "$tmp" >/dev/null 2>&1; then
                mv "$tmp" "$dest"
                chmod 440 "$dest"
            else
                warn "Rollback: restored sudoers file failed visudo -c — leaving current $dest in place"
                rm -f "$tmp"
            fi
        else
            cp -p "$f" "$dest"
        fi
    done
}

# ── Rollback ──────────────────────────────────────────────────────────────────
rollback() {
    # v5.14.0 — prefer flipping `current` back to the newest OTHER release
    # directory (it was never touched by this run).
    if [[ -d "$RELEASES_DIR" ]]; then
        local prev
        prev=$(find "$RELEASES_DIR" -mindepth 1 -maxdepth 1 -type d \
                 ! -name '*.staging-*' ! -name "$JEN_VERSION" -printf '%T@ %f\n' 2>/dev/null \
               | sort -rn | head -1 | cut -d' ' -f2-)
        if [[ -n "$prev" && -d "$RELEASES_DIR/$prev/app" ]]; then
            warn "Rolling back to release $prev..."
            ln -sfn "releases/$prev" "$CURRENT_LINK.tmp" && mv -T "$CURRENT_LINK.tmp" "$CURRENT_LINK"
            _restore_external_files
            systemctl daemon-reload
            systemctl restart jen 2>/dev/null || true
            warn "Rollback complete — release $prev restored"
            return
        fi
    fi
    # Legacy flat copy-back (a still-flat box whose versioned migration failed).
    if [[ -n "${ROLLBACK_JEN:-}" && -f "$ROLLBACK_JEN" ]]; then
        warn "Rolling back to previous installation..."
        rm -f "$CURRENT_LINK"
        cp "$ROLLBACK_JEN" "$INSTALL_DIR/run.py"
        if [[ -n "${ROLLBACK_PKG:-}" && -d "$ROLLBACK_PKG" ]]; then
            rm -rf "$INSTALL_DIR/jen"
            cp -r "$ROLLBACK_PKG" "$INSTALL_DIR/jen"
        fi
        _restore_external_files
        systemctl daemon-reload
        systemctl restart jen 2>/dev/null || true
        warn "Rollback complete — previous version restored"
    fi
}

# ── Migrate user content out of /opt/jen (v5.13.0) ───────────────────────────
# MOVE uploaded icons, the nav logo, a custom favicon, DB backups,
# registry-installed plugins and plugin enable markers, and the key
# fallbacks from the old /opt/jen locations into $CONTENT_DIR. Runs BEFORE
# install_files (which makes /opt/jen root-owned). Idempotent, never
# clobbers an existing destination.
_content_mv() {  # move $1 -> $2 only if $1 exists and $2 doesn't
    if [[ -e "$1" && ! -e "$2" ]]; then
        mkdir -p "$(dirname "$2")"
        mv "$1" "$2"
    fi
}

migrate_content() {
    local shipped_favicon="$SCRIPT_DIR/static/favicon.ico"
    local d pid f ext
    for d in icons branding backups plugins plugins-enabled keys; do
        mkdir -p "$CONTENT_DIR/$d"
    done

    if [[ -d "$INSTALL_DIR/static/icons/custom" ]]; then
        for f in "$INSTALL_DIR/static/icons/custom/"*; do
            [[ -e "$f" ]] || continue
            _content_mv "$f" "$CONTENT_DIR/icons/$(basename "$f")"
        done
    fi
    for ext in png svg jpg jpeg webp; do
        _content_mv "$INSTALL_DIR/static/nav_logo.$ext" "$CONTENT_DIR/branding/nav_logo.$ext"
    done
    if [[ -f "$INSTALL_DIR/static/favicon.ico" && ! -e "$CONTENT_DIR/branding/favicon.ico" ]]; then
        if [[ ! -f "$shipped_favicon" ]] || ! cmp -s "$INSTALL_DIR/static/favicon.ico" "$shipped_favicon"; then
            mv "$INSTALL_DIR/static/favicon.ico" "$CONTENT_DIR/branding/favicon.ico"
        fi
    fi
    if [[ -d "$INSTALL_DIR/backups" ]]; then
        for f in "$INSTALL_DIR/backups/"*; do
            [[ -e "$f" ]] || continue
            _content_mv "$f" "$CONTENT_DIR/backups/$(basename "$f")"
        done
    fi
    if [[ -d "$INSTALL_DIR/plugins" ]]; then
        for d in "$INSTALL_DIR/plugins/"*/; do
            [[ -d "$d" ]] || continue
            pid="$(basename "$d")"
            if [[ "$pid" != "ipam" && "$pid" != "network-discovery" ]]; then
                _content_mv "${d%/}" "$CONTENT_DIR/plugins/$pid"
                d="$CONTENT_DIR/plugins/$pid/"
            fi
            _content_mv "${d}.enabled" "$CONTENT_DIR/plugins-enabled/$pid"
        done
    fi
    _content_mv "$INSTALL_DIR/.secret_key" "$CONTENT_DIR/keys/.secret_key"
    _content_mv "$INSTALL_DIR/.mfa_key"    "$CONTENT_DIR/keys/.mfa_key"

    chown -R "$JEN_USER:$JEN_USER" "$CONTENT_DIR"
    chmod 750 "$CONTENT_DIR"
    # v5.67.0-beta.7 (Q119, item b) — on an UPGRADE, _resolve_layout_dirs
    # above (--for upgrade) may have just retroactively stamped a pre-Q117
    # install's marker, root:root — before this recursive chown ran. Don't
    # let it silently re-own that marker to the service user; -h so a
    # symlink there (which should never happen post-fix, but might on a
    # TOCTOU race) is never followed.
    [[ -e "$CONTENT_DIR/.jen-directory" ]] && chown -h root:root "$CONTENT_DIR/.jen-directory"
    ok "User content is under $CONTENT_DIR"
}

# ── Layout file (v5.67.0, Q114) ──────────────────────────────────────────────
# v5.67.0-beta.9 (Q121, item f) — written LAST in a fresh install (after
# verify_install), not at step 5 of 19. A fresh install that failed anywhere
# between used to leave this file behind recording directories that were never
# completed: a retry with DIFFERENT directories was then refused as
# "relocating an existing install", and uninstall.sh refused the half-made
# config directory. A file that only ever exists for a finished install cannot
# do either.
#
# Written once, on a genuinely fresh install only — an upgrade/repair/
# configure run against an existing install never reaches here with
# IS_UPGRADE false, and _resolve_layout_dirs above has already refused a
# disagreeing flag long before this step could run. Root:root 0644,
# outside $CONFIG_DIR (docs/ARCHITECTURE.md §3.1): the root updater must
# never learn a path from anywhere $JEN_USER can write, and $CONFIG_DIR is
# chowned to it.
write_layout_file() {
    [[ "$IS_UPGRADE" == "true" ]] && return 0
    [[ -f "$LAYOUT_FILE" ]] && return 0
    cat > "$LAYOUT_FILE" << EOF
# Jen install layout — written once by install.sh at first install. Read
# by jen-update-root.py (the root self-updater) and by install.sh itself
# on every later --upgrade/--repair/--configure run. Do not hand-edit to
# relocate an existing install — see docs/runbooks.md for that procedure.
[layout]
app_dir = $INSTALL_DIR
config_dir = $CONFIG_DIR
data_dir = $CONTENT_DIR
EOF
    chown root:root "$LAYOUT_FILE"
    chmod 644 "$LAYOUT_FILE"
    ok "Layout recorded  ${DIM}(app=$INSTALL_DIR config=$CONFIG_DIR data=$CONTENT_DIR)${NC}"
}

# ── Render jen.service (v5.67.0, Q114) ───────────────────────────────────────
# jen.service.template ships inside the release tree with @@APP_DIR@@ /
# @@CONFIG_DIR@@ / @@DATA_DIR@@ placeholders instead of literal paths — the
# unit has to reflect wherever THIS install's app/config/data actually
# live. jen-update-root.py renders the same template the same way on
# every in-app update (see install_external_files there), so a relocated
# install's unit is never silently overwritten with one hardcoded back to
# the defaults. Syntax-verified in verify_install() once `current` exists.
render_jen_service() {
    local template="$1" out="$2"
    sed -e "s#@@APP_DIR@@#$INSTALL_DIR#g" \
        -e "s#@@CONFIG_DIR@@#$CONFIG_DIR#g" \
        -e "s#@@DATA_DIR@@#$CONTENT_DIR#g" \
        "$template" > "$out"
}

# ── Install files ─────────────────────────────────────────────────────────────
# v5.14.0 — the whole tarball goes into releases/$JEN_VERSION/app; the
# shipped OUT-OF-TREE files (jen.service.template, jen-sudoers,
# jen-update-root.py, jen-update.service) are installed from that copy.
# `current` is NOT flipped here — setup_venv() has to build
# releases/$JEN_VERSION/venv first, then activate_release() does the
# atomic flip.
install_files() {
    blank
    echo -e "  ${B}${C}INSTALLING FILES${NC}"
    divider
    blank

    mkdir -p "$APP_DIR" "$CONFIG_DIR/ssl" "$CONFIG_DIR/ssh"

    spinner_start "Installing release $JEN_VERSION..."
    rm -rf "$APP_DIR"
    mkdir -p "$APP_DIR"
    # cp -r "$SCRIPT_DIR/." copies contents including dotfiles; then prune
    # the things a release directory has no use for.
    cp -r "$SCRIPT_DIR/." "$APP_DIR/"
    rm -rf "$APP_DIR/.git" "$APP_DIR/.github" "$APP_DIR/tests" "$APP_DIR/.venv" "$APP_DIR/venv"
    find "$APP_DIR" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
    find "$APP_DIR" -name '*.pyc' -delete 2>/dev/null || true
    spinner_stop
    ok "Installed release tree  ${DIM}($(find "$APP_DIR/jen" -name '*.py' 2>/dev/null | wc -l) modules)${NC}"

    # ── Out-of-tree files, from the just-installed release copy ──────────
    render_jen_service "$APP_DIR/jen.service.template" "$SERVICE_FILE"
    ok "Installed systemd service"

    if [[ -f "$APP_DIR/jen-sudoers" ]]; then
        cp "$APP_DIR/jen-sudoers" "$SUDOERS_FILE"
        chmod 440 "$SUDOERS_FILE"
        ok "Installed sudoers entry"
    fi

    # v5.2.6 security fix — the self-update helper script lives OUTSIDE
    # $INSTALL_DIR entirely (this script chowns the whole tree root:root,
    # which is fine, but the helper also has to be reachable by the
    # jen-update.service unit). See its own docstring for the rationale.
    if [[ -f "$APP_DIR/jen-update-root.py" ]]; then
        cp "$APP_DIR/jen-update-root.py" /usr/local/sbin/jen-update-root.py
        chown root:root /usr/local/sbin/jen-update-root.py
        chmod 700 /usr/local/sbin/jen-update-root.py
        ok "Installed root-privileged update script"
    fi
    if [[ -f "$APP_DIR/jen-update.service" ]]; then
        cp "$APP_DIR/jen-update.service" /etc/systemd/system/jen-update.service
        ok "Installed jen-update.service"
    fi
    # v5.27.0 (Q23) — the second oneshot unit, same reasoning as
    # jen-update.service above: jen-update-root.py --plugins runs as
    # root, invoked by www-data only via this fixed unit.
    if [[ -f "$APP_DIR/jen-plugin-install.service" ]]; then
        cp "$APP_DIR/jen-plugin-install.service" /etc/systemd/system/jen-plugin-install.service
        ok "Installed jen-plugin-install.service"
    fi

    # v5.13.0 — the whole application tree is root-owned and read-only to
    # the service user. User-writable content lives under $CONTENT_DIR
    # (migrate_content, above, chowns that to $JEN_USER). jen.config keeps
    # its own service-user ownership (write_config, below).
    #
    # v5.67.0-beta.5 (Q117) — `a+rX` alone only ADDS bits; it never clears
    # a write bit `mkdir -p`/`cp -r` left set under a permissive umask
    # (CI's own runner creates $INSTALL_DIR 0777 this way). `go-w` closes
    # that — found by _layout_appdir_itself_ok actually refusing the
    # result on this job's own later --upgrade leg, the first thing ever
    # checking "is app_dir itself group/other-writable" on a real run.
    spinner_start "Setting permissions..."
    chown -R root:root "$INSTALL_DIR"
    chmod -R a+rX,go-w "$INSTALL_DIR"
    chown -R "$JEN_USER:$JEN_USER" "$CONFIG_DIR"
    # v5.67.0-beta.7 (Q119, item b) — same reasoning as migrate_content's
    # own guard above: don't let this chown re-own an upgrade's own
    # already-stamped, root:root marker to the service user.
    [[ -e "$CONFIG_DIR/.jen-directory" ]] && chown -h root:root "$CONFIG_DIR/.jen-directory"
    spinner_stop
    ok "Permissions set  ${DIM}(app tree: root, content: ${JEN_USER})${NC}"
    blank
}

# ── Byte-compile the app as root ─────────────────────────────────────────────
# v5.13.0 — the app tree is root-owned, so $JEN_USER can't write __pycache__.
# Compile with the release's own venv interpreter so the .pyc match what runs.
compile_app() {
    local py="$VENV_PY"
    [[ -x "$py" ]] || py="python3"
    "$py" -m compileall -q "$APP_DIR/jen" "$APP_DIR/plugins" >/dev/null 2>&1 || true
}

# ── Activate the release (atomic symlink flip) ───────────────────────────────
# v5.14.0 — point `current` at releases/$JEN_VERSION. The symlink target is
# RELATIVE so /opt/jen can be bind-mounted; `ln -s` into a .tmp name then
# `mv -T` (rename(2), atomic) so `current` is never briefly absent.
activate_release() {
    chown -R root:root "$RELEASE_DIR"
    ln -sfn "releases/$JEN_VERSION" "$CURRENT_LINK.tmp"
    mv -T "$CURRENT_LINK.tmp" "$CURRENT_LINK"
    systemctl daemon-reload
    ok "Release $JEN_VERSION is current  ${DIM}($CURRENT_LINK -> releases/$JEN_VERSION)${NC}"
}

# ── Remove the flat leftovers after a successful versioned install ───────────
# v5.14.0 — everything lives under releases/<ver>/ now and is reached
# through `current`; the flat copies shadow nothing (JEN_ROOT resolves to
# current/app) but they waste disk and confuse. Only runs once `current`
# resolves to a real release.
remove_flat_leftovers() {
    [[ -L "$CURRENT_LINK" && -d "$CURRENT_LINK/app/jen" ]] || return 0
    local it removed=0
    for it in jen run.py templates static plugins venv CHANGELOG.md requirements.txt jen-kea-helper legacy; do
        if [[ -e "$INSTALL_DIR/$it" && ! -L "$INSTALL_DIR/$it" ]]; then
            rm -rf "${INSTALL_DIR:?}/$it"
            removed=$((removed + 1))
        fi
    done
    [[ "$removed" -gt 0 ]] && ok "Removed $removed flat leftover(s) from $INSTALL_DIR"
    return 0
}

# ── Start service ─────────────────────────────────────────────────────────────
start_service() {
    blank
    echo -e "  ${B}${C}STARTING SERVICE${NC}"
    divider
    blank

    systemctl daemon-reload

    if [[ "$IS_UPGRADE" == "true" || "$MODE_REPAIR" == "true" ]]; then
        warn "Jen web UI will be briefly unreachable during restart (~3s)"
        blank
        spinner_start "Restarting Jen service..."
        systemctl restart jen
    else
        spinner_start "Enabling and starting Jen service..."
        systemctl enable jen
        systemctl start jen
    fi
    sleep 3
    spinner_stop

    if systemctl is-active --quiet jen; then
        ok "Jen service running"
    else
        err "Jen service failed to start"
        blank
        journalctl -u jen -n 30 --no-pager
        blank
        fatal "Installation failed — see logs above"
    fi
    blank
}

# ── Verify install ────────────────────────────────────────────────────────────
verify_install() {
    blank
    echo -e "  ${B}${C}VERIFICATION${NC}"
    divider
    blank

    # Service
    # v5.67.0-beta.9 (Q121, item f) — every failure below goes through
    # fatal(), never a bare `return 1`/`exit 1`: fatal() is what rolls an
    # upgrade back (ROLLBACK_ARMED is still set here) and what the INT/TERM
    # trap's own cleanup is modelled on. A bare exit skipped all of it, so a
    # verification failure left a broken upgrade in place.
    systemctl is-active --quiet jen \
        && ok "Service running" \
        || { err "Service not running"; fatal "Verification failed — the service is not running (journalctl -u jen)"; }

    # Config
    [[ -f "$CONFIG_FILE" ]] \
        && ok "Config file present  ${DIM}(${CONFIG_FILE})${NC}" \
        || warn "Config file not found — Jen may not start correctly"

    # Unit (v5.67.0, Q114) — render_jen_service() only checks that `sed`
    # ran; this is the real syntax/semantics check, run here (not right
    # after rendering in install_files) because WorkingDirectory only
    # exists once activate_release has flipped `current` into place.
    if command -v systemd-analyze &>/dev/null; then
        local unit_result unit_status
        unit_result=$(systemd-analyze verify "$SERVICE_FILE" 2>&1) && unit_status=0 || unit_status=$?
        if [[ "$unit_status" -eq 0 ]]; then
            ok "systemd unit verified"
        else
            err "systemd-analyze verify failed for $SERVICE_FILE:"; echo "$unit_result"
            fatal "Verification failed — the rendered systemd unit is invalid"
        fi
    else
        warn "systemd-analyze not found — skipping unit verification"
    fi

    # Templates
    # v5.67.0 (Q113) — two real bugs, found together once install.sh first
    # ran somewhere that could actually reach this far. (1) This hand-
    # maintained filter list (utcfmt/utcdate/utctime) had drifted from the
    # real app's own five (jen/__init__.py also registers relfmt and
    # hostname) — any template using either failed Jinja's compile-time
    # filter lookup, which this check correctly treated as an error. (2)
    # `tpl_result=$(...)` followed by a bare `if [[ $? -eq 0 ]]` dies
    # silently under `set -e` the moment the command substitution itself
    # fails — the `err`/`echo` branch meant to explain the failure never
    # runs. Together: every fresh install has been failing this check
    # since relfmt/hostname were added, and failing SILENTLY, right after
    # "Config file present", with no visible reason. The fix uses the
    # real app's own Jinja environment (create_app() has already run once,
    # successfully, in _seed_jen_db above — never a hand-maintained filter
    # list to drift again) and the standard `cmd && ok=0 || ok=$?` idiom
    # so a genuine failure is reported instead of silently killing the
    # installer.
    # v5.67.0-beta.7 (Q119, item a) — this snippet calls create_app(),
    # which load_plugins()s every enabled plugin out of $CONTENT_DIR/plugins
    # — a directory the SERVICE USER owns. Running it unwrapped, as root
    # (the bug: every verify_install() call did, until this fix), means a
    # compromised service account that planted a plugin there gets it
    # imported as uid 0 on the very next install.sh run. runuser, exactly
    # like _seed_jen_db above (which already calls create_app() safely).
    local tpl_result tpl_status
    tpl_result=$(runuser -u "$JEN_USER" -- env JEN_ROOT="$(app_pyroot)" JEN_CONFIG_DIR="$CONFIG_DIR" JEN_CONTENT_DIR="$CONTENT_DIR" "$PYBIN" -c "
import os, sys
sys.path.insert(0, '$(app_pyroot)')
from jen import create_app
app = create_app()
errors = []
with app.app_context():
    for t in os.listdir('$(app_pyroot)/templates'):
        if t.endswith('.html'):
            try:
                app.jinja_env.get_template(t)
            except Exception as e:
                errors.append(f'{t}: {e}')
if errors:
    for e in errors:
        print(e)
    sys.exit(1)
print(len([f for f in os.listdir('$(app_pyroot)/templates') if f.endswith('.html')]))
" 2>&1) && tpl_status=0 || tpl_status=$?
    if [[ "$tpl_status" -eq 0 ]]; then
        ok "Templates validated  ${DIM}(${tpl_result} files)${NC}"
    else
        err "Template validation failed:"; echo "$tpl_result"
        fatal "Verification failed — a template does not compile"
    fi

    # Modules
    if [[ -d "$(app_pyroot)/jen" ]]; then
        # v5.67.0-beta.7 (Q119, item a) — same reasoning as the template
        # check above: this imports real jen.* modules, so it runs as the
        # service user, never root.
        local mod_result mod_status
        mod_result=$(runuser -u "$JEN_USER" -- env JEN_ROOT="$(app_pyroot)" JEN_CONFIG_DIR="$CONFIG_DIR" JEN_CONTENT_DIR="$CONTENT_DIR" "$PYBIN" -c "
import sys; sys.path.insert(0, '$(app_pyroot)')
errors = []
for m in ['jen.extensions','jen.config','jen.models.db','jen.models.user',
          'jen.services.kea','jen.services.alerts','jen.services.fingerprint',
          'jen.services.mfa','jen.services.auth']:
    try: __import__(m)
    except ImportError as e: errors.append(f'{m}: {e}')
    except Exception: pass
if errors:
    for e in errors: print(e); sys.exit(1)
else: print(len([m for m in ['jen.extensions','jen.config','jen.models.db','jen.models.user','jen.services.kea','jen.services.alerts','jen.services.fingerprint','jen.services.mfa','jen.services.auth']]))
" 2>&1) && mod_status=0 || mod_status=$?
        if [[ "$mod_status" -eq 0 ]]; then
            ok "Package modules verified  ${DIM}(${mod_result} modules)${NC}"
        else
            warn "Module check had issues (non-fatal):  ${DIM}${mod_result}${NC}"
        fi
    fi

    # HTTP check
    local http_p; http_p=$(grep -m1 "http_port" "$CONFIG_FILE" 2>/dev/null \
        | awk -F'=' '{print $2}' | tr -d ' ' || echo "5050")
    sleep 1
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --connect-timeout 5 "http://localhost:${http_p}/" 2>/dev/null || echo "000")
    if [[ "$http_code" =~ ^[23] ]] || [[ "$http_code" == "301" ]]; then
        ok "HTTP response on :${http_p}  ${DIM}(${http_code})${NC}"
    else
        warn "HTTP :${http_p} returned ${http_code} — Jen may still be starting"
    fi
    blank
}

# ── Summary ───────────────────────────────────────────────────────────────────
print_summary() {
    local server_ip http_p https_p
    server_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server")
    http_p=$(grep -m1 "http_port"  "$CONFIG_FILE" 2>/dev/null \
        | awk -F'=' '{print $2}' | tr -d ' ' || echo "5050")
    https_p=$(grep -m1 "https_port" "$CONFIG_FILE" 2>/dev/null \
        | awk -F'=' '{print $2}' | tr -d ' ' || echo "8443")
    local ssl_enabled=false
    [[ -f "$CONFIG_DIR/ssl/combined.crt" ]] && ssl_enabled=true

    echo ""
    echo -e "  ${C}╔══════════════════════════════════════════════════════╗${NC}"
    if [[ "$IS_UPGRADE" == "true" ]]; then
        _box_line "  ${G}${B}Jen v${JEN_VERSION} — Upgrade complete!${NC}"
    elif [[ "$MODE_REPAIR" == "true" ]]; then
        _box_line "  ${Y}${B}Jen v${JEN_VERSION} — Repair complete!${NC}"
    elif [[ "$MODE_CONFIGURE" == "true" ]]; then
        _box_line "  ${C}${B}Jen v${JEN_VERSION} — Reconfigured!${NC}"
    else
        _box_line "  ${G}${B}Jen v${JEN_VERSION} — Installation complete!${NC}"
    fi
    echo -e "  ${C}╠══════════════════════════════════════════════════════╣${NC}"
    _box_line ""
    _box_line "  ${B}Access Jen:${NC}"
    if [[ "$ssl_enabled" == "true" ]]; then
        _box_line "    ${C}https://${server_ip}:${https_p}${NC}"
    fi
    _box_line "    ${C}http://${server_ip}:${http_p}${NC}"
    _box_line ""
    if [[ "$IS_UPGRADE" == "false" && "$MODE_REPAIR" == "false" ]]; then
        if [[ -n "${ADMIN_PASS:-}" ]]; then
            _box_line "  ${B}Login:${NC}  ${C}admin${NC}  /  ${Y}(password you set above)${NC}"
        else
            _box_line "  ${B}Login:${NC}  ${C}admin${NC}"
            _box_line "  ${DIM}Initial password: sudo cat ${CONTENT_DIR}/initial-admin-password${NC}"
        fi
    else
        _box_line "  ${B}Login:${NC}  Your existing accounts are preserved"
    fi
    _box_line ""
    echo -e "  ${C}╠══════════════════════════════════════════════════════╣${NC}"
    _box_line ""
    _box_line "  ${DIM}Config:   ${CONFIG_FILE}${NC}"
    _box_line "  ${DIM}App:      ${INSTALL_DIR}${NC}"
    _box_line "  ${DIM}Logs:     sudo journalctl -u jen -f${NC}"
    _box_line "  ${DIM}Restart:  sudo systemctl restart jen${NC}"
    _box_line ""
    echo -e "  ${C}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# ── Docker path ───────────────────────────────────────────────────────────────
docker_install() {
    blank
    echo -e "  ${B}${C}DOCKER INSTALLATION${NC}"
    divider
    blank

    command -v docker &>/dev/null \
        || fatal "Docker not installed — install with: curl -fsSL https://get.docker.com | sudo sh"
    ok "Docker: $(docker --version | cut -d' ' -f3 | tr -d ',')"

    docker compose version &>/dev/null 2>&1 \
        || fatal "Docker Compose plugin not found — install with: sudo apt install docker-compose-plugin"
    # Compose >= 2.24 is required: earlier versions don't strip quotes or
    # interpolate env_file: values, so a password with a special char in
    # .env would reach the container mangled or literally quoted.
    local _cv
    _cv=$(docker compose version --short 2>/dev/null | tr -d 'v ')
    if [[ -n "$_cv" && "$(printf '2.24.0\n%s\n' "$_cv" | sort -V | head -1)" != "2.24.0" ]]; then
        fatal "Docker Compose $_cv is too old — Jen needs >= 2.24.0 (apt install docker-compose-plugin, or upgrade Docker Desktop)."
    fi
    ok "Docker Compose ${_cv:-available}"

    cd "$SCRIPT_DIR"

    # ── Reuse an existing .env? ──────────────────────────────────────────────
    if [[ -f "./.env" ]]; then
        ok ".env found in $(pwd)"
        if [[ "$(prompt_yn "Reuse the existing .env?" "y")" == "y" ]]; then
            _docker_pick_compose_and_run
            return
        fi
        info "Re-running configuration — the existing .env will be overwritten."
    fi

    # ── Database mode ───────────────────────────────────────────────────────
    blank
    echo -e "  ${B}Database Mode:${NC}"
    blank
    echo -e "    ${B}1)${NC}  External MySQL/MariaDB  ${DIM}(connect to an existing server)${NC}"
    echo -e "    ${B}2)${NC}  Bundled MariaDB         ${DIM}(Docker runs one locally for Jen)${NC}"
    blank
    local db_choice; db_choice=$(prompt_choice "1")
    local bundled=false db_mode="external"
    DOCKER_COMPOSE_FILE="docker-compose.yml"
    if [[ "$db_choice" == "2" ]]; then
        bundled=true
        db_mode="bundled"
        DOCKER_COMPOSE_FILE="docker-compose.mysql.yml"
        SKIP_JEN_DB=true
    fi

    # ── Guided setup wizard → .env ─────────────────────────────────────────
    IS_UPGRADE=false; CONFIGURE=true
    collect_config

    local mysql_root_pw="" jen_mysql_pw=""
    if [[ "$bundled" == "true" ]]; then
        mysql_root_pw=$(openssl rand -hex 24 2>/dev/null || head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')
        jen_mysql_pw=$(openssl rand -hex 24 2>/dev/null   || head -c 32 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9')
    fi

    # SUBNET_LINES is "id = Name, CIDR" per line; JEN_SUBNETS wants
    # "id=Name,CIDR;id=Name,CIDR" (run.py::_build_config_from_env parses it).
    local jen_subnets
    jen_subnets=$(echo -e "$SUBNET_LINES" | sed 's/^#.*//; s/ *= */=/; s/, */,/g; /^$/d' | paste -sd ';' -)

    umask 077
    cat > "./.env" << ENVEOF
# Jen — Docker configuration (generated by install.sh $(date +%Y-%m-%d))
# run.py turns these JEN_* vars into /etc/jen/jen.config on first start.
# Values with a \$, space or quote are quoted (Compose >= 2.24 strips them).

# Which compose file to use — the installer reads this back when you
# reuse an existing .env. external = docker-compose.yml, bundled = .mysql.yml
JEN_DATABASE_MODE=${db_mode}

JEN_KEA_API_URL=$(env_value "${KEA_API_URL}")
JEN_KEA_API_USER=$(env_value "${KEA_API_USER}")
JEN_KEA_API_PASS=$(env_value "${KEA_API_PASS}")
JEN_KEA_NAME=$(env_value "Kea Server 1")
JEN_KEA_ROLE=primary
JEN_HA_MODE=

JEN_KEA_DB_HOST=$(env_value "${KEA_DB_HOST}")
JEN_KEA_DB_USER=$(env_value "${KEA_DB_USER}")
JEN_KEA_DB_PASS=$(env_value "${KEA_DB_PASS}")
JEN_KEA_DB_NAME=$(env_value "${KEA_DB_NAME}")

JEN_DB_HOST=$(env_value "${JEN_DB_HOST}")
JEN_DB_USER=$(env_value "${JEN_DB_USER}")
JEN_DB_PASS=$(env_value "${JEN_DB_PASS}")
JEN_DB_NAME=$(env_value "${JEN_DB_NAME}")

JEN_KEA_SSH_HOST=$(env_value "${KEA_SSH_HOST}")
JEN_KEA_SSH_USER=$(env_value "${KEA_SSH_USER}")
JEN_KEA_CONF=$(env_value "${KEA_CONF_PATH}")

JEN_DDNS_PROVIDER=$(env_value "${DDNS_PROVIDER}")
JEN_DDNS_URL=$(env_value "${DDNS_URL}")
JEN_DDNS_TOKEN=$(env_value "${DDNS_TOKEN}")
JEN_DDNS_ZONE=$(env_value "${DDNS_ZONE}")
JEN_DDNS_LOG=$(env_value "${DDNS_LOG}")

JEN_SUBNETS=$(env_value "${jen_subnets}")

JEN_HTTP_PORT=${HTTP_PORT}
JEN_HTTPS_PORT=${HTTPS_PORT}
HTTP_PORT=${HTTP_PORT}
HTTPS_PORT=${HTTPS_PORT}

# One-time: seeds the 'admin' superadmin on first start, then never read again.
JEN_INITIAL_ADMIN_PASSWORD=$(env_value "${ADMIN_PASS:-}")

# Bundled MariaDB (docker-compose.mysql.yml) — ignored by docker-compose.yml.
MYSQL_ROOT_PASSWORD=$(env_value "${mysql_root_pw:-}")
JEN_MYSQL_PASSWORD=$(env_value "${jen_mysql_pw:-}")
ENVEOF
    umask 022
    # .env holds DB + API passwords. Lock it to the operator (the user who
    # sudo'd, so plain `docker compose` still works for them) — not world.
    chown "${SUDO_USER:-root}:${SUDO_USER:-root}" "./.env" 2>/dev/null || true
    chmod 600 "./.env" 2>/dev/null || true
    ok ".env written → ${DIM}$(pwd)/.env${NC}"

    _docker_pick_compose_and_run
}

_docker_pick_compose_and_run() {
    local compose_file="${DOCKER_COMPOSE_FILE:-docker-compose.yml}"
    # Reusing an existing .env: DOCKER_COMPOSE_FILE isn't set — read the
    # explicit JEN_DATABASE_MODE marker (v5.8.1). Older .env files without
    # it fall back to the one unambiguous signal: JEN_DB_HOST=jen-mysql is
    # only ever written for the bundled path.
    if [[ -z "${DOCKER_COMPOSE_FILE:-}" ]]; then
        local mode
        mode=$(sed -n "s/^JEN_DATABASE_MODE=['\"]\\?\\(bundled\\|external\\).*/\\1/p" ./.env 2>/dev/null | head -1)
        if [[ "$mode" == "bundled" ]]; then
            compose_file="docker-compose.mysql.yml"
        elif [[ -z "$mode" ]] && grep -qE "^JEN_DB_HOST=['\"]?jen-mysql['\"]?" ./.env 2>/dev/null; then
            compose_file="docker-compose.mysql.yml"
        fi
        blank
        info "Using ${compose_file} (override: re-run and reconfigure)."
    fi

    blank
    spinner_start "Building Jen Docker image..."
    docker compose -f "$compose_file" build
    spinner_stop
    ok "Image built"

    spinner_start "Starting Jen container..."
    docker compose -f "$compose_file" up -d
    spinner_stop

    docker ps | grep -q "jen" \
        || { err "Container failed to start"; docker compose -f "$compose_file" logs --tail=20; exit 1; }

    # v5.67.0-beta.7 (Q119, item e) — `docker ps` lists a crash-looping
    # container too (Docker keeps recreating it, so it's "there" between
    # restarts even though it never stays up) — the old check above never
    # actually proved Jen booted, only that something named "jen" exists.
    # A blank-Kea container hitting the _build_config_from_env() bug this
    # same Q fixes (or any other boot failure) printed "Installation
    # complete!" over a dead container. Wait for the real signal instead.
    local http_port
    http_port=$(sed -n "s/^HTTP_PORT=['\"]\\?\\([0-9]*\\).*/\\1/p" ./.env 2>/dev/null | head -1)
    http_port="${http_port:-5050}"
    spinner_start "Waiting for Jen to answer on :${http_port}..."
    local waited=0 healthy=false
    while [[ $waited -lt 60 ]]; do
        if command -v curl &>/dev/null \
            && curl -sf -m 3 "http://127.0.0.1:${http_port}/api/v1/health" 2>/dev/null | grep -q jen_version; then
            healthy=true
            break
        fi
        sleep 2
        waited=$((waited + 2))
    done
    spinner_stop
    if [[ "$healthy" == "true" ]]; then
        ok "Jen is healthy and answering"
    elif ! command -v curl &>/dev/null; then
        warn "curl not found — could not verify Jen actually answers; check 'docker compose logs jen'"
    else
        err "Jen did not answer /api/v1/health after ${waited}s"
        docker compose -f "$compose_file" logs --tail=40
        exit 1
    fi

    local server_ip login_line
    server_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server")
    if grep -q '^JEN_INITIAL_ADMIN_PASSWORD=.\+' ./.env 2>/dev/null; then
        login_line="  ${B}Login:${NC}   admin  ${DIM}(the password you set during setup)${NC}"
    else
        login_line="  ${B}Login:${NC}   admin  ${DIM}(initial password: docker compose logs jen | grep 'initial password')${NC}"
    fi
    blank
    echo -e "  ${G}${B}Jen Docker installation complete!${NC}"
    divider
    echo -e "  ${B}Access:${NC}  ${C}http://${server_ip}:${HTTP_PORT:-5050}${NC}"
    echo -e "$login_line"
    blank
    echo -e "  ${DIM}Config:   $(pwd)/.env    (edit + 'docker compose -f ${compose_file} up -d' to apply)${NC}"
    echo -e "  ${DIM}Logs:     docker compose -f ${compose_file} logs -f${NC}"
    echo -e "  ${DIM}Restart:  docker compose -f ${compose_file} restart jen${NC}"
    echo -e "  ${DIM}Stop:     docker compose -f ${compose_file} down${NC}"
    blank
}

# ── Main ──────────────────────────────────────────────────────────────────────
# v5.67.0 (Q113) — tiny one-line steps, wrapped as functions too, so every
# entry in MODE_STEPS below is a real function name and the table reads as
# a complete, literal list of what each mode actually does.
_skip_configure()   { CONFIGURE=false; }
_arm_rollback()      { ROLLBACK_ARMED=true; }
_disarm_rollback()   { ROLLBACK_ARMED=false; }

# v5.67.0 (Q113) — one step list per mode, so "what does --repair actually
# do" is a single line to read rather than a scroll through main(). "standard"
# covers both a fresh install and an upgrade: collect_config() (and, inside
# it, _configure_admin) already branch on IS_UPGRADE to keep the existing
# config instead of asking — that was true before this table existed too.
declare -A MODE_STEPS=(
    [standard]="preflight_checks install_dependencies collect_config backup_existing migrate_content snapshot_external_files _arm_rollback install_files setup_venv compile_app write_config activate_release start_service verify_install _disarm_rollback remove_flat_leftovers write_layout_file write_layout_markers print_summary"
    [repair]="preflight_checks install_dependencies _skip_configure backup_existing snapshot_external_files _arm_rollback install_files setup_venv compile_app activate_release start_service verify_install _disarm_rollback remove_flat_leftovers print_summary"
)

_run_steps() {
    local mode="$1" step
    for step in ${MODE_STEPS[$mode]}; do
        "$step"
    done
}

# Handle --restore mode (v5.44.0, Q45) — layers a recovery bundle onto
# an ALREADY-installed Jen (venv, systemd unit, sudoers untouched).
# Deliberately thin: every real decision (passphrase, version checks,
# what gets written, the DB import) lives in jen/tools/restore.py,
# which needs cryptography/pymysql and JSON/version parsing that are
# all far more pleasant in Python than bash. This shells out to it
# and does nothing else — no new sudoers-invoked command is added
# (rule 8), because this IS the installer, run directly by the
# operator via sudo, the same way every other mode here already is.
# Every path either fatal()s or exit 0s — never returns to main().
_run_restore_mode() {
    if [[ -n "${RESTORE_ROLLBACK:-}" ]]; then
        # --rollback <snapshot dir>: redo the rollback of a restore by hand.
        RESTORE_PY="$PYBIN"
        [[ -x "$RESTORE_PY" ]] || fatal "No Jen venv found ($RESTORE_PY) — run 'sudo ./install.sh' first."
        info "Rolling back from $RESTORE_ROLLBACK"
        # v5.67.0 (Q114) — pass this install's own layout explicitly: this
        # subprocess has no systemd Environment= lines to inherit
        # JEN_ROOT/JEN_CONFIG_DIR/JEN_CONTENT_DIR from, so a relocated
        # install would otherwise silently fall back to jen.tools.restore's
        # own historical defaults (--etc-jen/--content-dir cover the two
        # explicit arguments restore.run() takes; JEN_ROOT covers
        # extensions.JEN_ROOT, used internally for the bundled-plugin check).
        # v5.67.0-beta.9 (Q121, item e) — ALL THREE variables, on both of the
        # restore/rollback lines. With JEN_ROOT alone, extensions.CONFIG_DIR is
        # $JEN_ROOT/etc: every restore printed a reload warning, its sizing
        # pass and the rollback snapshot used whatever database the BUNDLE's
        # own config named, and a legacy writable plugin read as "code is not
        # installed here". tests/test_install_python_env.py scans every python
        # invocation in this script for the same three together.
        if ! (cd "$(app_pyroot)" && JEN_ROOT="$(app_pyroot)" JEN_CONFIG_DIR="$CONFIG_DIR" JEN_CONTENT_DIR="$CONTENT_DIR" "$RESTORE_PY" -m jen.tools.restore --rollback "$RESTORE_ROLLBACK" --etc-jen "$CONFIG_DIR" --content-dir "$CONTENT_DIR" ${RESTORE_NOSTOP:-}); then
            fatal "Rollback failed — see the messages above."
        fi
        ok "Rollback complete."
        exit 0
    fi
    if [[ -z "$RESTORE_BUNDLE" ]]; then
        fatal "Usage: sudo ./install.sh --restore /path/to/bundle.tar.enc [--no-stop] [--start] [--force]"
    fi
    if [[ ! -f "$RESTORE_BUNDLE" ]]; then
        fatal "Bundle not found: $RESTORE_BUNDLE"
    fi
    RESTORE_PY="$PYBIN"
    if [[ ! -x "$RESTORE_PY" ]]; then
        fatal "No Jen venv found ($RESTORE_PY) — run 'sudo ./install.sh' first, then --restore."
    fi
    info "Restoring from $RESTORE_BUNDLE"
    # `if ! ( ... )` — not a bare `cmd1 && cmd2` — so a nonzero exit
    # from the Python tool is caught here, not treated by `set -e`
    # as a reason to abort the whole script before fatal() can run.
    # v5.67.0 (Q114) — same explicit layout as the --rollback leg above
    # (this one was missed in step 2 — --etc-jen/--content-dir default to
    # extensions.CONFIG_DIR/CONTENT_DIR, which fall back to the historical
    # defaults without JEN_CONFIG_DIR/JEN_CONTENT_DIR set).
    if ! (cd "$(app_pyroot)" && JEN_ROOT="$(app_pyroot)" JEN_CONFIG_DIR="$CONFIG_DIR" JEN_CONTENT_DIR="$CONTENT_DIR" "$RESTORE_PY" -m jen.tools.restore "$RESTORE_BUNDLE" --etc-jen "$CONFIG_DIR" --content-dir "$CONTENT_DIR" ${RESTORE_FORCE:-} ${RESTORE_NOSTOP:-} ${RESTORE_START:-}); then
        fatal "Restore failed — see the messages above."
    fi
    ok "Restore complete."
    exit 0
}

# --configure mode: just re-run the wizard and restart the service. Keeps
# user content and the release tree untouched.
_run_configure_mode() {
    detect_existing
    show_mode_banner
    CONFIGURE=true
    collect_config
    write_config
    spinner_start "Restarting Jen to apply new config..."
    systemctl restart jen 2>/dev/null || true
    sleep 2; spinner_stop
    systemctl is-active --quiet jen && ok "Jen restarted" || warn "Jen may not have restarted cleanly"
    print_summary
    exit 0
}

# Standard flow only: offer Docker as the install type on a fresh install
# (never on an upgrade — MODE_DOCKER, once set, is decided for good). Exits
# via docker_install() when chosen; otherwise returns and the caller
# continues the bare-metal path.
_offer_docker_instead() {
    [[ "$IS_UPGRADE" == "true" ]] && return
    blank
    echo -e "  ${B}Install Type:${NC}"
    blank
    echo -e "    ${B}1)${NC}  Bare metal / systemd  ${DIM}(recommended)${NC}"
    echo -e "    ${B}2)${NC}  Docker"
    blank
    local itype; itype=$(prompt_choice "1")
    if [[ "$itype" == "2" ]]; then
        MODE_DOCKER=true
        docker_install
        exit 0
    fi
}

# Standard flow only: confirm an upgrade interactively and offer a
# pre-upgrade backup — skipped entirely on a fresh install, with
# --upgrade, or with --unattended. Exits 0 if the operator declines.
_confirm_upgrade_or_exit() {
    # `|| return` (no explicit code) inherits the FAILED condition's own
    # exit status (1) as the function's return value — harmless on a
    # fresh install called from an if/while condition, but fatal under
    # set -e when called as a bare statement from main(), which is
    # exactly how this one is called. `return 0` always reports success
    # for the (extremely common) early-return case.
    [[ "$IS_UPGRADE" == "true" && "$MODE_UPGRADE" == "false" && "$MODE_UNATTENDED" == "false" ]] || return 0
    blank
    echo -e "  ${B}Existing installation detected:${NC} v${EXISTING_VERSION/unknown/—}"
    blank
    [[ "$(prompt_yn "Upgrade to Jen v${JEN_VERSION}?" "y")" == "n" ]] && \
        { info "Upgrade canceled."; exit 0; }
    blank
    if [[ "$(prompt_yn "Create a database backup before upgrading?" "y")" == "y" ]]; then
        spinner_start "Backing up Jen's database..."
        if _preupgrade_backup; then
            spinner_stop
        else
            spinner_stop
            # A backup that did not happen is said so, and the operator decides —
            # the old code printed "Pre-upgrade backups saved" whatever had
            # actually been written, and carried on.
            if [[ "$(prompt_yn "No backup was written. Continue the upgrade without one?" "n")" == "n" ]]; then
                info "Upgrade canceled — nothing was changed."; exit 0
            fi
        fi
    fi
}

# v5.67.0-beta.9 (Q121, item g + the 2026-10-02 addition) — the pre-upgrade
# backup is the app's OWN backup primitive, not a second implementation of one:
# dbexport.write_jen_export() (a server-side cursor, one row at a time, every
# table export_tables() knows — plugin tables included — through the pool's own
# TLS settings) published by dbexport.publish_backup() (a 0600 temp file in the
# same directory, fsync'd, renamed into place: a failure mid-write leaves no
# final file at all) with its .meta.json sidecar — exactly what Settings'
# "back up before updating" and the manual/scheduled backups write.
#
# What this replaces held WHOLE databases in memory (fetchall() per table), read
# jen.config through a ConfigParser WITH interpolation (so a `%` in a password
# failed it), ran as ROOT, and wrote every failure to a stderr file while the
# summary printed "Pre-upgrade backups saved" regardless.
#
# It runs as the service user, like every other snippet here that imports Jen's
# code, with all three layout variables (the backup directory is
# $JEN_CONTENT_DIR/backups; tests/test_install_python_env.py scans for this).
# It imports the INSTALLED release's code — the one that is about to be replaced
# — so an install old enough to lack the primitive says so, instead of a
# second implementation quietly standing in for it.
#
# Returns 0 only when a backup file was written. Says exactly what was and was
# not backed up either way: Kea's own database is never part of it (Jen does
# not own that schema; the app's own backups do not include it by default
# either) — it is Kea's own tooling's to back up.
_preupgrade_backup() {
    local out rc=0 status detail
    out=$(runuser -u "$JEN_USER" -- env JEN_ROOT="$(app_pyroot)" JEN_CONFIG_DIR="$CONFIG_DIR" JEN_CONTENT_DIR="$CONTENT_DIR" "$PYBIN" -c "
import os, sys
sys.path.insert(0, '$(app_pyroot)')
try:
    from jen.config import app_config
    from jen.services import dbexport
    publish_backup = dbexport.publish_backup
    write_jen_export = dbexport.write_jen_export
    write_meta_sidecar = dbexport._write_meta_sidecar
    backup_dir = dbexport.BACKUP_DIR
except Exception as e:
    print('JEN_BACKUP_UNAVAILABLE ' + type(e).__name__ + ': ' + str(e))
    sys.exit(3)
try:
    from datetime import datetime, timezone
    app_config.reload()
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d-%H%M%S')
    path = os.path.join(backup_dir, 'jen-pre-upgrade-${JEN_VERSION}-' + ts + '.json.gz')
    meta = publish_backup(path, lambda f: write_jen_export(f))
    write_meta_sidecar(path, meta)
    print('JEN_BACKUP_OK ' + path)
except Exception as e:
    print('JEN_BACKUP_FAILED ' + type(e).__name__ + ': ' + str(e))
    sys.exit(1)
" 2>&1) || rc=$?
    status=$(printf '%s\n' "$out" | grep -m1 '^JEN_BACKUP_' || true)
    detail="${status#JEN_BACKUP_* }"
    case "$status" in
        JEN_BACKUP_OK*)
            ok "Jen's database backed up  ${DIM}(${detail})${NC}"
            info "Not included: Kea's own database (Jen does not own it — back it up with Kea's own tools)."
            return 0 ;;
        JEN_BACKUP_UNAVAILABLE*)
            warn "NO backup was written: the installed Jen predates the backup tool this step uses (${detail})."
            ;;
        JEN_BACKUP_FAILED*)
            warn "NO backup was written: ${detail}"
            ;;
        *)
            warn "NO backup was written: the backup step produced no result (exit ${rc})."
            [[ -n "$out" ]] && echo "$out" | tail -5
            ;;
    esac
    return 1
}

main() {
    show_banner
    require_root

    # v5.67.0-beta.9 (Q121, items a/h) — in THIS order, and no earlier:
    #  1. root, so nothing below (the answers file, the layout checker) is
    #     read or run by an unprivileged caller;
    #  2. umask 022 — a hardened sudo umask (077 is common) would otherwise
    #     make every file this script creates (the venv above all) unreadable
    #     to the service user;
    #  3. the answers file, so JEN_APP_DIR/JEN_CONFIG_DIR/JEN_DATA_DIR in it
    #     count (they used to be ignored: the layout was resolved at top
    #     level, before this ran);
    #  4. the layout — except for --docker, which has no layout at all.
    umask 022
    [[ -n "$ANSWERS_FILE" ]] && _load_answers_file "$ANSWERS_FILE"
    if [[ "$MODE_DOCKER" != "true" ]]; then
        _resolve_layout_dirs
        _set_paths
    fi

    [[ "$MODE_RESTORE" == "true" ]] && _run_restore_mode
    [[ "$MODE_CONFIGURE" == "true" ]] && _run_configure_mode

    if [[ "$MODE_REPAIR" == "true" ]]; then
        detect_existing
        show_mode_banner
        _run_steps repair
        exit 0
    fi

    if [[ "$MODE_DOCKER" == "true" ]]; then
        detect_existing
        show_mode_banner
        docker_install
        exit 0
    fi

    # Standard flow — auto-detect fresh install vs upgrade.
    detect_existing
    show_mode_banner
    _offer_docker_instead
    _confirm_upgrade_or_exit
    _run_steps standard
}

trap 'spinner_stop; err "Installer interrupted."; rollback; exit 1' INT TERM
trap 'spinner_stop' EXIT

main "$@"
