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
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

JEN_VERSION="5.23.0"

# ── Paths ────────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/jen"
CONFIG_DIR="/etc/jen"
CONTENT_DIR="/var/lib/jen"          # v5.13.0 — user-writable content (uploads, backups, plugins)
SERVICE_FILE="/etc/systemd/system/jen.service"
SUDOERS_FILE="/etc/sudoers.d/jen"
CONFIG_FILE="/etc/jen/jen.config"
BACKUP_DIR="/etc/jen/backups"       # jen.config backups (NOT the DB backups — those are $CONTENT_DIR/backups)
JEN_USER="www-data"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROLLBACK_JEN=""
ROLLBACK_PKG=""

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

# The app tree the installer's inline python helpers should import from:
# this run's release once install_files has populated it, else the live
# release, else a flat pre-5.14 tree.
app_pyroot() {
    if   [[ -d "$APP_DIR/jen" ]]; then echo "$APP_DIR"
    elif [[ -d "$CURRENT_LINK/app/jen" ]]; then echo "$CURRENT_LINK/app"
    else echo "$INSTALL_DIR"; fi
}

# ── Mode flags ────────────────────────────────────────────────────────────────
MODE_UPGRADE=false
MODE_CONFIGURE=false
MODE_REPAIR=false
MODE_UNATTENDED=false
MODE_DOCKER=false
IS_UPGRADE=false
CONFIGURE=false
EXISTING_VERSION=""
# v5.20.0 — true for the whole install_files..verify_install mutation window
# on an upgrade; fatal() rolls back automatically while this is set (below).
ROLLBACK_ARMED=false

for arg in "$@"; do
    case "$arg" in
        --upgrade)     MODE_UPGRADE=true ;;
        --configure)   MODE_CONFIGURE=true ;;
        --repair)      MODE_REPAIR=true ;;
        --unattended)  MODE_UNATTENDED=true ;;
        --docker)      MODE_DOCKER=true ;;
    esac
done

# ── ANSI colors ──────────────────────────────────────────────────────────────
R='\033[0;31m'    # red
G='\033[0;32m'    # green
Y='\033[1;33m'    # yellow
C='\033[0;36m'    # cyan
T='\033[0;32m'    # teal (green)
B='\033[1m'       # bold
DIM='\033[2m'     # dim
NC='\033[0m'      # reset
BG_T='\033[46m'   # teal background
BG_B='\033[40m'   # black background

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

# ── Spinner ───────────────────────────────────────────────────────────────────
_spinner_pid=""
spinner_start() {
    local msg="$1"
    if [[ "$MODE_UNATTENDED" == "true" ]]; then
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
    clear
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
        fatal "This installer must be run as root.  →  sudo ./install.sh $*"
    fi
}

# ── Detect existing install ───────────────────────────────────────────────────
detect_existing() {
    if [[ -f "$CURRENT_LINK/app/run.py" ]] || [[ -f "$INSTALL_DIR/run.py" ]] || [[ -f "$INSTALL_DIR/jen.py" ]] || [[ -d "$INSTALL_DIR/jen" ]]; then
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
            EXISTING_VERSION=$(grep -m1 'JEN_VERSION' "$ver_file" 2>/dev/null                 | grep -oP '"[0-9]+\.[0-9]+\.[0-9]+"' | tr -d '"' || echo "unknown")
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

    # Disk space
    local avail_kb
    avail_kb=$(df /opt 2>/dev/null | awk 'NR==2{print $4}' || echo "0")
    if [[ $avail_kb -gt 102400 ]]; then
        ok "Disk space: $(( avail_kb / 1024 ))MB free"
    else
        warn "Low disk space: $(( avail_kb / 1024 ))MB — recommend 100MB+"
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

# ── Configuration wizard ──────────────────────────────────────────────────────
collect_config() {
    blank
    echo -e "  ${B}${C}CONFIGURATION${NC}"
    divider
    blank

    # On upgrade with existing config — offer choices
    if [[ "$IS_UPGRADE" == "true" && -f "$CONFIG_FILE" && \
          "$MODE_UPGRADE" == "false" && "$MODE_REPAIR" == "false" ]]; then
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
    elif [[ "$MODE_UPGRADE" == "true" || "$MODE_REPAIR" == "true" ]]; then
        blank
        ok "Keeping existing configuration"
        CONFIGURE=false
        return
    else
        CONFIGURE=true
    fi

    blank
    info "Let's set up Jen. Press Enter to accept defaults shown in ${C}cyan${NC}."
    blank

    # ── Kea API ───────────────────────────────────────────────────────────────
    echo -e "  ${B}Kea Control Agent${NC}  ${DIM}(the Kea REST API)${NC}"
    blank
    KEA_API_URL=$(prompt_input  "API URL"      "http://YOUR-KEA-SERVER:8000")
    KEA_API_USER=$(prompt_input "API username" "kea-api")
    KEA_API_PASS=$(prompt_secret "API password")
    blank
    spinner_start "Testing Kea API connection..."
    sleep 0.5
    if test_kea_api "$KEA_API_URL" "$KEA_API_USER" "$KEA_API_PASS"; then
        spinner_stop; ok "Kea API connection successful"
    else
        spinner_stop; warn "Could not reach Kea API — check URL and credentials after install"
    fi

    # ── Kea DB ────────────────────────────────────────────────────────────────
    blank
    echo -e "  ${B}Kea MySQL Database${NC}"
    blank
    KEA_DB_HOST=$(prompt_input  "Host"     "YOUR-KEA-SERVER")
    KEA_DB_USER=$(prompt_input  "Username" "kea")
    KEA_DB_PASS=$(prompt_secret "Password")
    KEA_DB_NAME=$(prompt_input  "Database" "kea")
    blank
    spinner_start "Testing Kea database connection..."
    sleep 0.5
    if test_mysql "$KEA_DB_HOST" "$KEA_DB_USER" "$KEA_DB_PASS" "$KEA_DB_NAME"; then
        spinner_stop; ok "Kea database connection successful"
    else
        spinner_stop; warn "Could not connect to Kea database — check credentials after install"
    fi

    # ── Jen DB ────────────────────────────────────────────────────────────────
    # Skipped for the Docker "bundled MariaDB" path — docker-compose.mysql.yml
    # owns those credentials and wires them into the jen container itself.
    if [[ "${SKIP_JEN_DB:-false}" == "true" ]]; then
        JEN_DB_HOST="jen-mysql"; JEN_DB_USER="jen"; JEN_DB_PASS=""; JEN_DB_NAME="jen"
    else
        blank
        echo -e "  ${B}Jen MySQL Database${NC}  ${DIM}(users, audit log, settings)${NC}"
        blank
        JEN_DB_HOST=$(prompt_input  "Host"     "${KEA_DB_HOST:-localhost}")
        JEN_DB_USER=$(prompt_input  "Username" "jen")
        JEN_DB_PASS=$(prompt_secret "Password")
        JEN_DB_NAME=$(prompt_input  "Database" "jen")
        blank
        spinner_start "Testing Jen database connection..."
        sleep 0.5
        if test_mysql "$JEN_DB_HOST" "$JEN_DB_USER" "$JEN_DB_PASS" "$JEN_DB_NAME"; then
            spinner_stop; ok "Jen database connection successful"
        else
            spinner_stop
            warn "Could not connect to Jen database. Create it with:"
            blank
            echo -e "    ${C}CREATE DATABASE ${JEN_DB_NAME};${NC}"
            echo -e "    ${C}CREATE USER '${JEN_DB_USER}'@'%' IDENTIFIED BY 'yourpassword';${NC}"
            echo -e "    ${C}GRANT ALL PRIVILEGES ON ${JEN_DB_NAME}.* TO '${JEN_DB_USER}'@'%';${NC}"
            echo -e "    ${C}FLUSH PRIVILEGES;${NC}"
            blank
        fi
    fi

    # ── Admin password ────────────────────────────────────────────────────────
    if [[ "$IS_UPGRADE" == "false" ]]; then
        blank
        echo -e "  ${B}Admin Account${NC}"
        blank
        local admin_pass admin_pass2
        while true; do
            admin_pass=$(prompt_secret "Admin password (min 8 chars)")
            if [[ ${#admin_pass} -lt 8 ]]; then
                warn "Password must be at least 8 characters."; continue
            fi
            admin_pass2=$(prompt_secret "Confirm admin password")
            [[ "$admin_pass" == "$admin_pass2" ]] && break
            warn "Passwords do not match — try again."
        done
        ADMIN_PASS="$admin_pass"
        ok "Admin password set"
    fi

    # ── Subnets ───────────────────────────────────────────────────────────────
    blank
    echo -e "  ${B}Subnet Map${NC}  ${DIM}(your Kea subnets — you can add more later in Settings)${NC}"
    blank
    SUBNET_LINES=""
    local added=0
    while true; do
        printf "  ${Y}  ▸${NC} Subnet ID (Enter to finish): " > /dev/tty
        read -r SID < /dev/tty
        [[ -z "$SID" ]] && break
        if ! [[ "$SID" =~ ^[0-9]+$ ]]; then warn "Subnet ID must be a number"; continue; fi
        local sname scidr
        sname=$(prompt_input "  Friendly name" "Subnet${SID}")
        scidr=$(prompt_input "  CIDR"          "192.168.${SID}.0/24")
        SUBNET_LINES="${SUBNET_LINES}${SID} = ${sname}, ${scidr}\n"
        ok "Added: ${SID} = ${sname}, ${scidr}"
        added=$((added+1))
        blank
    done
    [[ $added -eq 0 ]] && {
        warn "No subnets added — edit $CONFIG_FILE to add them later"
        SUBNET_LINES="# 1 = Production, 10.10.10.0/24\n# 30 = IoT, 10.10.30.0/24\n"
    }

    # ── SSH ───────────────────────────────────────────────────────────────────
    blank
    echo -e "  ${B}SSH Access${NC}  ${DIM}(optional — enables subnet editing from the UI)${NC}"
    blank
    if [[ "$(prompt_yn "Configure SSH to Kea server?" "y")" == "y" ]]; then
        KEA_SSH_HOST=$(prompt_input  "Kea SSH host"  "${KEA_DB_HOST:-YOUR-KEA-SERVER}")
        KEA_SSH_USER=$(prompt_input  "SSH username"  "$(logname 2>/dev/null || echo 'ubuntu')")
        KEA_CONF_PATH=$(prompt_input "Kea config file" "/etc/kea/kea-dhcp4.conf")
    else
        KEA_SSH_HOST=""; KEA_SSH_USER=""; KEA_CONF_PATH="/etc/kea/kea-dhcp4.conf"
    fi

    # ── DDNS ──────────────────────────────────────────────────────────────────
    blank
    echo -e "  ${B}DDNS Integration${NC}  ${DIM}(optional — Technitium, Pi-hole, AdGuard, SSH)${NC}"
    blank
    if [[ "$(prompt_yn "Configure DDNS?" "n")" == "y" ]]; then
        echo -e "    ${B}1)${NC} Technitium  ${B}2)${NC} Pi-hole  ${B}3)${NC} AdGuard  ${B}4)${NC} SSH/Bind9  ${B}5)${NC} None"
        local dns_choice; dns_choice=$(prompt_choice "1")
        case "$dns_choice" in
            1) DDNS_PROVIDER="technitium"
               DDNS_URL=$(prompt_input   "Technitium API URL"   "https://your-technitium/api")
               DDNS_TOKEN=$(prompt_secret "Technitium API token") ;;
            2) DDNS_PROVIDER="pihole"
               DDNS_URL=$(prompt_input   "Pi-hole URL"           "http://your-pihole")
               DDNS_TOKEN=$(prompt_secret "Pi-hole password/token") ;;
            3) DDNS_PROVIDER="adguard"
               DDNS_URL=$(prompt_input   "AdGuard URL"           "http://your-adguard:3000")
               DDNS_TOKEN=$(prompt_secret "AdGuard password") ;;
            4) DDNS_PROVIDER="ssh"; DDNS_URL=""; DDNS_TOKEN="" ;;
            *) DDNS_PROVIDER="none"; DDNS_URL=""; DDNS_TOKEN="" ;;
        esac
        DDNS_LOG=$(prompt_input "DDNS log path" "/var/log/kea/kea-ddns.log")
        DDNS_ZONE=$(prompt_input "Forward zone"  "your.domain.com")
    else
        DDNS_PROVIDER="none"; DDNS_URL=""; DDNS_TOKEN=""
        DDNS_LOG="/var/log/kea/kea-ddns.log"; DDNS_ZONE=""
    fi

    # ── Ports ─────────────────────────────────────────────────────────────────
    blank
    echo -e "  ${B}Server Ports${NC}"
    blank
    HTTP_PORT=$(prompt_input  "HTTP port"  "5050")
    HTTPS_PORT=$(prompt_input "HTTPS port" "8443")
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
        local bak="${BACKUP_DIR}/jen.config.$(date +%Y%m%d_%H%M%S).bak"
        mkdir -p "$BACKUP_DIR"
        cp "$CONFIG_FILE" "$bak"
        ok "Backed up existing config → ${DIM}${bak}${NC}"
    fi

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
key_path = /etc/jen/ssh/jen_rsa
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
    chown "$JEN_USER:$JEN_USER" "$CONFIG_FILE"
    chmod 640 "$CONFIG_FILE"
    ok "Config written → ${DIM}${CONFIG_FILE}${NC}"

    # Set admin password if this is a fresh install
    if [[ "$IS_UPGRADE" == "false" && -n "${ADMIN_PASS:-}" ]]; then
        _set_admin_password "$ADMIN_PASS"
    fi
    blank
}

_set_admin_password() {
    local pass="$1"
    # v4.4.8: previously interpolated $pass directly into Python source
    # inside this heredoc (generate_password_hash('$pass', ...)) — a
    # password containing a single quote broke the Python syntax outright,
    # and since stderr is redirected to /dev/null with || true swallowing
    # the exit code, it failed completely silently: no error shown, no
    # "Admin password updated" message either, and the password was never
    # actually set. Passing it via an environment variable and reading it
    # with os.environ sidesteps quoting entirely — no character in the
    # password can break the Python source, because it's never embedded
    # in the source at all.
    JEN_INSTALL_ADMIN_PASS="$pass" "$PYBIN" << PYEOF 2>/dev/null || true
import os
import sys
sys.path.insert(0, '$(app_pyroot)')
try:
    # Use Jen's own hasher (scrypt as of v5.8.0) so the installer and the
    # app never disagree on the password-hash format.
    from jen.models.user import hash_password
    import pymysql, configparser
    cfg = configparser.ConfigParser(interpolation=None)
    cfg.read('$CONFIG_FILE')
    db = pymysql.connect(
        host=cfg.get('jen_db','host'), user=cfg.get('jen_db','user'),
        password=cfg.get('jen_db','password'), database=cfg.get('jen_db','database'),
        cursorclass=pymysql.cursors.DictCursor, connect_timeout=5
    )
    pw = os.environ['JEN_INSTALL_ADMIN_PASS']
    hashed = hash_password(pw)
    with db.cursor() as cur:
        # v5.6.0 — also clear must_change_password: the operator picked
        # this password in the wizard, so don't make them change it again
        # on first login. (The seed sets the flag; nothing cleared it,
        # so bare-metal installs forced a redundant change.)
        cur.execute("UPDATE users SET password=%s, must_change_password=0 WHERE username='admin'", (hashed,))
    db.commit(); db.close()
    print("  Admin password updated.")
except Exception as e:
    print(f"  Note: Could not set admin password now — set it on first login. ({e})")
PYEOF
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
)
snapshot_external_files() {
    [[ "$IS_UPGRADE" == "false" ]] && return

    local ts; ts=$(date +%Y%m%d_%H%M%S)
    local dir="${BACKUP_DIR}/ext.${ts}"
    local f found=false
    for f in "${_EXTERNAL_FILES[@]}"; do
        if [[ -f "$f" ]]; then
            mkdir -p "$dir"
            cp -p "$f" "$dir/$(basename "$f")"
            found=true
        fi
    done
    if [[ "$found" == "true" ]]; then
        ROLLBACK_EXT="$dir"
        export ROLLBACK_EXT
    fi
}

# ── Restore external files (used by rollback(), both branches) ──────────────
_restore_external_files() {
    [[ -z "${ROLLBACK_EXT:-}" ]] && return
    [[ -d "$ROLLBACK_EXT" ]] || return
    local f base dest
    for f in "$ROLLBACK_EXT"/*; do
        [[ -f "$f" ]] || continue
        base=$(basename "$f")
        case "$base" in
            "$(basename "$SERVICE_FILE")") dest="$SERVICE_FILE" ;;
            "$(basename "$SUDOERS_FILE")") dest="$SUDOERS_FILE" ;;
            jen-update-root.py) dest="/usr/local/sbin/jen-update-root.py" ;;
            jen-update.service) dest="/etc/systemd/system/jen-update.service" ;;
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
    ok "User content is under $CONTENT_DIR"
}

# ── Install files ─────────────────────────────────────────────────────────────
# v5.14.0 — the whole tarball goes into releases/$JEN_VERSION/app; the
# shipped OUT-OF-TREE files (jen.service, jen-sudoers, jen-update-root.py,
# jen-update.service) are installed from that copy. `current` is NOT
# flipped here — setup_venv() has to build releases/$JEN_VERSION/venv
# first, then activate_release() does the atomic flip.
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
    cp "$APP_DIR/jen.service" "$SERVICE_FILE"
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

    # v5.13.0 — the whole application tree is root-owned and read-only to
    # the service user. User-writable content lives under $CONTENT_DIR
    # (migrate_content, above, chowns that to $JEN_USER). jen.config keeps
    # its own service-user ownership (write_config, below).
    spinner_start "Setting permissions..."
    chown -R root:root "$INSTALL_DIR"
    chmod -R a+rX "$INSTALL_DIR"
    chown -R "$JEN_USER:$JEN_USER" "$CONFIG_DIR"
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
    systemctl is-active --quiet jen \
        && ok "Service running" \
        || { err "Service not running"; return 1; }

    # Config
    [[ -f "$CONFIG_FILE" ]] \
        && ok "Config file present  ${DIM}(${CONFIG_FILE})${NC}" \
        || warn "Config file not found — Jen may not start correctly"

    # Templates
    local tpl_result
    tpl_result=$("$PYBIN" -c "
from jinja2 import Environment, FileSystemLoader
import os, sys
env = Environment(loader=FileSystemLoader('$(app_pyroot)/templates'))
# Register custom filters used by Jen so validation doesn't false-fail
for f in ['utcfmt','utcdate','utctime']:
    env.filters[f] = lambda v, fmt=None: v
errors = []
for t in os.listdir('$(app_pyroot)/templates'):
    if t.endswith('.html'):
        try: env.get_template(t)
        except Exception as e: errors.append(f'{t}: {e}')
if errors:
    for e in errors: print(e)
    sys.exit(1)
else:
    print(len([f for f in os.listdir('$(app_pyroot)/templates') if f.endswith('.html')]))
" 2>&1)
    if [[ $? -eq 0 ]]; then
        ok "Templates validated  ${DIM}(${tpl_result} files)${NC}"
    else
        err "Template validation failed:"; echo "$tpl_result"; exit 1
    fi

    # Modules
    if [[ -d "$(app_pyroot)/jen" ]]; then
        local mod_result
        mod_result=$("$PYBIN" -c "
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
" 2>&1)
        if [[ $? -eq 0 ]]; then
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
    [[ -f "/etc/jen/ssl/combined.crt" ]] && ssl_enabled=true

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
    if [[ "$IS_UPGRADE" == "false" && "$MODE_REPAIR" == "false" ]]; then
        echo -e "  ${C}╠══════════════════════════════════════════════════════╣${NC}"
        _box_line ""
        _box_line "  ${B}Next steps:${NC}"
        _box_line "   1.  Open Jen and verify your Kea data appears"
        _box_line "   2.  Settings → SSH Key → Generate key, add to Kea"
        _box_line "   3.  Settings → Alerts → Add a notification channel"
        _box_line "   4.  Settings → MFA → Enable for your account"
        _box_line ""
    fi
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
    sleep 5

    docker ps | grep -q "jen" \
        && ok "Jen container running" \
        || { err "Container failed to start"; docker compose -f "$compose_file" logs --tail=20; exit 1; }

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
main() {
    show_banner
    require_root

    # Handle --configure mode (just re-run wizard, restart service)
    if [[ "$MODE_CONFIGURE" == "true" ]]; then
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
    fi

    # Handle --repair mode — rebuild this release's app/ and venv/ from the
    # tarball and re-activate it. Keeps user content and config untouched.
    if [[ "$MODE_REPAIR" == "true" ]]; then
        detect_existing
        show_mode_banner
        preflight_checks
        install_dependencies
        CONFIGURE=false
        backup_existing
        snapshot_external_files
        ROLLBACK_ARMED=true
        install_files
        setup_venv
        compile_app
        activate_release
        start_service
        verify_install
        ROLLBACK_ARMED=false
        remove_flat_leftovers
        print_summary
        exit 0
    fi

    # Handle --docker mode
    if [[ "$MODE_DOCKER" == "true" ]]; then
        detect_existing
        show_mode_banner
        docker_install
        exit 0
    fi

    # Standard flow — auto-detect
    detect_existing
    show_mode_banner

    if [[ "$IS_UPGRADE" == "false" ]]; then
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
    fi

    if [[ "$IS_UPGRADE" == "true" && "$MODE_UPGRADE" == "false" && "$MODE_UNATTENDED" == "false" ]]; then
        blank
        echo -e "  ${B}Existing installation detected:${NC} v${EXISTING_VERSION/unknown/—}"
        blank
        [[ "$(prompt_yn "Upgrade to Jen v${JEN_VERSION}?" "y")" == "n" ]] && \
            { info "Upgrade canceled."; exit 0; }
        blank
        if [[ "$(prompt_yn "Create a database backup before upgrading?" "y")" == "y" ]]; then
            spinner_start "Backing up Jen and Kea databases..."
            mkdir -p /var/lib/jen/backups
            # $PYBIN is the venv python on a 5.8.x→ upgrade, else system
            # python3 (which a pre-5.8.0 install populated with pymysql).
            if "$PYBIN" -c "
import sys, json, gzip, datetime, pymysql, pymysql.cursors, configparser
cfg = configparser.ConfigParser()
cfg.read('/etc/jen/jen.config')
ts = datetime.datetime.utcnow().strftime('%Y-%m-%d-%H%M%S')
errors = []
for which in ['jen','kea']:
    try:
        h = cfg.get(which+'_db' if which=='jen' else 'kea_db','host',fallback='')
        u = cfg.get(which+'_db' if which=='jen' else 'kea_db','user',fallback='')
        p = cfg.get(which+'_db' if which=='jen' else 'kea_db','password',fallback='')
        d = cfg.get(which+'_db' if which=='jen' else 'kea_db','database',fallback=which)
        conn = pymysql.connect(host=h,user=u,password=p,database=d,cursorclass=pymysql.cursors.DictCursor,connect_timeout=5)
        with conn.cursor() as cur:
            cur.execute('SHOW TABLES')
            tables = [list(r.values())[0] for r in cur.fetchall()]
        data = {}
        for tbl in tables:
            with conn.cursor() as cur:
                cur.execute(f'SELECT * FROM \`{tbl}\`')
                rows = cur.fetchall()
            data[tbl] = [{k: str(v) if hasattr(v,'isoformat') else v for k,v in r.items()} for r in rows]
        conn.close()
        payload = {'_meta':{'database':which,'exported_at':ts,'jen_export_version':1,'tables':tables},'data':data}
        fname = f'/var/lib/jen/backups/{which}-pre-upgrade-${JEN_VERSION}-{ts}.json.gz'
        with gzip.open(fname,'wt',encoding='utf-8') as f:
            json.dump(payload,f,default=str)
        import os; os.chmod(fname,0o600)
        print(f'ok:{which}:{fname}')
    except Exception as e:
        print(f'fail:{which}:{e}', file=sys.stderr)
" 2>/tmp/jen_backup_err; then
                spinner_stop
                ok "Pre-upgrade backups saved to /var/lib/jen/backups/"
            else
                spinner_stop
                warn "Pre-upgrade backup failed (non-fatal) — check /tmp/jen_backup_err"
            fi
        fi
    fi

    preflight_checks
    install_dependencies
    collect_config
    backup_existing
    migrate_content
    snapshot_external_files
    ROLLBACK_ARMED=true
    install_files
    setup_venv
    compile_app
    write_config
    activate_release
    start_service
    verify_install
    ROLLBACK_ARMED=false
    remove_flat_leftovers
    print_summary
}

trap 'spinner_stop; err "Installer interrupted."; rollback; exit 1' INT TERM
trap 'spinner_stop' EXIT

main "$@"
