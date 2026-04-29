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

JEN_VERSION="3.2.4"

# ── Paths ────────────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/jen"
CONFIG_DIR="/etc/jen"
SERVICE_FILE="/etc/systemd/system/jen.service"
SUDOERS_FILE="/etc/sudoers.d/jen"
CONFIG_FILE="/etc/jen/jen.config"
BACKUP_DIR="/etc/jen/backups"
JEN_USER="www-data"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROLLBACK_JEN=""
ROLLBACK_PKG=""

# ── Mode flags ────────────────────────────────────────────────────────────────
MODE_UPGRADE=false
MODE_CONFIGURE=false
MODE_REPAIR=false
MODE_UNATTENDED=false
MODE_DOCKER=false
IS_UPGRADE=false
CONFIGURE=false
EXISTING_VERSION=""

for arg in "$@"; do
    case "$arg" in
        --upgrade)     MODE_UPGRADE=true ;;
        --configure)   MODE_CONFIGURE=true ;;
        --repair)      MODE_REPAIR=true ;;
        --unattended)  MODE_UNATTENDED=true ;;
        --docker)      MODE_DOCKER=true ;;
    esac
done

# ── ANSI colours ──────────────────────────────────────────────────────────────
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
fatal()   { echo -e "  ${R}[ FATAL]${NC}  $*"; exit 1; }
step()    { echo -e "\n  ${B}${C}$*${NC}"; }
divider() { echo -e "  ${DIM}${C}$(printf '─%.0s' {1..54})${NC}"; }
blank()   { echo ""; }

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
    local bc="${2:-$C}"   # border colour
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
    echo -e "  ${C}║${NC}  ${DIM}Version ${JEN_VERSION}   •   github.com/ltkojak/jen-kea${NC}      ${C}║${NC}"
    echo -e "  ${C}║${NC}  ${DIM}GPLv3 — Copyright (C) 2026 Matthew Thibodeau${NC}        ${C}║${NC}"
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
    if [[ -f "$INSTALL_DIR/run.py" ]] || [[ -f "$INSTALL_DIR/jen.py" ]] || [[ -d "$INSTALL_DIR/jen" ]]; then
        IS_UPGRADE=true
        # Version is defined in jen/__init__.py (2.6.x+), jen.py (pre-2.6), or legacy/jen.py
        local ver_file=""
        if   [[ -f "$INSTALL_DIR/jen/__init__.py" ]]; then ver_file="$INSTALL_DIR/jen/__init__.py"
        elif [[ -f "$INSTALL_DIR/jen.py"          ]]; then ver_file="$INSTALL_DIR/jen.py"
        elif [[ -f "$INSTALL_DIR/legacy/jen.py"   ]]; then ver_file="$INSTALL_DIR/legacy/jen.py"
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

    spinner_start "Updating package lists..."
    apt-get update -qq 2>/dev/null
    spinner_stop
    ok "Package lists updated"

    local pkgs=()
    command -v pip3        &>/dev/null || pkgs+=(python3-pip)
    command -v mysql       &>/dev/null || pkgs+=(mariadb-client-core)
    command -v ssh-keygen  &>/dev/null || pkgs+=(openssh-client)
    command -v curl        &>/dev/null || pkgs+=(curl)
    command -v openssl     &>/dev/null || pkgs+=(openssl)

    if [[ ${#pkgs[@]} -gt 0 ]]; then
        spinner_start "Installing system packages: ${pkgs[*]}"
        apt-get install -y -qq "${pkgs[@]}" 2>/dev/null
        spinner_stop
        ok "System packages installed: ${pkgs[*]}"
    else
        ok "All system packages present"
    fi

    local missing_py=()
    for pkg in flask flask_login pymysql dbutils requests pyotp qrcode authlib jinja2 werkzeug; do
        python3 -c "import ${pkg}" 2>/dev/null || missing_py+=("${pkg/-/_}")
    done

    if [[ ${#missing_py[@]} -gt 0 ]]; then
        spinner_start "Installing Python packages..."
        pip3 install -q flask flask-login pymysql dbutils requests pyotp "qrcode[pil]" authlib \
            --break-system-packages 2>/dev/null || \
        pip3 install -q flask flask-login pymysql dbutils requests pyotp "qrcode[pil]" authlib
        spinner_stop
        ok "Python packages installed"
    else
        ok "All Python packages present"
    fi
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
        echo -e "    ${B}3)${NC}  Skip — continue upgrade without touching config"
        blank
        local choice
        while true; do
            printf "  ${Y}  ▸${NC} Choice [${C}1${NC}]: " > /dev/tty
            read -r choice < /dev/tty
            choice="${choice:-1}"
            case "$choice" in
                1|3)
                    blank
                    ok "Keeping existing configuration"; CONFIGURE=false; return ;;
                2)   break ;;
                *)   echo -e "  ${R}  Invalid — please enter 1, 2, or 3.${NC}" > /dev/tty ;;
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

    chown root:www-data "$CONFIG_FILE"
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
    python3 << PYEOF 2>/dev/null || true
import sys
sys.path.insert(0, '$INSTALL_DIR')
try:
    from werkzeug.security import generate_password_hash
    import pymysql, configparser
    cfg = configparser.ConfigParser()
    cfg.read('$CONFIG_FILE')
    db = pymysql.connect(
        host=cfg.get('jen_db','host'), user=cfg.get('jen_db','user'),
        password=cfg.get('jen_db','password'), database=cfg.get('jen_db','database'),
        cursorclass=pymysql.cursors.DictCursor, connect_timeout=5
    )
    hashed = generate_password_hash('$pass', method='pbkdf2:sha256')
    with db.cursor() as cur:
        cur.execute("UPDATE users SET password=%s WHERE username='admin'", (hashed,))
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

    if [[ -f "$INSTALL_DIR/run.py" ]]; then
        cp "$INSTALL_DIR/run.py" "${BACKUP_DIR}/run.py.${ts}.bak"
        ok "Backed up run.py"
    fi

    if [[ -d "$INSTALL_DIR/jen" ]]; then
        cp -r "$INSTALL_DIR/jen" "${BACKUP_DIR}/jen.${ts}.bak"
        ok "Backed up jen/ package"
    fi

    ROLLBACK_JEN="${BACKUP_DIR}/run.py.${ts}.bak"
    ROLLBACK_PKG="${BACKUP_DIR}/jen.${ts}.bak"
    export ROLLBACK_JEN ROLLBACK_PKG
    blank
}

# ── Rollback ──────────────────────────────────────────────────────────────────
rollback() {
    [[ -z "${ROLLBACK_JEN:-}" ]] && return
    [[ -f "$ROLLBACK_JEN" ]] || return
    warn "Rolling back to previous installation..."
    cp "$ROLLBACK_JEN" "$INSTALL_DIR/run.py"
    if [[ -n "${ROLLBACK_PKG:-}" && -d "$ROLLBACK_PKG" ]]; then
        rm -rf "$INSTALL_DIR/jen"
        cp -r "$ROLLBACK_PKG" "$INSTALL_DIR/jen"
    fi
    systemctl restart jen 2>/dev/null || true
    warn "Rollback complete — previous version restored"
}

# ── Install files ─────────────────────────────────────────────────────────────
install_files() {
    blank
    echo -e "  ${B}${C}INSTALLING FILES${NC}"
    divider
    blank

    mkdir -p "$INSTALL_DIR/templates" "$INSTALL_DIR/static" \
             "$INSTALL_DIR/static/icons/brands" \
             "$INSTALL_DIR/static/icons/custom" \
             "$CONFIG_DIR/ssl" "$CONFIG_DIR/ssh"

    spinner_start "Installing application files..."
    cp "$SCRIPT_DIR/run.py"  "$INSTALL_DIR/run.py"
    # Copy legacy monolith for reference (not executed)
    if [[ -f "$SCRIPT_DIR/legacy/jen.py" ]]; then
        mkdir -p "$INSTALL_DIR/legacy"
        cp "$SCRIPT_DIR/legacy/jen.py" "$INSTALL_DIR/legacy/jen.py"
    fi
    spinner_stop
    ok "Installed run.py"

    if [[ -d "$SCRIPT_DIR/jen" ]]; then
        spinner_start "Installing jen/ package..."
        mkdir -p "$INSTALL_DIR/jen"
        cp -r "$SCRIPT_DIR/jen/." "$INSTALL_DIR/jen/"
        spinner_stop
        ok "Installed jen/ package  ${DIM}($(find "$INSTALL_DIR/jen" -name '*.py' | wc -l) modules)${NC}"
    fi

    spinner_start "Installing templates..."
    cp -r "$SCRIPT_DIR/templates/." "$INSTALL_DIR/templates/"
    spinner_stop
    ok "Installed templates  ${DIM}($(ls "$SCRIPT_DIR/templates/" | wc -l) files)${NC}"

    if [[ -d "$SCRIPT_DIR/static/icons/brands" ]]; then
        spinner_start "Installing brand icons..."
        cp "$SCRIPT_DIR/static/icons/brands/"*.svg \
           "$INSTALL_DIR/static/icons/brands/" 2>/dev/null || true
        spinner_stop
        ok "Installed brand icons  ${DIM}($(ls "$INSTALL_DIR/static/icons/brands/" 2>/dev/null | wc -l) icons)${NC}"
    fi

    cp "$SCRIPT_DIR/jen.service" "$SERVICE_FILE"
    ok "Installed systemd service"

    cp "$SCRIPT_DIR/jen-sudoers" "$SUDOERS_FILE"
    chmod 440 "$SUDOERS_FILE"
    ok "Installed sudoers entry"

    # Download HTMX for local serving (works offline after install)
    local htmx_path="$INSTALL_DIR/static/js/htmx.min.js"
    if [[ ! -f "$htmx_path" ]] || [[ ! -s "$htmx_path" ]]; then
        spinner_start "Downloading HTMX..."
        mkdir -p "$INSTALL_DIR/static/js"
        if curl -sf --connect-timeout 10             "https://unpkg.com/htmx.org@1.9.12/dist/htmx.min.js"             -o "$htmx_path" 2>/dev/null; then
            spinner_stop
            ok "Downloaded HTMX  ${DIM}($(wc -c < "$htmx_path") bytes)${NC}"
        else
            spinner_stop
            # Try to copy from source if bundled
            if [[ -f "$SCRIPT_DIR/static/js/htmx.min.js" ]] &&                [[ -s "$SCRIPT_DIR/static/js/htmx.min.js" ]]; then
                cp "$SCRIPT_DIR/static/js/htmx.min.js" "$htmx_path"
                ok "Installed HTMX from package"
            else
                warn "Could not download HTMX — interactive table features will be disabled"
            fi
        fi
    else
        ok "HTMX already installed"
    fi

    spinner_start "Setting permissions..."
    chown -R "$JEN_USER:$JEN_USER" "$INSTALL_DIR" "$CONFIG_DIR"
    spinner_stop
    ok "Permissions set  ${DIM}(owner: ${JEN_USER})${NC}"
    blank
}

# ── Start service ─────────────────────────────────────────────────────────────
start_service() {
    blank
    echo -e "  ${B}${C}STARTING SERVICE${NC}"
    divider
    blank

    systemctl daemon-reload

    if [[ "$IS_UPGRADE" == "true" || "$MODE_REPAIR" == "true" ]]; then
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
        [[ "$IS_UPGRADE" == "true" ]] && rollback
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
    tpl_result=$(python3 -c "
from jinja2 import Environment, FileSystemLoader
import os, sys
env = Environment(loader=FileSystemLoader('$INSTALL_DIR/templates'))
errors = []
for t in os.listdir('$INSTALL_DIR/templates'):
    if t.endswith('.html'):
        try: env.get_template(t)
        except Exception as e: errors.append(f'{t}: {e}')
if errors:
    for e in errors: print(e)
    sys.exit(1)
else:
    print(len([f for f in os.listdir('$INSTALL_DIR/templates') if f.endswith('.html')]))
" 2>&1)
    if [[ $? -eq 0 ]]; then
        ok "Templates validated  ${DIM}(${tpl_result} files)${NC}"
    else
        err "Template validation failed:"; echo "$tpl_result"; exit 1
    fi

    # Modules
    if [[ -d "$INSTALL_DIR/jen" ]]; then
        local mod_result
        mod_result=$(python3 -c "
import sys; sys.path.insert(0, '$INSTALL_DIR')
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
        _box_line "  ${B}Login:${NC}  ${C}admin${NC}  /  ${Y}(password you set above)${NC}"
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
    ok "Docker Compose available"

    if [[ ! -f "./jen.config" ]]; then
        if [[ -f "./jen.config.example" ]]; then
            warn "jen.config not found in current directory"
            blank
            echo -e "    ${B}1)${NC}  Run guided setup wizard now"
            echo -e "    ${B}2)${NC}  Copy example and edit manually"
            blank
            local ch; ch=$(prompt_choice "1")
            if [[ "$ch" == "1" ]]; then
                IS_UPGRADE=false; CONFIGURE=true
                collect_config
                # write to ./jen.config
                cat > "./jen.config" << CONFEOF
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
                ok "jen.config written"
            else
                info "Copy jen.config.example to jen.config and edit it, then re-run."
                fatal "jen.config required for Docker install."
            fi
        else
            fatal "jen.config not found — copy jen.config.example to jen.config and edit it."
        fi
    else
        ok "jen.config found"
    fi

    blank
    echo -e "  ${B}Database Mode:${NC}"
    blank
    echo -e "    ${B}1)${NC}  External MySQL  ${DIM}(connect to existing server)${NC}"
    echo -e "    ${B}2)${NC}  Bundled MySQL   ${DIM}(Docker manages a local container)${NC}"
    blank
    local db_choice; db_choice=$(prompt_choice "1")
    local compose_file="docker-compose.yml"
    if [[ "$db_choice" == "2" ]]; then
        compose_file="docker-compose.mysql.yml"
        warn "Bundled MySQL: ensure [jen_db] host = jen-mysql in jen.config"
        [[ ! -f ".env" ]] && cp .env.example .env 2>/dev/null || true
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

    local server_ip
    server_ip=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server")
    blank
    echo -e "  ${C}╔══════════════════════════════════════════════════════╗${NC}"
    echo -e "  ${C}║${NC}  ${G}${B}  Jen Docker installation complete!${NC}                  ${C}║${NC}"
    echo -e "  ${C}╠══════════════════════════════════════════════════════╣${NC}"
    echo -e "  ${C}║${NC}  ${B}Access:${NC}  ${C}http://${server_ip}:5050${NC}                          ${C}║${NC}"
    echo -e "  ${C}║${NC}  ${B}Login:${NC}   admin / admin  ${Y}(change immediately!)${NC}       ${C}║${NC}"
    echo -e "  ${C}║${NC}                                                      ${C}║${NC}"
    echo -e "  ${C}║${NC}  ${DIM}Logs:     docker compose -f ${compose_file} logs -f${NC}   ${C}║${NC}"
    echo -e "  ${C}║${NC}  ${DIM}Restart:  docker compose -f ${compose_file} restart jen${NC}${C}║${NC}"
    echo -e "  ${C}║${NC}  ${DIM}Stop:     docker compose -f ${compose_file} down${NC}       ${C}║${NC}"
    echo -e "  ${C}╚══════════════════════════════════════════════════════╝${NC}"
    echo ""
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

    # Handle --repair mode
    if [[ "$MODE_REPAIR" == "true" ]]; then
        detect_existing
        show_mode_banner
        preflight_checks
        install_dependencies
        CONFIGURE=false
        backup_existing
        install_files
        start_service
        verify_install
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
            { info "Upgrade cancelled."; exit 0; }
    fi

    preflight_checks
    install_dependencies
    collect_config
    backup_existing
    install_files
    write_config
    start_service
    verify_install
    print_summary
}

trap 'spinner_stop; err "Installer interrupted."; rollback; exit 1' INT TERM
trap 'spinner_stop' EXIT

main "$@"
