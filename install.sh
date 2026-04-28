#!/bin/bash
# Jen - The Kea DHCP Management Console
# Copyright (C) 2026 Matthew Thibodeau
# Licensed under GNU General Public License v3
# https://www.gnu.org/licenses/gpl-3.0.txt
# ─────────────────────────────────────────────────────────────────────────────
# Jen - The Kea DHCP Management Console
# Installer / Upgrader
# Supports: Ubuntu 22.04, Ubuntu 24.04
# Usage:
#   ./install.sh          - Interactive install or upgrade
#   ./install.sh --unattended  - Skip prompts, use defaults (upgrade only)
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

# ─────────────────────────────────────────
# Colors and formatting
# ─────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }
fatal()   { echo -e "${RED}[FATAL]${NC} $*"; exit 1; }
header()  { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${NC}\n"; }
prompt()  { echo -e "${YELLOW}▶${NC}  $*"; }

# ─────────────────────────────────────────
# Constants
# ─────────────────────────────────────────
JEN_VERSION="2.5.10"
INSTALL_DIR="/opt/jen"
CONFIG_DIR="/etc/jen"
SERVICE_FILE="/etc/systemd/system/jen.service"
SUDOERS_FILE="/etc/sudoers.d/jen"
CONFIG_FILE="/etc/jen/jen.config"
BACKUP_DIR="/etc/jen/backups"
JEN_USER="www-data"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

UNATTENDED=false
if [[ "${1:-}" == "--unattended" ]]; then
    UNATTENDED=true
fi

# ─────────────────────────────────────────
# Helper: require root
# ─────────────────────────────────────────
require_root() {
    if [[ $EUID -ne 0 ]]; then
        fatal "This installer must be run as root. Use: sudo ./install.sh"
    fi
}

# ─────────────────────────────────────────
# Helper: yes/no prompt
# ─────────────────────────────────────────
ask_yes_no() {
    local question="$1"
    local default="${2:-y}"
    local answer
    if [[ "$UNATTENDED" == "true" ]]; then
        echo "$default"
        return
    fi
    while true; do
        if [[ "$default" == "y" ]]; then
            echo -e "${YELLOW}▶${NC}  $question [Y/n]: " > /dev/tty
        else
            echo -e "${YELLOW}▶${NC}  $question [y/N]: " > /dev/tty
        fi
        read -r answer < /dev/tty
        answer="${answer:-$default}"
        case "${answer,,}" in
            y|yes) echo "y"; return ;;
            n|no)  echo "n"; return ;;
            *) warn "Please answer yes or no." ;;
        esac
    done
}

# ─────────────────────────────────────────
# Helper: read with default
# ─────────────────────────────────────────
ask_value() {
    local question="$1"
    local default="$2"
    local answer
    if [[ "$UNATTENDED" == "true" ]]; then
        echo "$default"
        return
    fi
    echo -e "${YELLOW}▶${NC}  $question [${default}]: " > /dev/tty
    read -r answer < /dev/tty
    echo "${answer:-$default}"
}

ask_secret() {
    local question="$1"
    local answer
    echo -e "${YELLOW}▶${NC}  $question: " > /dev/tty
    read -rs answer < /dev/tty
    echo "" > /dev/tty
    echo "$answer"
}

# ─────────────────────────────────────────
# Pre-flight checks
# ─────────────────────────────────────────
preflight_checks() {
    header "Pre-flight Checks"
    local failed=0

    # OS check
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" == "ubuntu" ]]; then
            case "$VERSION_ID" in
                22.04|24.04)
                    success "OS: Ubuntu $VERSION_ID ✓" ;;
                *)
                    warn "OS: Ubuntu $VERSION_ID — not officially tested. Proceeding anyway." ;;
            esac
        else
            warn "OS: $PRETTY_NAME — not officially supported. Proceeding anyway."
        fi
    else
        warn "Could not detect OS. Proceeding anyway."
    fi

    # Root check
    if [[ $EUID -eq 0 ]]; then
        success "Running as root ✓"
    else
        error "Not running as root ✗"
        failed=$((failed + 1))
    fi

    # Python check
    if command -v python3 &>/dev/null; then
        PYTHON_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)' 2>/dev/null; then
            success "Python $PYTHON_VER ✓"
        else
            error "Python $PYTHON_VER found but 3.10+ required ✗"
            failed=$((failed + 1))
        fi
    else
        error "Python3 not found ✗"
        failed=$((failed + 1))
    fi

    # pip check
    if command -v pip3 &>/dev/null || python3 -m pip --version &>/dev/null 2>&1; then
        success "pip3 available ✓"
    else
        warn "pip3 not found — will attempt to install."
    fi

    # systemd check
    if command -v systemctl &>/dev/null; then
        success "systemd available ✓"
    else
        error "systemd not found — required for service management ✗"
        failed=$((failed + 1))
    fi

    # ssh-keygen check
    if command -v ssh-keygen &>/dev/null; then
        success "ssh-keygen available ✓"
    else
        warn "ssh-keygen not found — will attempt to install openssh-client."
    fi

    # openssl check
    if command -v openssl &>/dev/null; then
        success "openssl available ✓"
    else
        warn "openssl not found — HTTPS cert info in Settings will not display."
    fi

    # Disk space check (need at least 100MB)
    AVAIL_KB=$(df /opt 2>/dev/null | awk 'NR==2{print $4}' || echo "0")
    if [[ $AVAIL_KB -gt 102400 ]]; then
        success "Disk space: $(( AVAIL_KB / 1024 ))MB available ✓"
    else
        warn "Low disk space: $(( AVAIL_KB / 1024 ))MB available. Recommend at least 100MB."
    fi

    if [[ $failed -gt 0 ]]; then
        echo ""
        fatal "$failed pre-flight check(s) failed. Fix the above issues and re-run the installer."
    fi

    success "All required pre-flight checks passed."
}

# ─────────────────────────────────────────
# Detect existing installation
# ─────────────────────────────────────────
detect_existing() {
    EXISTING_VERSION=""
    IS_UPGRADE=false

    if [[ -f "$INSTALL_DIR/jen.py" ]]; then
        IS_UPGRADE=true
        EXISTING_VERSION=$(grep -m1 'JEN_VERSION' "$INSTALL_DIR/jen.py" 2>/dev/null | grep -oP '"[\d\.]+"' | tr -d '"' || echo "unknown")
        info "Existing Jen installation detected (v${EXISTING_VERSION})."
    fi
}

# ─────────────────────────────────────────
# Install system dependencies
# ─────────────────────────────────────────
install_dependencies() {
    header "Installing Dependencies"

    info "Updating package lists..."
    apt-get update -qq

    PKGS=()
    command -v pip3 &>/dev/null || PKGS+=(python3-pip)
    command -v mysql &>/dev/null || PKGS+=(mariadb-client-core)
    command -v ssh-keygen &>/dev/null || PKGS+=(openssh-client)
    command -v openssl &>/dev/null || PKGS+=(openssl)

    if [[ ${#PKGS[@]} -gt 0 ]]; then
        info "Installing: ${PKGS[*]}"
        apt-get install -y -qq "${PKGS[@]}"
        success "System packages installed."
    else
        success "All system packages already present."
    fi

    info "Checking Python packages..."
    MISSING_PKGS=()
    for pkg in flask flask_login pymysql requests pyotp qrcode authlib; do
        python3 -c "import ${pkg}" 2>/dev/null || MISSING_PKGS+=("${pkg/-/_}")
    done

    if [[ ${#MISSING_PKGS[@]} -gt 0 ]]; then
        info "Installing missing packages: ${MISSING_PKGS[*]}"
        pip3 install -q flask flask-login pymysql requests "pyotp" "qrcode[pil]" "authlib" --break-system-packages 2>/dev/null || \
        pip3 install -q flask flask-login pymysql requests pyotp "qrcode[pil]" authlib
        success "Python packages installed."
    else
        success "Python packages already installed."
    fi
}

# ─────────────────────────────────────────
# Test Kea API connectivity
# ─────────────────────────────────────────
test_kea_api() {
    local url="$1" user="$2" pass="$3"
    local result
    result=$(curl -s -u "${user}:${pass}" -X POST "${url}/" \
        -H "Content-Type: application/json" \
        -d '{"command":"version-get","service":["dhcp4"]}' \
        --connect-timeout 5 2>/dev/null || echo "CONN_FAILED")
    if echo "$result" | grep -q '"result": 0'; then
        return 0
    fi
    return 1
}

# ─────────────────────────────────────────
# Test MySQL connectivity
# ─────────────────────────────────────────
test_mysql() {
    local host="$1" user="$2" pass="$3" db="$4"
    mysql -h"$host" -u"$user" -p"$pass" "$db" -e "SELECT 1;" &>/dev/null 2>&1
}

# ─────────────────────────────────────────
# Collect configuration
# ─────────────────────────────────────────
collect_config() {
    header "Configuration"

    if [[ "$IS_UPGRADE" == "true" && -f "$CONFIG_FILE" ]]; then
        echo ""
        info "Existing config found at $CONFIG_FILE"
        echo ""
        echo -e "  ${BOLD}1)${NC} Keep existing config ${GREEN}(recommended)${NC}"
        echo -e "  ${BOLD}2)${NC} Configure now (reconfigure all values)"
        echo -e "  ${BOLD}3)${NC} Skip config (keep existing, continue with upgrade)"
        echo ""
        echo -e "${YELLOW}▶${NC}  Choice [1]: " > /dev/tty
        read -r CONFIG_CHOICE < /dev/tty
        CONFIG_CHOICE="${CONFIG_CHOICE:-1}"

        case "$CONFIG_CHOICE" in
            1|3)
                success "Keeping existing configuration."
                CONFIGURE=false
                return ;;
            2)
                warn "This will overwrite your existing configuration."
                if [[ "$(ask_yes_no "Are you sure you want to reconfigure?" "n")" == "n" ]]; then
                    success "Keeping existing configuration."
                    CONFIGURE=false
                    return
                fi
                CONFIGURE=true ;;
            *)
                success "Keeping existing configuration."
                CONFIGURE=false
                return ;;
        esac
    else
        CONFIGURE=true
    fi

    echo ""
    info "Let's configure Jen. Press Enter to accept defaults shown in brackets."
    echo ""

    # ── Kea API ──
    echo -e "${BOLD}Kea Control Agent API${NC}"
    KEA_API_URL=$(ask_value  "  Kea API URL"  "http://YOUR-KEA-SERVER:8000")
    KEA_API_USER=$(ask_value "  Kea API user" "kea-api")
    KEA_API_PASS=$(ask_secret "  Kea API password")

    echo ""
    info "Testing Kea API connection..."
    if test_kea_api "$KEA_API_URL" "$KEA_API_USER" "$KEA_API_PASS"; then
        success "Kea API connection successful ✓"
    else
        warn "Could not connect to Kea API. Check URL and credentials."
        warn "You can edit $CONFIG_FILE after installation to fix this."
    fi

    # ── Kea DB ──
    echo ""
    echo -e "${BOLD}Kea MySQL Database${NC}"
    KEA_DB_HOST=$(ask_value "  Host"     "YOUR-KEA-SERVER")
    KEA_DB_USER=$(ask_value "  User"     "kea")
    KEA_DB_PASS=$(ask_secret "  Password")
    KEA_DB_NAME=$(ask_value "  Database" "kea")

    echo ""
    info "Testing Kea database connection..."
    if test_mysql "$KEA_DB_HOST" "$KEA_DB_USER" "$KEA_DB_PASS" "$KEA_DB_NAME"; then
        success "Kea database connection successful ✓"
    else
        warn "Could not connect to Kea database. Check credentials and ensure remote access is enabled."
        warn "You can edit $CONFIG_FILE after installation to fix this."
    fi

    # ── Jen DB ──
    echo ""
    echo -e "${BOLD}Jen MySQL Database${NC}"
    info "Jen needs its own MySQL database for users, audit log, and settings."
    JEN_DB_HOST=$(ask_value "  Host"     "$KEA_DB_HOST")
    JEN_DB_USER=$(ask_value "  User"     "jen")
    JEN_DB_PASS=$(ask_secret "  Password")
    JEN_DB_NAME=$(ask_value "  Database" "jen")

    echo ""
    info "Testing Jen database connection..."
    if test_mysql "$JEN_DB_HOST" "$JEN_DB_USER" "$JEN_DB_PASS" "$JEN_DB_NAME"; then
        success "Jen database connection successful ✓"
    else
        warn "Could not connect to Jen database."
        echo ""
        echo -e "  To create it, run on your MySQL server:"
        echo -e "  ${CYAN}CREATE DATABASE ${JEN_DB_NAME};${NC}"
        echo -e "  ${CYAN}CREATE USER '${JEN_DB_USER}'@'localhost' IDENTIFIED BY 'yourpassword';${NC}"
        echo -e "  ${CYAN}CREATE USER '${JEN_DB_USER}'@'$(hostname -I | awk '{print $1}')' IDENTIFIED BY 'yourpassword';${NC}"
        echo -e "  ${CYAN}GRANT ALL PRIVILEGES ON ${JEN_DB_NAME}.* TO '${JEN_DB_USER}'@'localhost';${NC}"
        echo -e "  ${CYAN}GRANT ALL PRIVILEGES ON ${JEN_DB_NAME}.* TO '${JEN_DB_USER}'@'$(hostname -I | awk '{print $1}')';${NC}"
        echo -e "  ${CYAN}FLUSH PRIVILEGES;${NC}"
        echo ""
        warn "You can edit $CONFIG_FILE after installation to fix this."
    fi

    # ── Subnets ──
    echo ""
    echo -e "${BOLD}Subnet Map${NC}"
    info "Enter your Kea subnets (Kea subnet ID, friendly name, CIDR)."
    info "Press Enter with no subnet ID to finish."
    SUBNET_LINES=""
    while true; do
        prompt "  Subnet ID (or Enter to finish): "
        read -r SID
        [[ -z "$SID" ]] && break
        if ! [[ "$SID" =~ ^[0-9]+$ ]]; then
            warn "Subnet ID must be a number."; continue
        fi
        SNAME=$(ask_value "  Friendly name" "Subnet${SID}")
        SCIDR=$(ask_value "  CIDR" "192.168.${SID}.0/24")
        SUBNET_LINES="${SUBNET_LINES}${SID} = ${SNAME}, ${SCIDR}\n"
        success "  Added: $SID = $SNAME, $SCIDR"
        echo ""
    done
    if [[ -z "$SUBNET_LINES" ]]; then
        warn "No subnets configured. Edit $CONFIG_FILE to add subnets after install."
        SUBNET_LINES="# 1 = Production, 192.168.1.0/24\n# 30 = IoT, 192.168.30.0/24\n"
    fi

    # ── SSH for subnet editing ──
    echo ""
    echo -e "${BOLD}SSH (for subnet editing — optional)${NC}"
    if [[ "$(ask_yes_no "  Configure SSH access to Kea server for subnet editing?" "y")" == "y" ]]; then
        KEA_SSH_HOST=$(ask_value "  Kea server SSH host" "$KEA_DB_HOST")
        KEA_SSH_USER=$(ask_value "  SSH username" "$(logname 2>/dev/null || echo 'ubuntu')")
        KEA_CONF_PATH=$(ask_value "  Kea config file path" "/etc/kea/kea-dhcp4.conf")
    else
        KEA_SSH_HOST=""
        KEA_SSH_USER=""
        KEA_CONF_PATH="/etc/kea/kea-dhcp4.conf"
    fi

    # ── DDNS ──
    echo ""
    echo -e "${BOLD}DDNS (Technitium — optional)${NC}"
    if [[ "$(ask_yes_no "  Configure Technitium DDNS integration?" "n")" == "y" ]]; then
        DDNS_LOG=$(ask_value  "  DDNS log path"    "/var/log/kea/kea-ddns-technitium.log")
        DDNS_URL=$(ask_value  "  Technitium API URL" "https://your-technitium-server/api")
        DDNS_TOKEN=$(ask_secret "  Technitium API token")
        DDNS_ZONE=$(ask_value  "  Forward zone"    "your.domain.com")
    else
        DDNS_LOG="/var/log/kea/kea-ddns-technitium.log"
        DDNS_URL=""
        DDNS_TOKEN=""
        DDNS_ZONE=""
    fi

    # ── Ports ──
    echo ""
    echo -e "${BOLD}Server Ports${NC}"
    HTTP_PORT=$(ask_value  "  HTTP port"  "5050")
    HTTPS_PORT=$(ask_value "  HTTPS port" "8443")
}

# ─────────────────────────────────────────
# Write config file
# ─────────────────────────────────────────
write_config() {
    if [[ "$CONFIGURE" == "false" ]]; then
        return
    fi

    header "Writing Configuration"

    mkdir -p "$CONFIG_DIR"

    # Backup existing config if present
    if [[ -f "$CONFIG_FILE" ]]; then
        BACKUP_PATH="${BACKUP_DIR}/jen.config.$(date +%Y%m%d_%H%M%S).bak"
        mkdir -p "$BACKUP_DIR"
        cp "$CONFIG_FILE" "$BACKUP_PATH"
        info "Backed up existing config to $BACKUP_PATH"
    fi

    cat > "$CONFIG_FILE" << CONFEOF
# Jen - The Kea DHCP Management Console
# Configuration file
# Generated by installer on $(date)

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
api_url     = ${DDNS_URL}
api_token   = ${DDNS_TOKEN}
forward_zone = ${DDNS_ZONE}
CONFEOF

    chown root:www-data "$CONFIG_FILE"
    chmod 640 "$CONFIG_FILE"
    success "Configuration written to $CONFIG_FILE"
}

# ─────────────────────────────────────────
# Backup existing installation
# ─────────────────────────────────────────
backup_existing() {
    if [[ "$IS_UPGRADE" == "false" ]]; then
        return
    fi

    header "Backing Up Existing Installation"

    mkdir -p "$BACKUP_DIR"
    BACKUP_TS=$(date +%Y%m%d_%H%M%S)

    if [[ -f "$INSTALL_DIR/jen.py" ]]; then
        cp "$INSTALL_DIR/jen.py" "${BACKUP_DIR}/jen.py.${BACKUP_TS}.bak"
        success "Backed up jen.py to ${BACKUP_DIR}/jen.py.${BACKUP_TS}.bak"
    fi

    ROLLBACK_JEN="${BACKUP_DIR}/jen.py.${BACKUP_TS}.bak"
    export ROLLBACK_JEN
}

# ─────────────────────────────────────────
# Rollback on failure
# ─────────────────────────────────────────
rollback() {
    if [[ -n "${ROLLBACK_JEN:-}" && -f "$ROLLBACK_JEN" ]]; then
        warn "Rolling back to previous jen.py..."
        cp "$ROLLBACK_JEN" "$INSTALL_DIR/jen.py"
        systemctl restart jen 2>/dev/null || true
        warn "Rollback complete. Previous version restored."
    fi
}

# ─────────────────────────────────────────
# Install files
# ─────────────────────────────────────────
install_files() {
    header "Installing Jen Files"

    # Create directories
    mkdir -p "$INSTALL_DIR/templates" "$INSTALL_DIR/static" \
             "$INSTALL_DIR/static/icons/brands" \
             "$INSTALL_DIR/static/icons/custom" \
             "$CONFIG_DIR/ssl" "$CONFIG_DIR/ssh"

    # Copy application files
    cp "$SCRIPT_DIR/jen.py" "$INSTALL_DIR/jen.py"
    success "Installed jen.py"

    cp -r "$SCRIPT_DIR/templates/." "$INSTALL_DIR/templates/"
    success "Installed templates ($(ls "$SCRIPT_DIR/templates/" | wc -l) files)"

    # Copy bundled brand icons (never overwrite custom icons)
    if [ -d "$SCRIPT_DIR/static/icons/brands" ]; then
        cp "$SCRIPT_DIR/static/icons/brands/"*.svg "$INSTALL_DIR/static/icons/brands/" 2>/dev/null || true
        success "Installed brand icons ($(ls "$INSTALL_DIR/static/icons/brands/" 2>/dev/null | wc -l) icons)"
    fi

    # Install service file
    cp "$SCRIPT_DIR/jen.service" "$SERVICE_FILE"
    success "Installed systemd service"

    # Install sudoers
    cp "$SCRIPT_DIR/jen-sudoers" "$SUDOERS_FILE"
    chmod 440 "$SUDOERS_FILE"
    success "Installed sudoers entry"

    # Set permissions
    chown -R "$JEN_USER:$JEN_USER" "$INSTALL_DIR" "$CONFIG_DIR"
    success "Set file permissions for $JEN_USER"
}

# ─────────────────────────────────────────
# Enable and start service
# ─────────────────────────────────────────
start_service() {
    header "Starting Jen Service"

    systemctl daemon-reload

    if [[ "$IS_UPGRADE" == "true" ]]; then
        info "Restarting Jen service..."
        systemctl restart jen
    else
        info "Enabling and starting Jen service..."
        systemctl enable jen
        systemctl start jen
    fi

    # Wait for startup
    sleep 3

    if systemctl is-active --quiet jen; then
        success "Jen service is running ✓"
    else
        error "Jen service failed to start."
        journalctl -u jen -n 20 --no-pager
        if [[ "$IS_UPGRADE" == "true" ]]; then
            rollback
        fi
        fatal "Installation failed. See logs above."
    fi
}

# ─────────────────────────────────────────
# Post-install verification
# ─────────────────────────────────────────
verify_install() {
    header "Verifying Installation"

    # Check service
    if systemctl is-active --quiet jen; then
        success "Service: running ✓"
    else
        error "Service: not running ✗"
        return 1
    fi

    # Check config file
    if [[ -f "$CONFIG_FILE" ]]; then
        success "Config: $CONFIG_FILE ✓"
    else
        warn "Config: $CONFIG_FILE not found — Jen may not start correctly."
    fi

    # Validate templates (Jinja parse check)
    TEMPLATE_ERRORS=$(python3 -c "
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
        success "Templates: $TEMPLATE_ERRORS files validated ✓"
    else
        error "Template validation failed:\n$TEMPLATE_ERRORS"
        warn "Rolling back installation..."
        # Rollback is handled by the outer error trap
        exit 1
    fi

    # Get port from config
    HTTP_P=$(grep -m1 "http_port" "$CONFIG_FILE" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' || echo "5050")
    HTTPS_P=$(grep -m1 "https_port" "$CONFIG_FILE" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' || echo "8443")

    # Test HTTP response
    sleep 1
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 \
        "http://localhost:${HTTP_P}/" 2>/dev/null || echo "000")
    if [[ "$HTTP_CODE" =~ ^[23] ]] || [[ "$HTTP_CODE" == "301" ]]; then
        success "HTTP response on port ${HTTP_P}: $HTTP_CODE ✓"
    else
        warn "HTTP response on port ${HTTP_P}: $HTTP_CODE — Jen may still be starting up."
    fi
}

# ─────────────────────────────────────────
# Print summary
# ─────────────────────────────────────────
print_summary() {
    local SERVER_IP
    SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server")
    local HTTP_P HTTPS_P
    HTTP_P=$(grep -m1 "http_port" "$CONFIG_FILE" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' || echo "5050")
    HTTPS_P=$(grep -m1 "https_port" "$CONFIG_FILE" 2>/dev/null | awk -F'=' '{print $2}' | tr -d ' ' || echo "8443")

    echo ""
    echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    if [[ "$IS_UPGRADE" == "true" ]]; then
        echo -e "${BOLD}${GREEN}  Jen v${JEN_VERSION} upgrade complete!${NC}"
    else
        echo -e "${BOLD}${GREEN}  Jen v${JEN_VERSION} installation complete!${NC}"
    fi
    echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${BOLD}Access Jen at:${NC}"
    echo -e "  ${CYAN}http://${SERVER_IP}:${HTTP_P}${NC}"
    echo ""
    echo -e "  ${BOLD}Default credentials:${NC}"
    if [[ "$IS_UPGRADE" == "false" ]]; then
        echo -e "  Username: ${CYAN}admin${NC}"
        echo -e "  Password: ${CYAN}admin${NC}"
        echo -e "  ${YELLOW}⚠ Change your password immediately after first login!${NC}"
    else
        echo -e "  Your existing user accounts are preserved."
    fi
    echo ""
    echo -e "  ${BOLD}Config file:${NC}  $CONFIG_FILE"
    echo -e "  ${BOLD}App directory:${NC} $INSTALL_DIR"
    echo -e "  ${BOLD}Logs:${NC}          sudo journalctl -u jen -f"
    echo ""
    if [[ "$IS_UPGRADE" == "false" ]]; then
        echo -e "  ${BOLD}Next steps:${NC}"
        echo -e "  1. Open Jen in your browser"
        echo -e "  2. Change the default admin password"
        echo -e "  3. Go to Settings → SSH Key Management to enable subnet editing"
        echo -e "  4. Configure Telegram alerts in Settings if desired"
        echo ""
    fi
    echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────
main() {
    clear
    echo -e "${BOLD}${CYAN}"
    echo "  ╔══════════════════════════════════════════════╗"
    echo "  ║   Jen - The Kea DHCP Management Console      ║"
    printf "  ║   Installer v%-32s║\\n" "${JEN_VERSION}"
    echo "  ╚══════════════════════════════════════════════╝"
    echo -e "${NC}"

    require_root
    preflight_checks

    # Ask install type
    echo ""
    echo -e "  ${BOLD}Install Type:${NC}"
    echo -e "  ${BOLD}1)${NC} Bare metal / systemd ${GREEN}(recommended)${NC}"
    echo -e "  ${BOLD}2)${NC} Docker"
    echo ""
    while true; do
        printf "${YELLOW}▶${NC}  Choice [1]: " > /dev/tty
        read -r INSTALL_TYPE < /dev/tty
        INSTALL_TYPE="${INSTALL_TYPE:-1}"
        if [[ "$INSTALL_TYPE" == "1" || "$INSTALL_TYPE" == "2" ]]; then
            break
        fi
        echo -e "  ${RED}Invalid choice. Please enter 1 or 2.${NC}" > /dev/tty
    done

    if [[ "$INSTALL_TYPE" == "2" ]]; then
        docker_install
        exit 0
    fi

    detect_existing

    if [[ "$IS_UPGRADE" == "true" ]]; then
        echo ""
        echo -e "  ${BOLD}Existing installation detected (v${EXISTING_VERSION})${NC}"
        echo ""
        if [[ "$(ask_yes_no "Upgrade to Jen v${JEN_VERSION}?" "y")" == "n" ]]; then
            info "Upgrade cancelled."
            exit 0
        fi
    fi

    install_dependencies
    collect_config
    backup_existing
    install_files
    write_config
    start_service
    verify_install
    print_summary
}

trap 'error "Installer interrupted."; rollback; exit 1' INT TERM

main "$@"

# ─────────────────────────────────────────
# Docker install path (appended)
# ─────────────────────────────────────────
docker_install() {
    header "Docker Installation"

    # Check Docker is installed
    if ! command -v docker &>/dev/null; then
        error "Docker is not installed."
        echo ""
        echo -e "  Install Docker first:"
        echo -e "  ${CYAN}curl -fsSL https://get.docker.com | sudo sh${NC}"
        exit 1
    fi
    success "Docker available: $(docker --version | cut -d' ' -f3 | tr -d ',')"

    if ! command -v docker &>/dev/null || ! docker compose version &>/dev/null 2>&1; then
        error "Docker Compose plugin not found."
        echo -e "  Install with: ${CYAN}sudo apt install docker-compose-plugin${NC}"
        exit 1
    fi
    success "Docker Compose available ✓"

    # Config file
    if [[ ! -f "./jen.config" ]]; then
        if [[ -f "./jen.config.example" ]]; then
            echo ""
            warn "jen.config not found in current directory."
            echo -e "  ${BOLD}Option 1:${NC} Copy and edit the example: ${CYAN}cp jen.config.example jen.config && nano jen.config${NC}"
            echo -e "  ${BOLD}Option 2:${NC} Run the guided config now"
            echo ""
            if [[ "$(ask_yes_no "Run guided config now?" "y")" == "y" ]]; then
                CONFIGURE=true
                IS_UPGRADE=false
                collect_config
                write_config_local
            else
                fatal "Please create jen.config before running Docker install."
            fi
        else
            fatal "jen.config not found. Copy jen.config.example to jen.config and edit it."
        fi
    else
        success "jen.config found ✓"
    fi

    # MySQL mode
    echo ""
    echo -e "  ${BOLD}Jen Database Mode:${NC}"
    echo -e "  ${BOLD}1)${NC} External MySQL — connect to an existing MySQL server"
    echo -e "  ${BOLD}2)${NC} Bundled MySQL — Docker manages a local MySQL container for Jen"
    echo ""
    while true; do
        printf "${YELLOW}▶${NC}  Choice [1]: " > /dev/tty
        read -r DB_CHOICE < /dev/tty
        DB_CHOICE="${DB_CHOICE:-1}"
        if [[ "$DB_CHOICE" == "1" || "$DB_CHOICE" == "2" ]]; then
            break
        fi
        echo -e "  ${RED}Invalid choice. Please enter 1 or 2.${NC}" > /dev/tty
    done

    local COMPOSE_FILE="docker-compose.yml"
    if [[ "$DB_CHOICE" == "2" ]]; then
        COMPOSE_FILE="docker-compose.mysql.yml"
        echo ""
        warn "Using bundled MySQL. Make sure jen.config [jen_db] host is set to: jen-mysql"
        if [[ ! -f ".env" ]]; then
            cp .env.example .env 2>/dev/null || true
            info "Created .env file — edit MYSQL passwords before starting."
        fi
    fi

    echo ""
    info "Building Jen Docker image..."
    docker compose -f "$COMPOSE_FILE" build

    info "Starting Jen..."
    docker compose -f "$COMPOSE_FILE" up -d

    sleep 5

    if docker ps | grep -q "jen"; then
        success "Jen container is running ✓"
    else
        error "Jen container failed to start."
        docker compose -f "$COMPOSE_FILE" logs --tail=20
        exit 1
    fi

    local SERVER_IP
    SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "your-server")

    echo ""
    echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}${GREEN}  Jen Docker installation complete!${NC}"
    echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
    echo -e "  ${BOLD}Access Jen at:${NC} ${CYAN}http://${SERVER_IP}:5050${NC}"
    echo -e "  ${BOLD}Default login:${NC} admin / admin"
    echo ""
    echo -e "  ${BOLD}Useful commands:${NC}"
    echo -e "  docker compose -f ${COMPOSE_FILE} logs -f     # view logs"
    echo -e "  docker compose -f ${COMPOSE_FILE} restart jen  # restart"
    echo -e "  docker compose -f ${COMPOSE_FILE} down         # stop"
    echo ""
    echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}

write_config_local() {
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
api_url     = ${DDNS_URL}
api_token   = ${DDNS_TOKEN}
forward_zone = ${DDNS_ZONE}
CONFEOF
    success "jen.config written."
}
