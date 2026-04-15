#!/bin/bash
# Jen - The Kea DHCP Management Console
# Copyright (C) 2026 Matthew Thibodeau
# Licensed under GNU General Public License v3
# https://www.gnu.org/licenses/gpl-3.0.txt
# ─────────────────────────────────────────────────────────────────────────────
# Jen - The Kea DHCP Management Console
# Uninstaller
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

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
prompt()  { echo -e "${YELLOW}▶${NC}  $*"; }

INSTALL_DIR="/opt/jen"
CONFIG_DIR="/etc/jen"
SERVICE_FILE="/etc/systemd/system/jen.service"
SUDOERS_FILE="/etc/sudoers.d/jen"

if [[ $EUID -ne 0 ]]; then
    fatal "This uninstaller must be run as root. Use: sudo ./uninstall.sh"
fi

clear
echo -e "${BOLD}${RED}"
echo "  ╔════════════════════════════════════════╗"
echo "  ║   Jen - The Kea DHCP Management Console ║"
echo "  ║   Uninstaller                           ║"
echo "  ╚════════════════════════════════════════╝"
echo -e "${NC}"

# Check if installed
if [[ ! -f "$INSTALL_DIR/jen.py" && ! -f "$SERVICE_FILE" ]]; then
    warn "Jen does not appear to be installed. Nothing to remove."
    exit 0
fi

echo ""
echo -e "  ${BOLD}This will remove:${NC}"
echo -e "  • Jen application files ($INSTALL_DIR)"
echo -e "  • Systemd service"
echo -e "  • Sudoers entry"
echo ""
echo -e "  ${BOLD}This will NOT remove:${NC}"
echo -e "  • /etc/jen/jen.config  (your configuration)"
echo -e "  • /etc/jen/jen.db      (SQLite user database, if present)"
echo -e "  • /etc/jen/ssl/        (your SSL certificates)"
echo -e "  • /etc/jen/ssh/        (your SSH keys)"
echo -e "  • /etc/jen/backups/    (your backups)"
echo ""
echo -e "  ${YELLOW}These are preserved so you can reinstall without losing your setup.${NC}"
echo -e "  ${YELLOW}To remove them too, answer yes to the full removal question below.${NC}"
echo ""

prompt "Are you sure you want to uninstall Jen? [y/N]: "
read -r CONFIRM
if [[ "${CONFIRM,,}" != "y" && "${CONFIRM,,}" != "yes" ]]; then
    info "Uninstall cancelled."
    exit 0
fi

echo ""
prompt "Also remove all config, certificates, and user data? [y/N]: "
read -r REMOVE_ALL
REMOVE_ALL="${REMOVE_ALL,,}"

echo ""

# Stop and disable service
if systemctl is-active --quiet jen 2>/dev/null; then
    info "Stopping Jen service..."
    systemctl stop jen
    success "Service stopped."
fi

if systemctl is-enabled --quiet jen 2>/dev/null; then
    info "Disabling Jen service..."
    systemctl disable jen
    success "Service disabled."
fi

# Remove service file
if [[ -f "$SERVICE_FILE" ]]; then
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    success "Removed systemd service."
fi

# Remove sudoers
if [[ -f "$SUDOERS_FILE" ]]; then
    rm -f "$SUDOERS_FILE"
    success "Removed sudoers entry."
fi

# Remove application files
if [[ -d "$INSTALL_DIR" ]]; then
    rm -rf "$INSTALL_DIR"
    success "Removed application directory ($INSTALL_DIR)."
fi

# Remove config if requested
if [[ "$REMOVE_ALL" == "y" || "$REMOVE_ALL" == "yes" ]]; then
    echo ""
    echo -e "  ${RED}${BOLD}WARNING: This will permanently delete all Jen data including:${NC}"
    echo -e "  • Configuration file (jen.config)"
    echo -e "  • SSL certificates"
    echo -e "  • SSH keys"
    echo -e "  • Backups"
    echo ""
    prompt "Type 'DELETE' to confirm complete removal: "
    read -r DELETE_CONFIRM
    if [[ "$DELETE_CONFIRM" == "DELETE" ]]; then
        rm -rf "$CONFIG_DIR"
        success "Removed all Jen data ($CONFIG_DIR)."
    else
        warn "Full removal cancelled. Config files preserved at $CONFIG_DIR."
    fi
else
    success "Config and data preserved at $CONFIG_DIR."
fi

echo ""
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BOLD}${GREEN}  Jen has been uninstalled.${NC}"
echo -e "${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
if [[ "$REMOVE_ALL" != "y" && "$REMOVE_ALL" != "yes" ]]; then
    info "To reinstall, run: sudo ./install.sh"
    info "Your existing config at $CONFIG_DIR will be detected automatically."
fi
echo ""
