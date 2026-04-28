#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
#  Jen - The Kea DHCP Management Console
#  Uninstaller
#  Copyright (C) 2026 Matthew Thibodeau — GPLv3
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

INSTALL_DIR="/opt/jen"
CONFIG_DIR="/etc/jen"
SERVICE_FILE="/etc/systemd/system/jen.service"
SUDOERS_FILE="/etc/sudoers.d/jen"

# ── ANSI colours ──────────────────────────────────────────────────────────────
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
C='\033[0;36m'
B='\033[1m'
DIM='\033[2m'
NC='\033[0m'

ok()    { echo -e "  ${G}[  OK  ]${NC}  $*"; }
info()  { echo -e "  ${C}[ INFO ]${NC}  $*"; }
warn()  { echo -e "  ${Y}[ WARN ]${NC}  $*"; }
err()   { echo -e "  ${R}[ FAIL ]${NC}  $*"; }
fatal() { echo -e "  ${R}[FATAL ]${NC}  $*"; exit 1; }
blank() { echo ""; }
divider() { echo -e "  ${DIM}${R}$(printf '─%.0s' {1..54})${NC}"; }

# ── Root check ────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || fatal "Must run as root — sudo ./uninstall.sh"

# ── Banner ────────────────────────────────────────────────────────────────────
clear
echo ""
echo -e "  ${R}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "  ${R}║${NC}                                                      ${R}║${NC}"
echo -e "  ${R}║${NC}  ${B}\033[41m  J E N  \033[0m${NC}  ${B}The Kea DHCP Management Console${NC}         ${R}║${NC}"
echo -e "  ${R}║${NC}                                                      ${R}║${NC}"
echo -e "  ${R}║${NC}  ${DIM}Uninstaller${NC}                                          ${R}║${NC}"
echo -e "  ${R}║${NC}                                                      ${R}║${NC}"
echo -e "  ${R}╚══════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Check installation exists ─────────────────────────────────────────────────
if [[ ! -d "$INSTALL_DIR" && ! -f "$SERVICE_FILE" ]]; then
    warn "Jen does not appear to be installed — nothing to remove."
    exit 0
fi

# ── Detect installed version ──────────────────────────────────────────────────
INSTALLED_VER="unknown"
for f in "$INSTALL_DIR/run.py" "$INSTALL_DIR/jen.py"; do
    if [[ -f "$f" ]]; then
        INSTALLED_VER=$(grep -m1 'JEN_VERSION' "$f" 2>/dev/null \
            | grep -oP '"[\d\.]+"' | tr -d '"' || echo "unknown")
        break
    fi
done

# ── What's installed ──────────────────────────────────────────────────────────
blank
echo -e "  ${B}${C}INSTALLED COMPONENTS${NC}"
divider
blank

[[ -d  "$INSTALL_DIR"        ]] && info "App files:       $INSTALL_DIR" \
                                 || info "App files:       ${DIM}not found${NC}"
[[ -f  "$SERVICE_FILE"       ]] && info "Systemd service: $SERVICE_FILE" \
                                 || info "Systemd service: ${DIM}not found${NC}"
[[ -f  "$SUDOERS_FILE"       ]] && info "Sudoers entry:   $SUDOERS_FILE" \
                                 || info "Sudoers entry:   ${DIM}not found${NC}"
blank

echo -e "  ${B}${C}PRESERVED BY DEFAULT${NC}"
divider
blank
info "Config file:   ${CONFIG_DIR}/jen.config"
info "SSL certs:     ${CONFIG_DIR}/ssl/"
info "SSH keys:      ${CONFIG_DIR}/ssh/"
info "Backups:       ${CONFIG_DIR}/backups/"
blank
echo -e "  ${DIM}These are kept so you can reinstall without losing your setup.${NC}"
echo -e "  ${DIM}You can optionally remove them too — you'll be asked below.${NC}"
blank

# ── Service status ────────────────────────────────────────────────────────────
echo -e "  ${B}${C}CURRENT STATUS${NC}"
divider
blank
if systemctl is-active --quiet jen 2>/dev/null; then
    info "Jen v${INSTALLED_VER} is currently ${G}running${NC}"
else
    info "Jen v${INSTALLED_VER} is currently ${Y}stopped${NC}"
fi
blank

# ── Confirm removal ───────────────────────────────────────────────────────────
echo -e "  ${B}${R}CONFIRM UNINSTALL${NC}"
divider
blank
printf "  ${Y}  ▸${NC} Uninstall Jen v${INSTALLED_VER}? [y/N]: "
read -r CONFIRM
if [[ "${CONFIRM,,}" != "y" && "${CONFIRM,,}" != "yes" ]]; then
    info "Uninstall cancelled."
    exit 0
fi

# ── Remove config too? ────────────────────────────────────────────────────────
blank
echo -e "  ${B}Config + data removal:${NC}"
blank
echo -e "    ${B}1)${NC}  Remove app only  ${DIM}(keep config, certs, keys, backups)${NC}  ${G}← recommended${NC}"
echo -e "    ${B}2)${NC}  Remove app + config  ${DIM}(keep certs, keys, backups)${NC}"
echo -e "    ${B}3)${NC}  Remove everything  ${R}(wipe all Jen data — irreversible)${NC}"
blank
printf "  ${Y}  ▸${NC} Choice [1]: "
read -r REMOVAL_LEVEL
REMOVAL_LEVEL="${REMOVAL_LEVEL:-1}"
blank

# Extra confirmation for full wipe
if [[ "$REMOVAL_LEVEL" == "3" ]]; then
    echo -e "  ${R}${B}WARNING: This permanently deletes all Jen data.${NC}"
    blank
    printf "  ${Y}  ▸${NC} Type ${B}DELETE${NC} to confirm full removal: "
    read -r DELETE_CONFIRM
    if [[ "$DELETE_CONFIRM" != "DELETE" ]]; then
        warn "Full removal cancelled — downgrading to app-only removal."
        REMOVAL_LEVEL="1"
    fi
fi

blank
echo -e "  ${B}${C}REMOVING JEN${NC}"
divider
blank

# ── Stop and disable service ──────────────────────────────────────────────────
if systemctl is-active --quiet jen 2>/dev/null; then
    systemctl stop jen
    ok "Service stopped"
fi
if systemctl is-enabled --quiet jen 2>/dev/null; then
    systemctl disable jen
    ok "Service disabled"
fi

# ── Remove service file ───────────────────────────────────────────────────────
if [[ -f "$SERVICE_FILE" ]]; then
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload
    ok "Removed systemd service"
fi

# ── Remove sudoers ────────────────────────────────────────────────────────────
if [[ -f "$SUDOERS_FILE" ]]; then
    rm -f "$SUDOERS_FILE"
    ok "Removed sudoers entry"
fi

# ── Remove app files ──────────────────────────────────────────────────────────
if [[ -d "$INSTALL_DIR" ]]; then
    rm -rf "$INSTALL_DIR"
    ok "Removed app directory  ${DIM}(${INSTALL_DIR})${NC}"
fi

# ── Level 2: remove config ────────────────────────────────────────────────────
if [[ "$REMOVAL_LEVEL" == "2" ]]; then
    if [[ -f "${CONFIG_DIR}/jen.config" ]]; then
        local bak="${CONFIG_DIR}/jen.config.removed.$(date +%Y%m%d_%H%M%S)"
        cp "${CONFIG_DIR}/jen.config" "$bak"
        rm -f "${CONFIG_DIR}/jen.config"
        ok "Removed jen.config  ${DIM}(backup saved: ${bak})${NC}"
    fi
    ok "SSL certs, SSH keys, and backups preserved  ${DIM}(${CONFIG_DIR})${NC}"
fi

# ── Level 3: remove everything ────────────────────────────────────────────────
if [[ "$REMOVAL_LEVEL" == "3" ]]; then
    rm -rf "$CONFIG_DIR"
    ok "Removed all Jen data  ${DIM}(${CONFIG_DIR})${NC}"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
blank
echo -e "  ${R}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "  ${R}║${NC}  ${B}Jen has been uninstalled.${NC}                             ${R}║${NC}"
echo -e "  ${R}╠══════════════════════════════════════════════════════╣${NC}"

case "$REMOVAL_LEVEL" in
    1)
        echo -e "  ${R}║${NC}  ${DIM}Config + keys preserved at: ${CONFIG_DIR}${NC}          ${R}║${NC}"
        echo -e "  ${R}║${NC}  ${DIM}To reinstall: sudo ./install.sh${NC}                    ${R}║${NC}"
        echo -e "  ${R}║${NC}  ${DIM}Your existing config will be detected automatically.${NC}${R}║${NC}" ;;
    2)
        echo -e "  ${R}║${NC}  ${DIM}SSL certs + SSH keys preserved at: ${CONFIG_DIR}${NC}   ${R}║${NC}"
        echo -e "  ${R}║${NC}  ${DIM}To reinstall: sudo ./install.sh${NC}                    ${R}║${NC}" ;;
    3)
        echo -e "  ${R}║${NC}  ${DIM}All Jen data has been removed.${NC}                     ${R}║${NC}"
        echo -e "  ${R}║${NC}  ${DIM}To reinstall: sudo ./install.sh (fresh setup)${NC}      ${R}║${NC}" ;;
esac

echo -e "  ${R}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
