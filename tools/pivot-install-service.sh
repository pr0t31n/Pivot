#!/usr/bin/env bash
# =============================================================================
# tools/install_agent_service.sh
#
# Installs the Pivot agent as a systemd service on the relay device.
# Must be run as root on the relay device after `pip install .`.
#
# Usage:
#   sudo bash tools/install_agent_service.sh [CONFIG_FILE]
#
# Default CONFIG_FILE: /etc/pivot/agent_config.yaml
# =============================================================================

set -euo pipefail

info() { echo "[INFO]  $*"; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "This script must be run as root."
command -v systemctl >/dev/null 2>&1 || die "systemd not found."
command -v pivot-agent >/dev/null 2>&1 || die "'pivot-agent' command not found. Run: pip install . first."

CONFIG_FILE="${1:-/etc/pivot/agent_config.yaml}"
AGENT_BIN="$(command -v pivot-agent)"
SERVICE_FILE="/etc/systemd/system/pivot-agent.service"
LOG_DIR="/var/log/pivot"

# --- Create directories ------------------------------------------------------
info "Creating config and log directories..."
mkdir -p "$(dirname "$CONFIG_FILE")" "$LOG_DIR"
chmod 750 "$LOG_DIR"

# --- Install example config if no config present ----------------------------
if [[ ! -f "$CONFIG_FILE" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    EXAMPLE="$SCRIPT_DIR/../config/agent_config.yaml.example"
    if [[ -f "$EXAMPLE" ]]; then
        cp "$EXAMPLE" "$CONFIG_FILE"
        info "Installed example config to $CONFIG_FILE"
        info "IMPORTANT: Edit $CONFIG_FILE before starting the service!"
    else
        die "No config found at $CONFIG_FILE and no example to copy. Create it manually."
    fi
else
    info "Using existing config: $CONFIG_FILE"
fi

# --- Write systemd unit file -------------------------------------------------
info "Writing systemd service to $SERVICE_FILE..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Pivot Agent
Documentation=https://github.com/your-org/pivot
After=network-online.target openvpn.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${AGENT_BIN} --config ${CONFIG_FILE}
Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${LOG_DIR} /run /proc/sys/net/ipv4/ip_forward
# iptables/sysctl require CAP_NET_ADMIN; raw sockets require CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW

StandardOutput=journal
StandardError=journal
SyslogIdentifier=pivot-agent

[Install]
WantedBy=multi-user.target
EOF

# --- Enable and start --------------------------------------------------------
info "Reloading systemd daemon..."
systemctl daemon-reload

info "Enabling service (auto-start on boot)..."
systemctl enable pivot-agent.service

info ""
info "Service installed successfully."
info "To start now:    sudo systemctl start pivot-agent"
info "To check status: sudo systemctl status pivot-agent"
info "To view logs:    sudo journalctl -u pivot-agent -f"
info ""
info "Remember to edit $CONFIG_FILE before starting!"
