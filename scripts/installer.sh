#!/bin/bash

# install_env.sh
# Automates the setup of Toralizer environment on Debian/Ubuntu
# Installs dependencies and configures /etc/tor/torrc

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err() { echo -e "${RED}[ERROR]${NC} $1"; }

# Determine absolute path of the script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Project layout (assumes install_env.sh lives in /scripts)
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCRIPTS_DIR="$PROJECT_ROOT/scripts"
SRC_DIR="$PROJECT_ROOT/src"
BIN_DIR="$PROJECT_ROOT/bin"

if [ ! -d "$SRC_DIR" ]; then
    log_err "Source directory not found: $SRC_DIR"
    exit 1
fi

if [ ! -f "$SRC_DIR/toralizer.go" ]; then
    log_err "toralizer.go not found in $SRC_DIR"
    exit 1
fi

log_info "Script directory : $SCRIPT_DIR"
log_info "Project root    : $PROJECT_ROOT"


# 0. Read username argument
TARGET_USER="${1:-root}"

if [ "$TARGET_USER" != "root" ] && ! id "$TARGET_USER" &>/dev/null; then
    log_err "User '$TARGET_USER' does not exist."
    exit 1
fi

if [ "$TARGET_USER" = "root" ]; then
    BASHRC="/root/.bashrc"
else
    BASHRC="/home/$TARGET_USER/.bashrc"
fi

log_info "Using user: $TARGET_USER"

# 1. Check Root
if [ "$EUID" -ne 0 ]; then
    log_err "This script must be run as root."
    exit 1
fi

# 2. Update & Install Dependencies
log_info "Updating package lists..."
apt-get update

log_info "Installing dependencies (tor, nftables, iproute2, golang, curl)..."
apt-get install -y tor nftables iproute2 curl

log_info "Downloading go"
mkdir -p tmp
cd tmp
wget https://go.dev/dl/go1.25.5.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.25.5.linux-amd64.tar.gz
cd ..
rm -rf tmp

if ! grep -q "GOROOT=/usr/local/go/bin" "$BASHRC"; then
    echo 'export GOROOT=/usr/local/go/bin' >> "$BASHRC"
    log_info "Added GOROOT to $BASHRC"
else
    log_warn "GOROOT already present in $BASHRC"
fi


# 3. Configure Tor
TORRC="/etc/tor/torrc"
BACKUP_TORRC="/etc/tor/torrc.bak.$(date +%s)"

if [ -f "$TORRC" ]; then
    log_info "Backing up existing torrc to $BACKUP_TORRC"
    cp "$TORRC" "$BACKUP_TORRC"
else
    log_warn "$TORRC not found, creating new one."
    touch "$TORRC"
fi

# Check if configuration already exists to avoid duplication
if grep -q "Toralizer Configuration" "$TORRC"; then
    log_warn "Toralizer configuration block seems to already exist in $TORRC."
    log_warn "Skipping torrc modification. Please verify manually."
else
    log_info "Appending Toralizer configuration to $TORRC..."
    
    cat <<EOT >> "$TORRC"

# --- Toralizer Configuration ---
# Transparent Proxy Port (TCP)
TransPort 0.0.0.0:9040
# DNS Port (UDP)
DNSPort 0.0.0.0:9053
# Virtual Network for Onion Addresses
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
# Performance & Daemon settings
AvoidDiskWrites 1
RunAsDaemon 1
# -------------------------------
EOT
fi

# 4. Enable IPv4 Forwarding
SYSCTL_CONF="/etc/sysctl.d/99-toralizer.conf"
log_info "Enabling IPv4 forwarding..."

# Apply immediately
sysctl -w net.ipv4.ip_forward=1 > /dev/null

# Make persistent
echo "net.ipv4.ip_forward=1" > "$SYSCTL_CONF"
log_info "Forwarding enabled and saved to $SYSCTL_CONF"

# 5. Restart Tor Service
log_info "Restarting Tor service..."
systemctl restart tor
systemctl enable tor

# 6. Verify Tor Ports
sleep 2 # Wait for Tor to bind
if ss -nlt | grep -q ":9040"; then
    log_info "Tor is listening on TransPort 9040."
else
    log_err "Tor failed to bind to port 9040. Check 'journalctl -u tor'."
    exit 1
fi

if ss -nlu | grep -q ":9053"; then
    log_info "Tor is listening on DNSPort 9053."
else
    log_err "Tor failed to bind to port 9053. Check 'journalctl -u tor'."
    exit 1
fi

log_info "Installation complete! building Toralizer."
#log_info "Run: go build -o toralizer toralizer.go"
mkdir -p "$BIN_DIR"

sudo -u "$TARGET_USER" \
    env HOME="$(eval echo ~$TARGET_USER)" \
    /usr/local/go/bin/go build \
    -o "$BIN_DIR/toralizer" \
    "$SRC_DIR/toralizer.go"

log_info "Build finished, executable is at $BIN_DIR/toralizer"
log_info "You should now run: $SCRIPTS_DIR/setup.sh"