#!/bin/bash

# setup_check.sh
# Validates the environment for Toralizer (Debian/Linux)

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err() { echo -e "${RED}[ERROR]${NC} $1"; }

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_err "Please run as root."
        exit 1
    fi
}

check_dependencies() {
    local dependencies=("tor" "nft" "ip" "go")
    local missing=0

    for cmd in "${dependencies[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_err "Dependency missing: $cmd"
            missing=1
        else
            log_info "Found dependency: $cmd"
        fi
    done

    if [ $missing -ne 0 ]; then
        log_err "Install missing dependencies via: apt install tor nftables iproute2 golang"
        exit 1
    fi
}

check_tor_config() {
    local torrc="/etc/tor/torrc"
    
    if [ ! -f "$torrc" ]; then
        log_warn "torrc not found at $torrc. Assuming custom config or defaults."
        return
    fi

    # Check for TransPort
    if grep -q "^TransPort.*9040" "$torrc"; then
        log_info "Tor TransPort 9040 configuration detected."
    else
        log_err "Tor TransPort 9040 NOT detected in $torrc"
        echo "Please add: TransPort 9040"
        exit 1
    fi

    # Check for DNSPort
    if grep -q "^DNSPort.*9053" "$torrc"; then
        log_info "Tor DNSPort 9053 configuration detected."
    else
        log_err "Tor DNSPort 9053 NOT detected in $torrc"
        echo "Please add: DNSPort 9053"
        exit 1
    fi
}

check_tor_service() {
    if systemctl is-active --quiet tor; then
        log_info "Tor service is running."
    else
        log_err "Tor service is NOT running."
        exit 1
    fi
}

check_kernel_modules() {
    # Basic check for IP forwarding
    if [ "$(sysctl -n net.ipv4.ip_forward)" -eq 0 ]; then
        log_warn "IPv4 forwarding is disabled. Enabling it now..."
        sysctl -w net.ipv4.ip_forward=1
    else
        log_info "IPv4 forwarding is enabled."
    fi
}

main() {
    echo "--- Toralizer Environment Check ---"
    check_root
    check_dependencies
    check_tor_config
    check_tor_service
    check_kernel_modules
    echo "--- System Ready ---"
}

main