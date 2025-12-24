SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Project layout (assumes install_env.sh lives in /scripts)
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCRIPTS_DIR="$PROJECT_ROOT/scripts"
SRC_DIR="$PROJECT_ROOT/src"
BIN_DIR="$PROJECT_ROOT/bin"

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

sudo -u "$TARGET_USER" \
    env HOME="$(eval echo ~$TARGET_USER)" \
    /usr/local/go/bin/go build \
    -o "$BIN_DIR/toralizer" \
    "$SRC_DIR/toralizer.go"

log_info "Build finished, executable is at $BIN_DIR/toralizer"
log_info "You should now run: $SCRIPTS_DIR/setup.sh"