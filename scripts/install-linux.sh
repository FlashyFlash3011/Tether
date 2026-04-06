#!/usr/bin/env bash
# Install tether on Linux/WSL2.
# Run from the Tether repo root after `make build-linux`.
set -euo pipefail

BINARY="dist/tether-linux-amd64"
INSTALL_PATH="/usr/local/bin/tether"
SERVICE_SRC="deploy/tether.service"
SYSTEMD_DIR="$HOME/.config/systemd/user"

if [[ ! -f "$BINARY" ]]; then
  echo "Binary not found: $BINARY — run 'make build-linux' first"
  exit 1
fi

echo "Installing tether binary to $INSTALL_PATH ..."
sudo install -m 755 "$BINARY" "$INSTALL_PATH"

echo "Granting cap_net_admin (required for TUN interface) ..."
sudo setcap cap_net_admin+ep "$INSTALL_PATH"

# WSL2 supports systemd with `[boot] systemd=true` in /etc/wsl.conf.
# Check if systemd is running.
if systemctl --user status > /dev/null 2>&1; then
  echo "Installing systemd user service ..."
  mkdir -p "$SYSTEMD_DIR"
  cp "$SERVICE_SRC" "$SYSTEMD_DIR/tether.service"
  systemctl --user daemon-reload
  systemctl --user enable tether.service
  echo ""
  echo "To start now:    systemctl --user start tether.service"
  echo "To check status: systemctl --user status tether.service"
else
  echo "systemd not running (WSL2: add 'systemd=true' to /etc/wsl.conf and restart WSL)"
  echo "You can start tether manually with: tether up"
fi

echo ""
echo "Next steps:"
echo "  1. tether setup     — print setup instructions"
echo "  2. tether keygen    — generate WireGuard keys"
echo "  3. tether pskgen    — generate PSK (copy to both nodes)"
echo "  4. Edit ~/.config/tether/config.toml with your Worker URL and node ID"
echo "  5. tether keystore set api-token <TOKEN_PC>"
echo "  6. tether keystore set wg-psk <PSK>"
echo "  7. tether up"
