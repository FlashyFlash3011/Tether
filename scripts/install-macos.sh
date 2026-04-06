#!/usr/bin/env bash
# Install tether on macOS (M4 arm64).
# Run on the Mac after copying dist/tether-darwin-arm64 (or building natively).
set -euo pipefail

BINARY="dist/tether-darwin-arm64"
INSTALL_PATH="/usr/local/bin/tether"
PLIST_SRC="deploy/com.tether.agent.plist"
LAUNCH_AGENTS="$HOME/Library/LaunchAgents"

if [[ ! -f "$BINARY" ]]; then
  echo "Binary not found: $BINARY"
  echo "On this Mac: run 'make build-mac-native' then re-run this script."
  exit 1
fi

echo "Installing tether to $INSTALL_PATH ..."
sudo install -m 755 "$BINARY" "$INSTALL_PATH"

echo "Installing launchd agent ..."
mkdir -p "$LAUNCH_AGENTS"
cp "$PLIST_SRC" "$LAUNCH_AGENTS/com.tether.agent.plist"
launchctl load "$LAUNCH_AGENTS/com.tether.agent.plist"

echo ""
echo "Next steps:"
echo "  1. tether keygen    — generate WireGuard keys (stored in Keychain)"
echo "  2. Edit ~/Library/Application Support/Tether/config.toml"
echo "  3. tether keystore set api-token <TOKEN_MAC>"
echo "  4. tether keystore set wg-psk <PSK>   (same PSK from the PC)"
echo "  5. launchctl start com.tether.agent   (or relogin for auto-start)"
