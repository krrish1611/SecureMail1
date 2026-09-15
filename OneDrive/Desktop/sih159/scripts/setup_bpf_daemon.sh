#!/usr/bin/env bash
# Sets up a permanent macOS LaunchDaemon so /dev/bpf* permissions (chmod 666)
# are automatically configured on every system startup without asking for passwords.

set -e

if [[ "$OSTYPE" != "darwin"* ]]; then
  echo "[!] This script is only needed for macOS (Darwin)."
  exit 0
fi

if [[ $EUID -ne 0 ]]; then
  echo "[*] Elevating to root..."
  exec sudo "$0" "$@"
fi

PLIST_PATH="/Library/LaunchDaemons/com.securemailscope.chmodbpf.plist"

echo "[*] Creating LaunchDaemon at $PLIST_PATH..."
cat <<'EOF' > "$PLIST_PATH"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.securemailscope.chmodbpf</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>/bin/chmod 666 /dev/bpf*</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF

chown root:wheel "$PLIST_PATH"
chmod 644 "$PLIST_PATH"

echo "[*] Loading LaunchDaemon into launchd..."
launchctl unload "$PLIST_PATH" 2>/dev/null || true
launchctl load -w "$PLIST_PATH"

# Apply immediately
chmod 666 /dev/bpf* 2>/dev/null || true

echo "[✓] Successfully installed com.securemailscope.chmodbpf!"
echo "[✓] /dev/bpf* devices will now automatically have read/write access on every system boot."
