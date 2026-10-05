#!/bin/bash
# Installs (or reinstalls) RetrieverServer as a launchd agent that starts at login.
set -euo pipefail

LABEL="local.retriever-server"
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/.build/release/RetrieverServer"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG="$HOME/Library/Logs/RetrieverServer.log"

[ -x "$BIN" ] || { echo "Binary not found. Run: swift build -c release"; exit 1; }

# Sign the server with the identity named in signing.conf, if there is one.
# The identity can be a self-signed certificate or a Developer ID: only its
# name is given here. Without signing.conf the build's ad-hoc signature
# stays, and macOS treats every rebuild as a different program.
IDENTITY=""
[ -f "$HERE/signing.conf" ] && . "$HERE/signing.conf"
if [ -n "$IDENTITY" ]; then
    codesign --force --sign "$IDENTITY" --identifier "$LABEL" "$BIN"
    echo "Signed with \"$IDENTITY\"."
else
    echo "No signing.conf: leaving the ad-hoc signature."
fi

read -rsp "Key (base64 of 32 bytes; leave empty to generate one): " KEY; echo
if [ -z "$KEY" ]; then
    KEY=$(openssl rand -base64 32)
    echo "Generated key. Enter it in the plugin's settings: $KEY"
fi
[[ "$KEY" =~ ^[A-Za-z0-9+/]{43}=$ ]] || { echo "Key must be base64 of 32 bytes."; exit 1; }

mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$LABEL</string>
    <key>ProgramArguments</key>
    <array>
        <string>$BIN</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RETRIEVER_KEY</key>
        <string>$KEY</string>
    </dict>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$LOG</string>
    <key>StandardErrorPath</key>
    <string>$LOG</string>
</dict>
</plist>
EOF
chmod 600 "$PLIST"   # the key is stored in this file

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "Loaded $LABEL. Log: $LOG"
