#!/bin/bash
# Installs (or reinstalls) RetrieverServer as a launchd agent that starts at login.
set -euo pipefail

LABEL="local.retriever-server"
BIN="$(cd "$(dirname "$0")" && pwd)/.build/release/RetrieverServer"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG="$HOME/Library/Logs/RetrieverServer.log"

[ -x "$BIN" ] || { echo "Binary not found. Run: swift build -c release"; exit 1; }

read -rsp "Token (letters and digits only): " TOKEN; echo
[[ "$TOKEN" =~ ^[A-Za-z0-9]+$ ]] || { echo "Token must be letters and digits only."; exit 1; }

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
        <key>REMINDERS_TOKEN</key>
        <string>$TOKEN</string>
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
chmod 600 "$PLIST"   # the token is stored in this file

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "Loaded $LABEL. Log: $LOG"
