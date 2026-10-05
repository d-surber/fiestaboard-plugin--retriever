#!/bin/bash
# Installs (or reinstalls) RetrieverServer as a launchd agent that starts at login.
set -euo pipefail

LABEL="local.retriever-server"
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="$HERE/.build/release/RetrieverServer"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG="$HOME/Library/Logs/RetrieverServer.log"

[ -x "$BIN" ] || { echo "Binary not found. Run: swift build -c release"; exit 1; }

# Sign the server and the source modules with the identity named in
# signing.conf, if there is one. The identity can be a self-signed
# certificate or a Developer ID: only its name is given here. The server and
# its modules only talk to programs signed by their own signer, so without
# signing.conf the modules are not installed and their sources are missing.
IDENTITY=""
[ -f "$HERE/signing.conf" ] && . "$HERE/signing.conf"
MODULES=()
if [ -n "$IDENTITY" ]; then
    codesign --force --sign "$IDENTITY" --identifier "$LABEL" "$BIN"
    echo "Signed the server with \"$IDENTITY\"."
    for MODULE in "$HERE"/.build/release/RetrieverSource*; do
        [ -f "$MODULE" ] && [ -x "$MODULE" ] || continue
        MODULES+=("$MODULE")
    done
else
    echo "No signing.conf: leaving the ad-hoc signature. Source modules are not installed."
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

# Each module is its own agent, started by launchd when the server first asks
# for it. A module's service name is also its signing identifier.
for MODULE in ${MODULES[@]+"${MODULES[@]}"}; do
    SERVICE=$("$MODULE" --service)
    [[ "$SERVICE" =~ ^local\.retriever-source\.[a-z0-9-]+$ ]] || { echo "Unexpected service name from $MODULE: $SERVICE"; exit 1; }
    codesign --force --sign "$IDENTITY" --identifier "$SERVICE" "$MODULE"
    MODULE_PLIST="$HOME/Library/LaunchAgents/$SERVICE.plist"
    cat > "$MODULE_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$SERVICE</string>
    <key>ProgramArguments</key>
    <array>
        <string>$MODULE</string>
    </array>
    <key>MachServices</key>
    <dict>
        <key>$SERVICE</key>
        <true/>
    </dict>
    <key>StandardOutPath</key>
    <string>$LOG</string>
    <key>StandardErrorPath</key>
    <string>$LOG</string>
</dict>
</plist>
EOF
    launchctl bootout "gui/$(id -u)/$SERVICE" 2>/dev/null || true
    launchctl bootstrap "gui/$(id -u)" "$MODULE_PLIST"
    echo "Installed module $SERVICE."
done

launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "$PLIST"
echo "Loaded $LABEL. Log: $LOG"
