#!/bin/bash
# Developer step: build the server and the source modules, and sign them with
# the identity named in signing.conf. Installing is then the same command
# anyone would run on programs that arrived already signed:
#   sudo .build/release/RetrieverServer install
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

IDENTITY=""
[ -f signing.conf ] && . ./signing.conf
[ -n "$IDENTITY" ] || { echo "Name a code-signing identity in signing.conf (see signing.conf.example)."; exit 1; }

swift build -c release
BUILT="$HERE/.build/release"

codesign --force --sign "$IDENTITY" --identifier local.retriever-server "$BUILT/RetrieverServer"
echo "Signed the server."
for MODULE in "$BUILT"/RetrieverSource*; do
    [ -f "$MODULE" ] && [ -x "$MODULE" ] && [[ "$(basename "$MODULE")" != *.* ]] || continue
    # A module's signing identifier is its service name, which it can report.
    SERVICE=$("$MODULE" --service)
    [[ "$SERVICE" =~ ^local\.retriever-source\.[a-z0-9-]+$ ]] || { echo "Unexpected service name from $MODULE: $SERVICE"; exit 1; }
    codesign --force --sign "$IDENTITY" --identifier "$SERVICE" "$MODULE"
    echo "Signed module $SERVICE."
done

echo "Install with: sudo \"$BUILT/RetrieverServer\" install"
