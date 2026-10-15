#!/bin/bash
# Usage: sign_app.sh <out.app> <main-binary> [extra entitlement keys (boolean true) ...]
# Builds a minimal bundle around <main-binary>, embeds the winehost provisioning profile and signs it with the
# Developer ID identity (hardened runtime). Base entitlements: cross-architecture-support, application-identifier,
# team-identifier, allow-jit, disable-library-validation.
set -eu
APP=$1; BIN=$2; shift 2
ID=${ID:-7492E391094B7E2B51A7A5D14CBB9CFBF29FB277}
PROF=${PROF:-$HOME/Downloads/winehost_developer_id_2.provisionprofile}
TEAM=NP94WB3P75; BID=fr.gcqd.winehost
NAME=$(basename "$BIN")
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS"
cp "$BIN" "$APP/Contents/MacOS/$NAME"
cp "$PROF" "$APP/Contents/embedded.provisionprofile"
printf '<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>%s</string><key>CFBundleIdentifier</key><string>%s</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>' "$NAME" "$BID" > "$APP/Contents/Info.plist"
E=$(mktemp /tmp/entXXXXXX)
{
echo '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>'
echo '<key>com.apple.developer.cross-architecture-support</key><true/>'
echo "<key>com.apple.application-identifier</key><string>$TEAM.$BID</string>"
echo "<key>com.apple.developer.team-identifier</key><string>$TEAM</string>"
echo '<key>com.apple.security.cs.allow-jit</key><true/>'
echo '<key>com.apple.security.cs.disable-library-validation</key><true/>'
for k in "$@"; do echo "<key>$k</key><true/>"; done
echo '</dict></plist>'
} > $E
if [ -n "${NORUNTIME:-}" ]; then OPTS=""; else OPTS="--options runtime"; fi
codesign -f -s "$ID" --entitlements $E $OPTS "$APP" 2>&1 | tail -1
rm -f $E
