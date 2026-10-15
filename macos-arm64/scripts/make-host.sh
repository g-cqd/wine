#!/bin/bash
# Assemble the runnable, signed host from the `make install` tree and the winehost provisioning profile.
#   install/usr/local/lib/wine/aarch64-unix/wine  ->  symlink to  host/winehost.app/Contents/MacOS/wine   (signed, entitled)
#   host/winehost.app/Contents/MacOS/ntdll.so    ->  symlink to  the installed ntdll.so (loader/main.c dlopens dir-of-exe/ntdll.so)
#   host/exec4k                                   ->  unentitled launcher that execs the loader with the 4K attribute
# Usage: make-host.sh   (needs the Developer ID identity in the keychain and the profile; neither is ever committed)
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ID="${ID:-F5A93858FCDA865CA073CCED906BE07935CBDC91}"   # pairs with the 7208E67A cert embedded in winehost_developer_id.provisionprofile
if ! security find-identity -v -p codesigning 2>/dev/null | grep -q "$ID"; then
    echo "the pinned Developer ID identity $ID is not in the keychain; pass ID=<hash> of the identity whose certificate matches the profile"
    security find-identity -v -p codesigning || true
    exit 1
fi
PROFILE="${PROFILE:-$HOME/Downloads/winehost_developer_id.provisionprofile}"  # the non-"2" profile matches the 7208E67A certificate
TEAM=NP94WB3P75; BID=fr.gcqd.winehost
INST="$ROOT/install/usr/local"
UNIX="$INST/lib/wine/aarch64-unix"
APP="$ROOT/host/winehost.app"
EXTRA_ENT="${EXTRA_ENT:-}"          # additional boolean entitlements, space separated

mkdir -p "$ROOT/host"
/usr/bin/clang -arch arm64 -O1 -o "$ROOT/host/exec4k" "$ROOT/scripts/exec4k.c"

# the pristine installed loader (kept next to the bundle so that this script can be re-run)
[ -f "$ROOT/host/wine.orig" ] || { [ -L "$UNIX/wine" ] && echo "installed loader already replaced" >&2; cp "$UNIX/wine" "$ROOT/host/wine.orig"; }

rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS"
cp "$ROOT/host/wine.orig" "$APP/Contents/MacOS/wine"
cp "$PROFILE" "$APP/Contents/embedded.provisionprofile"
cat > "$APP/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>wine</string>
<key>CFBundleIdentifier</key><string>$BID</string>
<key>CFBundleName</key><string>winehost</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSUIElement</key><true/>
</dict></plist>
EOF
ENT="$ROOT/host/winehost.entitlements"
{
echo '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>'
echo '<key>com.apple.developer.cross-architecture-support</key><true/>'
echo "<key>com.apple.application-identifier</key><string>$TEAM.$BID</string>"
echo "<key>com.apple.developer.team-identifier</key><string>$TEAM</string>"
echo '<key>com.apple.security.cs.allow-jit</key><true/>'
echo '<key>com.apple.security.cs.disable-library-validation</key><true/>'
for k in $EXTRA_ENT; do echo "<key>$k</key><true/>"; done
echo '</dict></plist>'
} > "$ENT"
codesign -f -s "$ID" --entitlements "$ENT" --options runtime "$APP"
# symlinks are added after signing (they point outside the bundle; AMFI only checks the main executable and the profile)
ln -sfn "$UNIX/ntdll.so" "$APP/Contents/MacOS/ntdll.so"
ln -sfn "$APP/Contents/MacOS/wine" "$UNIX/wine"
ln -sfn "$APP/Contents/MacOS/wine" "$INST/bin/wine"
echo "host ready: $INST/bin/wine -> $APP/Contents/MacOS/wine ; run with: $ROOT/host/exec4k $INST/bin/wine <args>"
