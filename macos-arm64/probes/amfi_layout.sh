#!/bin/bash
# Probe (e): which bundle layouts satisfy AMFI for the restricted entitlement (profile discovery).
set -u
cd "$(dirname "$0")"; W=/tmp/wa64p; ID=7492E391094B7E2B51A7A5D14CBB9CFBF29FB277; PROF=$HOME/Downloads/winehost_developer_id_2.provisionprofile
A=$W/layout.app; rm -rf $A $W/outside; mkdir -p $A/Contents/MacOS $A/Contents/Helpers $W/outside
cp $W/spawn4k $A/Contents/MacOS/main; cp $W/spawn4k $A/Contents/MacOS/second; cp $W/spawn4k $A/Contents/Helpers/helper
cp $PROF $A/Contents/embedded.provisionprofile
printf '<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>main</string><key>CFBundleIdentifier</key><string>fr.gcqd.winehost</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>' > $A/Contents/Info.plist
cat > $W/ent.plist <<EOP
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>
<key>com.apple.developer.cross-architecture-support</key><true/>
<key>com.apple.application-identifier</key><string>NP94WB3P75.fr.gcqd.winehost</string>
<key>com.apple.developer.team-identifier</key><string>NP94WB3P75</string>
<key>com.apple.security.cs.allow-jit</key><true/><key>com.apple.security.cs.disable-library-validation</key><true/>
</dict></plist>
EOP
# sign nested executables first (each with the entitlements), then the bundle
for f in $A/Contents/MacOS/second $A/Contents/Helpers/helper; do codesign -f -s $ID --entitlements $W/ent.plist --options runtime $f 2>&1 | tail -1; done
codesign -f -s $ID --entitlements $W/ent.plist --options runtime $A 2>&1 | tail -1
ln -s $A/Contents/MacOS/main $W/outside/symlink_main
ln $A/Contents/MacOS/main $W/outside/hardlink_main
for x in $A/Contents/MacOS/main $A/Contents/MacOS/second $A/Contents/Helpers/helper $W/outside/symlink_main $W/outside/hardlink_main; do
  echo "### $x"; $W/launch 4k $x report layout 2>&1 | head -3
done
