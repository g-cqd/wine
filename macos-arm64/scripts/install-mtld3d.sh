#!/bin/bash
# Install the arm64 mtld3d pair into ./install (additive: new names only, Wine's own d3d9 stays) and make a test prefix.
# Native-override route of mtld3d/INSTALL.md: mtld3d.dll (builtin pair, marker created by wineboot) + mtld3d.so go into lib/wine;
# the unmarked d3d9.dll goes next to the test program; HKCU\Software\Wine\DllOverrides d3d9=native.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
O="$ROOT/mtld3d/out-arm64"; I="$ROOT/install/usr/local"; PFX=${PFX:-/tmp/wa64-pfx/d3d}
cp "$O/mtld3d.dll" "$I/lib/wine/aarch64-windows/mtld3d.dll"
cp "$O/mtld3d.so" "$I/lib/wine/aarch64-unix/mtld3d.so"
rm -rf "$PFX"; mkdir -p "$(dirname "$PFX")" "$ROOT/host/d3dtest"
export WINEPREFIX="$PFX" WINEDEBUG=-all
W="$ROOT/host/exec4k $I/bin/wine"
$W wineboot -u >/dev/null 2>&1
$W reg add 'HKCU\Software\Wine\DllOverrides' /v d3d9 /d native /f
cp "$O/native/d3d9.dll" "$ROOT/host/d3dtest/d3d9.dll"
ls -la "$PFX/drive_c/windows/system32/mtld3d.dll" "$ROOT/host/d3dtest"
