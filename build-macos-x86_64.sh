#!/bin/sh
#
# Configure and build Wine for x86_64 (Rosetta) on this Apple Silicon Mac.
#
# Native arm64 hosting is not viable: the kernel refuses any fixed-address
# mapping below 4GB, which Windows' KUSER_SHARED_DATA requires at 0x7ffe0000.
# Building for x86_64 and running under Rosetta 2 sidesteps that entirely.
#
# Usage:
#   ./build-macos-x86_64.sh configure [extra configure args...]
#   ./build-macos-x86_64.sh make [make args...]
#   ./build-macos-x86_64.sh            # does both
#   ./build-macos-x86_64.sh run [wine args...]   # e.g. run notepad
#
# Dependencies not available for x86_64 via the arm64 Homebrew install are
# pulled from the Intel Homebrew prefix (/usr/local), installed with:
#   arch -x86_64 /usr/local/Homebrew/bin/brew install \
#       molten-vk vulkan-loader freetype gnutls libusb sdl2-compat ffmpeg gstreamer krb5

set -e

cd "$(dirname "$0")"

DARWIN_VER=$(uname -r | cut -d. -f1)

export CC="clang -arch x86_64"
export CXX="clang++ -arch x86_64"
export LDFLAGS="-L/usr/local/lib"
# /usr/local/lib/pkgconfig aggregates all non-keg-only x86_64 Homebrew
# formulae (glib, gstreamer, freetype, gnutls, libusb, sdl2, ffmpeg, vulkan,
# ...) so transitive deps like glib/gettext resolve to x86_64, not the arm64
# Homebrew install. krb5 is keg-only and needs its own path added.
export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/local/opt/krb5/lib/pkgconfig"
# llvm-dlltool (needed by winebuild for import libraries) only ships in the
# arm64 Homebrew LLVM keg, which isn't linked onto PATH.
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"

do_configure() {
    ./configure --host="x86_64-apple-darwin${DARWIN_VER}" --enable-archs=x86_64 "$@"
}

do_make() {
    make -j"$(sysctl -n hw.ncpu)" "$@"
}

do_run() {
    codesign -s - -f --entitlements wine-entitlements.plist loader/wine server/wineserver tools/wine/wine >/dev/null 2>&1
    # This macOS version's dyld no longer falls back to /usr/local/lib by
    # default, so Wine's dlopen("libfreetype.6.dylib", ...) (and other
    # runtime-loaded x86_64 Homebrew libs) fails to find it without this.
    DYLD_FALLBACK_LIBRARY_PATH=/usr/local/lib ./wine "$@"
}

case "$1" in
    configure) shift; do_configure "$@" ;;
    make)      shift; do_make "$@" ;;
    run)       shift; do_run "$@" ;;
    "")        do_configure && do_make ;;
    *)         echo "usage: $0 [configure|make|run] [args...]" >&2; exit 1 ;;
esac
