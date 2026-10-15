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
#   ./build-macos-x86_64.sh builddir   # print the resolved build directory
#
# Environment:
#   WINE_BUILD_DIR   where the build happens:
#                      .  or in-tree   the source tree (as before)
#                      PATH            an out-of-tree build directory, created
#                                      if missing; relative paths are taken from
#                                      the current directory
#                      unset           the source tree if it is already configured
#                                      there (config.status exists), else
#                                      /Volumes/ExT2/GameHub/build/wine
#                    A path under /Volumes/<name> is refused unless that volume
#                    is mounted, so nothing lands on the internal disk by mistake.
#   WINE_BUILD_JOBS  make parallelism (default: hw.ncpu)
#
# The default build directory is on the ExT2 volume because build artifacts are
# runtime-adjacent (wine runs from them and they are large), and keeping them
# out of the source tree leaves git status showing only sources.
#
# Dependencies not available for x86_64 via the arm64 Homebrew install are
# pulled from the Intel Homebrew prefix (/usr/local), installed with:
#   arch -x86_64 /usr/local/Homebrew/bin/brew install \
#       molten-vk vulkan-loader freetype gnutls libusb sdl2-compat ffmpeg gstreamer krb5

set -e

SRC=$(cd "$(dirname "$0")" && pwd -P)
DEFAULT_BUILD_DIR=/Volumes/ExT2/GameHub/build/wine

resolve_build_dir() {
    case "${WINE_BUILD_DIR:-}" in
        "")
            if [ -f "$SRC/config.status" ]; then
                echo "build: $SRC is configured in-tree, building there (set WINE_BUILD_DIR to override)" >&2
                BUILD=$SRC
            else
                BUILD=$DEFAULT_BUILD_DIR
            fi ;;
        .|in-tree) BUILD=$SRC ;;
        /*)        BUILD=$WINE_BUILD_DIR ;;
        *)         BUILD=$PWD/$WINE_BUILD_DIR ;;
    esac

    BUILD=${BUILD%/}
    case "/$BUILD/" in
        */../*)
            echo "build directory must not contain '..': $BUILD" >&2
            exit 1 ;;
    esac
    if [ -d "$BUILD" ]; then
        BUILD=$(cd "$BUILD" && pwd -P)
    fi
    if [ "$BUILD" = "$SRC" ]; then
        return
    fi

    case "$BUILD" in
        /Volumes/*)
            vol=${BUILD#/Volumes/}
            vol=${vol%%/*}
            if [ -z "$vol" ] || [ ! -d "/Volumes/$vol" ]; then
                echo "build volume not mounted: /Volumes/$vol (needed for $BUILD)" >&2
                exit 1
            fi ;;
    esac
}

resolve_build_dir

WINE_BUILD_JOBS=${WINE_BUILD_JOBS:-$(sysctl -n hw.ncpu)}

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
    mkdir -p "$BUILD"
    cd "$BUILD"
    "$SRC/configure" --host="x86_64-apple-darwin${DARWIN_VER}" --enable-archs=x86_64 "$@"
}

do_make() {
    if [ ! -f "$BUILD/Makefile" ]; then
        echo "not configured: run ./build-macos-x86_64.sh configure" >&2
        exit 1
    fi
    make -C "$BUILD" -j"$WINE_BUILD_JOBS" "$@"
}

do_run() {
    codesign -s - -f --entitlements "$SRC/wine-entitlements.plist" "$BUILD/loader/wine" "$BUILD/server/wineserver" "$BUILD/tools/wine/wine" >/dev/null 2>&1
    # This macOS version's dyld no longer falls back to /usr/local/lib by
    # default, so Wine's dlopen("libfreetype.6.dylib", ...) (and other
    # runtime-loaded x86_64 Homebrew libs) fails to find it without this.
    DYLD_FALLBACK_LIBRARY_PATH=/usr/local/lib "$BUILD/wine" "$@"
}

case "$1" in
    configure) shift; do_configure "$@" ;;
    make)      shift; do_make "$@" ;;
    run)       shift; do_run "$@" ;;
    builddir)  echo "$BUILD" ;;
    "")        do_configure && do_make ;;
    *)
        echo "usage: $0 [configure|make|run|builddir] [args...]" >&2
        echo "  WINE_BUILD_DIR   build directory: . or in-tree, a path, or unset (default $DEFAULT_BUILD_DIR, or in-tree if already configured there)" >&2
        echo "  WINE_BUILD_JOBS  make parallelism (default hw.ncpu)" >&2
        exit 1 ;;
esac
