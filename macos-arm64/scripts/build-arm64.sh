#!/bin/bash
# Native arm64 macOS Wine build (PE side: llvm-mingw aarch64 + i386). Usage: build-arm64.sh [--clean] [configure|make]
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WINE_SRC="${WINE_SRC:-$ROOT/..}"   # the wine source is this repository itself (macos-arm64/ is the arm64 workspace)
BUILD_DIR="${BUILD_DIR:-$ROOT/build}"
MINGW_DIR="${MINGW_DIR:-$HOME/Developer/Games/bump-tools/llvm-mingw}"   # explicit; never /opt/llvm-mingw
BREW="${BREW:-/opt/homebrew}"
# dlopen()ed third-party libs (freetype, gnutls, SDL2): the sonames are @rpath/<lib> and every Wine .so carries an rpath to $BREW/lib,
# because dyld ignores DYLD_* variables for the hardened, signed loader and a bare leaf name is not searched in /opt/homebrew/lib
[ -x "$MINGW_DIR/bin/aarch64-w64-mingw32-clang" ] || { echo "llvm-mingw not found at $MINGW_DIR"; exit 1; }
export PATH="$BREW/opt/bison/bin:$BREW/bin:$PATH:$MINGW_DIR/bin"   # llvm-mingw LAST: its clang must not shadow the host compiler
export MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-26.4}"
CLEAN=0; if [ "${1:-}" = "--clean" ]; then CLEAN=1; shift; fi
STEP="${1:-all}"
[ "$CLEAN" = 1 ] && rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"; cd "$BUILD_DIR"
if [ "$STEP" = all ] || [ "$STEP" = configure ]; then
  if [ "$CLEAN" = 1 ] || [ ! -f Makefile ]; then
    "$WINE_SRC/configure" \
        --host=aarch64-apple-darwin \
        --enable-archs=aarch64,i386 \
        --with-mingw=llvm-mingw \
        --with-coreaudio --with-gnutls --with-sdl --with-unwind \
        --without-alsa --without-capi --without-cups --without-dbus --without-ffmpeg --without-fontconfig \
        --without-gettext --without-gphoto --without-gssapi --without-gstreamer --without-hwloc \
        --without-inotify --without-krb5 --without-netapi --without-opencl --without-oss --without-pcap \
        --without-pcsclite --without-pulse --without-sane --without-udev --without-usb --without-v4l2 \
        --without-vulkan --without-wayland --without-x \
        CC="/usr/bin/clang -arch arm64" \
        PKG_CONFIG_PATH="$BREW/lib/pkgconfig:$BREW/share/pkgconfig" \
        CFLAGS="-g -O2 -I$BREW/include" \
        LDFLAGS="-L$BREW/lib -Wl,-rpath,$BREW/lib" \
        ac_cv_lib_soname_freetype=@rpath/libfreetype.6.dylib \
        ac_cv_lib_soname_gnutls=@rpath/libgnutls.30.dylib \
        ac_cv_lib_soname_SDL2=@rpath/libSDL2-2.0.0.dylib
  fi
fi
if [ "$STEP" = all ] || [ "$STEP" = make ]; then
  # winegcc links the PE test programs through "<target>-gcc" found on PATH: llvm-mingw must win over Homebrew's GNU mingw
  # for that (bare clang is not used by the generated Makefile: CC is absolute)
  PATH="$MINGW_DIR/bin:$PATH" nice -n 10 make -j"${JOBS:-3}"
fi
