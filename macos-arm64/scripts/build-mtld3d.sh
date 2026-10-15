#!/bin/bash
# Build mtld3d for the native arm64 Wine in ./install: arm64 mtld3d.so + plain ARM64 (not ARM64X) d3d9.dll / mtld3d.dll.
# Why not `EC=1 make`: the ARM64X leg needs Wine's ARM64X link archives (a Wine built with --enable-archs=arm64ec,aarch64), the EC half
# is only for x64 processes, and the default C/C++ include paths point at an xwin MSVC SDK in /opt/xwin (needs sudo). Here the native
# ARM64 half is built alone, and the C/C++ of snmalloc-sys is compiled against llvm-mingw's headers. Output: mtld3d/out-arm64/.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/scripts/mtld3d-env.sh"
M="$ROOT/mtld3d"; OUT="$M/out-arm64"; T=aarch64-pc-windows-msvc
PROFILE=${PROFILE:-release}
MG=$LLVM_MINGW/aarch64-w64-mingw32
mkdir -p "$OUT"
# mtld3d's shim/build.rs expects Wine's ARM64X libwinecrt0.a, whose members are stored as <arch>-windows/unix_lib.o; a plain aarch64 Wine
# stores a bare unix_lib.o. Stage a copy of the two archives with the member renamed (see docs/BRINGUP.md, mtld3d issue 1).
S="$WINE_SDK_ARM64X/lib/wine/aarch64-windows"
if [ ! -f "$S/libwinecrt0.a" ]; then
  mkdir -p "$S"; T0=$(mktemp -d)
  ( cd "$T0" && "$LLVM_MINGW/bin/llvm-ar" x "$WINE_SDK/lib/wine/aarch64-windows/libwinecrt0.a" unix_lib.o )
  python3 - "$T0/unix_lib.o" "$S/libwinecrt0.a" <<'PY'
import sys   # llvm-ar strips directories when creating, so write the GNU ar archive by hand
data = open(sys.argv[1], 'rb').read(); name = b'aarch64-windows/unix_lib.o'; lt = name + b'/\n'
def hdr(n, size): return ('%-16s%-12d%-6d%-6d%-8s%-10d`\n' % (n, 0, 0, 0, '100644', size)).encode()
out = b'!<arch>\n' + hdr('//', len(lt)) + lt + (b'\n' if len(lt) % 2 else b'') + hdr('/0', len(data)) + data + (b'\n' if len(data) % 2 else b'')
open(sys.argv[2], 'wb').write(out)
PY
  rm -rf "$T0"; cp "$WINE_SDK/lib/wine/aarch64-windows/libntdll.a" "$S/libntdll.a"
fi
# unix side (host arm64 dylib named mtld3d.so)
( cd "$M/unix" && cargo build --profile $PROFILE --target aarch64-apple-darwin )
cp "$M/unix/target/aarch64-apple-darwin/$PROFILE/libmtld3d_unix.dylib" "$OUT/mtld3d.so"
# PE side, ARM64 half only, static libs
export PATH="$LLVM_MINGW/bin:$PATH"
export LLVM_AR="$LLVM_MINGW/bin/llvm-ar"
export CC_aarch64_pc_windows_msvc="$LLVM_MINGW/bin/aarch64-w64-mingw32-clang" CXX_aarch64_pc_windows_msvc="$LLVM_MINGW/bin/aarch64-w64-mingw32-clang++"
export CFLAGS_aarch64_pc_windows_msvc="-fno-omit-frame-pointer"
export CXXFLAGS_aarch64_pc_windows_msvc="-fno-exceptions -fno-rtti -fno-threadsafe-statics -DSNMALLOC_USE_THREAD_CLEANUP -include cstdlib -fno-omit-frame-pointer -DARM64_SYSREG(op0,op1,crn,crm,op2)=((((op0)&1)<<14)|(((op1)&7)<<11)|(((crn)&15)<<7)|(((crm)&15)<<3)|((op2)&7))"
( cd "$M/windows" && for crate in mtld3d d3d9; do
    WINE_SDK="$WINE_SDK_ARM64X" cargo rustc --profile $PROFILE --target $T -p $crate --crate-type staticlib
  done )
P="$M/windows/target/$T/$PROFILE"
link() { # name def
  "$ARM64X_LLD" -lldmingw /dll /machine:arm64 /nodefaultlib /opt:ref,icf /entry:DllMainCRTStartup \
    /def:"$M/windows/$2" /debug /pdb:"$OUT/$1.pdb" /out:"$OUT/$1.dll" \
    "$MG/lib/dllcrt2.o" "$P/$1.lib" \
    $(for l in mingw32 mingwex ucrt kernel32 mincore user32 advapi32 gdi32 ws2_32 userenv bcrypt dbghelp; do echo "$MG/lib/lib$l.a"; done) \
    "$WINE_SDK_ARM64X/lib/wine/aarch64-windows/libntdll.a"
}
link mtld3d shim/mtld3d.def
link d3d9 d3d9/d3d9.def
mkdir -p "$OUT/native"; cp "$OUT/d3d9.dll" "$OUT/native/d3d9.dll"     # unmarked: native-override route
"$WINE_SDK/bin/winebuild" --builtin "$OUT/mtld3d.dll"
"$WINE_SDK/bin/winebuild" --builtin "$OUT/d3d9.dll"                      # builtin-marked: replaces Wine's d3d9 if installed into lib/wine
ls -la "$OUT"
