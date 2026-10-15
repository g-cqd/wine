# source me: private toolchain copy (clonefile of ~/Games/bump-tools rust + aarch64/arm64ec windows targets), llvm-mingw, our Wine install
R="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")/.." && pwd)"
if [ -d "$R/toolchain/rustup" ]; then
    export CARGO_HOME=$R/toolchain/cargo RUSTUP_HOME=$R/toolchain/rustup   # private copy (APFS clone of the shared toolchain)
else
    export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}" RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"   # the toolchain dir was wiped; use the shared rustup (1.99.0 is installed there)
fi
export PATH="$CARGO_HOME/bin:$PATH"
unset CARGO_NET_OFFLINE
export CARGO_BUILD_JOBS=3
export RUST_STABLE=1.99.0
export RUSTUP_TOOLCHAIN=1.99.0-aarch64-apple-darwin   # the shared rustup defaults to stable; force the pinned toolchain (has the aarch64-pc-windows-msvc std)
export WINE_SDK=$R/install/usr/local          # tools (winebuild) and aarch64-windows link archives
export WINE_SDK_ARM64X=$R/sdk-arm64x           # staged by build-mtld3d.sh from the install tree (ARM64 half only)
export WINE_ARM64=$WINE_SDK
export LLVM_MINGW=$HOME/Developer/Games/bump-tools/llvm-mingw
export ARM64X_LLD=$LLVM_MINGW/bin/lld-link
