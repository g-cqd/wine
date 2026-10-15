#!/bin/bash
# make install into ./install and re-sign the host bundle (run after `build-arm64.sh make`)
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="$HOME/Developer/Games/bump-tools/llvm-mingw/bin:/opt/homebrew/opt/bison/bin:/opt/homebrew/bin:$PATH"
(cd "$ROOT/build" && make install DESTDIR="$ROOT/install" >/tmp/wa64-install.log 2>&1)
"$ROOT/scripts/make-host.sh" 2>&1 | tail -1
