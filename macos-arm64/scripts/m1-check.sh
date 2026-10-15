#!/bin/bash
# M1 regression: cmd /c ver, arm64 hello PE, reg query, on a throw-away prefix. Prints PASS/FAIL per step.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export WINEPREFIX=${WINEPREFIX:-/tmp/wa64-pfx/m1}; export WINEDEBUG=${WINEDEBUG:--all}
W="$ROOT/host/exec4k $ROOT/install/usr/local/bin/wine"
[ -n "$KEEP" ] || rm -rf "$WINEPREFIX"; mkdir -p "$(dirname "$WINEPREFIX")"
t() { local n=$1 want=$2; shift 2; local out; out=$(perl -e 'alarm 240; exec @ARGV' "$@" 2>&1); local rc=$?; echo "$out" | grep -q "$want" && [ $rc = 0 ] && echo "PASS $n (rc 0)" || { echo "FAIL $n rc=$rc"; echo "$out" | head -5; }; }
t ver "Microsoft Windows" $W cmd /c ver
t hello "hello from arm64 PE" $W "$ROOT/tests/hello_arm64.exe"
t reg "HKEY_LOCAL_MACHINE.Software" $W reg query 'HKLM\Software'
