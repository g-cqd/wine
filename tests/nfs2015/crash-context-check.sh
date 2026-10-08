#!/bin/sh
# usage: crash-context-check.sh /path/to/wine crash-context.exe   (WINEPREFIX must be set)
# Passes when the child's unhandled fault produced the whole wine-crash block with the known register values.
log=$(mktemp)
"$1" "$2" 2> "$log"
fail=0
need() { grep -q "$1" "$log" || { echo "FAIL missing: $1"; fail=1; }; }
need 'wine-crash: begin'
need 'code=c0000005'
need 'access=1 target=85BC35850173FF31'
need 'rax=1111111111111111'
need 'rbx=2222222222222222'
need 'rcx=85BC35850173FF31'
need 'rdx=3333333333333333'
need 'r8=0808080808080808'
need 'r15=1515151515151515'
need 'pc-bytes\[[0-9]*\]=48 89 01'
need 'target 85BC35850173FF31 not queryable'
need 'wine-crash: tf state='
need 'wine-crash: end'
grep '^wine-crash' "$log"
[ $fail = 0 ] && echo "ok   crash-context block complete"
rm -f "$log"
exit $fail
