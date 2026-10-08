#!/bin/sh
# usage: crash-context-check.sh /path/to/wine crash-context.exe [page]   (WINEPREFIX must be set)
# Passes when the child's unhandled fault produced the whole wine-crash block with the known register values.
log=$(mktemp); out=$(mktemp)
"$1" "$2" $3 > "$out" 2> "$log"
fail=0
need() { grep -q "$1" "$log" || { echo "FAIL missing: $1"; fail=1; }; }
if [ "$3" = page ]; then
    need 'wine-crash: begin'
    need 'access=1 target=85BC35850173FF31'
    need 'pc-bytes\[[0-9]*\]=a2 31 ff 73 01 85 35 bc 85 e8 ac 52 48 8d 15 ba'
    need 'type=20000 region='
    need 'wine-crash: vq\[[0-9A-Fa-f]*\] alloc='
    need 'wine-crash: threads='
    need 'wine-crash: window pc='
    need 'wine-crash: near-pc: .*r12=pc-0x76'
    need 'wine-crash: code\[[0-9A-Fa-f]*\]: '
    sum=$(sed -n 's/.*fnv1a64=\([0-9a-f]*\) .*/\1/p' "$out" | head -1)
    [ -n "$sum" ] && need "pagesum .* fnv1a64=$sum zero16="
    [ -z "$sum" ] && { echo "FAIL no expected checksum from the child"; fail=1; }
    need 'wine-crash: end'
    grep '^wine-crash' "$log"
    [ $fail = 0 ] && echo "ok   crash-context page block complete"
    rm -f "$log" "$out"
    exit $fail
fi
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
rm -f "$log" "$out"
exit $fail
