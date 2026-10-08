# Execution-breakpoint regression fixture

`exec-breakpoint-prefix.c` covers the two halves of the `nfs2015-fix` series:
delivery of an x86 hardware *execution* breakpoint to a translated process, and
the prefixed `PUSHF`/`POPF` forms the trap-flag emulator has to decode.

It is deliberately **not** a `dlls/ntdll/tests` case and nothing in the build
refers to it. Three reasons:

- It is a standalone `main()` whose exit status is the number of failed checks.
  The winetest harness reports through `ok()`/`START_TEST` instead, so adopting
  it would mean rewriting every assertion — and the behaviour quoted below was
  verified against *this* program, not a translation of it.
- Checks 6-10 need a hardware execution breakpoint to actually be delivered. In
  `dlls/ntdll/tests` they would fail any `make test` run on Rosetta that did not
  also set `WINE_TF_EMULATION=1`, i.e. the default, turning a working tree red.
- Nothing under this directory is in `configure`'s `SUBDIRS`, so makedep never
  descends here and the file cannot affect a normal build.

Checks 1-5 are pure architecture and must hold on real hardware too, so a stock
Windows or bare-metal Intel run is a valid control. Checks 6-10 are the ones
that fail on Wine + Rosetta without this series.

## Build

    x86_64-w64-mingw32-gcc -O1 -o exec-breakpoint-prefix.exe exec-breakpoint-prefix.c

## Run

    WINE_TF_EMULATION=1 WINE_TF_MAX_STEPS=0 WINE_TF_MAX_NS=0 wine exec-breakpoint-prefix.exe

## Expected

Reported on the Wine 11.18 build of this series, 10 checks total:

| environment                                               | failures |
| --------------------------------------------------------- | -------- |
| `WINE_TF_EMULATION` unset                                 | 2        |
| `WINE_TF_EMULATION=1 WINE_TF_MAX_STEPS=0 WINE_TF_MAX_NS=0` | 0        |

The two failures without the mode are the delivery checks: the breakpoint is
never raised, so `hits` stays 0 and `DR6` never reports breakpoint 0.

## Crash-context block

`crash-context.c` and `crash-context-check.sh` cover the `wine-crash:` lines that
`UnhandledExceptionFilter` (dlls/kernelbase/debug.c) writes to Wine's stderr just before it starts the
debugger: registers, flags, MXCSR, segments, the 16 bytes at the instruction pointer, 8 stack slots, the page
state/protection/module of the pc and of the faulting address, and the trap-flag emulation counters kept in the
TEB (`tf state`, `guest_flags`, `steps`; 0 unless `WINE_TF_EMULATION=1` has stepped that thread). Useful when
winedbg only reports `Couldn't get first exception`. Build and run:

    x86_64-w64-mingw32-gcc -O1 -o crash-context.exe crash-context.c
    WINEPREFIX=... ./crash-context-check.sh /path/to/wine crash-context.exe

Expect `ok   crash-context block complete`. winedbg is still started afterwards and may wait for input when
stdin is not a terminal; kill it, the child's exit status stays `c0000005`.
