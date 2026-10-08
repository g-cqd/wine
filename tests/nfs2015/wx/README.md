# Rosetta self-modifying-code tests

Standalone programs for the Rosetta 2 late-resume defect and the optional W^X emulation that works around it
(`docs/rosetta-self-modifying-code.md`). Like the other fixtures in `tests/nfs2015` they are not part of any
`SUBDIRS`, nothing in the build refers to them, and each `main()` returns the number of failed checks.

| file | what it covers |
| --- | --- |
| `rosetta_smc.c` | The smallest reproducer of the Rosetta defect. A native x86_64 Mach-O (`clang -arch x86_64 -O1`), no Wine. Prints how many rounds faulted and the resume offset. Optional arguments: `<gap> <mode> <rounds>` (`mode 1` = one store instead of two). |
| `smc2.c` | The NFS16 stub on a private RWX page, with variants (fixed address `0x1B30000`, fresh pages, spinning threads, trap flag). Builds as a PE (mingw) and as a native Mach-O. |
| `wx-traps.c` | Regression tests for `WINE_RWX_WX_EMULATION`: guest stores, kernel/host writes into the page, two threads, protection transitions, free and reallocate, mixed code/data loop, SEH after a store, guest-set trap flag, a child process. Every case must give the same result with the switch off and on. |
| `hot-stale.c` | The stub in a loop must never fault or be released as busy (T16), a released page is emulated again after a protection change or decommit (T17), a pure data page is still released (T18). |
| `hot-dr.c` | The stub with a debug-register thread (hardware execution breakpoint set through `SetThreadContext`) so that the trap-flag emulation is armed. |
| `alloc-paths.c` | The stub on pages created through different Windows paths (reserve then commit, protect transitions, 64K regions, top-down, write-watch, fixed address). |
| `stress.c` | Chromium/V8-like stress: threads storing into RWX pages while another thread suspends them and reads and writes their contexts. Counts stray `EXCEPTION_SINGLE_STEP`. |

## Build and run

    x86_64-w64-mingw32-gcc -O1 -o wx-traps.exe wx-traps.c      # likewise for the other PE tests
    WINE_RWX_WX_EMULATION=1 wine wx-traps.exe
    clang -arch x86_64 -O1 -o rosetta_smc rosetta_smc.c && ./rosetta_smc

Run every PE test with the switch off, on, on with `WINE_TF_EMULATION=1 WINE_TF_MAX_STEPS=0 WINE_TF_MAX_NS=0`, and on
with `WINE_RWX_WX_HOT_LIMIT=0`. With the emulation off the stub tests are expected to fault on Wine + Rosetta;
with it on they must not. Wine refuses a prefix under `/tmp`; use a prefix inside the home directory.
