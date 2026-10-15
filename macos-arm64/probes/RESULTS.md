# Risk probes before the native arm64 Wine build (2026-10-07, M1 / macOS 27.2 `26B5091g`)

Setup: tiny native arm64 C programs, signed with Developer ID `7492E391...B277` inside a `.app` that embeds
`winehost_developer_id_2.provisionprofile` (`sign_app.sh`); entitlements `com.apple.developer.cross-architecture-support`,
`com.apple.application-identifier` = `NP94WB3P75.fr.gcqd.winehost`, `com.apple.developer.team-identifier`,
`cs.allow-jit`, `cs.disable-library-validation` (+ per-probe extras), hardened runtime unless noted. The 4 KiB process is created by an
unentitled launcher (`launch.c`) with `posix_spawnattr_set_4k_page_size_np`. Full raw outputs: `out/*.txt`; re-run: `./run_all.sh`.
Measured under load average 40-70 (other agents), so timings are indicative only.

## Verdicts

| probe | verdict |
|---|---|
| (a) x18 | **works with X**: x18 is a persistent GPR only between `os_set_custom_x18_abi_enabled(true)` and `(false)` (public API, SDK `os/arch/arm64.h`, macOS 26.4+). Plain x18 is zeroed by the kernel on every syscall/exception/context switch. The `custom-x18-abi-toggle` entitlement is NOT needed (the cross-architecture entitlement already grants it). |
| (b) executable mappings | **works with X**: file-backed `mmap(PROT_EXEC)` of an unsigned file is refused (EPERM) in every variant; but mapping without PROT_EXEC (even clean, never-written, `MAP_PRIVATE` or `MAP_SHARED`, read-only) and calling `mprotect(PROT_READ|PROT_EXEC)` afterwards works and the code runs (also RX->RW->RX, anon RW->RX). RWX outside `MAP_JIT` is refused (EACCES) in every variant. Wine's existing `map_file_into_view` (mmap without PROT_EXEC, mprotect later) therefore works as is. |
| (c) spawn / 4K | **works with X**: 4K is NOT inherited by exec, `execve`, fork+exec or `posix_spawn` without the attribute (all become 16K); `POSIX_SPAWN_SETEXEC` + attribute keeps/creates 4K (also from a 16K process); the attribute on an unentitled binary (system tools) fails with rc 88. So every Wine spawn/exec of an entitled binary must carry the attribute, and Wine must never pass it to system binaries. |
| (d) low reserve | **works**: with the default image layout (optionally `-Wl,-x86_64_layout_emulation`, no effect on the output) the kernel's soft page zero is ONE VM entry `[0x1000, image base)` (image lands above 4 GiB, e.g. 0x102c39000), so the whole low 4 GiB is already reserved from the first instruction and nothing (dyld, shared cache, libraries, malloc, thread stacks, 7 `dlopen`s) lands below 4 GiB. Wine just keeps it and carves with `MAP_FIXED`. Small page zero values (0x10000) are worse (image and a stray allocation end up low); 0x1000/segalign 0x1000 = SIGBUS. |

## (a) x18 (`x18.c`, `x18b.c`, `out/a_x18.txt`)

Control (ad-hoc, no entitlement, plain) and every entitled variant, x18 used as an ordinary register (`x18.c`):
```
  immediate                          x18=0x1122334455667788 OK
  after raw svc getpid               x18=0x0000000000000000 CLOBBERED
  SIGUSR1: hits=1 handler-entry x18=0x0 (zero)
  24 threads x 3000000 iters: clobber count=70631; new-thread initial x18: zero=24
  400M-iteration busy loop (timer preemption): clobbers=164
RESULT NOT-PERSISTENT
```
(identical with and without `com.apple.security.custom-x18-abi-toggle`, 16K and 4K.)

With `os_set_custom_x18_abi_enabled(true)` (`x18b.c`), with and without the toggle entitlement, 16K and 4K, all four runs identical:
```
  toggle true+false pair: ~17 ns
  immediate / raw svc getpid / raw select(1ms) / mach trap swtch_pri / after SIGUSR1 return / after SIGSEGV return : x18 intact
  SIGUSR1 handler entry: x18=0x1122334455667788 custom_mode_at_entry=1 hits=1
  SIGSEGV handler entry: x18=0x1122334455667788 custom_mode_at_entry=1
  24 threads x 3000000 iters (raw swtch_pri + select sleeps): clobbers=0; initial x18 zero in 24/24
  400M busy loop (timer preemption): clobbers=0
RESULT PERSISTENT (syscalls ok, signals ok)
```
Without the cross-architecture entitlement (ad-hoc binary) `os_set_custom_x18_abi_enabled(true)` traps (rc 133).

Consequences for Wine (design input): (1) PE code runs with the custom mode on and x18 = TEB. (2) The Unix side (ntdll.so, libc, any
macOS code) must run with the mode off, so it cannot read the TEB from x18: the syscall/unix-call dispatchers and the signal handlers
must save x18, toggle off, and find the TEB through a TSD slot; on return toggle on and reload x18. (3) Signal handlers are entered
in custom mode with the interrupted x18 intact, so they must call `os_set_custom_x18_abi_enabled(false)` before touching libc.
(4) A new thread starts with the mode off and x18 = 0. (5) XNU source (`libsyscall/os/x18.c`, `osfmk/arm64/machine_task.c:333`):
the mode flag lives in TPIDR_EL0 bit 48; a binary linked with an SDK < 13.0 would get `preserve_x18_always` (x18 preserved without the API),
a possible fallback that was not tried.

## (b) executable mappings (`mapexec.c`, `out/b_mapexec.txt`; identical at 0x400000, 0x10000000, 0x7ffe0000 and in all 4 variants)

Variants: hardened runtime; + `allow-unsigned-executable-memory`; + `disable-executable-page-protection`; no hardened runtime.
```
  b1 mmap(R|X, PRIVATE|FIXED, file@0x1000) -> FAIL errno 1            (EPERM; also MAP_SHARED b7, also 0x2000-long b1b)
  b2 mmap(RW, PRIVATE|FIXED, file) -> ok;  b2 mprotect(R|X) after write -> 0;  b2 exec: executed, returned 42
  b2 mprotect(RWX) -> -1 errno 13 (EACCES)
  b3 anon RW fixed -> ok; mprotect(R|X) after write -> 0; exec: returned 42
  b8 RX->RW 0, write, RW->RX 0; exec#2 returned 43
  b4 anon RWX without MAP_JIT -> FAIL errno 13
  b5 anon RWX MAP_JIT|MAP_FIXED -> ok (write with pthread_jit_write_protect_np(0), exec returned 42)
  b9 clean MAP_PRIVATE RO -> mprotect(R|X) -> 0, exec returned 42;  b9s clean MAP_SHARED RO -> mprotect(R|X) -> 0
```
Consequence: Wine's `map_file_into_view` already maps without PROT_EXEC and applies it through `mprotect` later, which works; `PAGE_EXECUTE_READWRITE` for ordinary PE memory cannot be honoured literally
(RWX only inside `MAP_JIT`), so Wine must degrade it (RW now, switch to RX on demand). Guest x86 code is never executed natively (translator JIT lives in `MAP_JIT`).

## (c) spawn / exec / 4K inheritance (`spawn4k.c`, `out/c_spawn.txt`)

```
start 4K  exec_attr   (SETEXEC + 4k attr, same pid):   parent 4096/min 0x1000 -> exec'd image 4096/min 0x1000
start 4K  exec_plain  (SETEXEC, no attr):               parent 4096 -> exec'd image 16384/min 0x4000
start 4K  execve:                                       parent 4096 -> 16384
start 4K  spawn_attr  (child, 4k attr):                 child 4096
start 4K  spawn_plain (child, no attr):                 child 16384   (NOT inherited)
start 4K  fork+execve:                                  child 16384
start 4K  sys_plain   (/usr/bin/pagesize, no attr):     prints 16384, fine
start 4K  sys_attr    (/usr/bin/pagesize, 4k attr):     posix_spawn rc=88 (Malformed Mach-o file)
start 4K  exec_sys    (SETEXEC of /usr/bin/pagesize):   works, 16384
start 16K exec_attr:                                    parent 16384 -> exec'd image 4096
start 16K spawn_attr:                                   child 4096
```
Consequence: an unentitled 16K launcher can `posix_spawn(SETEXEC)` + attribute into the entitled Wine loader (no extra process needed); every
Wine `exec`/spawn of the entitled loader (`preloader_exec`, `exec_wineloader`, `reexec_loader`) needs `posix_spawn` + attribute. The wineserver is not entitled (probe e) and must be spawned WITHOUT the attribute.

## (d) low reserve (`lowres.c`, `out/d_lowres.txt`)

Default layout, 4K process, entitled: `min_address 0x1000`, image at `0x102c39000`, dyld shared cache `0x18fa50000 + 0x1cb0f8000`.
```
  0x00000001000-0x00102c39000  4239584K prot ---/---                         (the soft page zero: one entry; the image follows)
  reserve mmap(0x1000, 0xFFFFF000, PROT_NONE, FIXED|NORESERVE) -> ok         (replaces the low 4 GiB of that entry by our own)
  after hammering (4000 NULL-hint mmaps, 512MiB malloc, 8 threads, 7 dlopens incl. Metal/AppKit/CoreAudio/gnutls/freetype): allocations below 4 GiB = 0
  carve: 0x10000000 ok, 0x7ffe0000 ok, 0xfffe0000 ok, 0x1000 ok
```
`-pagezero_size 0x10000` (+emulation): image at 0x2e08000 (inside the range we want), reserve mmap EACCES, hole walk reserves 0xf6fc8000 bytes and
one stray allocation below 4 GiB appears. `-pagezero_size 0x1000 -segalign 0x1000`: killed by SIGBUS. A link-time zerofill reserve cannot sit below
the image in this layout, so the page-zero entry itself is the reserve. Note the shared cache and every system library are above 4 GiB, so there is no
conflict with a 4 GiB low reserve; the 4 GiB reserve is `[0x1000, 0x100000000)` (the image/stack/heap live at >= 0x100000000).

## (e) AMFI / profile discovery for the bundle layout (`amfi_layout.sh`, `out/e_layout.txt`)

```
Contents/MacOS/main  (CFBundleExecutable)            4K spawn OK
Contents/MacOS/second, Contents/Helpers/helper       posix_spawn rc=88 (profile not applied to non-main executables, although each is signed with the entitlements)
/tmp/.../symlink_main -> bundle main                 4K spawn OK (profile is found through the resolved path)
/tmp/.../hardlink_main (hard link of bundle main)    4K spawn OK (probably the vnode's cached validation: do not rely on it)
```
Consequence: the entitled loader must be the CFBundleExecutable of its own bundle (one bundle per entitled executable) and may be reached
through a symlink. `wineserver` does not run guest code and is left unentitled (plain 16K process).
