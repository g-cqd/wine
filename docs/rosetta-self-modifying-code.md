# Rosetta 2 and self-modifying code right ahead of the instruction pointer

Status: used by the Need for Speed (2015) runtime of this fork (`nfs2015-runtime-0010`). The workaround is off by
default in Wine and switched on by the packaging that ships the runtime. Everything below was measured on one Apple M1
Mac (macOS 27.2) with an x86_64 Wine under Rosetta 2; i386 processes and the native arm64 route are not covered.

## The defect

An x86-64 program that builds its own *next* instruction with two successive stores to the same bytes and then falls
into them does not behave as it does on an x86 CPU under Rosetta 2. Rosetta resumes one byte after the start of the
new instruction, the CPU decodes the instruction's second byte as another instruction and the process dies.

Smallest reproducer (`tests/nfs2015/wx/rosetta_smc.c`, native Mach-O, no Wine): a 23-byte stub in a private RWX page,

    53                           push rbx
    66 C7 05 09 00 00 00 90 F0   mov word [rip+9], 0xF090     ; stores 90 F0 at offset 19
    66 81 35 00 00 00 00 9F 52   xor word [rip+0], 0x529F     ; 0xF090 ^ 0x529F = 0xA20F -> 0F A2 (cpuid)
    00 00                        placeholder, becomes the next instruction
    5B C3                        pop rbx ; ret

runs 2000 of 2000 rounds into a fault at `page+0x14` (the cpuid starts at `page+0x13`); the fault address is the
operand of the misdecoded `a2 <moffs64>`. One store instead of two works (2000 of 2000). A gap of 1, 8 or 64 NOP bytes
between the stores and the built instruction fails the same way, and so does a single round in a fresh process.

Working hypothesis (not verified): Rosetta translates ahead after the first store using the intermediate bytes (`90` is
a one-byte NOP), the second store invalidates the translation, and execution resumes at the stale instruction boundary.

## Symptom in NFS16

`NFS16.exe` (anti-tamper code) dies at start-up or shortly after the display mode change with

    wine: Unhandled page fault on write access to 85BC35850173FF31 at address 0000000001B30159

The "bad pointer" is the operand of the misdecoded `a2` instruction. The page at `0x1B30000` is a private 4 KiB RWX page
holding junk-byte-obfuscated code; at offset `0x146` it builds a CPUID exactly like the reproducer above
(`mov word [rip+9], 0xF090` then `xor word [rip+0], 0x529F`) and falls into it. `rip` is `0x...159`, the second byte.
It happened with MetalFX on and (less often, with other signatures) without, and with every Wine runtime tried.

## Workaround: W^X emulation (`WINE_RWX_WX_EMULATION=1`)

Private committed `PAGE_EXECUTE_READWRITE` pages (not image sections, file views or system views) are mapped R+X on
the host. A store faults, the page is opened for exactly that one instruction with the trap flag and closed again by the
single-step trap, so Rosetta sees every store as its own event and retranslates before the next instruction.
x86_64 Wine under Rosetta only; off by default.

Pages are *released* (left writable until their protection changes or they are freed) when they are written from host
code or by the kernel (`read`, `recvmsg`, server replies), when a store is done from another process, and when a pure
data page is hammered (`WINE_RWX_WX_HOT_LIMIT`). Details added by later patches:

- 0009: the step trap can arrive while the thread is still in Rosetta's signal-return trampoline, before the store has
  run. Clearing the trap flag there left the guest with a stray single-step (found when EA's own Chromium process died
  with an unhandled `EXCEPTION_SINGLE_STEP`); a step trap on the signal stack is now left alone, thread-context captures
  close the window and strip the flag first, and a store that straddles two protected pages no longer livelocks.
- 0010: a page that has seen a store from code on or next to it is never released for being busy
  (`WINE_RWX_WX_NEAR_LIMIT`, default 0 = never). With the old busy limit the stub page was released after about 2000
  runs and the next run crashed. The released state is evaluated again after any protection change or decommit.
  Faults under the trap-flag emulation are emulated like any other (`WINE_RWX_WX_TF_RELEASE=1` restores the old release).

Cost: about 62-77 microseconds per store while a page is protected, about 0.2 microseconds once it is released.

## Environment variables

| variable | meaning |
| --- | --- |
| `WINE_RWX_WX_EMULATION=1` | enable the W^X emulation (default off) |
| `WINE_RWX_WX_HOT_LIMIT=<n>` | stores per second after which a pure data page is released (default 4096, 0 = never) |
| `WINE_RWX_WX_NEAR_LIMIT=<n>` | the same for pages that patch code next to themselves (default 0 = never release) |
| `WINE_RWX_WX_TF_RELEASE=1` | give a page up for good when it faults under the trap-flag emulation (old behaviour) |
| `WINE_RWX_WX_LOG=<hexstart>-<hexend>\|all` | per-page log, at most 200 lines per process |
| `WINE_ROSETTA_FLUSH_TOGGLE=1` | `NtFlushInstructionCache` re-toggles the executable pages of the range (did not help for this defect) |
| `WINE_ROSETTA_PROTECT_TOGGLE=1` | the same when `NtProtectVirtualMemory` gives a range an execute bit (did not help) |
| `WINE_TRACE_PAGE=<hexstart>-<hexend>` | numeric `wine-trace:` lines for allocate/free/protect/write/flush/map/unmap in the window |

Log lines: `wine-rwx: active pid=<n> first page <addr>` and, at process exit,
`wine-rwx: pid=<n> stores=<n> released(host=<n> carrier=<n> hot=<n>)`; with `WINE_RWX_WX_LOG`:
`wine-rwx: page <a> protect(reason=alloc|commit|protect|other) vprot=<hex>`,
`skipped(reason=flags|noview|notvalloc|system|released)`, `store #<n> rip=<hex> tid=<hex>` for the first five stores,
`release(reason=hot|hot-smc|host|host-kernel|cross|tf) stores=<n>` and
`released state dropped after a protection change`.

## Crash-context block (patches 0005 and 0006)

`winedbg` cannot get a context for these crashes under Rosetta ("Couldn't get first exception"). `start_debugger` in
`dlls/kernelbase/debug.c` therefore prints a block of `wine-crash:` lines before it starts the debugger: `begin`,
`access=`/`target=`, registers (64-bit and 32-bit forms), `pc` page state and module, `pc-bytes[16]`, the target page,
`stack[...]`, `tf state=`, `vq[...]` for the page and its neighbours, `pagesum` (FNV-1a 64 and the count of zero
16-byte runs), `threads=`/`teb=`, `ret[n]=` as module+offset, `window <reg>=` with `code[addr]:` rows of 32 bytes
(256 bytes either side of pc), `near-pc:` and `end`. The first real capture is what showed the page was executing
non-code bytes.

## Tests

`tests/nfs2015/wx/` (see its README) and `tests/nfs2015/crash-context*`. On the shipped build every test passes with the
emulation on; the reproducer faults 100% of rounds with it off and 0% with it on, including with four spinning threads,
the trap-flag emulation armed through a debug-register thread, fresh pages and the fixed address `0x1B30000`.
A Chromium-like stress (threads storing into RWX pages while another suspends them and reads their contexts) gave
4-21 stray single-steps per 8 s run on the 0008 patch in 7 of 8 configurations and none with 0009 and later.

## Real game

With patch 0010, W^X emulation on and MetalFX at 1.33x, `NFS16.exe` ran past the display mode change that used to kill it
within seconds. That is one observation by the owner, not a statistical result; the log showed the stub page protected
from allocation and never released.

## Open items

- Not verified: i386 processes, the native arm64 route (there the translator has its own handling of stores into code),
  longer sessions and several launches, mixed code/data pages that are written heavily (they cost a fault per store).
- A bug report with the minimal reproducer was prepared for Apple (Feedback Assistant) by the owner.
