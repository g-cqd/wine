# Native arm64 macOS Wine bring-up (milestone M1)

Status (2026-10-08, M1 / macOS 27.2): **M1 passes.** A native arm64 macOS Wine (Wine 11.0 + CodeWeavers patches, athei/wine `cx-26-patched`
base `1a7b0c7`) built with llvm-mingw runs, as an entitled 4 KiB-page process with the low 4 GiB reserved:

```
$ WINEPREFIX=/tmp/wa64-pfx/p2 host/exec4k install/usr/local/bin/wine cmd /c ver
Microsoft Windows 10.0.19045                      (rc 0; first run creates the prefix, ~5 s; warm runs 0.05 s)
$ WINEPREFIX=/tmp/wa64-pfx/p1 host/exec4k install/usr/local/bin/wine tests/hello_arm64.exe     # arm64 PE, WriteFile + ExitProcess
hello from arm64 PE on native arm64 Wine          (rc 0)
$ WINEDEBUG=+virtual ... | grep host            ->  virtual_init host page size: 4k / host addr space limit: 0x7ffffdff0000
```
No Rosetta, no x86 code anywhere. SIP/AMFI/boot-args untouched; only the owner's Developer ID + the `winehost` provisioning profile (never committed).

Batch 2 (same day) fixed winedevice's NULL heap, FreeType/GnuTLS lookup and RWX memory: see "Batch 2" and "Known issues" at the end (no 32-bit x86 execution yet = M2).

## Layout (now `macos-arm64/` inside the wine repository)

The arm64 workspace lives in `macos-arm64/` of this wine repo (merged 2026-10-15; the former
this repository's `macos-arm64/` standalone repo is retired). The wine source is the repository itself:
the arm64 enablement series is part of `main`, and `patches-onmain/` is its export.

| path | content |
|---|---|
| `../` (the repository) | Wine source; the 12-commit arm64 macOS enablement series is merged into `main` (base of the series: `e640179a62b`) |
| `scripts/build-arm64.sh` | configure + make (llvm-mingw at `~/Developer/Games/bump-tools/llvm-mingw`, explicit path, never `/opt`) |
| `scripts/make-host.sh` | builds the signed `winehost.app` from the `make install` tree, symlinks, launcher |
| `scripts/exec4k.c` | unentitled launcher: `POSIX_SPAWN_SETEXEC` + `posix_spawnattr_set_4k_page_size_np` |
| `scripts/gen-apple-stack-thunks.py` | generates the Darwin-ABI syscall adapters (item 7 below) |
| `probes/` | the five risk probes with sources, raw outputs (`out/`) and `RESULTS.md` |
| `tests/hello_arm64.c` | arm64 PE console test |
| `build/`, `install/`, `host/` | ignored: build tree (5.4 GB), `make install` tree (1.6 GB), signed bundle (contains the profile copy: never commit) |
| `SOURCES.md` | downloads (llvm-mingw 20261006, sha256 verified) and source provenance |

Base: the `wine-cursor-src` rsync copy was dropped on the coordinator's instruction in favour of the unpatched athei/wine commit
`1a7b0c766262276e7e7bb50c80abe5ccd08e292b` (shallow clone of `/Users/gc/Developer/Games/wine-rebuild/src/wine`, used read-only). The cursor tree
is an older snapshot of the same lineage; `docs/cursor-vs-base.diffstat` lists the 10 files that differ (the base is newer: it adds the compatdb
DPI hack, dwarf div-by-zero guard, freetype/sysparams fixes, winemac cocoa changes). Nothing from it is needed for arm64; no NFS-specific patch was carried.

## Rebuild

```
cd macos-arm64
./scripts/build-arm64.sh --clean        # configure (arm64, --enable-archs=aarch64,i386, --with-mingw=llvm-mingw, no vulkan/x11/...) + make -j3 (~35 min on a loaded machine)
(cd build && make install DESTDIR=$PWD/../install)
./scripts/make-host.sh                  # EXTRA_ENT="com.apple.security.cs.allow-dyld-environment-variables" to allow DYLD_* vars
mkdir -p /tmp/wa64-pfx && WINEPREFIX=/tmp/wa64-pfx/p1 host/exec4k install/usr/local/bin/wine cmd /c ver
```
Notes: Homebrew's GNU `i686-w64-mingw32-gcc` would shadow llvm-mingw for `winegcc`'s test links, hence llvm-mingw is first on PATH for `make` (the
script does it) but last for configure (llvm-mingw's bare `clang` must not replace Apple's). The prefix must live in a directory you own
(`/tmp/wa64-pfx`, not `/tmp` itself: Wine refuses to create a config dir in a directory it does not own). Run builds through
`/Users/gc/.agent-harness/bin/work run --weight 3 --kind build -- ./scripts/build-arm64.sh make` on the shared machine.

## What was changed in Wine and why (patches in `patches/`, in order)

1. **configure**: the aarch64 loader links with the default 4 GiB `__PAGEZERO` + `-Wl,-x86_64_layout_emulation`; the x86 flags
   `-pagezero_size 0x1000 -segalign 0x1000` make the arm64 image unloadable (probe d: SIGBUS / ENOMEM). `configure` was edited by hand next to `configure.ac`
   (autoconf 2.73 would rewrite 4000 lines of the 2.72 file).
2. **loader/main.c**: arm64 `wine_main_preload_info` = `{0x1000, 0xfffff000}` and a `MAP_FIXED|PROT_NONE` re-creation at startup. The kernel leaves the unused part of
   the 4 GiB page zero as ONE soft entry `[0x1000, image base)` (image lands at ~0x102xxxxxx), so nothing (dyld, shared cache at 0x18...,
   libraries, malloc, stacks) can be placed in the low 4 GiB; Wine only has to know that the range is its own. The bundle-name rewrite that writes into signed `__TEXT` is skipped on arm64.
3. **ntdll/unix/loader.c**: `spawn_wine_binary()` = `posix_spawn` + `posix_spawnattr_set_4k_page_size_np` (+ `POSIX_SPAWN_SETEXEC` for the loader re-exec in
   `preloader_exec`). 4K is not inherited by exec/fork+exec/spawn (probe c). No exe-name hard-link hack (CW 22144: the exec path must stay inside the bundle that
   carries the profile), no Rosetta x87 sidecar and no cooperative handshake on arm64.
4. **winemac.drv** (two patches): `WineMetalLayer` and `macdrv_client_surface_presented` belong to the x86_64-only D3DMetal hooks (`d3dmetal*.c/m` are `#if __x86_64__`).
5. **ntdll/unix/signal_arm64.c, x18 protocol** (probe a): the OS zeroes x18 on every syscall/interrupt/switch unless the thread is in the "custom x18 ABI" mode
   (`os_set_custom_x18_abi_enabled`, macOS 26.4+, granted by the cross-architecture entitlement alone). PE code runs in that mode with x18 = TEB; the Unix side runs
   with it off and finds the TEB through the pthread TSD (`NtCurrentTeb()` already is a TSD lookup for all Unix code in this Wine). Toggles:
   - `__wine_syscall_dispatcher`: TEB moved to x24, args x0-x8 spilled, mode off, then the usual dispatch; on return the mode is switched on after the
     `syscall_dispatcher_return_slowpath` decision (the slow path raises SIGUSR2 and the signal wrapper re-enters PE mode), before x18/x19 are reloaded;
   - `__wine_unix_call_dispatcher`: same, around the unix call; `call_user_mode_callback`: TEB kept in x19, mode on right before `br`;
   - the global `__wine_syscall_dispatcher_return` stub reads the TEB from x24 (set by `handle_syscall_fault`, which resumes in Unix mode);
   - every signal handler is wrapped (`x18_signal_entry`): handlers are entered in PE mode when they interrupt PE code, run in Unix mode, and the mode is restored
     when the resumed context is PE (interrupted PE code, or `usr2_handler`'s installed PE frame). A redundant toggle aborts the process, so every transition is paired.
6. **wineserver stays unentitled** (probe e: only the CFBundleExecutable of a bundle gets the profile): plain `posix_spawn`, 16K pages; it runs no guest code.
7. **ntdll + win32u, Darwin stack-slot adapters** (found by the first `NtMapViewOfSection` with `protect == 0`): the PE caller (Windows ARM64 ABI) gives every stack argument an
   8-byte slot, Apple's ABI packs small ones. 43 syscalls with more than 8 arguments get generated thunks taking 64-bit slots (`apple_stack_thunks*.h`, table
   renamed only around the syscall table); only ~19 actually differ, the thunk is uniform. Regenerate with `scripts/gen-apple-stack-thunks.py src`.
8. **virtual.c**: on macOS the host address-space limit comes from `task_info(TASK_VM_INFO).max_address` (mmap hint probing cannot find it; it produced
   endless `try_map_free_area` errors above 0x7ffffe000000).

Not touched because they are x86-only by construction (`#if __x86_64__` already): `server.c:2004` msthunk, `sync.c`, `thread.c` hacks, `winemac.drv/d3dmetal*`.

## Signing and spawn recipe (what works, `scripts/make-host.sh`)

- Developer ID Application `7492E391094B7E2B51A7A5D14CBB9CFBF29FB277`, hardened runtime (`--options runtime`), entitlements
  `com.apple.developer.cross-architecture-support`, `com.apple.application-identifier` = `NP94WB3P75.fr.gcqd.winehost`, `com.apple.developer.team-identifier`,
  `cs.allow-jit`, `cs.disable-library-validation` (needed to dlopen the ad-hoc signed `ntdll.so`/`*.so`). `custom-x18-abi-toggle` is NOT needed.
- The loader must be the `CFBundleExecutable` of `winehost.app` with `Contents/embedded.provisionprofile`; other executables in the bundle do not get the profile
  (posix_spawn rc 88). A symlink to the bundle executable works (`install/usr/local/bin/wine` and `.../lib/wine/aarch64-unix/wine` are symlinks, so Wine's
  installed-layout logic and `loader_exec` find it). `Contents/MacOS/ntdll.so` is a symlink to the installed `ntdll.so` because `loader/main.c` dlopens `dir-of-real-exe/ntdll.so`.
  The symlinks are created after signing (they point outside the bundle: `codesign --verify --deep --strict` of the bundle will complain; AMFI only checks the main executable and the profile).
- The outermost process is started by `host/exec4k <wine> args...` (unentitled, `POSIX_SPAWN_SETEXEC` + 4K attribute); all further loaders are re-exec'd by Wine itself with the same attribute.
- Run from the install layout, not the build tree: in build-tree mode Wine re-execs `build/loader/wine`, which cannot be a bundle main executable.

## Probe results (details and raw output in `probes/RESULTS.md`)

| probe | result |
|---|---|
| (a) x18 | works with X: persistent only in `os_set_custom_x18_abi_enabled(true)` mode (survives syscalls, SIGUSR1/SIGSEGV, 24 threads, timer preemption, 400M-iteration loop; handlers are entered in that mode with the interrupted x18; ~17 ns per toggle pair) |
| (b) exec mappings | works with X: `mmap(PROT_EXEC)` of unsigned files is EPERM everywhere, but `mmap` without exec + `mprotect(R\|X)` works (clean file mappings too); RWX only in `MAP_JIT` regions |
| (c) spawn/4K | works with X: 4K is never inherited; SETEXEC + attribute works (from a 16K or 4K parent); attribute on an unentitled binary = rc 88 |
| (d) low reserve | works: default layout = one soft page-zero entry, nothing lands below 4 GiB; `-pagezero_size 0x10000` is worse, `0x1000/-segalign 0x1000` = SIGBUS |
| (e) bundle layout | profile applies to the bundle's main executable only; symlinks to it work |

## Batch 2 (2026-10-08): fixes after M1

| commit (src, branch `arm64-macos`) | fix |
|---|---|
| `4dffdcd`, `a3433d0` | SIGBUS permission faults; RWX policy (fixes the NULL heap) |
| `cbf1476` (outer repo, `scripts/build-arm64.sh`) | `@rpath` sonames + rpath for freetype/gnutls/SDL2 |

1. **NULL heap in winedevice (cause found).** `ntoskrnl.exe` does `ntoskrnl_heap = HeapCreate( HEAP_CREATE_ENABLE_EXECUTE, 0, 0 )`; the heap's
   `NtAllocateVirtualMemory(PAGE_EXECUTE_READWRITE)` failed (`mprotect` RWX is EACCES on macOS arm64, status `c0000017` was visible in x24), the global stayed NULL and
   the first `ExAllocatePool*` crashed in `RtlAllocateHeap(NULL,...)`. Fixed by the RWX policy below. Evidence: no more `unsafe_heap_from_handle`/`Unhandled page fault`
   with `err+all,+seh` during `wine cmd /c ver`, `net start winebus`, `sc query`; `tests/rwx_arm64.exe` passes `HeapCreate(HEAP_CREATE_ENABLE_EXECUTE)`.
2. **macOS arm64 reports page-permission faults as SIGBUS** (write to an RX page, execute of an RW page, any access to PROT_NONE; si_code BUS_ADRALN, only ESR tells them
   apart from real alignment faults; probed with a C program). `bus_handler` now routes EC 0x20/0x21/0x24/0x25 with DFSC != 0x21 to `segv_handler`. This also makes guard pages,
   stack growth and write watches work, which relied on SIGSEGV.
3. **RWX policy (`PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_WRITECOPY`; `virtual.c`)**:
   - `get_unix_prot()`: a vprot with EXEC and WRITE/WRITECOPY maps to host RW (no PROT_EXEC). The requested protection stays in Wine's vprot, so `VirtualQuery`/`VirtualProtect`
     report what the guest asked for.
   - *Native arm64 code*: W^X toggle on fault in `virtual_handle_fault`: execute fault on such a page => `mprotect(R|X)` + icache flush, write fault => `mprotect(R|W)`. Both are idempotent
     (no extra state), per 4 KiB host page. Cost: one fault + mprotect per RW<->X transition (JIT-style code that keeps writing next to code will be slow).
   - *x86 guest memory* (WoW64 process, page below 4 GiB): never flipped, stays RW; the translator reads it as data and executes only its own `MAP_JIT` output. An execute fault there is an ordinary access violation.
   - The CodeWeavers x86-Rosetta fault hacks (24945, 25719, "read fault is write fault") are compiled out on arm64 (`virtual.c`).
   - Tested: `tests/rwx_arm64.exe` (VirtualAlloc RWX, run, rewrite, run again, VirtualQuery, VirtualProtect RW->RWX, executable heap) passes. The WoW64/below-4GiB branch is untested because no
     32-bit process can run before the BTCpu exists (M2); it is a one-line condition.
4. **FreeType/GnuTLS/SDL2**: configure is run with `ac_cv_lib_soname_{freetype,gnutls,SDL2}=@rpath/<lib>` and `LDFLAGS=-Wl,-rpath,/opt/homebrew/lib`, so every Wine `.so` has
   `LC_RPATH /opt/homebrew/lib` and `dlopen("@rpath/libfreetype.6.dylib")` finds the Homebrew copy (DYLD_* variables are ignored by the hardened loader; a bare leaf name is not
   searched in /opt/homebrew/lib). Evidence: `+font` shows `init_freetype FreeType version is 2.14.3`, fonts load; `tests/font_tls_arm64.exe` gets a width/height from
   `GetTextExtentPoint32W` with face `Tahoma` and `AcquireCredentialsHandleW(SChannel)` returns `SEC_E_OK` with no `winediag` message. Needs a reconfigure (`./scripts/build-arm64.sh --clean`, ~17 min).
5. Regression after each step: `scripts/m1-check.sh` (fresh prefix: `cmd /c ver`, `hello_arm64.exe`, `reg query HKLM\Software`) passes. `scripts/refresh-host.sh` = `make install` + re-sign.

## Known issues / next steps

- ~~`winebth.sys` fails to load; `wineusb.inf` copy error 1812; `rundll32.exe` in `C:\windows\sysarm32`~~: fixed upstream (g-cqd/wine main `e640179a62b`) — see the
  "Prefix-creation noise: fixed" section below. A fresh prefix now prints only the generic upstream COM marshaling noise.
- `sc query` for an unknown service reports 1060 as expected; there is no console command here that prints the driver list on this Wine.
- Patches 2-3 assume the 4 GiB low area is wanted for all processes; the 64-bit PE preferred base 0x140000000 is above it (PE images are relocated).
- M2 prerequisites already present: `--enable-archs=aarch64,i386` builds `i386-windows` PE dlls, `wow64.dll`/`wow64win.dll` for aarch64; the BTCpu DLL is r3-wow64's (branch `wow64-cpu`, `src-wow64`).
- Hard link of the bundle executable outside the bundle also got the 4K spawn through, probably from a cached vnode validation: do not rely on it.

## M4 preparation: mtld3d (D3D9 to Metal) on the native arm64 Wine (2026-10-08, build and headless proof only)

Source: read-only clone `mtld3d/` (`git clone --local` of `/Users/gc/Developer/mtld3d`, branch `development`, tip `7d108a4`; the original is untouched; ignored by git).
Toolchain: `toolchain/` = APFS clone of the shared `~/Games/bump-tools` Rust 1.99.0 (the shared copy is NOT modified) plus `aarch64-pc-windows-msvc` and `arm64ec-pc-windows-msvc`
rust-std; llvm-mingw 20261006 (lld-link 23.1.3, satisfies the ">= 23" rule). `scripts/mtld3d-env.sh` sets the paths.

```
./scripts/build-mtld3d.sh      # (work run --weight 3 ...)  ->  mtld3d/out-arm64/{mtld3d.so,mtld3d.dll,d3d9.dll,native/d3d9.dll,*.pdb}   (~2 min cold)
./scripts/install-mtld3d.sh    # mtld3d.dll -> install/.../aarch64-windows, mtld3d.so -> aarch64-unix, test prefix /tmp/wa64-pfx/d3d, d3d9=native override
```
What is built (all native arm64): `mtld3d.so` (Mach-O arm64, 3.7 MB, links Metal/MetalFX/AppKit/QuartzCore/CoreVideo), `d3d9.dll` and `mtld3d.dll` as plain `IMAGE_FILE_MACHINE_ARM64`
PEs (`d3d9.dll` exports `Direct3DCreate9`, `D3DPERF_*`). There is no d3d8 and no dxgi for aarch64: `windows/d3d8` is only built for i686/x86_64 by mtld3d's Makefile, and mtld3d has no dxgi.
`build-mtld3d.sh` produces two `d3d9.dll`: the builtin-marked one (`out-arm64/d3d9.dll`, would replace Wine's d3d9 if copied into `lib/wine/aarch64-windows`) and the unmarked
`out-arm64/native/d3d9.dll` for the native-override route, which is what `install-mtld3d.sh` uses (Wine's own d3d9 stays; only the new names `mtld3d.dll`/`mtld3d.so` are added to the install tree).
Route used = "native override" of mtld3d `INSTALL.md`: `HKCU\Software\Wine\DllOverrides d3d9=native`, `d3d9.dll` next to the program (`host/d3dtest/`), `mtld3d.dll` stamped into the prefix by `wineboot`
because it was installed before the prefix was created.

### Why not `EC=1 make`
`EC=1` links ARM64X images (ARM64 + ARM64EC halves) and needs Wine's ARM64X link archives (a Wine built with `--enable-archs=arm64ec,aarch64`); our build has `aarch64,i386`
and the EC half only serves x64 processes. We build the ARM64 half alone and link `/machine:arm64` ourselves with the same lld-link command line as the Makefile minus the EC bits.

### mtld3d build issues found (for the mtld3d owner)
1. `windows/shim/build.rs:96` panics on any non-ARM64X aarch64 Wine: `libwinecrt0.a carries no aarch64-windows/unix_lib.o`. Reproducer: `llvm-ar t <wine>/lib/wine/aarch64-windows/libwinecrt0.a` lists a bare
   `unix_lib.o`; `WINE_SDK=<that wine> cargo rustc --target aarch64-pc-windows-msvc -p mtld3d --crate-type staticlib` in `windows/`. Fix: fall back to the bare member name when no `<arch>/unix_lib.o`
   exists. Workaround here: `build-mtld3d.sh` re-packs the member under the expected path (llvm-ar strips directories, so the ar file is written by hand).
2. `windows/.cargo/config.toml` points the C/C++ include paths of the aarch64/arm64ec targets at `/opt/xwin` (MSVC SDK, needs `sudo make setup`). Without it snmalloc-sys fails with llvm-mingw's clang:
   `pal_windows.h:254: use of undeclared identifier 'abort'`. Workaround: compile snmalloc with `-include cstdlib` against llvm-mingw's headers (env `CXXFLAGS_aarch64_pc_windows_msvc`, see script).
3. The Makefile's `RUST_STABLE ?= stable` assumes a rustup channel named `stable`; our pinned toolchain is `1.99.0` (the script calls cargo directly, `make unix-arm64 RUST_STABLE=1.99.0` also works).
4. `EC=1` has no ARM64-only (non-hybrid) leg; a native arm64 Wine without ARM64X archives cannot use the build as is.

### Headless proof (`tests/d3d9_load_arm64.c`, no device, no window)
```
$ WINEPREFIX=/tmp/wa64-pfx/d3d host/exec4k install/usr/local/bin/wine reg query 'HKCU\Software\Wine\DllOverrides'
    d3d9    REG_SZ    native
$ WINEPREFIX=/tmp/wa64-pfx/d3d host/exec4k install/usr/local/bin/wine host/d3dtest/d3d9_load_arm64.exe
d3d9.dll base          = 0x00006ffffcb90000
d3d9.dll path          = Z:\Users\gc\Developer\wine-arm64\host\d3dtest\d3d9.dll        (native, from the app dir)
Direct3DCreate9        = 0x00006ffffcb915b0
mtld3d.dll base        = 0x00006ffffcb20000                                            (+loaddll: C:\windows\system32\mtld3d.dll builtin, d3d9.dll native)
```
`mtld3d.so` is loaded lazily by the builtin `mtld3d.dll` (no `+unix` trace line exists for it in this Wine); proof that it is mapped into the arm64 process: run the probe with the argument `wait`
(sleeps 6 s) and `vmmap <pid> | grep mtld3d` shows `__TEXT ... /Users/gc/Developer/wine-arm64/install/usr/local/lib/wine/aarch64-unix/mtld3d.so`. `scripts/m1-check.sh` still passes.

### Plan for the on-screen triangle test (NOT run; needs the owner's agreement: opens a 336x279 window for 5 s and creates a Metal device)
Program: `tests/d3d9_triangle_arm64.c` (compiled to `host/d3dtest/d3d9_triangle_arm64.exe`, arm64 PE): registers a window class, creates the window, `Direct3DCreate9`, `CreateDevice` (windowed, HAL),
then for 5 s `Clear` (dark blue 0xff102040), `DrawPrimitiveUP` of one TL-FVF triangle (red, green, blue vertices, no shaders), `Present`, and prints `frames presented`.
Command (from this repository's `macos-arm64/`, prefix created by `scripts/install-mtld3d.sh`):
```
WINEPREFIX=/tmp/wa64-pfx/d3d WINEDEBUG=err+all,+loaddll host/exec4k install/usr/local/bin/wine host/d3dtest/d3d9_triangle_arm64.exe
```
Expected: console lines `Direct3DCreate9 -> 0x...` (non-zero), `CreateDevice hr = 0x0000000000000000`, one window with a blue background and a gradient triangle, then `frames presented = N` (N in the hundreds if vsync is
not forced) and rc 0. Likely first failures, in order: (1) winemac.drv cannot create the window in a non-bundled, non-GUI-launched process (LSUIElement is set in `winehost.app`, may need `LSUIElement=false`);
(2) `CreateDevice` fails because mtld3d needs a Metal device handle from winemac (`macdrv` view / CAMetalLayer): `WINEDEBUG=+d3d9,+macdrv` and mtld3d's own log (`mtld3d.conf`); (3) the winemac.drv x86-only
`d3dmetal` hooks are compiled out on arm64, which mtld3d does not use. Success criteria: nonzero frames, no `err:` lines mentioning mtld3d, `vmmap` shows `Metal.framework` mapped.
Cleanup after the run: `wine wineserver -k` (`install/usr/local/bin/wineserver -k` with the same WINEPREFIX), `rm -rf /tmp/wa64-pfx/d3d`.

## Rebase onto the force-pushed `cx-26-patched` (2026-10-08)

- New base: athei/wine `cx-26-patched` tip **`d23b3977452`** (Wine 11.0 stable `db11d0fe6a` + 15 commits). Old base `1a7b0c7` is not an ancestor. `git diff 1a7b0c7 d23b3977452` = 4 files:
  `dlls/ntdll/unix/loader.c` (+287: compatdb-decided x87sidecar, `get_x87_sidecar_path`, `set_compat_x87`, `query_compatdb_x87[_preinit]`, `get_first_process_target`, large-address-aware plumbing),
  `process.c` (+49: `NtCreateUserProcess` decides the x87 sidecar before fork), `unix_private.h` (+5), `virtual.c` (+20: `virtual_recheck_large_address_space`).
- Branch `arm64-macos-rebased` (in `src/`) = `d23b3977452` + our 11 commits + 1 new; the old `arm64-macos` (base `1a7b0c7`) is untouched; `wow64-cpu` (src-wow64) is based on the old one.
  Series: `patches-rebased/0001..0012` (`git format-patch d23b397..`), tip `b92f4ed`.
- Conflicts: only the 4K-spawn commit (`aafe620`), in `loader.c`: the Rosetta block of `preloader_exec` and `x87_coop_unhooked` were rewritten upstream. Resolution keeps our semantics: the whole new
  sidecar block and the cooperative-handshake/unhooked-warning helpers stay `#ifndef __aarch64__`. configure, main.c, virtual.c, signal_arm64.c, winemac patches applied cleanly (the configure patch is by hand in
  both `configure.ac` and `configure`, still default 4 GiB soft page zero + `-x86_64_layout_emulation`).
- New commit `b92f4ed`: `get_x87_sidecar_path()` returns NULL on arm64, because the new `NtCreateUserProcess` calls it (and compatdb) before every i386 child and honours `ROSETTA_X87_PATH`; there is no sidecar on a native arm64 Wine.
  On arm64 the now-unused statics (`get_first_process_target`, `query_compatdb_x87_preinit`) compile as unused (warnings only). `virtual_recheck_large_address_space` (new, 4 GiB LAA for WoW64) is compatible with our RWX/limit changes; untested until M2.
- Verification on the rebased tree (incremental build in the existing tree, no reconfigure, 1.5 min): `scripts/m1-check.sh` (ver, hello, reg query) PASS; `rwx_arm64.exe` 5/5 ok; `font_tls_arm64.exe` (Tahoma 196x29, SChannel SEC_E_OK) ok;
  `d3d9_load_arm64.exe` on the mtld3d prefix ok (Direct3DCreate9 resolved, mtld3d.dll builtin loaded); no `unsafe_heap_from_handle`/page fault in `cmd /c ver`.
- The other session also plans to cherry-pick g-cqd/wine `7190c0da4 'configure: Don't shrink __PAGEZERO on arm64 macOS'`, which overlaps our first commit (`20c0848`): expect a conflict in `configure.ac` `WINELOADER_LDFLAGS` for aarch64; our version drops `-pagezero_size/-segalign` for aarch64 entirely, so theirs can supersede it.

## Series on top of g-cqd/wine `development` (2026-10-08)

- Base `9bd6d74b374` (g-cqd/wine `development` = athei `d23b3977452` + 9 commits: NFS patches touching signal_x86_64.c/thread.c/virtual.c/unix_private.h and server/{thread,mach}.c, winemac cursor fixes,
  `get_thread_times` for macOS, `virtual_read_executable_byte`, vkd3d msl cache). Branch `arm64-macos-onto-dev` (in `src/`), tip **`89a212b`** = base + the same 12 commits as `arm64-macos-rebased`; one linear history.
  Export: `patches-ondev/0001..0012`. All 12 cherry-picks applied without conflicts; no change was needed for coexistence (their patches are x86_64-host or generic; `get_thread_times`, `virtual_read_executable_byte` and the mach.c
  server changes compile on arm64 and read pages through `get_unix_prot`, so the RWX-as-RW policy keeps them valid). Tree diff to `arm64-macos-rebased` is exactly their 9 commits.
- Verification (incremental build 1 min 45 s, no reconfigure): `scripts/m1-check.sh` PASS (ver, hello, reg), `rwx_arm64` 5/5, `font_tls_arm64` (Tahoma 196x29, SChannel ok), `d3d9_load_arm64` ok, no heap fault in `cmd /c ver`.
- Authors/committers of all 12 commits: `Gigi <42325924+g-cqd@users.noreply.github.com>` (same form as `development`); no personal address.

## Rebase onto g-cqd/wine main (2026-10-15)

- New base `e3401db4bb0` (single-main wine, see `UPSTREAM.md` there) = the `9bd6d74b374` development base of the last rebase + ~70 commits, the big ones for us: the ntdll raw-Windows-syscall emulation (`winsyscall.c`, `win10_19045_syscalls.h`, x86_64-only), the x86 W^X-emulation series in `virtual.c` (+640), kernelbase crash-context snapshots, winemac full-screen/display/cursor work, the out-of-tree build directory, and the EA anti-cheat Zw-stub patches. `loader.c` grew `save/restore_rosetta_aot_env` around the sidecar handshake.
- Branch `arm64-macos-onto-main` (in `src/`) = `e3401db4bb0` + the same 12 commits; export `patches-onmain/0001..0012`, tip `ea77693`. Commits 1-2 and 4-12 applied cleanly; only the 4K-spawn commit (0003) conflicted, in `loader.c`, three hunks: the compatdb-x87 preinit block of `preloader_exec` (now wrapped whole in `#ifndef __aarch64__` with the guarded `rosetta_path/target` declarations), and the `x87_coop_unhooked`/`x87_cooperative_handshake` guards (`#if defined(__APPLE__) && !defined(__aarch64__)`). Upstream's `restore_rosetta_aot_env()` call in `__wine_main` stays unguarded: on arm64 the saved variable is never set, so it returns immediately.
- The upstream W^X emulation and our arm64 RWX-as-RW toggle coexist: theirs faults on and toggles x86 self-modifying private pages under Rosetta (x86_64 host), ours maps requested-RWX arm64 pages RW and toggles RX on execute faults; `get_unix_prot` keeps meaning the same thing for both.
- Toolchain: `~/Developer/Games/bump-tools` had been wiped; llvm-mingw 20261006 ucrt macos-universal re-downloaded, sha256 verified against SOURCES.md, reinstalled at the documented path.
- Signing: the old Developer ID hash `7492E391...` is gone from the keychain. `make-host.sh` now resolves the Developer ID Application identity dynamically (first valid one) when `ID` is unset. Two profiles exist in `~/Downloads`: `winehost_developer_id_2` embeds a certificate that is not in this keychain (SIGKILL at spawn); `winehost_developer_id` (no "2") embeds the `7208E67A` certificate that pairs with identity `F5A93858...` — that pairing works. The `PROFILE` default was fixed accordingly.
- Verification (clean configure + build, 43 min on the loaded machine; `refresh-host.sh`, then `m1-check.sh`): **ver / hello / reg PASS**; `rwx_arm64.exe` 5/5 (exec, rewrite-after-exec, VirtualQuery reports RWX, VirtualProtect RW->RWX, executable heap); `font_tls_arm64.exe` Tahoma 29px + SChannel SEC_E_OK. The known wow64 `rundll32 c0000135` noise during prefix creation is unchanged (M2 item).

## On-screen d3d9 triangle: RUN AND PASSED (2026-10-15, on the wine-main base)

The test the section above left unrun, now on the `arm64-macos-onto-main` build: `host/d3dtest/d3d9_triangle_arm64.exe`
under the d3d prefix (`WINEDEBUG=err+all,+loaddll`, 90 s timeout). Result, rc 0:

```
Direct3DCreate9 -> 0x0000000000b94240
CreateDevice hr  = 0x0000000000000000
frames presented = 0x000000000000d6dd   (54,497 frames in 5 s, ~10.9k/s, windowed, unthrottled)
```

None of the three predicted first failures happened: `winemac.drv` created the window in the non-GUI-launched process,
`CreateDevice` returned D3D_OK with the Metal device from the `CAMetalLayer` view, and the compiled-out x86 `d3dmetal`
hooks were not needed (mtld3d does not use them). This is the on-screen proof of D3D9 -> Metal on the native arm64 Wine.

mtld3d was rebuilt for this (the private `toolchain/` copy and `mtld3d/` clone had been wiped): fresh `git clone --local`
of `~/Developer/mtld3d` (main, `fcd099d`; the repo is main-only now, the old clone was development `7d108a4`), the shared
rustup in place of the private copy (`mtld3d-env.sh` falls back to `~/.cargo`/`~/.rustup` and now pins
`RUSTUP_TOOLCHAIN=1.99.0-aarch64-apple-darwin`, whose `aarch64-pc-windows-msvc` std was re-added), llvm-mingw as above.
Build 17 s; `install-mtld3d.sh` then the headless `d3d9_load_arm64.exe` (base/path/Direct3DCreate9/mtld3d.dll printed, ok)
before the on-screen run. Prefix removed after the run per the cleanup recipe.

## Prefix-creation noise: fixed (2026-10-15; merged into g-cqd/wine main e640179a62b)

A fresh prefix under `WINEDEBUG=err+all` printed twelve err lines; the diagnosis and the fix (merged into g-cqd/wine main `e640179a62b`, so it also benefits the x86_64 build; not part of the arm64 series):

| noise | cause | fix |
|---|---|---|
| `ZwLoadDriver ... winebth: c00000e5` + `SetupDiInstallDevice 1359/1062` | the unix `bluetooth_init` returns `STATUS_INTERNAL_ERROR` when there is no bluez dbus (macOS), and `DriverEntry` propagated it, so the service never started | `DriverEntry` treats it as "no radios": the driver loads, the service starts, every Bluetooth request returns `STATUS_NOT_SUPPORTED` |
| `SetupDefaultQueueCallbackW copy error 1812 '@%12%\wineusb.sys,-1'` | wine.inf's `[InfFiles]` extracts the driver inf from a resource of the .sys; `wineusb.sys` is not built on macOS | the copy-queue callback reports an unavailable source (file/path/resource errors) as a warning + skip, and `wineboot` skips a root device whose driver file is not installed |
| `wine: failed to start C:\windows\sysarm32\rundll32.exe: c0000135` | the wineserver of this build reports ARMNT as a supported wow64 machine in addition to i386, so wineboot ran a Wow64Install round per machine; `sysarm32` is the ARMNT dir and neither its (`wowarmhw.dll`) nor the i386 (`xtajit.dll`, or the `Wow64\x86` registry value) CPU DLL exists | `wineboot` mirrors wow64's `get_cpu_dll_name` and skips the round of any machine whose CPU DLL is not installed; the rounds return by themselves once a BTCpu (`r3wow64.dll`, M2) is staged and registered under `HKLM\Software\Microsoft\Wow64\x86` |
| `do_file_copyW Unsupported style(s) 0x10` ×4 | setupapi ERR-logs in-use/skip style flags it does not implement, although the copy proceeds | warn level, with wording that says the copy proceeds |

Verified: fresh prefix `err+all` 12 → 3 err lines (only the generic `CoMarshalInterface`/`apartment_get_local_server_stream` E_NOINTERFACE lines that upstream prints on every platform); `m1-check.sh` PASS (ver/hello/reg); `rwx_arm64.exe` 5/5; `font_tls_arm64.exe` Tahoma 29px + SChannel `SEC_E_OK`. Note the discovery along the way: the server's supported-machine list is `{aa64, i386, armnt}` — `sysarm32` is the ARMNT (not the i386) WoW64 directory.
