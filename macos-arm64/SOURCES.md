# Downloads and sources

| What | URL | Date | Size | sha256 | Licence |
|---|---|---|---|---|---|
| llvm-mingw 20261006 (ucrt, macOS universal; clang 23.1.3, aarch64/arm64ec/i686/x86_64 mingw targets) | https://github.com/mstorsjo/llvm-mingw/releases/download/20261006/llvm-mingw-20261006-ucrt-macos-universal.tar.xz | 2026-10-07 | 124399776 B | a7a19b11048e89372637d26279cdb7c430ed3cf8c1e224310421312bf986ebf6 (equals the digest published by the GitHub release API) | Apache-2.0 with LLVM exceptions, MinGW-w64 ZPL/public domain |

Installed at `~/Developer/Games/bump-tools/llvm-mingw` (768 MB, outside this repo; tarball deleted).

Wine source (`src/`, its own git repo, branch `arm64-macos`): shallow clone of the local athei/wine tree (CrossOver cx-26-patched 'wine-11.0', `/Users/gc/Developer/Games/wine-rebuild/src/wine`, used read-only) at the unpatched base commit `1a7b0c766262276e7e7bb50c80abe5ccd08e292b` ("ntdll, win32u: Let compatdb.so set the process DPI awareness."), as instructed by the coordinator. LGPL-2.1+.
The earlier `wine-cursor-src` tree (NFSMW-tools) was evaluated and dropped: it is an older snapshot of the same lineage; `docs/cursor-vs-base.diffstat` lists the 10 files that differ (the base is newer: it adds the compatdb DPI hack and bug fixes); nothing from it is needed for arm64.

Homebrew (arm64, /opt/homebrew) packages used from the existing install, nothing new installed: bison 3.8.2, flex 2.6.4 (system /usr/bin/flex), freetype, gnutls, sdl2/sdl3, pkgconf.

## Rebase onto athei/wine cx-26-patched (2026-10-08)
`git fetch --depth=50 https://github.com/athei/wine.git cx-26-patched` (read-only, in `src/`), tip `d23b3977452` ("loader: Substitute Menlo for Lucida Console."), Wine 11.0 stable `db11d0fe6a` + 15 commits.
Old base `1a7b0c7` is not an ancestor (force-push); old->new tree diff = 4 files (loader.c, process.c, unix_private.h, virtual.c).

## Rebase onto g-cqd/wine development (2026-10-08)
`git fetch https://github.com/g-cqd/wine development` (read-only), tip `9bd6d74b374` (= athei cx-26-patched `d23b3977452` + 9 commits: NFS patches, winemac cursor fixes, get_thread_times, vkd3d msl cache).

## Rebase onto g-cqd/wine main (2026-10-15)

`git fetch /Users/gc/Developer/wine main` (read-only, in `src/`), tip `e3401db4bb0` ("docs: explicitly open the scope to anti-tamper..."; wine is single-main now, `UPSTREAM.md`). The tip is `9bd6d74b374` + ~70 commits: ntdll raw-syscall emulation for the EA anti-cheat loader, the x86 W^X emulation series, kernelbase crash-context, winemac full-screen/cursor work, the out-of-tree build directory, tests, docs.
Branch `arm64-macos-onto-main` (in `src/`) = `e3401db4bb0` + the same 12 commits; one linear history. Export: `patches-onmain/0001..0012`, tip `ea77693`. The 13th commit of the series (prefix-creation noise: winebth/wineusb/wow64-rounds/setupapi) was merged into g-cqd/wine main as `e640179a62b`, and the series was rebased on top of it on 2026-10-15: base `e640179a62b`, export `patches-onmain/0001..0012`, tip `20a817a`.

llvm-mingw 20261006 was re-downloaded and sha256-verified (`a7a19b11...`) after `~/Developer/Games/bump-tools` was wiped; same release, same digest, installed back at the documented path.
