# Keeping this fork current

## Policy

- `main` is the only working branch of g-cqd/wine. No development or topic branches are pushed.
- Never force-push `main`. Never force-push the `master` branch on origin either (it is the upstream mirror; leave it alone).
- Never push to the `athei` remote; it is read-only upstream (https://github.com/athei/wine.git, branch `cx-26-patched`).
- Retired work lives in `archive/*` tags, not branches. The former `nfsmw-macos` patch branch is preserved by the tag `archive/nfsmw-macos-20261011`.
- History is never rewritten once pushed. Upstream updates are folded into `main` with merge commits (below).

## Clone once

```sh
git clone git@github.com:g-cqd/wine.git
cd wine
git remote add athei https://github.com/athei/wine.git
git fetch athei --tags
```

The source lives at `/Users/gc/Developer/wine`. Build output does not live in the tree; see `build-macos-x86_64.sh` (`WINE_BUILD_DIR`, default `/Volumes/ExT2/GameHub/build/wine`).

## Current upstream base

`athei/cx-26-patched` at `93429c6e7c8` ("loader: Substitute Menlo for Lucida Console."), folded into `main` by merge commit `d0953441aba` on 2026-10-14. Update this section whenever a sync lands.

To check for new upstream commits:

```sh
git fetch athei --tags
git log --oneline main..athei/cx-26-patched    # empty: main already contains upstream
```

## Pull an upstream update into main (no force-push)

Start from a clean working tree on `main`, up to date with origin:

```sh
git switch main
git fetch origin
git merge --ff-only origin/main
git fetch athei --tags
OLD_BASE=93429c6e7c8   # the "Current upstream base" above
```

Decide which path applies:

```sh
git merge-base --is-ancestor $OLD_BASE athei/cx-26-patched && echo "path A" || echo "path B"
```

### Path A: upstream only added commits

`$OLD_BASE` is still an ancestor of the new `athei/cx-26-patched`. Merge it directly:

```sh
git merge athei/cx-26-patched
```

Resolve conflicts, run the build and test gates (below), then `git push origin main` (a plain fast-forward push). To back out before pushing: `git merge --abort`, or after the merge commit exists, `git reset --hard origin/main` (nothing is published yet).

### Path B: upstream rewrote its history

`$OLD_BASE` is no longer an ancestor, so a plain merge would replay every old patch against rewritten upstream commits and conflict endlessly. Rebasing `main` itself would rewrite published history. Instead, rebase the local patches onto the new upstream in a scratch branch that is never pushed, validate it, then record it on `main` as a merge whose resulting tree is the validated rebased tree. This is how `d0953441aba` was landed.

```sh
git switch -c sync-scratch main               # local only, never pushed
git rebase --onto athei/cx-26-patched $OLD_BASE sync-scratch
```

Resolve each conflict (`git rebase --abort` returns to the starting point), then run the build and test gates on `sync-scratch`. When it passes:

```sh
git switch main
git merge --no-ff --no-commit -s ours sync-scratch   # records both parents, keeps main's tree for now
git read-tree -u --reset sync-scratch                # working tree and index become the validated tree
test "$(git write-tree)" = "$(git rev-parse 'sync-scratch^{tree}')" && echo "tree matches"
git commit -m "Merge sync-scratch: rebase onto athei/cx-26-patched <new tip>"
```

Check the result before publishing:

```sh
git show -s --format=%p HEAD                          # two parents: the published main tip, then the rebased tip
git merge-base --is-ancestor athei/cx-26-patched main && echo "upstream contained in main"
git diff --stat sync-scratch main                     # empty
git push origin main                                  # fast-forward: the published tip is parent 1
git branch -D sync-scratch
```

The next update is then Path A, because the new upstream tip is an ancestor of `main`.

### Gates before pushing

Build with `./build-macos-x86_64.sh` (out-of-tree), run the tests that cover the files that conflicted, and try the resulting `ntdll` in a disposable prefix before replacing any deployed runtime. Then update "Current upstream base" in this file in a follow-up commit on `main`.
