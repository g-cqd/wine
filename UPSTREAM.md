# Keeping this fork current

The upstream `cx-26-patched` branch stays unchanged. Local NFSMW patches live on `nfsmw-macos`. The pinned base and verification limits are documented alongside the patches.

## Clone once

```sh
git clone git@github.com:g-cqd/wine.git
cd wine
git remote add upstream https://github.com/athei/wine.git
git fetch origin
git switch --track origin/nfsmw-macos
```

## Test an upstream update

Start with a clean working tree. Choose a new branch name for each attempt.

```sh
git fetch upstream --tags
git switch -c nfsmw-upstream-update origin/nfsmw-macos
git rebase upstream/cx-26-patched
```

Resolve each conflict and run the project's build and test gates, including the NFSMW regressions, before trying the updated runtime in a disposable player folder. Update the pinned revision and verification notes. `git rebase --abort` returns an interrupted rebase to its starting point.

Push the tested candidate as a new branch for review:

```sh
git push -u origin nfsmw-upstream-update
```

Keep the existing `nfsmw-macos` branch and installed runtime available until the candidate is verified. Replacing the patch branch after a rebase rewrites history; coordinate with other users and use `--force-with-lease` only for that deliberate replacement. Never force-push the upstream `cx-26-patched` branch.
